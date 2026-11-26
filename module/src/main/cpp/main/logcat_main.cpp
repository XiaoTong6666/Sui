/*
 * This file is part of Sui.
 *
 * Sui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sui is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Sui.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2021-2026 Sui Contributors
 */

// Stand-alone native logd reader. Private liblog APIs are loaded at runtime
// so the collector can outlive the Java daemon without a shell logcat process.
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr size_t kLogEntryMax = 5 * 1024;
constexpr off_t kRotateBytes = 1024 * 1024;
constexpr const char* kProcessName = "sui_logcat";
// Sui-owned code uses one tag with the component in the message.
// The shared Shizuku API and Rish retain their Android log tags. Keep the
// complete pre-migration filter set as well, so a running old process or
// an app still on the old build cannot silently lose its logs during upgrade.
constexpr std::string_view kSuiTag = "Sui";
constexpr std::string_view kCompatibilityTags[] = {
    "SuiDaemon",
    "SuiServer",
    "SuiSystemServer",
    "SuiManager",
    "SuiSettings",
    "SuiShortcut",
    "SuiApk",
    "SuiInstaller",
    "SuiUninstaller",
    "SuiConfirmationDialog",
    "SuiSystemDialogRootView",
    "SuiBridgeDebug",
    "SuiViewModel",
    "SuiShortcutRPC",
    "SQLiteDataBaseRemoteCompat",
    "AppLabelCache",
    "AppIconCache",
    "LayoutInflaterKt",
    "TextUtilsCompat",
    "Service",
    "ClientRecord",
    "UserServiceManager",
    "UserServiceRecord",
    "ConfigManager",
    "ConfigPackageEntry",
    "RemoteProcessHolder",
    "TransferThread",
    "SuiUserServiceStarter",
    "RISH",
    "RISHConfig",
    "RishHost",
    "RishService",
    "RishTerminal",
};

// Layout from Android liblog's logger_entry / AndroidLogEntry. Keep this
// private ABI isolated here rather than exposing it in Sui's shared headers.
struct LoggerEntry {
    uint16_t len;
    uint16_t hdr_size;
    int32_t pid;
    uint32_t tid;
    uint32_t sec;
    uint32_t nsec;
    uint32_t lid;
    uint32_t uid;
};
struct LogMessage {
    union alignas(4) {
        unsigned char buf[kLogEntryMax + 1];
        LoggerEntry entry;
    };
};
struct DecodedEntry {
    time_t tv_sec;
    long tv_nsec;
    android_LogPriority priority;
    int32_t uid;
    int32_t pid;
    int32_t tid;
    const char* tag;
    size_t tagLen;
    size_t messageLen;
    const char* message;
};

// Android's private liblog decoder ABI changed twice. These are the exact
// AndroidLogEntry layouts from AOSP log/logprint.h, not the on-wire logger
// entry layout (whose hdr_size is supplied by liblog at runtime).
// Android 6 / API 23: no uid, no tagLen.
// https://android.googlesource.com/platform/system/core/+/android-6.0.1_r11/include/log/logprint.h#47
struct DecodedEntryM {
    time_t tv_sec;
    long tv_nsec;
    android_LogPriority priority;
    int32_t pid;
    int32_t tid;
    const char* tag;
    size_t messageLen;
    const char* message;
};

// Android 7 / API 24-25: uid added, but tagLen is not present yet.
// https://android.googlesource.com/platform/system/core/+/android-7.0.0_r1/include/log/logprint.h#52
// Android 8 adds tagLen to the decoded entry:
// https://android.googlesource.com/platform/system/core/+/android-8.0.0_r1/liblog/include/log/logprint.h#56
struct DecodedEntryN {
    time_t tv_sec;
    long tv_nsec;
    android_LogPriority priority;
    int32_t uid;
    int32_t pid;
    int32_t tid;
    const char* tag;
    size_t messageLen;
    const char* message;
};

static_assert(sizeof(DecodedEntryM) <= sizeof(DecodedEntry));
static_assert(sizeof(DecodedEntryN) <= sizeof(DecodedEntry));
static_assert(sizeof(LoggerEntry) == 28, "The v4 logger header must remain 28 bytes");

int device_sdk() {
    char value[PROP_VALUE_MAX]{};
    if (__system_property_get("ro.build.version.sdk", value) <= 0)
        return -1;
    char* end = nullptr;
    long sdk = strtol(value, &end, 10);
    return end != value && *end == '\0' && sdk >= 23 && sdk <= INT_MAX ? static_cast<int>(sdk) : -1;
}

// The log buffer IDs are not stable across the early Android releases:
// M:    0..4 + 5(kernel)
// N/O:  0..4 + 5(security) + 6(kernel)
// P+:   0..4 + 5(stats) + 6(security) + 7(kernel)
int max_log_id(int sdk) {
    return sdk == 23 ? 5 : sdk <= 27 ? 6 : 7;
}

bool is_binary_buffer(int sdk, uint32_t id) {
    if (id == 2)
        return true;  // events on every supported release
    if (sdk == 23)
        return false;
    if (sdk <= 27)
        return id == 5;         // security, NOT kernel
    return id == 5 || id == 6;  // stats + security
}
struct LoggerList;
struct Logger;
struct EventTagMap;

struct LogApi {
    void* handle = nullptr;
    LoggerList* (*alloc)(int, unsigned int, pid_t) = nullptr;
    void (*free_list)(LoggerList*) = nullptr;
    Logger* (*open)(LoggerList*, int) = nullptr;
    int (*read)(LoggerList*, LogMessage*) = nullptr;
    // Opaque decoder output: the actual AndroidLogEntry structure depends on
    // the device's API level and is selected by decode_entry().
    int (*text)(LoggerEntry*, void*) = nullptr;
    int (*binary)(LoggerEntry*, void*, const EventTagMap*, char*, int) = nullptr;
    EventTagMap* (*open_events)(const char*) = nullptr;
    void (*close_events)(EventTagMap*) = nullptr;

    bool load() {
        handle = dlopen("liblog.so", RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            return false;
        alloc = reinterpret_cast<decltype(alloc)>(dlsym(handle, "android_logger_list_alloc"));
        free_list =
            reinterpret_cast<decltype(free_list)>(dlsym(handle, "android_logger_list_free"));
        open = reinterpret_cast<decltype(open)>(dlsym(handle, "android_logger_open"));
        read = reinterpret_cast<decltype(read)>(dlsym(handle, "android_logger_list_read"));
        text = reinterpret_cast<decltype(text)>(dlsym(handle, "android_log_processLogBuffer"));
        binary =
            reinterpret_cast<decltype(binary)>(dlsym(handle, "android_log_processBinaryLogBuffer"));
        open_events =
            reinterpret_cast<decltype(open_events)>(dlsym(handle, "android_openEventTagMap"));
        close_events =
            reinterpret_cast<decltype(close_events)>(dlsym(handle, "android_closeEventTagMap"));
        // Binary event decoding must be available or -b all is not preserved.
        return alloc && free_list && open && read && text && binary && open_events;
    }
};

bool is_tracked_tag(std::string_view tag) {
    if (tag == kSuiTag)
        return true;
    for (auto compatible_tag : kCompatibilityTags) {
        if (tag == compatible_tag)
            return true;
    }
    return false;
}

bool write_all(int fd, const char* data, size_t length) {
    while (length) {
        ssize_t n = write(fd, data, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        data += n;
        length -= static_cast<size_t>(n);
    }
    return true;
}

class RotatingLog {
   public:
    explicit RotatingLog(std::string directory)
        : path_(std::move(directory) + "/sui.log"), backup_(path_ + ".1") {
    }

    ~RotatingLog() {
        if (fd_ >= 0)
            close(fd_);
    }

    bool open_current() {
        if (fd_ >= 0)
            close(fd_);
        fd_ = open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
        if (fd_ < 0)
            return false;
        struct stat st{};
        written_ = fstat(fd_, &st) == 0 ? st.st_size : 0;
        return true;
    }

    bool append(const char* data, size_t length) {
        if (fd_ < 0 && !open_current())
            return false;
        if (written_ >= kRotateBytes) {
            close(fd_);
            fd_ = -1;
            unlink(backup_.c_str());
            if (rename(path_.c_str(), backup_.c_str()) < 0 && errno != ENOENT) {
                return false;
            }
            if (!open_current())
                return false;
        }
        if (!write_all(fd_, data, length)) {
            close(fd_);
            fd_ = -1;
            return false;
        }
        written_ += static_cast<off_t>(length);
        return true;
    }

   private:
    std::string path_;
    std::string backup_;
    int fd_ = -1;
    off_t written_ = 0;
};

bool append_entry(RotatingLog& log, const DecodedEntry& entry) {
    struct tm time_info{};
    if (!localtime_r(&entry.tv_sec, &time_info))
        return false;
    char prefix[256];
    char priority = '?';
    constexpr char kPriorities[] = "??VDIWEFS";
    auto numeric = static_cast<unsigned>(entry.priority);
    if (numeric < sizeof(kPriorities) - 1)
        priority = kPriorities[numeric];
    int n = snprintf(prefix, sizeof(prefix),
                     "%02d-%02d %02d:%02d:%02d.%03ld %5d %5d %c %-8.*s: ", time_info.tm_mon + 1,
                     time_info.tm_mday, time_info.tm_hour, time_info.tm_min, time_info.tm_sec,
                     entry.tv_nsec / 1000000, entry.pid, entry.tid, priority,
                     static_cast<int>(entry.tagLen), entry.tag);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(prefix))
        return false;

    // Match threadtime: each physical line of a multiline log gets its own
    // metadata prefix, without truncating the message.
    const char* cursor = entry.message;
    const char* end = cursor + entry.messageLen;
    do {
        const char* newline = static_cast<const char*>(memchr(cursor, '\n', end - cursor));
        const char* finish = newline ? newline : end;
        std::string line(prefix, static_cast<size_t>(n));
        line.append(cursor, finish - cursor);
        line.push_back('\n');
        if (!log.append(line.data(), line.size()))
            return false;
        if (!newline)
            break;
        cursor = newline + 1;
    } while (cursor < end);
    return true;
}

template <typename LegacyEntry>
void normalize_legacy_entry(const LegacyEntry& source, DecodedEntry& target) {
    target.tv_sec = source.tv_sec;
    target.tv_nsec = source.tv_nsec;
    target.priority = source.priority;
    target.pid = source.pid;
    target.tid = source.tid;
    target.tag = source.tag;
    // Legacy AOSP decoders provide NUL-terminated tags rather than tagLen.
    // https://android.googlesource.com/platform/system/core/+/android-6.0.1_r11/liblog/logprint.c#418
    target.tagLen = source.tag ? strnlen(source.tag, kLogEntryMax) : 0;
    target.messageLen = source.messageLen;
    target.message = source.message;
}

int decode_entry(LogApi& api, LoggerEntry* raw, int sdk, EventTagMap* event_tags, char* buffer,
                 int buffer_size, DecodedEntry& result) {
    const bool binary = is_binary_buffer(sdk, raw->lid);
    auto decode = [&](void* entry) {
        return binary ? api.binary(raw, entry, event_tags, buffer, buffer_size)
                      : api.text(raw, entry);
    };
    int rc;
    if (sdk == 23) {
        DecodedEntryM old{};
        rc = decode(&old);
        if (rc == 0) {
            normalize_legacy_entry(old, result);
            result.uid = -1;
        }
    } else if (sdk <= 25) {
        DecodedEntryN old{};
        rc = decode(&old);
        if (rc == 0) {
            normalize_legacy_entry(old, result);
            result.uid = old.uid;
        }
    } else {
        rc = decode(&result);
    }
    // Normalize once for filtering and threadtime formatting on every SDK.
    if (rc == 0 && result.tag && result.tagLen && result.tag[result.tagLen - 1] == '\0') {
        --result.tagLen;
    }
    return rc;
}

int collect(const std::string& directory, LogApi& api, int sdk) {
    RotatingLog file(directory);
    if (!file.open_current())
        return 1;
    // M/N logcat passes EVENT_TAG_MAP_FILE; M requires a path for open().
    // https://android.googlesource.com/platform/system/core/+/android-6.0.1_r11/logcat/logcat.cpp#157
    // https://android.googlesource.com/platform/system/core/+/android-6.0.1_r11/liblog/event_tag_map.c#74
    // O already accepts null and loads platform tag maps. Keep the explicit
    // path through API 27 for compatibility with the existing collector.
    // https://android.googlesource.com/platform/system/core/+/android-8.0.0_r1/liblog/event_tag_map.cpp#404
    EventTagMap* event_tags = api.open_events(sdk <= 27 ? "/system/etc/event-log-tags" : nullptr);
    // A missing map is permitted: binary entries still receive numeric tags.
    unsigned int tail = 1;  // Preserve the previous logcat -T 1 start.
    for (;;) {
        LoggerList* readers = api.alloc(0, tail, 0);
        tail = 10;  // Reconnect with some history after a logd restart.
        if (!readers) {
            sleep(1);
            continue;
        }
        int opened = 0;
        // Equivalent to -b all, but LOG_ID_MAX and its meanings depend on SDK.
        for (int id = 0; id <= max_log_id(sdk); ++id) {
            if (api.open(readers, id))
                ++opened;
        }
        if (opened == 0) {
            api.free_list(readers);
            if (event_tags && api.close_events)
                api.close_events(event_tags);
            return 1;
        }

        LogMessage msg{};
        char event_buffer[8192];
        while (api.read(readers, &msg) > 0) {
            DecodedEntry entry{};
            // M delivers a v3 (24-byte) raw header; N can deliver v4
            // (28 bytes) to privileged readers, v3 otherwise. Never access
            // raw uid unconditionally: it overlaps the payload with v3.
            // https://android.googlesource.com/platform/system/core/+/android-6.0.1_r11/logd/LogBufferElement.cpp#193
            // https://android.googlesource.com/platform/system/core/+/android-7.0.0_r1/logd/LogBufferElement.cpp#202
            if (msg.entry.hdr_size < 24 || msg.entry.hdr_size + msg.entry.len > sizeof(msg.buf))
                continue;
            int rc = decode_entry(api, &msg.entry, sdk, event_tags, event_buffer,
                                  sizeof(event_buffer), entry);
            if (rc < 0 || !entry.tag)
                continue;
            // Error reports from this reader are intentionally tagged Sui.
            // Exclude our own PID to avoid retrying an unwritable log file
            // indefinitely when disk space runs out.
            if (entry.pid == getpid())
                continue;
            if (!is_tracked_tag(std::string_view(entry.tag, entry.tagLen)))
                continue;
            if (!append_entry(file, entry)) {
                // Visible in logcat, but excluded from our own output above.
                // Limit repeated reports while the filesystem is unwritable.
                static time_t last_warning = 0;
                time_t now = time(nullptr);
                if (now - last_warning >= 60) {
                    last_warning = now;
                    __android_log_print(ANDROID_LOG_ERROR, "Sui",
                                        "[Logcat] Native log collector failed to write: %d", errno);
                }
            }
        }
        api.free_list(readers);
        sleep(1);
    }
}

bool get_running_pid(const std::string& directory, pid_t& pid) {
    std::string path = directory + "/logcat.pid";
    FILE* f = fopen(path.c_str(), "r");
    if (!f)
        return false;
    long parsed = 0;
    bool ok = fscanf(f, "%ld", &parsed) == 1 && parsed > 1;
    fclose(f);
    if (!ok)
        return false;
    pid = static_cast<pid_t>(parsed);
    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    f = fopen(comm_path.c_str(), "r");
    if (!f)
        return false;
    char name[64]{};
    ok = fgets(name, sizeof(name), f) && strncmp(name, kProcessName, strlen(kProcessName)) == 0 &&
         name[strlen(kProcessName)] == '\n';
    fclose(f);
    if (!ok)
        return false;
    // Match the PID, process name and log directory, including across upgrades.
    // The flock lock remains authoritative for preventing duplicate readers.
    std::string argv_path = "/proc/" + std::to_string(pid) + "/cmdline";
    f = fopen(argv_path.c_str(), "rb");
    if (!f)
        return false;
    char argv_bytes[PATH_MAX + 128]{};
    size_t count = fread(argv_bytes, 1, sizeof(argv_bytes) - 1, f);
    fclose(f);
    const char* first_end = static_cast<const char*>(memchr(argv_bytes, '\0', count));
    if (!first_end)
        return false;
    const char* cmd = first_end + 1;
    if (cmd >= argv_bytes + count)
        return false;
    const char* cmd_end =
        static_cast<const char*>(memchr(cmd, '\0', static_cast<size_t>(argv_bytes + count - cmd)));
    if (!cmd_end || std::string_view(cmd, cmd_end - cmd) != "run")
        return false;
    const char* dir = cmd_end + 1;
    if (dir >= argv_bytes + count)
        return false;
    const char* dir_end =
        static_cast<const char*>(memchr(dir, '\0', static_cast<size_t>(argv_bytes + count - dir)));
    return dir_end && std::string_view(dir, dir_end - dir) == directory;
}

int start_collector(const std::string& directory, int sdk) {
    umask(0077);
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST)
        return 1;
    chmod(directory.c_str(), 0700);
    std::string lock_path = directory + "/logcat.lock";
    int lock_fd = open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        return 1;
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        int flock_errno = errno;
        close(lock_fd);
        return flock_errno == EWOULDBLOCK ? 0 : 1;
    }
    LogApi api;
    if (!api.load()) {
        __android_log_print(ANDROID_LOG_ERROR, "Sui", "[Logcat] Native liblog reader unavailable");
        close(lock_fd);
        return 1;
    }
    prctl(PR_SET_NAME, kProcessName);
    std::string pid_path = directory + "/logcat.pid";
    int pid_fd = open(pid_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (pid_fd >= 0) {
        char text[40];
        int n = snprintf(text, sizeof(text), "%ld\n", static_cast<long>(getpid()));
        write_all(pid_fd, text, n);
        close(pid_fd);
    }
    int rc = collect(directory, api, sdk);
    unlink(pid_path.c_str());
    close(lock_fd);
    return rc;
}
}  // namespace

int sui_logcat_main(int argc, char** argv) {
    if (argc != 3 || geteuid() != 0)
        return 1;
    const std::string directory(argv[2]);
    // Only root-owned persistent directories are allowed by the caller.
    if (directory.compare(0, strlen("/data/adb/"), "/data/adb/") != 0)
        return 1;
    const std::string command(argv[1]);
    if (command == "run") {
        int sdk = device_sdk();
        if (sdk < 23)
            return 1;
        return start_collector(directory, sdk);
    }
    if (command == "status" || command == "stop") {
        pid_t pid = -1;
        if (!get_running_pid(directory, pid)) {
            return command == "status" ? 1 : 0;
        }
        return command == "stop" ? (kill(pid, SIGTERM) == 0 ? 0 : 1) : 0;
    }
    return 1;
}
