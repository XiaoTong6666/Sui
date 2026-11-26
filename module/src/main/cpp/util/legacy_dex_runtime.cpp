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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Copyright (c) 2021-2026 Sui Contributors
 */

#define SUI_LOG_COMPONENT "LegacyDex"
#include <legacy_dex_runtime.h>
#include <logging.h>
#include <misc.h>

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace sui::legacy {
namespace {

constexpr const char* kParent = "/data/system";
constexpr const char* kPrefix = ".sui_rt_";
constexpr uid_t kSystemUid = 1000;

std::string BootId() {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return {};
    char value[40]{};
    ssize_t bytes = read_eintr(fd, value, sizeof(value) - 1);
    close(fd);
    if (bytes < 36)
        return {};
    for (size_t i = 0; i < 36; ++i) {
        char c = value[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return {};
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return {};
        }
    }
    return std::string(value, 36);
}

bool RandomSuffix(char suffix[17]) {
    unsigned char bytes[8]{};
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool ok = read_full(fd, bytes, sizeof(bytes)) == 0;
    close(fd);
    if (!ok)
        return false;
    constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        suffix[i * 2] = hex[bytes[i] >> 4];
        suffix[i * 2 + 1] = hex[bytes[i] & 15];
    }
    suffix[16] = '\0';
    return true;
}

bool ValidRuntimeName(const char* name) {
    if (strncmp(name, kPrefix, strlen(kPrefix)) != 0 || strlen(name) != strlen(kPrefix) + 16)
        return false;
    for (const char* p = name + strlen(kPrefix); *p; ++p)
        if (!(('0' <= *p && *p <= '9') || ('a' <= *p && *p <= 'f')))
            return false;
    return true;
}

bool ExistingBootRuntime(const std::string& boot, std::string& dex_path, std::string& oat_dir) {
    int parent_fd = open(kParent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0)
        return false;
    DIR* parent = fdopendir(parent_fd);
    if (!parent) {
        close(parent_fd);
        return false;
    }
    bool found = false;
    struct dirent* entry;
    while ((entry = readdir(parent)) != nullptr) {
        if (!ValidRuntimeName(entry->d_name))
            continue;
        int dir = openat(parent_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dir < 0)
            continue;
        struct stat st{};
        bool valid = fstat(dir, &st) == 0 && st.st_uid == kSystemUid && (st.st_mode & 0777) == 0700;
        int marker = valid ? openat(dir, ".boot", O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
        if (marker < 0)
            valid = false;
        if (valid) {
            valid = fstat(marker, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == kSystemUid &&
                    (st.st_mode & 0777) == 0600;
            char recorded[40]{};
            valid = valid && read_eintr(marker, recorded, sizeof(recorded)) == 36 &&
                    std::string(recorded, 36) == boot;
        }
        if (marker >= 0)
            close(marker);
        int oat = valid ? openat(dir, "oat", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
        valid = valid && oat >= 0;
        if (valid)
            valid = fstat(oat, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == kSystemUid &&
                    (st.st_mode & 0777) == 0700;
        if (oat >= 0)
            close(oat);
        if (valid) {
            const std::string base = std::string(kParent) + "/" + entry->d_name;
            dex_path = base + "/sui.dex";
            oat_dir = base + "/oat";
            found = true;
        }
        close(dir);
        if (found)
            break;
    }
    closedir(parent);
    return found;
}

// ART outputs can be owned by system or root inside the validated private tree.
// Never follow links or descend into files owned by other UIDs.
bool RemoveOwnedContents(int dir_fd, unsigned depth) {
    int copy = dup(dir_fd);
    if (copy < 0)
        return false;
    DIR* dir = fdopendir(copy);
    if (!dir) {
        close(copy);
        return false;
    }
    bool success = true;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        struct stat st{};
        if (fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            (st.st_uid != kSystemUid && st.st_uid != 0)) {
            success = false;
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            if (unlinkat(dir_fd, entry->d_name, 0) != 0)
                success = false;
        } else if (S_ISLNK(st.st_mode)) {
            // Remove only the link itself; never follow its target.
            if (unlinkat(dir_fd, entry->d_name, 0) != 0)
                success = false;
        } else if (S_ISDIR(st.st_mode) && depth > 0) {
            int child =
                openat(dir_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0)
                success = false;
            else {
                bool empty = RemoveOwnedContents(child, depth - 1);
                close(child);
                if (!empty || unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR) != 0)
                    success = false;
            }
        } else {
            success = false;
        }
    }
    closedir(dir);
    return success;
}

}  // namespace

bool CreateDexRuntime(std::string& dex_path, std::string& oat_dir) {
    if (getuid() != kSystemUid)
        return false;
    std::string boot = BootId();
    if (boot.empty())
        return false;

    // One verified runtime per boot avoids accumulating dirs on system_server restart.
    if (ExistingBootRuntime(boot, dex_path, oat_dir))
        return true;

    for (int attempt = 0; attempt < 8; ++attempt) {
        char suffix[17]{};
        if (!RandomSuffix(suffix))
            return false;
        std::string directory = std::string(kParent) + "/" + kPrefix + suffix;
        if (mkdir(directory.c_str(), 0700) != 0) {
            if (errno == EEXIST)
                continue;
            PLOGE("mkdir legacy runtime");
            return false;
        }
        // Android 6 DexPathList requires a writable optimized directory.
        // https://android.googlesource.com/platform/libcore/+/android-6.0.1_r11/dalvik/src/main/java/dalvik/system/DexPathList.java#108
        oat_dir = directory + "/oat";
        std::string marker = directory + "/.boot";
        int fd = open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        bool valid = fd >= 0;
        if (valid) {
            valid = write_full(fd, boot.data(), boot.size()) == 0 && fsync(fd) == 0;
            close(fd);
        }
        if (valid)
            valid = mkdir(oat_dir.c_str(), 0700) == 0;
        if (valid) {
            dex_path = directory + "/sui.dex";
            return true;
        }
        unlink(marker.c_str());
        rmdir(oat_dir.c_str());
        rmdir(directory.c_str());
        return false;
    }
    return false;
}

void PruneStaleDexRuntimes(bool include_current) {
    if (getuid() != 0)
        return;
    const std::string boot = BootId();
    if (boot.empty())
        return;
    int parent_fd = open(kParent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0)
        return;
    DIR* parent = fdopendir(parent_fd);
    if (!parent) {
        close(parent_fd);
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(parent)) != nullptr) {
        if (!ValidRuntimeName(entry->d_name))
            continue;
        struct stat st{};
        if (fstatat(parent_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(st.st_mode) || st.st_uid != kSystemUid || (st.st_mode & 0777) != 0700)
            continue;
        int dir = openat(parent_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dir < 0)
            continue;
        char recorded[40]{};
        int marker = openat(dir, ".boot", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        ssize_t length = marker >= 0 ? read_eintr(marker, recorded, sizeof(recorded)) : -1;
        if (marker >= 0)
            close(marker);
        // Preserve the current boot and unknown directories; prune only verified old ones.
        if (length == 36 && (include_current || std::string(recorded, 36) != boot) &&
            RemoveOwnedContents(dir, 4) && unlinkat(parent_fd, entry->d_name, AT_REMOVEDIR) == 0) {
            LOGI("removed stale legacy DEX runtime");
        }
        close(dir);
    }

    // A previous release used a fixed /data/system/sui directory. Remove
    // only its recognized files after a reboot, never during live upgrade.
    const char* install_boot_marker = "/data/adb/sui/install_boot_id";
    int marker = open(install_boot_marker, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char install_boot[40]{};
    ssize_t bytes = marker >= 0 ? read_eintr(marker, install_boot, sizeof(install_boot)) : -1;
    if (marker >= 0)
        close(marker);
    if (include_current || (bytes >= 36 && std::string(install_boot, 36) != boot)) {
        int fixed = openat(parent_fd, "sui", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fixed >= 0) {
            struct stat st{};
            if (fstat(fixed, &st) == 0 && st.st_uid == kSystemUid && S_ISDIR(st.st_mode) &&
                (st.st_mode & 0777) == 0751) {
                for (const auto* name : {"sui.apk", "sui.dex"}) {
                    struct stat file{};
                    if (fstatat(fixed, name, &file, AT_SYMLINK_NOFOLLOW) == 0 &&
                        S_ISREG(file.st_mode) &&
                        file.st_uid == (strcmp(name, "sui.apk") == 0 ? 0 : kSystemUid))
                        unlinkat(fixed, name, 0);
                }
                int oat = openat(fixed, "oat", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                if (oat >= 0) {
                    struct stat oat_st{};
                    if (fstat(oat, &oat_st) == 0 && oat_st.st_uid == kSystemUid &&
                        S_ISDIR(oat_st.st_mode) && (oat_st.st_mode & 0777) == 0700 &&
                        RemoveOwnedContents(oat, 4))
                        unlinkat(fixed, "oat", AT_REMOVEDIR);
                    close(oat);
                }
                if (unlinkat(parent_fd, "sui", AT_REMOVEDIR) == 0)
                    LOGI("removed obsolete fixed legacy runtime");
            }
            close(fixed);
        }
    }
    closedir(parent);
}

}  // namespace sui::legacy
