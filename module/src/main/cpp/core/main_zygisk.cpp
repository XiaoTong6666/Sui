#include <zygisk.hpp>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <limits>
#include <logging.h>
#include <cstdio>
#include <sys/socket.h>
#include <bit>
#include <unistd.h>
#include <config.h>
#include <dex_file.h>
#include <memory.h>
#include <sys/mman.h>
#include <misc.h>
#include <nativehelper/scoped_utf_chars.h>
#include <fcntl.h>
#include <cinttypes>
#include <memory>
#include <mutex>
#include <algorithm>
#include <socket.h>
#include <sys/system_properties.h>
#include "system_server.h"
#include "patcher_main.h"
#include "settings_process.h"
#include "manager_process.h"

inline constexpr auto kProcessNameMax = 256;

static void CopyString(char* dst, size_t dst_size, const char* src) {
    if (dst_size == 0) {
        return;
    }
    if (src == nullptr) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_size, "%s", src);
}

enum Identity : int {

    IGNORE = 0,
    SYSTEM_SERVER = 1,
    SYSTEM_UI = 2,
    SETTINGS = 3,
};

class ZygiskModule : public zygisk::ModuleBase {
   public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        char process_name[kProcessNameMax]{0};
        char app_data_dir[PATH_MAX]{0};

        if (args->nice_name) {
            ScopedUtfChars niceName{env_, args->nice_name};
            CopyString(process_name, sizeof(process_name), niceName.c_str());
        }

        if (args->app_data_dir) {
            ScopedUtfChars appDataDir{env_, args->app_data_dir};
            CopyString(app_data_dir, sizeof(app_data_dir), appDataDir.c_str());
        }

        if (process_name[0] == '\0' && app_data_dir[0] != '\0') {
            auto p = strrchr(app_data_dir, '/');
            if (p != nullptr) {
                CopyString(process_name, sizeof(process_name), p + 1);
            }
        }

        LOGI("SuiZygisk: preAppSpecialize: uid=%d, process=%s, app_data_dir=%s", args->uid,
             process_name, app_data_dir);

        InitCompanion(false, args->uid, process_name);

        if (whoami == Identity::IGNORE) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }

        UmountApexAdbd();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        LOGD("postAppSpecialize");

        if (whoami == Identity::IGNORE) {
            return;
        }

        LOGI("SuiZygisk: postAppSpecialize start for identity %d", whoami);
        char app_data_dir[PATH_MAX]{0};

        if (args->app_data_dir) {
            ScopedUtfChars appDataDir{env_, args->app_data_dir};
            CopyString(app_data_dir, sizeof(app_data_dir), appDataDir.c_str());
            LOGI("SuiZygisk: app_data_dir is %s", app_data_dir);
        } else {
            LOGI("SuiZygisk: app_data_dir is NULL");
        }

        if (whoami == Identity::SETTINGS) {
            LOGI("SuiZygisk: Calling Settings::main");
            Settings::main(env_, app_data_dir, dex.get());
        } else if (whoami == Identity::SYSTEM_UI) {
            LOGI("SuiZygisk: Calling Manager::main");
            Manager::main(env_, app_data_dir, dex.get());
        }
        LOGI("SuiZygisk: postAppSpecialize finished");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        LOGD("preServerSpecialize");

        InitCompanion(true, args->uid);
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        LOGD("postServerSpecialize");

        if (__system_property_find("ro.vendor.product.ztename")) {
            auto* process = env_->FindClass("android/os/Process");
            auto* set_argv0 = env_->GetStaticMethodID(process, "setArgV0", "(Ljava/lang/String;)V");
            env_->CallStaticVoidMethod(process, set_argv0, env_->NewStringUTF("system_server"));
        }

        SystemServer::main(env_, dex.get());
    }

   private:
    zygisk::Api* api_{};
    JNIEnv* env_{};

    Identity whoami = Identity::IGNORE;
    std::unique_ptr<Dex> dex;

    void InitCompanion(bool is_system_server, int uid, const char* process_name = nullptr) {
        auto companion = api_->connectCompanion();
        if (companion == -1) {
            LOGE("Zygote: failed to connect to companion");
            return;
        }

        if (is_system_server) {
            write_int(companion, 1);
            whoami = Identity::SYSTEM_SERVER;
        } else {
            write_int(companion, 0);
            write_int(companion, uid);
            write_full(companion, process_name, kProcessNameMax);
            whoami = static_cast<Identity>(read_int(companion));
        }

        if (whoami != Identity::IGNORE) {
            auto fd = recv_fd(companion);
            auto size = (size_t)read_int(companion);

            if (whoami == Identity::SETTINGS) {
                LOGI("Zygote: in Settings");
            } else if (whoami == Identity::SYSTEM_UI) {
                LOGI("Zygote: in SystemUi");
            } else {
                LOGI("Zygote: in SystemServer");
            }

            LOGI("Zygote: dex fd is %d, size is %" PRIdPTR, fd, size);
            dex = std::make_unique<Dex>(fd, size);
            close(fd);
        }

        close(companion);
    }
};

static int dex_mem_fd = -1;
static size_t dex_size = 0;
static std::mutex companion_prepare_mutex;
static bool companion_prepared = false;

struct AppIdentity {
    char package[kProcessNameMax]{};
    uid_t uid = static_cast<uid_t>(-1);
    char process[kProcessNameMax]{};
};

static AppIdentity manager, settings;
static std::mutex identity_mutex;

static bool ReadLine(const uint8_t* bytes, size_t size, size_t& offset, char* value,
                     size_t value_size) {
    if (offset >= size || value_size == 0) {
        return false;
    }

    size_t end = offset;
    while (end < size && bytes[end] != '\r' && bytes[end] != '\n') {
        ++end;
    }

    size_t length = end - offset;
    if (length == 0 || length >= value_size) {
        return false;
    }
    memcpy(value, bytes + offset, length);
    value[length] = '\0';

    while (end < size && (bytes[end] == '\r' || bytes[end] == '\n')) {
        ++end;
    }
    offset = end;
    return true;
}

static bool ReadApplicationInfo(const char* name, AppIdentity& identity) {
    char buf[PATH_MAX];
    snprintf(buf, PATH_MAX, "/data/adb/modules/%s/%s", ZYGISK_MODULE_ID, name);
    auto file = Buffer(buf);
    auto bytes = file.data();
    auto size = file.size();
    if (bytes == nullptr || size == 0) {
        LOGW("ReadApplicationInfo: failed to read %s", buf);
        return false;
    }

    char uid_string[32]{};
    size_t offset = 0;
    if (!ReadLine(bytes, size, offset, identity.package, sizeof(identity.package)) ||
        !ReadLine(bytes, size, offset, uid_string, sizeof(uid_string)) ||
        !ReadLine(bytes, size, offset, identity.process, sizeof(identity.process))) {
        LOGW("ReadApplicationInfo: invalid data in %s", buf);
        return false;
    }

    char* end = nullptr;
    errno = 0;
    unsigned long uid = strtoul(uid_string, &end, 10);
    if (errno != 0 || end == uid_string || *end != '\0' ||
        uid > std::numeric_limits<uid_t>::max()) {
        LOGW("ReadApplicationInfo: invalid uid in %s", buf);
        return false;
    }
    identity.uid = static_cast<uid_t>(uid);
    return true;
}

static void RefreshApplicationInfo(AppIdentity& manager_snapshot, AppIdentity& settings_snapshot) {
    std::lock_guard lock(identity_mutex);

    AppIdentity identity;
    if (ReadApplicationInfo(MANAGER_APPLICATION_INFO, identity)) {
        manager = identity;
    }
    identity = {};
    if (ReadApplicationInfo(SETTINGS_APPLICATION_INFO, identity)) {
        settings = identity;
    }

    manager_snapshot = manager;
    settings_snapshot = settings;
}

static bool PrepareCompanion() {
    bool result = false;
    void* addr = MAP_FAILED;

    auto path = "/data/adb/modules/" ZYGISK_MODULE_ID "/" DEX_NAME;
    int fd = open(path, O_RDONLY);
    int prepared_fd = -1;
    ssize_t size = -1;
    AppIdentity manager_snapshot, settings_snapshot;

    if (fd == -1) {
        PLOGE("open %s", path);
        goto cleanup;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size <= 0) {
        PLOGE("lseek %s", path);
        goto cleanup;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        PLOGE("lseek %s", path);
        goto cleanup;
    }

    LOGD("Companion: dex size is %" PRIdPTR, size);

    prepared_fd = CreateSharedMem("sui.dex", size);
    if (prepared_fd == -1) {
        PLOGE("CreateSharedMem %s", path);
        goto cleanup;
    }
    addr = mmap(nullptr, size, PROT_WRITE, MAP_SHARED, prepared_fd, 0);
    if (addr == MAP_FAILED) {
        PLOGE("mmap %s", path);
        goto cleanup;
    }
    if (read_full(fd, addr, size) != 0) {
        PLOGE("read %s", path);
        goto cleanup;
    }
    munmap(addr, size);
    addr = MAP_FAILED;
    if (SetSharedMemProt(prepared_fd, PROT_READ) != 0) {
        PLOGE("SetSharedMemProt %s", path);
        goto cleanup;
    }

    dex_mem_fd = prepared_fd;
    dex_size = size;
    prepared_fd = -1;

    LOGI("Companion: dex fd is %d", dex_mem_fd);

    RefreshApplicationInfo(manager_snapshot, settings_snapshot);

    LOGI("Companion: SystemUI %s %d %s", manager_snapshot.package, manager_snapshot.uid,
         manager_snapshot.process);
    LOGI("Companion: Settings %s %d %s", settings_snapshot.package, settings_snapshot.uid,
         settings_snapshot.process);

    result = true;

cleanup:
    if (fd != -1)
        close(fd);
    if (prepared_fd != -1)
        close(prepared_fd);
    if (addr != MAP_FAILED)
        munmap(addr, size);

    return result;
}

static void CompanionEntry(int socket) {
    bool prepared;
    {
        std::lock_guard lock(companion_prepare_mutex);
        if (!companion_prepared) {
            companion_prepared = PrepareCompanion();
        }
        prepared = companion_prepared;
    }
    if (!prepared) {
        LOGE("PrepareCompanion failed, dropping connection");
        close(socket);
        return;
    }

    AppIdentity manager_snapshot, settings_snapshot;
    RefreshApplicationInfo(manager_snapshot, settings_snapshot);

    char process_name[kProcessNameMax]{0};
    Identity whoami;

    int is_system_server = read_int(socket) == 1;
    if (is_system_server != 0) {
        whoami = Identity::SYSTEM_SERVER;
    } else {
        int uid = read_int(socket);
        read_full(socket, process_name, kProcessNameMax);

        LOGI("SuiCompanion: Checking app: uid=%d, process=%s", uid, process_name);
        if (uid == manager_snapshot.uid && strcmp(process_name, manager_snapshot.process) == 0) {
            whoami = Identity::SYSTEM_UI;
            LOGI("SuiCompanion: Matched SYSTEM_UI!");
        } else if (uid == settings_snapshot.uid &&
                   strcmp(process_name, settings_snapshot.process) == 0) {
            whoami = Identity::SETTINGS;
            LOGI("SuiCompanion: Matched SETTINGS!");
        } else {
            whoami = Identity::IGNORE;
        }

        write_int(socket, whoami);
    }

    if (whoami != Identity::IGNORE) {
        send_fd(socket, dex_mem_fd);
        write_int(socket, dex_size);
    }

    close(socket);
}

REGISTER_ZYGISK_MODULE(ZygiskModule)

REGISTER_ZYGISK_COMPANION(CompanionEntry)
