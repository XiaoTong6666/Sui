#include <zygisk.hpp>
#include <cstring>
#include <cerrno>
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
#include <socket.h>
#include <sys/system_properties.h>
#include "system_server.h"
#include "patcher_main.h"
#include "settings_process.h"
#include "manager_process.h"

inline constexpr auto kProcessNameMax = 256;

enum Identity : int {

    IGNORE = 0,
    SYSTEM_SERVER = 1,
    SYSTEM_UI = 2,
    SETTINGS = 3,
};

class ZygiskModule : public zygisk::ModuleBase {

public:
    ZygiskModule() = default;
    ZygiskModule(zygisk::Api *api, JNIEnv *env) {
        api_ = api;
        env_ = env;
    }
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        char process_name[kProcessNameMax]{0};
        char app_data_dir[PATH_MAX]{0};

        if (args->nice_name) {
            ScopedUtfChars niceName{env_, args->nice_name};
            strcpy(process_name, niceName.c_str());
        }

#ifdef DEBUG
        if (args->app_data_dir) {
            ScopedUtfChars appDataDir{env_, args->app_data_dir};
            strcpy(app_data_dir, appDataDir.c_str());
        }
#endif
        LOGI("SuiZygisk: preAppSpecialize: uid=%d, process=%s, app_data_dir=%s", args->uid, process_name, app_data_dir);

        InitCompanion(false, args->uid, process_name);

        if (whoami == Identity::IGNORE) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }

        UmountApexAdbd();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGD("postAppSpecialize");

        if (whoami == Identity::IGNORE) {
            return;
        }

        char app_data_dir[PATH_MAX]{0};

        if (args->app_data_dir) {
            ScopedUtfChars appDataDir{env_, args->app_data_dir};
            strcpy(app_data_dir, appDataDir.c_str());
        }

        if (whoami == Identity::SETTINGS) {
            Settings::main(env_, app_data_dir, dex);
        } else if (whoami == Identity::SYSTEM_UI) {
            Manager::main(env_, app_data_dir, dex);
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        LOGD("preServerSpecialize");

        InitCompanion(true, args->uid);
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override {
        LOGD("postServerSpecialize");

        if (__system_property_find("ro.vendor.product.ztename")) {
            auto *process = env_->FindClass("android/os/Process");
            auto *set_argv0 = env_->GetStaticMethodID(
                    process, "setArgV0", "(Ljava/lang/String;)V");
            env_->CallStaticVoidMethod(process, set_argv0, env_->NewStringUTF("system_server"));
        }

        SystemServer::main(env_, dex);
    }

private:
    zygisk::Api *api_{};
    JNIEnv *env_{};

    Identity whoami = Identity::IGNORE;
    Dex *dex = nullptr;

    void InitCompanion(bool is_system_server, int uid, const char *process_name = nullptr) {
        LOGI("SuiCore-Companion: InitCompanion started. is_system_server=%d", is_system_server);
        auto companion = api_->connectCompanion();
        if (companion == -1) {
            LOGE("SuiCore-Companion: Failed to connect to companion socket from sui_daemon!");
            return;
        }
        LOGI("SuiCore-Companion: Companion socket connected, fd=%d", companion);

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
            auto size = (size_t) read_int(companion);

            // 新增的日志，用于立即查看收到的值
            LOGI("SuiCore-Companion: Received dex fd=%d, size=%zu", fd, size);

            // 新增的检查，判断 fd 是否有效
            if (fd < 0) {
                LOGE("SuiCore-Companion: Received invalid dex fd! Dex object will not be created.");
            } else {
                // 保留原有的上下文日志
                if (whoami == Identity::SETTINGS) {
                    LOGI("SuiCore-Companion: Context identified as Settings.");
                } else if (whoami == Identity::SYSTEM_UI) {
                    LOGI("SuiCore-Companion: Context identified as SystemUi.");
                } else {
                    LOGI("SuiCore-Companion: Context identified as SystemServer.");
                }

                // 执行核心逻辑
                dex = new Dex(fd, size);
                close(fd);

                // 新增的确认日志
                LOGI("SuiCore-Companion: Dex object created successfully.");
            }
        }

        close(companion);
    }
};

static int dex_mem_fd = -1;
static size_t dex_size = 0;
static uid_t manager_uid = -1, settings_uid = -1;
static char manager_process[kProcessNameMax], settings_process[kProcessNameMax];

static void ReadApplicationInfo(const char *package, uid_t &uid, char *process) {
    char buf[PATH_MAX];
    snprintf(buf, PATH_MAX, "/data/adb/modules/%s/%s", ZYGISK_MODULE_ID, package);
    auto file = Buffer(buf);
    auto bytes = file.data();
    auto size = file.size();
    for (int i = 0; i < size; ++i) {
        if (bytes[i] == '\n') {
            memset(process, 0, 256);
            memcpy(process, bytes + i + 1, size - i - 1);
            bytes[i] = 0;
            uid = atoi((char *) bytes);
            break;
        }
    }
}

static bool PrepareCompanion() {
    bool result = false;

    auto path = "/data/adb/modules/" ZYGISK_MODULE_ID "/" DEX_NAME;
    int fd = open(path, O_RDONLY);
    ssize_t size;

    if (fd == -1) {
        PLOGE("open %s", path);
        goto cleanup;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        PLOGE("lseek %s", path);
        goto cleanup;
    }
    lseek(fd, 0, SEEK_SET);

    LOGD("Companion: dex size is %" PRIdPTR, size);

    dex_mem_fd = CreateSharedMem("sui.dex", size);
    if (dex_mem_fd >= 0) {
        auto addr = (uint8_t *) mmap(nullptr, size, PROT_WRITE, MAP_SHARED, dex_mem_fd, 0);
        if (addr != MAP_FAILED) {
            read_full(fd, addr, size);
            dex_size = size;
            munmap(addr, size);
        }
        SetSharedMemProt(dex_mem_fd, PROT_READ);
    }

    LOGI("Companion: dex fd is %d", dex_mem_fd);

    ReadApplicationInfo(MANAGER_APPLICATION_ID, manager_uid, manager_process);
    ReadApplicationInfo(SETTINGS_APPLICATION_ID, settings_uid, settings_process);

    LOGI("Companion: SystemUI %d %s", manager_uid, manager_process);
    LOGI("Companion: Settings %d %s", settings_uid, settings_process);

    result = true;

    cleanup:
    if (fd != -1) close(fd);

    return result;
}

static void CompanionEntry(int socket) {
    static auto prepare = PrepareCompanion();

    char process_name[kProcessNameMax]{0};
    Identity whoami;

    int is_system_server = read_int(socket) == 1;
    if (is_system_server != 0) {
        whoami = Identity::SYSTEM_SERVER;
    } else {
        int uid = read_int(socket);
        read_full(socket, process_name, kProcessNameMax);

        LOGI("SuiCompanion: Checking app: uid=%d, process=%s", uid, process_name);
        if (uid == manager_uid && strcmp(process_name, manager_process) == 0) {
            whoami = Identity::SYSTEM_UI;
            LOGI("SuiCompanion: Matched SYSTEM_UI!");
        } else if (uid == settings_uid && strcmp(process_name, settings_process) == 0) {
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

// ... (文件前面的所有代码保持不变) ...

// 在文件末尾
REGISTER_ZYGISK_MODULE(ZygiskModule)

REGISTER_ZYGISK_COMPANION(CompanionEntry)

// ==========================================================
// [SUI STANDALONE 新增]
// 为 Standalone 模式添加入口点。
// 这个函数会被 libsui_loader.so 调用。
// ==========================================================
extern "C" [[gnu::visibility("default")]]
void sui_standalone_init(zygisk::Api *api, JNIEnv *env) {
    LOGI("SuiCore: sui_standalone_init invoked!"); // [日志]

    char process_name[256] = {0};
    FILE* fp = fopen("/proc/self/cmdline", "r");
    if (fp) {
        fread(process_name, 1, sizeof(process_name) - 1, fp);
        fclose(fp);
    }
    LOGI("SuiCore: Current process is '%s'", process_name); // [日志]

    if (strcmp(process_name, "system_server") != 0) {
        LOGI("SuiCore: Not in system_server, skipping."); // [日志]
        return;
    }

    LOGI("SuiCore: In system_server, performing manual initialization.");

    ZygiskModule module(api, env);

    LOGI("SuiCore: Calling preServerSpecialize..."); // [日志]
    module.preServerSpecialize(nullptr);
    LOGI("SuiCore: preServerSpecialize finished."); // [日志]

    LOGI("SuiCore: Calling postServerSpecialize..."); // [日志]
    module.postServerSpecialize(nullptr);
    LOGI("SuiCore: postServerSpecialize finished."); // [日志]

    LOGI("SuiCore: Manual initialization completed."); // [日志]
}