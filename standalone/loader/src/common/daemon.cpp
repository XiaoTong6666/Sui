#include "daemon.hpp"

#include <linux/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include "logging.hpp"
#include "socket_utils.hpp"

namespace zygiskd {
    static std::string TMP_PATH;

    void Init(const char *path) { TMP_PATH = path; }

    std::string GetTmpPath() { return TMP_PATH; }

    int Connect(uint8_t retry) {
        int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{
                .sun_family = AF_UNIX,
                .sun_path = {0},
        };

        // [SUI MOD] 强制指定 Socket 名称，与 Rust 端 (zygiskd.rs) 的 lp_select! 保持一致
        // Rust 端: lp_select!("/sui_32.sock", "/sui_64.sock")
#if defined(__LP64__)
        std::string socket_name = "/sui_64.sock";
#else
        std::string socket_name = "/sui_32.sock";
#endif

        // 拼接路径: TMP_PATH (通常是 /dev) + socket_name
        auto socket_path = TMP_PATH + socket_name;

        // 安全检查，防止路径过长溢出
        if (socket_path.length() >= sizeof(addr.sun_path)) {
            LOGE("Socket path too long: %s", socket_path.c_str());
            close(fd);
            return -1;
        }

        strcpy(addr.sun_path, socket_path.c_str());
        socklen_t socklen = sizeof(addr);

        while (retry--) {
            int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
            if (r == 0) return fd;
            if (retry) {
                // 降低一点日志级别，防止在启动初期疯狂刷屏
                LOGV("retrying to connect to sui_daemon, sleep 1s");
                sleep(1);
            }
        }

        close(fd);
        return -1;
    }

    bool PingHeartbeat() {
        UniqueFd fd = Connect(5);
        if (fd == -1) {
            // 修改日志内容，明确我们在连谁
            PLOGE("connecting to sui_daemon");
            return false;
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::PingHeartbeat);
        return true;
    }

    uint32_t GetProcessFlags(uid_t uid) {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("GetProcessFlags");
            return 0;
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags);
        socket_utils::write_u32(fd, uid);
        return socket_utils::read_u32(fd);
    }

    void CacheMountNamespace(pid_t pid) {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("CacheMountNamespace");
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace);
        socket_utils::write_u32(fd, (uint32_t) pid);
    }

    std::string UpdateMountNamespace(MountNamespace type) {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("UpdateMountNamespace");
            return "socket not connected";
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace);
        socket_utils::write_u8(fd, (uint8_t) type);
        uint32_t target_pid = socket_utils::read_u32(fd);
        int target_fd = (int) socket_utils::read_u32(fd);
        if (target_fd == 0) return "not cached yet";
        return "/proc/" + std::to_string(target_pid) + "/fd/" + std::to_string(target_fd);
    }

    std::vector<Module> ReadModules() {
        std::vector<Module> modules;
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("ReadModules");
            return modules;
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::ReadModules);
        size_t len = socket_utils::read_usize(fd);
        for (size_t i = 0; i < len; i++) {
            std::string name = socket_utils::read_string(fd);
            int module_fd = socket_utils::recv_fd(fd);
            modules.emplace_back(name, module_fd);
        }
        return modules;
    }

    int ConnectCompanion(size_t index) {
        int fd = Connect(1);
        if (fd == -1) {
            PLOGE("ConnectCompanion");
            return -1;
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket);
        socket_utils::write_usize(fd, index);
        if (socket_utils::read_u8(fd) == 1) {
            return fd;
        } else {
            close(fd);
            return -1;
        }
    }

    int GetModuleDir(size_t index) {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("GetModuleDir");
            return -1;
        }
        socket_utils::write_u8(fd, (uint8_t) SocketAction::GetModuleDir);
        socket_utils::write_usize(fd, index);
        return socket_utils::recv_fd(fd);
    }

    void ZygoteRestart() {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            if (errno == ENOENT) {
                LOGD("could not notify ZygoteRestart (maybe it hasn't been created)");
            } else {
                PLOGE("notify ZygoteRestart");
            }
            return;
        }
        if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ZygoteRestart)) {
            PLOGE("request ZygoteRestart");
        }
    }

    void SystemServerStarted() {
        UniqueFd fd = Connect(1);
        if (fd == -1) {
            PLOGE("report system server started");
        } else {
            if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::SystemServerStarted)) {
                PLOGE("report system server started");
            }
        }
    }
}  // namespace zygiskd