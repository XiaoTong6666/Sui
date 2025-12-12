#include "zygote_abi.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <csignal>

#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

ZygoteAbiManager::ZygoteAbiManager(AppMonitor& monitor, bool is_64bit)
        : abi_name_(is_64bit ? "64" : "32"),
        // [SUI STANDALONE 修改]
        // 原来指向 ./bin/app_process，这里保持不变，因为是系统路径
          program_path_(is_64bit ? "/system/bin/app_process64" : "/system/bin/app_process"),
        // [SUI STANDALONE 修改]
        // 关键！原来的路径是 ./bin/zygisk-ptraceXX。
        // 但在我们的独立模式下，sui_monitor 就是那个可执行文件。
        // 当需要执行 trace 操作时，我们应该调用自己 (/proc/self/exe)。
          tracer_path_("/proc/self/exe"),
          monitor_(monitor) {}

const Status& ZygoteAbiManager::get_status() const { return status_; }

void ZygoteAbiManager::notify_injected() { status_.zygote_injected = true; }

void ZygoteAbiManager::set_daemon_info(std::string_view info) { status_.daemon_info = info; }

void ZygoteAbiManager::set_daemon_crashed(std::string_view error) {
    status_.daemon_running = false;
    status_.daemon_error_info = error;
}

bool ZygoteAbiManager::is_in_crash_loop() {
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - counter.last_start_time.tv_sec < ZygoteAbiManager::CRASH_LOOP_WINDOW_SECONDS) {
        counter.count++;
    } else {
        counter.count = 1;
    }
    counter.last_start_time = now;
    return counter.count >= ZygoteAbiManager::CRASH_LOOP_RETRY_COUNT;
}

// [SUI STANDALONE 修改] 核心修改点
bool ZygoteAbiManager::ensure_daemon_created() {
    status_.zygote_injected = false;

    // 我们不再 fork 子进程来启动 daemon。
    // 假设外部脚本 (post-fs-data.sh) 已经把 sui_daemon 启动好了。

    /* 原有逻辑被注释掉
    if (status_.daemon_pid == -1) {
        auto pid = fork();
        if (pid < 0) {
            PLOGE("create daemon (abi=%s)", abi_name_);
            return false;
        }
        if (pid == 0) {
            std::string daemon_name = "./bin/zygiskd";
            daemon_name += abi_name_;
            execl(daemon_name.c_str(), daemon_name.c_str(), nullptr);
            PLOGE("exec daemon %s", daemon_name.c_str());
            exit(1);
        }
        status_.supported = true;
        status_.daemon_pid = pid;
        status_.daemon_running = true;
    }
    */

    // 直接设置状态为正常
    status_.supported = true;
    status_.daemon_running = true;
    // daemon_pid 保持默认 (-1)，表示我们不管理它

    // 降低日志级别防止刷屏，或者只打印一次
    // LOGI("SuiMonitor: Assuming external daemon is running.");

    return true;
}

const char* ZygoteAbiManager::check_and_prepare_injection() {
    if (is_in_crash_loop()) {
        monitor_.request_stop("zygote crashed");
        return nullptr;
    }
    if (!ensure_daemon_created()) {
        monitor_.request_stop("daemon not running");
        return nullptr;
    }
    return tracer_path_;
}

// [SUI STANDALONE 修改]
bool ZygoteAbiManager::handle_daemon_exit_if_match(int pid, int process_status) {
    // 因为我们没有启动子进程，所以永远不会收到 daemon 退出的信号。
    // 直接返回 false。
    return false;

    /* 原有逻辑
    if (status_.supported && pid == status_.daemon_pid) {
        auto status_str = parse_status(process_status);
        LOGW("ZygoteAbiManager: daemon%s (pid %d) exited: %s", abi_name_, pid, status_str.c_str());
        status_.daemon_running = false;
        if (status_.daemon_error_info.empty()) {
            status_.daemon_error_info = status_str;
        }
        monitor_.update_status();
        return true;
    }
    return false;
    */
}