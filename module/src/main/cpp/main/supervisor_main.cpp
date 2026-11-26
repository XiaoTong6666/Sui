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

#define SUI_LOG_COMPONENT "Supervisor"
#include <logging.h>
#include <android/api-level.h>
#include <misc.h>
#include <private/ScopedFd.h>
#include <selinux.h>
#include <legacy_dex_runtime.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <string>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

int prepare_adb_root_main(int argc, char** argv, bool* already_prepared);
bool adbd_apex_running_from_backup();
int sui_logcat_main(int argc, char** argv);

namespace {

constexpr const char* kDataDir = "/data/adb/sui";
volatile sig_atomic_t stopping = 0;
using Clock = std::chrono::steady_clock;
constexpr auto kPairStartupTimeout = std::chrono::seconds(120);
constexpr auto kStopTimeout = std::chrono::seconds(30);

void OnSignal(int) {
    stopping = 1;
}

bool EnsureDirectory(const std::string& path, mode_t mode, uid_t uid, gid_t gid) {
    struct stat st{};
    if (lstat(path.c_str(), &st) != 0 && (errno != ENOENT || mkdir(path.c_str(), mode) != 0))
        return false;
    if (lstat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    return chown(path.c_str(), uid, gid) == 0 && chmod(path.c_str(), mode) == 0;
}

std::string ReadFile(const std::string& path, size_t limit = 4096) {
    ScopedFd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd.get() < 0)
        return {};
    std::string result;
    char buffer[512];
    while (result.size() < limit) {
        ssize_t n = read_eintr(fd.get(), buffer, std::min(limit - result.size(), sizeof(buffer)));
        if (n <= 0)
            break;
        result.append(buffer, static_cast<size_t>(n));
    }
    return result;
}

struct Metadata {
    std::string package;
    uid_t uid = static_cast<uid_t>(-1);
    std::string process;
    bool valid = false;
};

Metadata ReadMetadata(const std::string& path) {
    Metadata meta;
    const std::string content = ReadFile(path);
    size_t first = content.find('\n');
    size_t second = first == std::string::npos ? first : content.find('\n', first + 1);
    if (first == std::string::npos || second == std::string::npos)
        return meta;
    meta.package = content.substr(0, first);
    std::string uid_text = content.substr(first + 1, second - first - 1);
    meta.process = content.substr(second + 1);
    while (!meta.process.empty() && (meta.process.back() == '\n' || meta.process.back() == '\r'))
        meta.process.pop_back();
    if (meta.package.empty() || meta.process.empty() ||
        meta.process.find('\n') != std::string::npos || uid_text.empty())
        return meta;
    for (char c : uid_text)
        if (c < '0' || c > '9')
            return meta;
    char* end = nullptr;
    errno = 0;
    unsigned long uid = strtoul(uid_text.c_str(), &end, 10);
    if (errno || !end || *end || uid > 999999)
        return meta;
    meta.uid = static_cast<uid_t>(uid);
    meta.valid = true;
    return meta;
}

bool SameMetadata(const Metadata& lhs, const Metadata& rhs) {
    return lhs.valid && rhs.valid && lhs.package == rhs.package && lhs.uid == rhs.uid &&
           lhs.process == rhs.process;
}

struct Process {
    pid_t pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    std::string name;
    std::string start_time;
};

struct ProcessTarget {
    std::string name;
    uid_t uid;
};

Process InspectProcess(pid_t pid, std::initializer_list<ProcessTarget> targets) {
    Process result;
    const std::string base = "/proc/" + std::to_string(pid);
    const std::string cmdline = ReadFile(base + "/cmdline");
    if (cmdline.empty())
        return result;
    result.name = cmdline.substr(0, cmdline.find('\0'));
    if (std::none_of(targets.begin(), targets.end(),
                     [&](const auto& target) { return target.name == result.name; }))
        return result;
    const std::string status = ReadFile(base + "/status");
    const size_t index = status.find("Uid:");
    unsigned real_uid = 0;
    if (index == std::string::npos || sscanf(status.c_str() + index, "Uid: %u", &real_uid) != 1)
        return result;
    result.uid = static_cast<uid_t>(real_uid);
    if (std::none_of(targets.begin(), targets.end(), [&](const auto& target) {
            return target.name == result.name && target.uid == result.uid;
        }))
        return result;
    const std::string stat = ReadFile(base + "/stat");
    const size_t paren = stat.rfind(')');
    if (paren == std::string::npos)
        return result;
    size_t begin = paren + 1;
    for (int field = 3; field <= 22; ++field) {
        begin = stat.find_first_not_of(' ', begin);
        if (begin == std::string::npos)
            return result;
        size_t end = stat.find(' ', begin);
        if (field == 22) {
            result.start_time = stat.substr(begin, end - begin);
            break;
        }
        if (end == std::string::npos)
            return result;
        begin = end;
    }
    if (!result.start_time.empty())
        result.pid = pid;
    return result;
}

bool FindProcesses(std::initializer_list<ProcessTarget> targets, std::vector<Process>& matches) {
    return foreach_proc([&](pid_t pid) {
        auto process = InspectProcess(pid, targets);
        if (process.pid > 0)
            matches.push_back(std::move(process));
        return false;
    });
}

bool FindServerProcesses(std::vector<Process>& matches) {
    return FindProcesses({{"sui", 0}, {"sui_shell", 2000}}, matches);
}

bool SameProcess(const Process& process) {
    Process now = InspectProcess(process.pid, {{process.name, process.uid}});
    return now.pid == process.pid && now.uid == process.uid && now.name == process.name &&
           now.start_time == process.start_time;
}

void SignalProcess(const Process& process, int signal) {
    if (SameProcess(process))
        kill(process.pid, signal);
}

bool StopNamedPair() {
    std::vector<Process> processes;
    if (!FindServerProcesses(processes))
        return false;
    if (processes.empty())
        return true;
    for (const auto& process : processes)
        SignalProcess(process, SIGTERM);
    auto alive = [&]() { return std::any_of(processes.begin(), processes.end(), SameProcess); };
    auto deadline = Clock::now() + std::chrono::seconds(1);
    while (alive() && Clock::now() < deadline)
        usleep(100000);
    for (const auto& process : processes)
        SignalProcess(process, SIGKILL);
    deadline = Clock::now() + kStopTimeout;
    while (alive() && Clock::now() < deadline)
        usleep(100000);
    return !alive();
}

bool PairHealthy(pid_t group = -1) {
    std::vector<Process> processes;
    if (!FindServerProcesses(processes) || processes.size() != 2 ||
        processes[0].uid == processes[1].uid)
        return false;
    if (group < 0)
        return true;
    const auto& root = processes[0].uid == 0 ? processes[0] : processes[1];
    const auto& shell = processes[0].uid == 2000 ? processes[0] : processes[1];
    return root.pid == group && getpgid(shell.pid) == group;
}

// Keep the group leader unreaped until its entire startup group has exited.
// The PID cannot be recycled while the leader is still our child.
bool GroupHasLiveProcesses(pid_t group) {
    bool live = false;
    bool scanned = foreach_proc([&](pid_t pid) {
        if (getpgid(pid) != group)
            return false;
        auto stat = ReadFile("/proc/" + std::to_string(pid) + "/stat");
        auto paren = stat.rfind(')');
        if (paren == std::string::npos || paren + 2 >= stat.size())
            live = getpgid(pid) == group;
        else {
            char state = stat[paren + 2];
            live = state != 'Z' && state != 'X' && state != 'x';
        }
        return live;
    });
    return !scanned || live;
}

struct ServerPair {
    pid_t pid = -1;
    Clock::time_point started;
    bool running = false;
    Clock::time_point stop_started{};
    bool stop_timeout_reported = false;
};

bool LeaderExited(pid_t pid) {
    siginfo_t info{};
    int rc;
    do {
        rc = waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT);
    } while (rc < 0 && errno == EINTR);
    return rc < 0 || info.si_pid != 0;
}

// Advance shutdown one tick at a time; retain the leader and block new launches
// until the entire group has drained, even if SIGKILL cannot complete promptly.
void StopOwnedPair(ServerPair& pair) {
    if (pair.pid <= 0)
        return;
    const auto now = Clock::now();
    const bool first = pair.stop_started == Clock::time_point{};
    if (first)
        pair.stop_started = now;
    if (!pair.stop_timeout_reported && now - pair.stop_started >= kStopTimeout) {
        LOGE("Sui process group %d is still stopping; refusing to start another pair", pair.pid);
        pair.stop_timeout_reported = true;
    }

    siginfo_t info{};
    int rc;
    do {
        rc = waitid(P_PID, static_cast<id_t>(pair.pid), &info, WEXITED | WNOHANG | WNOWAIT);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        // Without child ownership, never signal a potentially recycled PID or PGID.
        if (first)
            PLOGE("cannot inspect owned Sui launcher %d", pair.pid);
        return;
    }

    if (info.si_pid != 0 && !GroupHasLiveProcesses(pair.pid)) {
        if (waitpid(pair.pid, nullptr, WNOHANG) == pair.pid)
            pair = {};
        return;
    }

    if (pair.running && now - pair.stop_started < std::chrono::seconds(1)) {
        if (first)
            kill(-pair.pid, SIGTERM);
        return;
    }
    // Covers the shell child even before its credential transition and PDEATHSIG.
    kill(-pair.pid, SIGKILL);
    kill(pair.pid, SIGKILL);
}

// Only terminate the exact UID/name/start-time identity recorded by PM.
bool RestartPackageOnce(const Metadata& meta) {
    if (!meta.valid || meta.uid == 0 || meta.process == "init" || meta.process == "system_server" ||
        meta.process.rfind("zygote", 0) == 0)
        return true;
    std::vector<Process> processes;
    if (!FindProcesses({{meta.process, meta.uid}}, processes))
        return false;
    for (const auto& process : processes)
        SignalProcess(process, SIGKILL);
    return !processes.empty();
}

struct PendingRestart {
    Metadata target;
    std::chrono::steady_clock::time_point deadline;
};

void PollPendingRestarts(std::vector<PendingRestart>& pending) {
    auto now = std::chrono::steady_clock::now();
    for (auto it = pending.begin(); it != pending.end();) {
        // Retry new PM identities without blocking the root/shell watchdog.
        if (RestartPackageOnce(it->target) || now >= it->deadline)
            it = pending.erase(it);
        else
            ++it;
    }
}

void KillAndReapChild(pid_t pid) {
    if (pid <= 0)
        return;
    kill(pid, SIGKILL);
    while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
    }
}

int WaitChild(pid_t pid, unsigned timeout_seconds) {
    int status = 0;
    for (unsigned i = 0; i < timeout_seconds * 10 && !stopping; ++i) {
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        if (ret < 0 && errno != EINTR)
            return 1;
        usleep(100000);
    }
    KillAndReapChild(pid);
    return 1;
}

pid_t Spawn(const std::vector<std::string>& args, bool new_group = false) {
    if (args.empty())
        return -1;
    const pid_t parent = getpid();
    pid_t pid = fork();
    if (pid != 0) {
        if (pid > 0 && new_group && setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
            KillAndReapChild(pid);
            return -1;
        }
        return pid;
    }
    if (new_group) {
        if (setpgid(0, 0) != 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
            _exit(127);
    }
    // Do not inherit the supervisor's cooperative stop handler before exec.
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    std::vector<char*> argv;
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2)
            close(null_fd);
    }
    execv(args[0].c_str(), argv.data());
    _exit(127);
}

void RestartChangedTarget(const Metadata& previous, const Metadata& current,
                          std::vector<PendingRestart>& pending) {
    if (SameMetadata(previous, current))
        return;
    if (previous.valid && (previous.uid != current.uid || previous.process != current.process))
        RestartPackageOnce(previous);
    pending.push_back({current, Clock::now() + std::chrono::seconds(10)});
}

bool ApplyMetadataResult(const std::string& module, Metadata& ui, Metadata& settings, int rc,
                         std::vector<PendingRestart>& pending, ServerPair& pair) {
    Metadata new_ui = ReadMetadata(module + "/system_ui");
    Metadata new_settings = ReadMetadata(module + "/settings");
    if (rc != 0 || !new_ui.valid || !new_settings.valid) {
        LOGW("Installer failed (%d); %s", rc,
             ui.valid && settings.valid ? "keeping validated metadata" : "metadata unavailable");
        return false;
    }
    if (!SameMetadata(ui, new_ui) || !SameMetadata(settings, new_settings)) {
        LOGI("package metadata changed, refreshing injected processes");
        pending.clear();
        RestartChangedTarget(ui, new_ui, pending);
        RestartChangedTarget(settings, new_settings, pending);
        PollPendingRestarts(pending);
        StopOwnedPair(pair);
    }
    ui = new_ui;
    settings = new_settings;
    return true;
}

// PackageManager can take up to 120 seconds to become ready. Its Java query
// must never block the native watchdog from recovering a crashed server pair.
struct MetadataRefresh {
    pid_t pid = -1;
    std::chrono::steady_clock::time_point started;
};

void StartMetadataRefresh(const std::string& module, MetadataRefresh& refresh) {
    const std::string dex = "-Djava.class.path=" + module + "/sui.dex";
    refresh.pid = Spawn({"/system/bin/app_process", dex, "/system/bin", "--nice-name=sui_installer",
                         "rikka.sui.installer.Installer", module});
    refresh.started = std::chrono::steady_clock::now();
    if (refresh.pid < 0)
        LOGW("could not start Java metadata installer");
}

// Return true only once the outstanding installer attempt has finished.
bool PollMetadataRefresh(const std::string& module, MetadataRefresh& refresh, Metadata& ui,
                         Metadata& settings, std::vector<PendingRestart>& pending,
                         ServerPair& pair) {
    if (refresh.pid <= 0)
        return false;
    int status = 0;
    pid_t result = waitpid(refresh.pid, &status, WNOHANG);
    if (result < 0 && errno == EINTR)
        return false;
    if (result == 0) {
        if (std::chrono::steady_clock::now() - refresh.started < std::chrono::seconds(125))
            return false;
        LOGW("Java installer timed out; stopping it");
        KillAndReapChild(refresh.pid);
    }
    int rc = result == refresh.pid && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    refresh.pid = -1;
    ApplyMetadataResult(module, ui, settings, rc, pending, pair);
    return true;
}

void EnsureLogCollector(const std::string& module, pid_t& collector) {
    if (collector > 0) {
        pid_t result = waitpid(collector, nullptr, WNOHANG);
        if (result == 0 || (result < 0 && errno == EINTR))
            return;
        collector = -1;
    }
    if (stopping)
        return;
    const std::string binary = module + "/bin/sui_logcat";
    pid_t checker = Spawn({binary, "status", kDataDir});
    if (checker > 0 && WaitChild(checker, 3) == 0)
        return;
    if (stopping)
        return;
    collector = Spawn({binary, "run", kDataDir});
    if (collector < 0)
        LOGW("failed to launch log collector");
}

// Keep the existing adb_root native backend. Policy is normally loaded by
// Magisk/KernelSU/APatch; only apply it explicitly when the native checker
// says the effective policy is missing.
bool CheckAdbPolicy(const std::string& module) {
    const std::string checker = module + "/bin/sepolicy_checker";
    chmod(checker.c_str(), 0755);
    auto check = [&]() -> bool {
        pid_t pid = Spawn({checker});
        return pid > 0 && WaitChild(pid, 10) == 0;
    };
    if (check())
        return true;
    if (stopping)
        return false;
    const std::string rules = module + "/sepolicy.rule";
    std::vector<std::vector<std::string>> candidates = {
        {"/data/adb/ksud", "sepolicy", "apply", rules},
        {"/data/adb/ksu/bin/ksud", "sepolicy", "apply", rules},
        {"/data/adb/ap/bin/apd", "sepolicy", "apply", rules},
        {"/data/adb/apd", "sepolicy", "apply", rules},
        {"/sbin/magiskpolicy", "--live", "--apply", rules},
        {"/debug_ramdisk/magiskpolicy", "--live", "--apply", rules},
        {"/data/adb/magisk/magiskpolicy", "--live", "--apply", rules},
    };
    for (const auto& command : candidates) {
        if (stopping)
            return false;
        if (access(command[0].c_str(), X_OK) != 0)
            continue;
        pid_t pid = Spawn(command);
        if (pid > 0 && WaitChild(pid, 15) == 0 && check())
            return true;
    }
    LOGW("adb root SELinux policy verification failed");
    return false;
}

// Adbd is often already running when service.sh executes. A successful
// preparation therefore requires an adbd restart to pick up the backend.
void PrepareAdbRoot(const std::string& module) {
    const std::string once = std::string(kDataDir) + "/enable_adb_root_once";
    const bool enabled = access(once.c_str(), F_OK) == 0 ||
                         access((std::string(kDataDir) + "/enable_adb_root").c_str(), F_OK) == 0;
    if (!enabled)
        return;
    unlink(once.c_str());
    if (!CheckAdbPolicy(module))
        LOGW("continuing optional adb root setup with unverified SELinux rules");
    if (stopping)
        return;
    const bool inject =
        access((std::string(kDataDir) + "/enable_adb_root_injection").c_str(), F_OK) == 0;
    std::string command = module + "/bin/adb_root";
    char* args[] = {const_cast<char*>(command.c_str()), const_cast<char*>(module.c_str()),
                    inject ? const_cast<char*>("--inject") : nullptr, nullptr};
    bool already_prepared = false;
    int rc = prepare_adb_root_main(inject ? 3 : 2, args, &already_prepared);
    if (rc != 0)
        LOGW("optional adb root initialization failed: %d", rc);
    else if (!stopping) {
        // If a previous supervisor died between mounting and requesting restart,
        // adbd may still be executing the original APEX inode.
        if (already_prepared && adbd_apex_running_from_backup()) {
            LOGI("APEX adb root is already active; skipping adbd restart");
            return;
        }
        LOGI("optional adb root backend prepared (%s)", inject ? "ZN" : "bind mount");
        pid_t pid = Spawn({"/system/bin/setprop", "ctl.restart", "adbd"});
        if (pid <= 0 || WaitChild(pid, 5) != 0)
            LOGW("could not request adbd restart after late-start setup");
    }
}

int OpenSupervisorLock() {
    return open((std::string(kDataDir) + "/supervisor.lock").c_str(),
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
}

int RunSupervisor(const std::string& module) {
    struct sigaction action{};
    action.sa_handler = OnSignal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);
    // Explicitly retain child exit status even if the calling shell ignored SIGCHLD.
    signal(SIGCHLD, SIG_DFL);
    if (!EnsureDirectory(kDataDir, 0700, 0, 0))
        return 1;
    ScopedFd lock(OpenSupervisorLock());
    if (lock.get() < 0)
        return 1;
    if (flock(lock.get(), LOCK_EX | LOCK_NB) != 0)
        return errno == EWOULDBLOCK ? 0 : 1;
    if (stopping || access((module + "/remove").c_str(), F_OK) == 0)
        return 0;

    // Current-boot DEX paths are owned by system_server; remove only verified old ones.
    sui::legacy::PruneStaleDexRuntimes();
    if (!stopping)
        PrepareAdbRoot(module);
    pid_t collector = -1;
    EnsureLogCollector(module, collector);
    Metadata ui = ReadMetadata(module + "/system_ui");
    Metadata settings = ReadMetadata(module + "/settings");
    MetadataRefresh refresh;
    ServerPair pair;
    std::vector<PendingRestart> pending_restarts;
    auto next_refresh = Clock::now();
    auto next_start = Clock::now();
    auto next_pair_check = Clock::now();
    auto next_log = Clock::now() + std::chrono::seconds(30);
    unsigned backoff = 1;
    LOGI("supervisor started for %s", module.c_str());
    while (!stopping || pair.pid > 0) {
        if (stopping) {
            // Keep the supervisor lock while the owned group drains. --stop may
            // time out, but no replacement supervisor can start meanwhile.
            StopOwnedPair(pair);
            if (pair.pid > 0)
                sleep(1);
            continue;
        }
        if (PollMetadataRefresh(module, refresh, ui, settings, pending_restarts, pair))
            next_refresh =
                Clock::now() + std::chrono::seconds(ui.valid && settings.valid ? 300 : 30);
        if (stopping)
            continue;
        PollPendingRestarts(pending_restarts);
        if (refresh.pid < 0 && Clock::now() >= next_refresh) {
            StartMetadataRefresh(module, refresh);
            next_refresh = Clock::now() + std::chrono::seconds(30);
        }
        if (pair.stop_started != Clock::time_point{}) {
            StopOwnedPair(pair);
        } else if (pair.pid > 0 && Clock::now() >= next_pair_check) {
            bool exited = LeaderExited(pair.pid);
            if (!exited && PairHealthy(pair.pid)) {
                if (!pair.running)
                    LOGI("Sui process pair is running");
                pair.running = true;
                backoff = 1;
            } else if (pair.running || exited ||
                       Clock::now() - pair.started >= kPairStartupTimeout) {
                LOGW("Sui process pair unavailable, retry in %us", backoff);
                StopOwnedPair(pair);
                next_start = Clock::now() + std::chrono::seconds(backoff);
                backoff = std::min(backoff * 2, 60u);
            }
            // A live launcher without both final app_process names is still starting.
            next_pair_check = Clock::now() + std::chrono::seconds(pair.running ? 5 : 1);
        }
        if (!stopping && pair.pid < 0 && ui.valid && settings.valid && Clock::now() >= next_start) {
            // Retire any named pair left by an older supervisor before owning a new launch.
            if (StopNamedPair() && !stopping) {
                const std::string binary = module + "/bin/sui";
                pair.pid = Spawn({binary, module, "--foreground"}, true);
                pair.started = Clock::now();
                next_pair_check = pair.started;
                LOGI("starting Sui process pair (pid=%d)", pair.pid);
            }
            if (pair.pid < 0) {
                next_start = Clock::now() + std::chrono::seconds(backoff);
                backoff = std::min(backoff * 2, 60u);
            }
        }
        if (!stopping && Clock::now() >= next_log) {
            EnsureLogCollector(module, collector);
            next_log = Clock::now() + std::chrono::seconds(30);
        }
        if (!stopping)
            sleep(1);
    }
    KillAndReapChild(refresh.pid);
    KillAndReapChild(collector);
    return 0;
}

bool IsSupervisor(const Process& process, const std::string& module) {
    // Exclude --stop/--status and other applet invocations sharing argv[0].
    std::string expected = module + "/bin/sui_supervisor";
    expected.push_back('\0');
    expected += module;
    expected.push_back('\0');
    return ReadFile("/proc/" + std::to_string(process.pid) + "/cmdline") == expected;
}

bool WaitForLock(int fd, const std::function<void()>& on_wait = {}) {
    if (fd < 0)
        return false;
    auto deadline = Clock::now() + kStopTimeout;
    while (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if ((errno != EWOULDBLOCK && errno != EINTR) || Clock::now() >= deadline)
            return false;
        if (on_wait)
            on_wait();
        usleep(100000);
    }
    return true;
}

int StopSupervisor(const std::string& module) {
    if (!EnsureDirectory(kDataDir, 0700, 0, 0))
        return 1;
    ScopedFd lock(OpenSupervisorLock());
    if (lock.get() < 0)
        return 1;
    if (!WaitForLock(lock.get(), [&] {
            std::vector<Process> processes;
            if (FindProcesses({{module + "/bin/sui_supervisor", 0}}, processes))
                for (const auto& process : processes)
                    if (process.pid != getpid() && IsSupervisor(process, module))
                        SignalProcess(process, SIGTERM);
        })) {
        LOGE("cannot acquire supervisor lock; refusing unsynchronized cleanup");
        return 1;
    }
    if (!StopNamedPair()) {
        LOGE("could not stop the remaining Sui servers");
        return 1;
    }
    char logcat[] = "sui_logcat";
    char stop[] = "stop";
    char directory[] = "/data/adb/sui";
    char* log_args[] = {logcat, stop, directory, nullptr};
    int rc = sui_logcat_main(3, log_args);
    // Keep the supervisor lock until the log reader has released its own lock.
    ScopedFd log_lock(open((std::string(kDataDir) + "/logcat.lock").c_str(),
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!WaitForLock(log_lock.get()))
        rc = 1;
    return rc;
}
}  // namespace

int run_sui_supervisor_main(int argc, char** argv) {
    if (argc < 2)
        return 1;
    std::string module = argv[1];
    if (module.empty() || module[0] != '/')
        return 1;
    if (argc == 3 && strcmp(argv[2], "--status") == 0)
        return PairHealthy() ? 0 : 1;
    if (argc == 3 && strcmp(argv[2], "--prune-legacy-all") == 0) {
        sui::legacy::PruneStaleDexRuntimes(true);
        return 0;
    }
    if (argc == 3 && strcmp(argv[2], "--stop") == 0)
        return StopSupervisor(module);
    if (argc != 2)
        return 1;
    return RunSupervisor(module);
}
