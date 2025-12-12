// src/zygiskd.rs

//! The core logic for the Zygisk daemon (`zygiskd`).
//!
//! This module is responsible for:
//! - Initializing paths and communication channels.
//! - Loading Zygisk modules from the designated directory.
//! - Listening on a Unix domain socket for requests from the Zygisk injector.
//! - Handling requests such as providing module libraries, querying process flags,
//!   and managing companion processes.

use crate::constants::{DaemonSocketAction, ProcessFlags, ZKSU_VERSION};
use crate::mount::{MountNamespace, MountNamespaceManager};
use crate::utils::{self, UnixStreamExt};
use crate::{constants, lp_select, root_impl};
use anyhow::{Context as AnyhowContext, Result, bail};
use log::{debug, error, info, trace, warn};
use passfd::FdPassingExt;
use rustix::io::{FdFlags, fcntl_setfd};
use std::fs;
use std::io::Error;
use std::os::fd::AsRawFd;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf}, // 引入 PathBuf
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    thread,
};

/// Represents a loaded Zygisk module.
struct Module {
    name: String,
    lib_fd: OwnedFd,
    /// A handle to the module's companion process socket, if it exists and is running.
    companion: Mutex<Option<UnixStream>>,
    /// [新增] 记录模块的真实安装目录，避免因模块名和文件夹名不一致导致找不到目录
    root_dir: PathBuf,
}

/// The shared context for the daemon, containing all loaded modules and a mount namespace manager
struct AppContext {
    modules: Vec<Module>,
    mount_manager: Arc<MountNamespaceManager>,
}

// Global paths, initialized once at startup.
static TMP_PATH: OnceLock<String> = OnceLock::new();
static CONTROLLER_SOCKET: OnceLock<String> = OnceLock::new();
static DAEMON_SOCKET_PATH: OnceLock<String> = OnceLock::new();

/// The main function for the zygiskd daemon.
pub fn main() -> Result<()> {
    info!("Welcome to NeoZygisk ({}) !", ZKSU_VERSION);

    initialize_globals()?;
    let modules = load_modules()?;
    send_startup_info(&modules)?;

    let mount_manager = Arc::new(MountNamespaceManager::new());
    let context = Arc::new(AppContext {
        modules,
        mount_manager,
    });
    let listener = create_daemon_socket()?;

    info!("Daemon listening on {}", DAEMON_SOCKET_PATH.get().unwrap());

    // Main event loop: accept and handle incoming connections.
    for stream in listener.incoming() {
        let stream = stream.context("Failed to accept incoming connection")?;
        let context = Arc::clone(&context);
        if let Err(e) = handle_connection(stream, context) {
            warn!("Error handling connection: {}", e);
        }
    }

    Ok(())
}

/// Handles a single incoming connection from Zygisk.
fn handle_connection(mut stream: UnixStream, context: Arc<AppContext>) -> Result<()> {
    let action = stream.read_u8()?;
    let action = DaemonSocketAction::try_from(action)
        .with_context(|| format!("Invalid daemon action code: {}", action))?;
    trace!("New daemon action: {:?}", action);

    match action {
        // These actions are lightweight and handled synchronously.
        DaemonSocketAction::CacheMountNamespace => {
            let pid = stream.read_u32()? as i32;
            context
                .mount_manager
                .save_mount_namespace(pid, MountNamespace::Clean)?;
            context
                .mount_manager
                .save_mount_namespace(pid, MountNamespace::Root)?;
        }
        DaemonSocketAction::PingHeartbeat => {
            // [SUI STANDALONE 修改] 不发送，只打印日志
            debug!("SuiDaemon: Received PingHeartbeat");
            // let value = constants::ZYGOTE_INJECTED;
            // utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        DaemonSocketAction::ZygoteRestart => {
            info!("Zygote restarted, cleaning up companion sockets.");
            for module in &context.modules {
                module.companion.lock().unwrap().take();
            }
        }
        DaemonSocketAction::SystemServerStarted => {
            // [SUI STANDALONE 修改] 不发送，只打印日志
            info!("SuiDaemon: System Server Started!");
            // let value = constants::SYSTEM_SERVER_STARTED;
            // utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        // Heavier actions are spawned into a separate thread.
        _ => {
            thread::spawn(move || {
                if let Err(e) = handle_threaded_action(action, stream, &context) {
                    warn!(
                        "Error handling daemon action '{:?}': {:?}\nBacktrace: {}",
                        action,
                        e,
                        e.backtrace()
                    );
                }
            });
        }
    }
    Ok(())
}

/// Handles potentially long-running actions in a dedicated thread.
fn handle_threaded_action(
    action: DaemonSocketAction,
    mut stream: UnixStream,
    context: &AppContext,
) -> Result<()> {
    match action {
        DaemonSocketAction::GetProcessFlags => handle_get_process_flags(&mut stream),
        DaemonSocketAction::UpdateMountNamespace => {
            handle_update_mount_namespace(&mut stream, context)
        }
        DaemonSocketAction::ReadModules => handle_read_modules(&mut stream, context),
        DaemonSocketAction::RequestCompanionSocket => {
            handle_request_companion_socket(&mut stream, context)
        }
        DaemonSocketAction::GetModuleDir => handle_get_module_dir(&mut stream, context),
        // Other cases are handled synchronously and won't reach here.
        _ => unreachable!(),
    }
}

/// Initializes global path variables from the environment.
fn initialize_globals() -> Result<()> {
    let tmp_path = std::env::var("TMP_PATH").context("TMP_PATH environment variable not set")?;
    TMP_PATH.set(tmp_path).unwrap();

    // [修改] 不再强制设置 CONTROLLER_SOCKET，或者设为一个不存在的值
    // CONTROLLER_SOCKET.set(format!("{}/init_monitor", TMP_PATH.get().unwrap())).unwrap();
    // 我们可以直接注释掉上面这行，因为我们在 send_startup_info 里会跳过发送

    DAEMON_SOCKET_PATH
        .set(format!(
            "{}/{}",
            TMP_PATH.get().unwrap(),
            lp_select!("/sui_32.sock", "/sui_64.sock")
        ))
        .unwrap();
    Ok(())
}

/// Sends initial status information to the controller.
fn send_startup_info(modules: &[Module]) -> Result<()> {
    // [SUI STANDALONE 修改]
    // 这是一个独立 daemon，没有上级 controller 监听我们。
    // 所以我们只打印日志，不尝试发送 Socket 消息。

    let info = match root_impl::get() {
        root_impl::RootImpl::APatch
        | root_impl::RootImpl::KernelSU
        | root_impl::RootImpl::Magisk => {
            let module_names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
            if !module_names.is_empty() {
                format!(
                    "Root: {:?}, Modules ({}): {}",
                    root_impl::get(),
                    modules.len(),
                    module_names.join(", ")
                )
            } else {
                format!("Root: {:?}", root_impl::get())
            }
        }
        _ => {
            format!("Invalid root implementation: {:?}", root_impl::get())
        }
    };

    // 只记录日志，不发送
    info!("SuiDaemon: Startup Info - {}", info);

    // [删除或注释掉原来的发送逻辑]
    /*
    let mut msg = Vec::<u8>::new();
    // ... (构造 msg 的代码) ...
    utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &msg)
        .context("Failed to send startup info to controller")
    */

    Ok(())
}

/// Detects the device architecture.
fn get_arch() -> Result<&'static str> {
    let system_arch = utils::get_property("ro.product.cpu.abi")?;
    if system_arch.contains("arm") {
        Ok(lp_select!("armeabi-v7a", "arm64-v8a"))
    } else if system_arch.contains("x86") {
        Ok(lp_select!("x86", "x86_64"))
    } else {
        bail!("Unsupported system architecture: {}", system_arch)
    }
}

/// Scans the module directory, loads valid modules, and creates memfds for their libraries.
fn load_modules() -> Result<Vec<Module>> {
    let arch = get_arch()?;
    debug!("SuiDaemon: Daemon architecture: {arch}"); // [日志]

    let mut modules = Vec::new();

    let mut self_path = std::env::current_exe()?;
    self_path.pop();
    self_path.pop();
    self_path.pop();

    let root_dir = self_path.clone();
    let so_path = self_path.join(format!("lib/{}/libsui.so", arch));
    let name = "rikka.sui".to_string();

    info!("SuiDaemon: Module root is {:?}", root_dir); // [日志]
    info!("SuiDaemon: Looking for library at {:?}", so_path); // [日志]

    if so_path.exists() {
        info!("SuiDaemon: Found libsui.so, creating memfd..."); // [日志]
        match create_library_fd(&so_path) {
            Ok(lib_fd) => {
                info!("SuiDaemon: Memfd created successfully for {}", name); // [日志]
                modules.push(Module {
                    name,
                    lib_fd,
                    companion: Mutex::new(None),
                    root_dir,
                });
            }
            Err(e) => {
                error!("SuiDaemon: CRITICAL - Failed to create memfd for `{}`: {}", name, e); // [日志]
            }
        };
    } else {
         error!("SuiDaemon: CRITICAL - libsui.so not found at {:?}", so_path); // [日志]
    }
    Ok(modules)
}

/// Creates a sealed, read-only memfd containing the module's shared library.
/// This is a security measure to prevent the library from being tampered with after loading.
fn create_library_fd(so_path: &Path) -> Result<OwnedFd> {
    let opts = memfd::MemfdOptions::default().allow_sealing(true);
    let memfd = opts.create("sui-module")?;

    // Copy the library content into the memfd.
    let file = fs::File::open(so_path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut writer = memfd.as_file();
    std::io::copy(&mut reader, &mut writer)?;

    // Apply seals to make the memfd immutable.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    seals.insert(memfd::FileSeal::SealWrite);
    seals.insert(memfd::FileSeal::SealSeal);
    memfd.add_seals(&seals)?;

    Ok(OwnedFd::from(memfd.into_file()))
}

/// Creates and binds the main daemon Unix socket.
fn create_daemon_socket() -> Result<UnixListener> {
    utils::set_socket_create_context("u:r:zygote:s0")?;
    let listener = utils::unix_listener_from_path(DAEMON_SOCKET_PATH.get().unwrap())?;
    Ok(listener)
}

/// Spawns a companion process for a module.
///
/// This involves forking, setting up a communication channel (Unix socket pair),
/// and re-executing the daemon binary with special arguments (`companion <fd>`).
fn spawn_companion(name: &str, lib_fd: RawFd) -> Result<Option<UnixStream>> {
    let (mut daemon_sock, companion_sock) = UnixStream::pair()?;

    // FIXME: A more robust way to get the current executable path is desirable.
    let self_exe = std::env::args().next().unwrap();
    let nice_name = self_exe.split('/').last().unwrap_or("sui_daemon");

    // The fork/exec logic is now handled directly here.
    // # Safety
    // This is highly unsafe because it uses `fork()` and `exec()`. The child
    // process must not call any non-async-signal-safe functions before `exec()`.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            // Fork failed
            bail!(Error::last_os_error());
        }

        if pid == 0 {
            // --- Child Process ---
            drop(daemon_sock); // Child doesn't need the daemon's end of the socket.

            // The companion socket FD must be passed to the new process,
            // so we must remove the `FD_CLOEXEC` flag.
            fcntl_setfd(companion_sock.as_fd(), FdFlags::empty())
                .expect("Failed to clear CLOEXEC on companion socket");

            // The first argument (`arg0`) is used to set a descriptive process name.
            let arg0 = format!("{}-{}", nice_name, name);
            let companion_fd_str = format!("{}", companion_sock.as_raw_fd());

            // exec replaces the current process; it does not return on success.
            let err = Command::new(&self_exe)
                .arg0(arg0)
                .arg("companion")
                .arg(companion_fd_str)
                .exec();

            // If exec returns, it's always an error.
            bail!("exec failed: {}", err);
        }

        // --- Parent Process ---
        drop(companion_sock); // Parent doesn't need the companion's end of the socket.

        // Now, establish communication with the newly spawned companion.
        daemon_sock.write_string(name)?;
        daemon_sock.send_fd(lib_fd)?;

        // Wait for the companion's response to know if it loaded the module successfully.
        match daemon_sock.read_u8()? {
            0 => Ok(None),              // Module has no companion entry point or failed to load.
            1 => Ok(Some(daemon_sock)), // Companion is ready.
            _ => bail!("Invalid response from companion setup"),
        }
    }
}

// --- Action Handlers ---

fn handle_get_process_flags(stream: &mut UnixStream) -> Result<()> {
    let uid = stream.read_u32()? as i32;
    let mut flags = ProcessFlags::empty();

    if root_impl::uid_is_manager(uid) {
        flags |= ProcessFlags::PROCESS_IS_MANAGER;
    } else {
        if root_impl::uid_granted_root(uid) {
            flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
        }
        if root_impl::uid_should_umount(uid) {
            flags |= ProcessFlags::PROCESS_ON_DENYLIST;
        }
    }

    match root_impl::get() {
        root_impl::RootImpl::APatch => flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH,
        root_impl::RootImpl::KernelSU => flags |= ProcessFlags::PROCESS_ROOT_IS_KSU,
        root_impl::RootImpl::Magisk => flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK,
        _ => (), // No flag for None, TooOld, or Multiple
    }

    trace!("Flags for UID {}: {:?}", uid, flags);
    stream.write_u32(flags.bits())?;
    Ok(())
}

fn handle_update_mount_namespace(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let namespace_type = MountNamespace::try_from(stream.read_u8()?)?;
    stream.write_u32(unsafe { libc::getpid() } as u32)?;
    if let Some(fd) = context.mount_manager.get_namespace_fd(namespace_type) {
        // Namespace is already cached, send the FD to the client.
        stream.write_u32(fd as u32)?;
    } else {
        error!("Namespace {:?} is not cached yet.", namespace_type);
        stream.write_u32(0)?;
    }
    Ok(())
}

fn handle_read_modules(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    stream.write_usize(context.modules.len())?;
    for module in &context.modules {
        stream.write_string(&module.name)?;
        stream.send_fd(module.lib_fd.as_raw_fd())?;
    }
    Ok(())
}

fn handle_request_companion_socket(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let index = stream.read_usize()?;
    let module = &context.modules[index];
    let mut companion = module.companion.lock().unwrap();

    // Check if the existing companion socket is still alive.
    if let Some(sock) = companion.as_ref() {
        if !utils::is_socket_alive(sock) {
            error!(
                "Companion for module `{}` appears to have crashed.",
                module.name
            );
            companion.take();
        }
    }

    // If no companion exists, try to spawn one.
    if companion.is_none() {
        match spawn_companion(&module.name, module.lib_fd.as_raw_fd()) {
            Ok(Some(sock)) => {
                trace!("Spawned new companion for `{}`.", module.name);
                *companion = Some(sock);
            }
            Ok(None) => {
                warn!(
                    "Module `{}` does not have a companion entry point.",
                    module.name
                );
            }
            Err(e) => {
                warn!("Failed to spawn companion for `{}`: {}", module.name, e);
            }
        };
    }

    // Send the companion FD to the client if available.
    if let Some(sock) = companion.as_ref() {
        if let Err(e) = sock.send_fd(stream.as_raw_fd()) {
            error!(
                "Failed to send companion socket FD for module `{}`: {}",
                module.name, e
            );
            // Inform client of failure.
            stream.write_u8(0)?;
        }
        // If successful, the companion itself will notify the client.
    } else {
        // Inform client that no companion is available.
        stream.write_u8(0)?;
    }
    Ok(())
}

fn handle_get_module_dir(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let index = stream.read_usize()?;
    let module = &context.modules[index];

    // [修正] 直接使用我们在 load_modules 里计算并保存的真实 root_dir
    // 而不是尝试用模块名去拼接路径 (因为模块名 rikka.sui 和文件夹名 sui 不一致)
    let dir = fs::File::open(&module.root_dir)?;

    stream.send_fd(dir.as_raw_fd())?;
    Ok(())
}