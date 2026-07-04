# Sui

[🇨🇳中文README](https://github.com/XiaoTong6666/Sui/blob/main/README.zh-CN.md) | [🇯🇵日本語README](https://github.com/XiaoTong6666/Sui/blob/main/README.ja.md)

Modern super user interface (SUI) implementation for Android. ~~The name, Sui, also comes from [a character](https://github.com/XiaoTong6666/Sui/issues/1).~~

## Introduction

Sui provides Java APIs, namely [Shizuku API](https://github.com/RikkaApps/Shizuku-API), for root / shell apps. It mainly provides two abilities:

1. Use Android Framework APIs directly, almost as if calling system APIs from Java as root or shell.
2. Start an app-defined AIDL-style Java service under root or shell.

This makes privileged Android app development much more comfortable.

Another advantage is that Sui does not add binaries to `PATH` and does not install a standalone manager app. This means we no longer need to spend a huge amount of time fighting apps that detect them.

To be clear, the full implementation of "root" is far more than `su` itself. There is a lot of hard work to be done before it. Sui is not a full root solution. It requires an existing root environment and runs as a Zygisk module.

<details>
  <summary>Why "su" is unfriendly for app development</summary>

`su`, a "shell" running as root, is too far from the Android world.

To explain this, we need to briefly talk about how system APIs work. For example, we can use `PackageManager#getInstalledApplications` to get the app list. This is actually an inter-process communication (IPC) process between the app process and the system_server process. The Android Framework just hides the details for us.

Android uses `Binder` for this type of IPC. `Binder` allows the server side to learn the uid and pid of the client side, so system_server can check whether the app has permission to perform the operation.

Back to `su`. In a `su` environment, we usually only have commands provided by the Android system. In the same example, to get the app list with `su`, we have to run `pm list`. This is painful:

1. **Text-based output**: there is no structured data like `PackageInfo` in Java. You have to parse text.
2. **Slow**: running a command means at least one new process is started, and `PackageManager#getInstalledApplications` is still called inside `pm list`.
3. **Limited ability**: commands only cover a small part of Android APIs.

Although it is possible to use Java APIs as root with `app_process` through libraries such as libsu or librootjava, transferring Binder objects between the app process and the root process is painful. If you want the root process to run as a daemon, once the app process restarts, there is no cheap way to get the Binder of the root process again.

In fact, for Magisk and other root solutions, making `su` work is not as easy as some people think. Both `su` itself and the communication between `su` and the manager app involve a lot of unpleasant work behind the scenes.

</details>

## User guide

Note: the behavior of existing apps that only support `su` will NOT change.

### Install

You can install Sui directly in KernelSU or another compatible root manager such as Magisk or APatch. Or download the zip from [release](https://github.com/XiaoTong6666/Sui/releases) and use **Install from storage** in your root manager.

Sui requires a compatible root environment. On Magisk, this means Magisk 24.0+ with Zygisk enabled. On KernelSU or APatch, it additionally requires a separate Zygisk implementation such as [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext), [ReZygisk](https://github.com/PerformanC/ReZygisk), or [NeoZygisk](https://github.com/JingMatrix/NeoZygisk). Do not add SystemUI or Settings to Zygisk DenyList, otherwise the injected management UI may not work properly.

### Management UI

* Long press the **System Settings** icon on the home screen to see the Sui shortcut
* In the Sui management interface, tap the menu button in the top-right corner and select **Add shortcut to home screen**
* Enter `*#*#784784#*#*` in the default dialer app
* Open the Sui management interface via the **Action** button in KernelSU/Magisk manager

> **Note:** On some systems, the Sui shortcut may not appear when long-pressing Settings.     
> Additionally, to avoid disturbing users, newer versions have **removed** the feature that automatically prompts to add a shortcut when entering **Developer options**.

### Permission modes

Sui stores permission states by UID. The main modes are:

* **Ask / default**: the app can connect to Sui and request permission through the normal flow.
* **Allow root**: the app will be routed to the root backend.
* **Allow shell**: the app will be routed to the shell backend.
* **Deny**: deny the app from using Sui.
* **Hide**: hide Sui from the target app. When Hide is enabled, the target app UID is intercepted in the Native Binder `execTransact` stage. Its Sui bridge transaction is swallowed before it can enter BridgeService and obtain the Sui Binder.

When the permission state changes, Sui may force-stop affected apps to cut off old Binder handles and make them obtain the correct backend on the next launch.

### Interactive shell

Sui provides an interactive shell.

Since Sui does not add files to `PATH`, the required files need to be copied manually. See `/data/adb/sui/post-install.example.sh` to learn how to do this automatically.

After the files are correctly copied, use `rish` as `sh` to start an interactive shell.

### adb root

Sui also provides optional `adb root` support. When enabled, Sui sets up an `adbd` wrapper plus preload hook so that `adbd` can run under the current root implementation's SELinux domain while keeping the expected `adbd` socket label.

This feature is disabled by default. Enable it by creating one of the following marker files from a root shell, then reboot so Sui can apply the setup during `post-fs-data`:

* Enable for the next boot only:

  ```sh
  touch /data/adb/sui/enable_adb_root_once
  ```

* Enable persistently for every boot:

  ```sh
  touch /data/adb/sui/enable_adb_root
  ```

After reboot, use `adb root` normally.

To disable the persistent mode again:

```sh
rm /data/adb/sui/enable_adb_root
```
> This feature depends on your root implementation and SELinux policy. Sui checks the required `setcurrent`, `dyntransition`, and `setsockcreate` permissions before enabling it.
> Existing app behavior does not change. This only affects the device `adbd` path.
> If your device uses a heavily customized `adbd` implementation, compatibility may vary.

## Application development guide

Sui app development should still primarily follow the upstream Shizuku API documentation:

[https://github.com/RikkaApps/Shizuku-API](https://github.com/RikkaApps/Shizuku-API)

Apps are recommended to use `rikka.shizuku.Shizuku` as the unified compatibility layer. Do not maintain a Sui-only code path. In this way, one wrapper can support both Shizuku and Sui.

In the normal integration pattern, you only need `ShizukuProvider` plus the regular Shizuku API flow. `ShizukuProvider` already attempts Sui initialization automatically, so app code usually does not need to import or call `rikka.sui.Sui` directly.

If you intentionally disable `ShizukuProvider`'s automatic Sui initialization, you can still call `Sui.init(packageName)` manually inside your wrapper. If it receives a Binder, it passes it to the Shizuku API layer; if not, the app can continue with the normal Shizuku flow.

Example pattern with the normal auto-initialization flow:

```kotlin
import android.content.pm.PackageManager
import android.content.pm.IPackageManager
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuBinderWrapper
import rikka.shizuku.SystemServiceHelper

fun initPrivilegedApi() {
    Shizuku.addBinderReceivedListener {
        checkShizukuPermission()
    }

    if (Shizuku.pingBinder()) {
        checkShizukuPermission()
    }
}

fun checkShizukuPermission() {
    if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
        val binder = SystemServiceHelper.getSystemService("package")
            ?: return

        val pm = IPackageManager.Stub.asInterface(
            ShizukuBinderWrapper(binder)
        )

        pm.isPackageAvailable("android", 0)
    } else {
        Shizuku.requestPermission(0)
    }
}
```

If you want manual initialization instead, add `import rikka.sui.Sui` and call `Sui.init(packageName)` before waiting for the binder.

Common APIs include:

* `Shizuku.pingBinder()`
* `Shizuku.checkSelfPermission()`
* `Shizuku.requestPermission(requestCode)`
* `Shizuku.getUid()`, which can be used to check the current backend identity, for example `0` for root and `2000` for shell
* `SystemServiceHelper.getSystemService(name)`
* `ShizukuBinderWrapper`, used to wrap Android Framework service binders
* `bindUserService()`, used to start an app-defined Java service running as root or shell

## Build

> **Note:** Clone the repository with submodules, otherwise required API projects will be missing.

```bash
git clone --recurse-submodules https://github.com/XiaoTong6666/Sui.git
```

Gradle tasks:

`BuildType` could be `Debug` or `Release`.

* `:module:assemble<BuildType>`

  Build the module. After assemble finishes, the flashable module zip will be generated to `out`.

* `:module:zip<BuildType>`

  Generate the flashable module zip to `out`.

* `:module:push<BuildType>`

  Push the zip with adb to `/data/local/tmp`.

* `:module:flash<BuildType>`

  Install the zip with `adb shell su -c magisk --install-module`.

* `:module:flashWithKsud<BuildType>`

  Install the zip with `adb shell su -c ksud module install`.

* `:module:flashAndReboot<BuildType>`

  Install the zip and reboot the device.

* `:module:flashWithKsudAndReboot<BuildType>`

  Install the zip with ksud and reboot the device.

For example:

```bash
./gradlew :module:assembleRelease
./gradlew :module:zipRelease
./gradlew :module:flashRelease
```

## Troubleshooting

### Capture Sui logs

```sh
adb logcat -v time | grep -i sui
```

### How to report problems

If you need to report a problem, please provide logs reproduced on a **debug** build.

- Install or flash a **debug** build of Sui and reproduce the issue.
- If you use **KernelSU** or **APatch**, export logs from the root manager first. These logs are usually more complete for module mounting, Zygisk injection, SELinux, and early boot/runtime issues.
- Also [capture Sui logs](#capture-sui-logs).
- Include basic environment information:
  - root implementation and version
  - Zygisk implementation and version
  - Android version / ROM
  - whether `SystemUI` or `Settings` is in DenyList
  - exact reproduction steps

If the issue cannot be reproduced on the debug build and only happens on release builds, include a short description of the release-only behavior and the exact reproduction steps.

### Cannot access the Sui management interface

- Your root environment is supported (Magisk with Zygisk enabled, or KernelSU/APatch with a compatible Zygisk implementation).
- `SystemUI` and `Settings` are **not** included in the Zygisk DenyList.
- The device has been rebooted after installing or updating Sui.

### Optional features do not work as expected

- Reboot once after changing Sui module files or marker files.
- If needed, export logs from KernelSU / APatch and [capture Sui logs](#capture-sui-logs).
- If needed, also inspect the files under `/data/adb/sui/` to confirm marker files and generated artifacts are present.

## Internals

Sui requires [Zygisk](https://github.com/topjohnwu/zygisk-module-sample). Zygisk allows us to inject into system_server, SystemUI, Settings and related app processes.

Overall, there are five main parts, and an optional `adb root` path:

* **Root process**

  This is a root process started by the root implementation during the post-fs-data stage. It starts a Java server that implements Shizuku API and private APIs used by other parts.

  The root server is the main source of permission configuration. It maintains the UID permission database and syncs hidden, root allowed, shell allowed, denied and default mode states to system_server.

* **Shell process**

  The shell server runs as shell and serves apps granted with shell permission.

  It loads UID permission states from the configuration file mirrored by the root server. When the shell backend needs to show a permission confirmation window, it delegates the request to the root server, which then triggers the SystemUI confirmation UI.

* **SystemServer inject**

  * Hooks `Binder#execTransact` to intercept the dedicated Binder transaction used by Sui inside `system_server`
  * Keeps the root binder, shell binder, and permission caches for hidden/root allowed/shell allowed/denied/default mode
  * Chooses which backend Binder to return based on the UID's effective permission: root gets the root binder, shell gets the shell binder
  * For hidden UIDs, blocks the Sui bridge request directly; for ask/deny, still returns the root binder so the client can continue through the normal permission or denial result flow

* **SystemUI inject**

  * Opens the Sui APK fd from Sui service and loads Sui `Resources` plus the permission dialog class
  * Attaches to the service and shows permission confirmation dialogs on callback
  * Registers secret-code style entry points and, when triggered, launches the Sui management UI hosted in the Settings process

* **Settings inject**

  * Opens the Sui APK fd from Sui service and loads Sui `Resources` plus `SuiActivity`
  * Replaces `ActivityThread` instrumentation during Settings process startup
  * Maintains dynamic/pinned shortcuts and handles pinned-shortcut requests relayed from SystemUI
  * When the target `Activity` intent carries the Sui extra and token, instantiates and displays `SuiActivity` instead

* **adbd wrapper / preload (optional)**

  * During `post-fs-data`, when `adb root` support is enabled, Sui prepares an `adbd` wrapper and preload library for `/apex/com.android.adbd/bin/adbd` or `/system/bin/adbd`
  * The wrapper rewrites `--root_seclabel=...` to the current root implementation's SELinux domain and injects `LD_PRELOAD`
  * The preload hook intercepts `selinux_android_setcon()` / `setcon()` so `adbd` can switch into the root domain while restoring `sockcreate` to the expected `adbd` label

## License

Sui is licensed under GPL-3.0-or-later.
