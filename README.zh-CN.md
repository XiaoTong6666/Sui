# Sui

[🇺🇸English README](https://github.com/XiaoTong6666/Sui/blob/main/README.md) | [🇯🇵日本語README](https://github.com/XiaoTong6666/Sui/blob/main/README.ja.md)

用于 Android 的现代超级用户界面（SUI）实现。~~名字 Sui 也来自于一个[角色](https://github.com/XiaoTong6666/Sui/issues/1)。~~

## 简介

Sui 为 root / shell 应用提供 Java API（即 [Shizuku API](https://github.com/RikkaApps/Shizuku-API)）。它主要提供两项能力：

1. 让应用能够直接调用 Android Framework API（几乎等同于以 root 或 shell 身份在 Java 层调用系统 API）。
2. 以 root 或 shell 身份启动应用自身的、AIDL 风格的 Java 服务。

这会让高权限 Android 应用的开发变得更加舒适。

另一个优势是：Sui 不会向 `PATH` 中添加二进制文件，也不会安装一个独立的管理器应用。这意味着我们不需要花大量时间去对抗那些会检测这些东西的应用。

需要说明的是，“root”的完整实现远不止 `su` 本身。在它之前还有很多工作要做。Sui 不是一个完整的 root 方案，它需要已有的 root 环境，并作为 Zygisk 模块运行。

<details>
  <summary>为什么 “su” 对应用开发不友好</summary>

`su` 提供的是一个以 root 身份运行的 “shell”，它离 Android 的世界太远了。

为了说明这一点，我们先简要解释系统 API 的工作方式。比如我们可以用 `PackageManager#getInstalledApplications` 来获取应用列表。这个过程本质上是应用进程与 system_server 进程之间的 IPC（跨进程通信），只是 Android Framework 帮我们封装好了内部细节。

Android 使用 `Binder` 来完成这类 IPC。`Binder` 会让 server 端知道 client 的 uid 和 pid，从而 system_server 可以据此检查 client 是否有权限执行相应操作。

回到 `su`。在 `su` 环境下，我们通常只能使用系统提供的命令。还是同一个例子，如果想用 `su` 获取应用列表，就得执行 `pm list`。这非常痛苦：

1. **文本化输出**：这意味着你拿不到像 Java 里的 `PackageInfo` 那样的结构化数据，只能去解析文本。
2. **速度慢**：每执行一个命令至少要启动一个新进程，而 `PackageManager#getInstalledApplications` 本身也会在 `pm list` 内部被调用。
3. **能力有限**：命令能做的事情很少，只覆盖了 Android API 的一小部分。

虽然可以通过 `app_process` 以 root 身份调用 Java API（已有如 libsu、librootjava 等库），但在 app 进程和 root 进程之间传递 Binder 非常麻烦。尤其当你希望 root 进程作为常驻 daemon 时，一旦 app 进程重启，就没有廉价的方式重新获得 root 进程的 Binder。

事实上，对于 Magisk 或其他 root 方案来说，要让 `su` 正常工作并不如很多人想象的那么简单（无论是 `su` 本身，还是 `su` 与管理器应用之间的通信，都有大量不愉快的幕后工作）。

</details>

## 用户指南

注意：现有只支持 `su` 的应用，其行为不会发生变化。

### 安装

你可以直接在 KernelSU 或其他兼容的 root 管理器中安装 Sui，例如 Magisk / APatch。或者从 [release](https://github.com/XiaoTong6666/Sui/releases) 下载 zip 包，并在 root 管理器的 **从本地安装（Install from storage）** 中刷入。

Sui 需要一个兼容的 root 环境。对于 Magisk，需要 Magisk 24.0+ 且启用 Zygisk；对于 KernelSU / APatch，则需要额外配合独立实现的 Zygisk，例如 [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)、[ReZygisk](https://github.com/PerformanC/ReZygisk) 或 [NeoZygisk](https://github.com/JingMatrix/NeoZygisk)。请不要将 SystemUI 或 Settings 加入 Zygisk DenyList，否则注入式管理界面可能无法正常工作。

### 管理界面（Management UI）

* 在桌面长按系统设置图标，会看到 Sui 的快捷方式
* 在 Sui 管理界面点击右上角菜单（三个点），点击 **“添加快捷方式到桌面”** 即可在桌面创建快捷方式
* 在默认拨号器中输入 `*#*#784784#*#*`
* 可以通过 KernelSU/Magisk 的 Action 按钮打开 Sui 管理界面

> **注意：** 对于部分系统，长按设置可能不会出现 Sui 快捷方式；    
> 为了避免打扰用户，新版本已 **移除** 进入 **“开发者选项”** 时自动询问添加快捷方式的功能。

### 权限模式

Sui 按 UID 保存应用的权限状态。主要模式包括：

* **询问 / 默认**：应用可以连接到 Sui，并通过正常流程请求授权。
* **允许 root**：应用会被路由到 root 后端，相关 API 以 root 身份执行。
* **允许 shell**：应用会被路由到 shell 后端，相关 API 以 shell 身份执行。
* **拒绝**：拒绝应用使用 Sui。
* **隐藏**：对目标应用隐藏 Sui。开启隐藏后，目标应用 UID 会在 Native Binder `execTransact` 阶段被拦截，其发起的 Sui bridge transaction 会被直接吞掉，无法继续进入 BridgeService 获取 Sui Binder。

修改权限状态后，Sui 可能会强制停止受影响应用，以切断旧 Binder 句柄，并让应用下次启动时获取正确的后端。

### 交互式 shell

Sui 提供交互式 shell。

由于 Sui 不会向 `PATH` 写入文件，所以需要手动复制所需文件。你可以参考 `/data/adb/sui/post-install.example.sh` 学习如何自动完成这一步。

文件正确复制后，就可以使用 `rish` 作为 `sh` 来启动交互式 shell。

### adb root

Sui 还提供可选的 `adb root` 支持。启用后，Sui 会为 `adbd` 配置 wrapper 和 preload hook，使 `adbd` 运行在当前 root 实现对应的 SELinux 域下，同时保持预期的 `adbd` socket label。

该功能默认关闭。请在 root shell 中创建下面的标记文件之一，然后重启设备，让 Sui 在 `post-fs-data` 阶段完成配置：

* 仅对下一次开机启用：

  ```sh
  touch /data/adb/sui/enable_adb_root_once
  ```

* 对之后每次开机都启用：

  ```sh
  touch /data/adb/sui/enable_adb_root
  ```

重启完成后，像平常一样使用 `adb root` 即可。

如果要关闭持久启用模式：

```sh
rm /data/adb/sui/enable_adb_root
```
> 该功能依赖你的 root 实现和设备 SELinux 策略。Sui 会在启用前检查所需的 `setcurrent`、`dyntransition` 和 `setsockcreate` 权限。
>  现有应用行为不会变化；这个功能只影响设备上的 `adbd` 链路。
> 如果设备使用了高度定制的 `adbd` 实现，兼容性可能会有所不同。

## 应用开发指南

应用开发时，API 仍应以上游 Shizuku API 文档为主：

[https://github.com/RikkaApps/Shizuku-API](https://github.com/RikkaApps/Shizuku-API)

应用侧建议以 `rikka.shizuku.Shizuku` 作为统一兼容层，不要维护一套只面向 Sui 的调用路径。这样应用可以通过同一套包装器同时兼容 Shizuku 与 Sui。

在常规接入方式里，只需要接入 `ShizukuProvider` 和标准的 Shizuku API 流程即可。`ShizukuProvider` 本身已经会自动尝试初始化 Sui，因此应用代码通常不需要直接 `import rikka.sui.Sui` 或手动调用 `Sui.init(...)`。

如果你有意关闭了 `ShizukuProvider` 的自动 Sui 初始化，也可以在自己的包装器里手动调用 `Sui.init(packageName)`。如果成功拿到 Binder，它会交给 Shizuku API 层；如果没有拿到，应用继续走普通 Shizuku 启动流程即可。

下面示例展示的是常规自动初始化流程：

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

如果你想手动初始化，再额外 `import rikka.sui.Sui`，并在等待 Binder 前调用 `Sui.init(packageName)` 即可。

常用 API 包括：

* `Shizuku.pingBinder()`
* `Shizuku.checkSelfPermission()`
* `Shizuku.requestPermission(requestCode)`
* `Shizuku.getUid()`，可用于判断当前后端身份，例如 root 为 `0`，shell 为 `2000`
* `SystemServiceHelper.getSystemService(name)`
* `ShizukuBinderWrapper`，用于包装 Android Framework service binder
* `bindUserService()`，用于启动应用自己定义的、以 root 或 shell 身份运行的 Java 服务

## 编译/构建（Build）

> **注意：** 请使用带 submodule 的方式克隆仓库，否则所需的 API 子项目会缺失。

```bash
git clone --recurse-submodules https://github.com/XiaoTong6666/Sui.git
```

Gradle 任务：

`BuildType` 可为 `Debug` 或 `Release`。

* `:module:assemble<BuildType>`

  构建模块。完成后可刷入的模块 zip 会生成在 `out` 目录。

* `:module:zip<BuildType>`

  生成可刷入的模块 zip 至 `out`。

* `:module:push<BuildType>`

  通过 adb 推送 zip 至 `/data/local/tmp`。

* `:module:flash<BuildType>`

  用 `adb shell su -c magisk --install-module` 安装 zip。

* `:module:flashWithKsud<BuildType>`

  用 `adb shell su -c ksud module install` 安装 zip。

* `:module:flashAndReboot<BuildType>`

  安装 zip 并重启设备。

* `:module:flashWithKsudAndReboot<BuildType>`

  使用 ksud 安装并重启。

例如：

```bash
./gradlew :module:assembleRelease
./gradlew :module:zipRelease
./gradlew :module:flashRelease
```

## 故障排查

### 抓取 Sui 日志

```sh
adb logcat -v time | grep -i sui
```

### 如何反馈问题

如需反馈问题，请提供 **debug** 版本下复现得到的日志。

- 先安装或刷入 **debug** 版 Sui，并复现问题。
- 如果你使用的是 **KernelSU** 或 **APatch**，优先从 root 管理器中导出日志。这类日志通常对模块挂载、Zygisk 注入、SELinux 以及早期启动/运行阶段的问题更完整。
- 同时[抓取 Sui 日志](#抓取-sui-日志)。
- 反馈时请附带基本环境信息：
  - root 实现及版本
  - Zygisk 实现及版本
  - Android 版本 / ROM
  - `SystemUI` 或 `Settings` 是否被加入 DenyList
  - 明确的复现步骤

如果问题无法在 debug 版本中复现、只存在于 release 版本，请补充说明 release 特有现象以及准确的复现步骤。

### 无法进入 Sui 管理界面

- 你的 root 环境是否受支持（Magisk + Zygisk，或 KernelSU / APatch + 兼容的 Zygisk 实现）。
- `SystemUI` 和 `Settings` **没有** 被加入 Zygisk DenyList。
- 安装或更新 Sui 后设备已经重启。

### 可选功能异常

- 修改 Sui 模块文件或 marker 文件后，先重启一次设备。
- 如有需要，优先导出 KernelSU / APatch 日志，同时[抓取 Sui 日志](#抓取-sui-日志)。
- 必要时再检查 `/data/adb/sui/` 下的 marker 文件和生成文件是否存在。

## 内部实现（Internals）

Sui 依赖 [Zygisk](https://github.com/topjohnwu/zygisk-module-sample)，它允许我们注入 system_server、SystemUI、Settings 以及相关应用进程。

整体上有五个主要部分，以及可选的 `adb root` 路径：

* **Root 进程（Root process）**

  这是一个由 root 实现在 Post-fs-data 阶段启动的 root 进程。它会启动一个 Java server，实现 Shizuku API 以及其他部分所需的私有 API。
  Root server 是权限配置的主要来源。它维护 UID 权限数据库，并将 hidden、root allowed、shell allowed、denied 和 default mode 等状态同步到 system_server。

* **Shell 进程（Shell process）**

  Shell server 以 shell 身份运行，用于服务被授予 shell 权限的应用。
  它会从 root server 同步出的配置文件中加载 UID 权限状态。当 shell 后端需要显示授权确认窗口时，会将请求委托给 root server，由 root server 负责触发 SystemUI 授权界面。

* **SystemServer 注入（SystemServer inject）**

    * Hook `Binder#execTransact`，在 `system_server` 中接管 Sui 使用的特殊 Binder transaction
    * 维护 root binder、shell binder，以及 hidden/root allowed/shell allowed/denied/default mode 的权限缓存
    * 根据 UID 的有效权限决定返回哪个后端 Binder：root 返回 root binder，shell 返回 shell binder
    * 对 `hidden` UID，直接拦截其 Sui bridge 请求；对 `ask` / `deny`，仍返回 root binder，使客户端可以继续走授权或拒绝结果流程

* **SystemUI 注入（SystemUI inject）**

    * 从 Sui service 打开 APK fd，加载 Sui 的 `Resources` 与权限确认对话框类
    * attach 到服务后，在收到回调时显示权限确认窗口
    * 注册 secret code 等入口，并在触发时启动承载于 Settings 进程中的 Sui 管理界面

* **Settings 注入（Settings inject）**

    * 从 Sui service 打开 APK fd，加载 Sui 的 `Resources` 与 `SuiActivity`
    * 在 Settings 进程启动时替换 `ActivityThread` 的 `Instrumentation`
    * 维护动态/固定 shortcut，并响应来自 SystemUI 的固定 shortcut 请求
    * 当目标 `Activity` 的 intent 带有 Sui 特殊 extra 和 token 时，改为实例化并显示 `SuiActivity`

* **adbd wrapper / preload（可选）**

    * 当启用了 `adb root` 支持时，Sui 会在 `post-fs-data` 阶段为 `/apex/com.android.adbd/bin/adbd` 或 `/system/bin/adbd` 准备 `adbd` wrapper 和 preload 库
    * wrapper 会把 `--root_seclabel=...` 改写为当前 root 实现对应的 SELinux 域，并注入 `LD_PRELOAD`
    * preload hook 会拦截 `selinux_android_setcon()` / `setcon()`，让 `adbd` 切换到 root 域，同时把 `sockcreate` 恢复为预期的 `adbd` label

## License

Sui 使用 GPL-3.0-or-later 许可证。
