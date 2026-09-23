# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `553`
- **Commit:** [`e37d54c`](https://github.com/XiaoTong6666/Sui/commit/e37d54c3914bf614fd96daf32641d0865c382762)
- **Build time:** `2m 48s`
- **SHA256:** `a9363704d070b68514c62d656d2c6ede95c0c07da21507de11c8d4514287f4ad`

## Message

```text
fix(module): harden shell runtime and framework compatibility #124

修复部分 OEM 系统上 shell runtime 文件继承错误 SELinux 标签的问题。启动时先检查实际 context，只有标签异常时才修正为 shell_data_file，并在修改后重新校验。

统一 shell runtime 文件准备流程。system_ui、settings、sui.dex 和 librish.so 在降权前完成复制、标签、权限与属主设置，关键步骤失败时直接终止 shell child，避免以半初始化状态继续启动。

移除无效的 libsui.so shell runtime staging。libsui.so 安装后会作为 Zygisk 模块移动到 zygisk/<abi>.so，模块根目录并不存在 libsui.so，shell server 运行时也不依赖该文件。

保持 shell 权限切换顺序不变。runtime 准备完成后再依次设置 supplementary groups、GID、UID，并最终切换到 u:r:shell:s0，避免扩大 shell 对 system_data_file 的访问权限。

将长驻 SuiService 的 SystemUI 和 Settings 解析改为读取 Installer 生成的 metadata，避免 server 为获取 system context 调用 ActivityThread.systemMain()，减少 OEM framework 初始化带来的副作用。

Installer 与 Uninstaller 优先使用未 attach 的 ActivityThread 配合 ContextImpl.createSystemContext() 获取 system resources 和 PackageManager，保留 config_systemUIServiceComponent 与 Settings 的动态解析能力。

为旧 Android 或定制 framework 保留 ActivityThread.systemMain() fallback。detached context 构造失败时会输出明确诊断信息后回退原路径，兼顾新路径的低副作用和旧设备兼容性。

metadata 变化时同步刷新相关目标并重启 Sui root/shell pair，确保 SystemUI、Settings 身份变化后运行时状态与 Zygisk 注入目标保持一致。

```
