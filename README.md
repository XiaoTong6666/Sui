# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `541`
- **Commit:** [`2465053`](https://github.com/XiaoTong6666/Sui/commit/2465053afad18ddffffbb0eff803081f24bfb4d7)
- **Build time:** `2m 22s`
- **SHA256:** `8ff9dc9c826893307c904b69213c91a63ecf2679add8845397bfc733f6277ce5`

## Message

```text
feat(shell): prevent KernelSU re-escalation

为 Sui Shell 增加可选的 KernelSU no-escape 保护，在 shell child 降到 UID 2000 前通过 KernelSU driver ioctl 设置 DISABLE_ESCAPE_TO_ROOT，并让该限制随进程树继承，阻止 Rish、shell 模式 Shizuku API 与 UserService 再次通过 KernelSU 获取 root。
新增右上角开关、marker 持久化与状态同步；当目前的 KernelSU 不支持这个 UAPI 时自动移除 marker。

```
