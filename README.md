# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `541`
- **Commit:** [`c5984e4`](https://github.com/XiaoTong6666/Sui/commit/c5984e4ff2690b524b2d9e664280b41363a91761)
- **Build time:** `2m 59s`
- **SHA256:** `c96b1b6af5d0d734795dc798dae6b71c1a3b11b97900a3fe3d720cfa6da0337e`

## Message

```text
feat(shell): prevent KernelSU re-escalation

为 Sui Shell 增加可选的 KernelSU no-escape 保护，在 shell child 降到 UID 2000 前通过 KernelSU driver ioctl 设置 DISABLE_ESCAPE_TO_ROOT，并让该限制随进程树继承，阻止 Rish、shell 模式 Shizuku API 与 UserService 再次通过 KernelSU 获取 root。
新增右上角开关、marker 持久化与状态同步；当目前的 KernelSU 不支持这个 UAPI 时自动移除 marker。

```
