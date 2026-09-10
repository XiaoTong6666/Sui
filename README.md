# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `537`
- **Commit:** [`6aeee19`](https://github.com/XiaoTong6666/Sui/commit/6aeee19fef0f99f81bc66269b2d1fb41695428d2)
- **Build time:** `1m 30s`
- **SHA256:** `20ea278b6152ab4e958435c8c13eaf5af345716d113a221afa664ea0970b2e9d`

## Message

```text
fix(shell): align shell server credentials and routing

修复 shell server 的完整身份构造流程，在子进程启动时初始化 libselinux，先设置与 adbd 一致的 supplementary groups，再完成 GID/UID 降权并切换到 u:r:shell:s0，避免提前进入 shell domain 后因缺少 setgid 能力导致启动失败，同时补充关键阶段的 UID、GID 与 SELinux context 日志用于诊断。

修复 shell UID 2000 被应用 UID 过滤条件排除的问题，仅在 FLAG_ALLOWED_SHELL 路由中允许 Process.SHELL_UID 进入 shell UID 列表，使 system_server 能将 adb shell 与 rish 请求正确分发到 shell service binder，而不是回退到 root server。

```
