# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `537`
- **Commit:** [`fb0c9f6`](https://github.com/XiaoTong6666/Sui/commit/fb0c9f6658ae339be0264653e20026052721213a)
- **Build time:** `1m 22s`
- **SHA256:** `733e5126db67ea4ffed5acf7614a143cf4814f46cbafbb5edf0d04ace0241f48`

## Message

```text
fix(shell): align shell server credentials and routing

修复 shell server 的完整身份构造流程，在子进程启动时初始化 libselinux，先设置与 adbd 一致的 supplementary groups，再完成 GID/UID 降权并切换到 u:r:shell:s0，避免提前进入 shell domain 后因缺少 setgid 能力导致启动失败，同时补充关键阶段的 UID、GID 与 SELinux context 日志用于诊断。

修复 shell UID 2000 被应用 UID 过滤条件排除的问题，仅在 FLAG_ALLOWED_SHELL 路由中允许 Process.SHELL_UID 进入 shell UID 列表，使 system_server 能将 adb shell 与 rish 请求正确分发到 shell service binder，而不是回退到 root server。

在 AVD 上验证 sui_shell 与真实 adb shell 的 UID、primary GID、supplementary groups 和 SELinux context 一致，rish 创建的进程保持相同身份并命中 shell server。

Signed-off-by: XiaoTong6666 <xiaotong6666666666@gmail.com>

```
