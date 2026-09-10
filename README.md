# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `537`
- **Commit:** [`9e35b74`](https://github.com/XiaoTong6666/Sui/commit/9e35b741f10017d370b7f7d084c3bd84ad055da1)
- **Build time:** `2m 53s`
- **SHA256:** `af786261aa4fe3ea143e7eef4e9cd83f68b76659ec174b3bd8143eea8b4090af`

## Message

```text
fix(shell): restore shell server identity and routing

修复 shell server 的 SELinux 身份初始化与降权顺序，在启动 shell 子进程时显式初始化 libselinux，并先完成 GID/UID 降权后再切换到 u:r:shell:s0，避免进入 shell domain 后因缺少 setgid 能力导致启动失败，同时补充关键阶段的 UID、GID 与 SELinux context 日志用于诊断。

修复 shell UID 2000 被应用 UID 过滤条件排除的问题，在 FLAG_ALLOWED_SHELL 路由中显式允许 Process.SHELL_UID 进入 shell UID 列表，使 system_server 能正确将 adb shell/rish 请求分发到 shell service binder，而不是回退到 root server。

Signed-off-by: XiaoTong6666 <xiaotong6666666666@gmail.com>

```
