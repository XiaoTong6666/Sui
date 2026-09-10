# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `538`
- **Commit:** [`8bd7c43`](https://github.com/XiaoTong6666/Sui/commit/8bd7c431f6f8694618c3b131b544ec10a5a9ff8b)
- **Build time:** `2m 46s`
- **SHA256:** `517395389f962a0c15dc16f132b16c6151387ccf64e525f3ecb8ae2ebc5c00eb`

## Message

```text
fix(shell): align shell privileges with adbd

按 Android API 动态匹配 supplementary groups 和 SELinux 权限规则。
完善 shell domain 切换和 PDEATHSIG 设置时序，并让 SELinux 初始化失败时直接拒绝继续运行。

```
