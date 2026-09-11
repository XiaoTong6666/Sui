# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `543`
- **Commit:** [`a45ef9c`](https://github.com/XiaoTong6666/Sui/commit/a45ef9cde466c7b7a5025d43c21cb3771520cb20)
- **Build time:** `2m 26s`
- **SHA256:** `7ed911dc05a075ab9844532a230f7268228700f6b2474a60bc14a18370bf2fb4`

## Message

```text
fix(sui): synchronize permission revocation lifecycle

在 Sui 层同步权限变更、服务器 Binder 路由和能力撤销流程。

撤销远程进程、Rish 宿主和用户服务，处理 shell/root 切换及用户服务进程注册，避免权限降级后继续持有高权限能力。

```
