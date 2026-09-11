# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `543`
- **Commit:** [`5b2aa16`](https://github.com/XiaoTong6666/Sui/commit/5b2aa1606e4734adeec3fbddf48800c564c8c8d4)
- **Build time:** `1m 52s`
- **SHA256:** `fb3286bdaedee32ee4a040495c9ddcd27e84252bd4f9ccd2e326d4cbcdc56177`

## Message

```text
fix(sui): synchronize permission revocation lifecycle

在 Sui 层同步权限变更、服务器 Binder 路由和能力撤销流程。

撤销远程进程、Rish 宿主和用户服务，处理 shell/root 切换及用户服务进程注册，避免权限降级后继续持有高权限能力。

```
