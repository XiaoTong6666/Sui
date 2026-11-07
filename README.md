# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `577`
- **Commit:** [`c5cbf06`](https://github.com/XiaoTong6666/Sui/commit/c5cbf06db2bacff2d6100ba7623051a91190aee5)
- **Build time:** `2m 31s`
- **SHA256:** `fbcc286344fdb729df42e834a7d7699356afc502e86ebdd207e83d2aca8048df`

## Message

```text
fix(legacy): Harden Sui DEX directory permissions, Meow

修复旧版 Android 首次启动时 /data/system/sui 权限异常导致 system_server DEX 注入失败的问题喵
注入前校验工作目录的属主及类型，并在权限异常时自动恢复；将共享目录收紧为 0751、oat 收紧为 0700，同时清理缓存的组与其他用户权限，补充启动脚本的失败日志喵

```
