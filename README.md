# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `544`
- **Commit:** [`221cf29`](https://github.com/XiaoTong6666/Sui/commit/221cf2945dc3446f16b6748b926fb031e51cc265)
- **Build time:** `2m 50s`
- **SHA256:** `e707f5ae8af535d2bb629d9d225bcb9ac27539d74ffa012047e43eb2eace3f41`

## Message

```text
fix(server): restart legacy clients after permission approval

授权弹窗确认后，若旧版 API 客户端不支持 Binder handoff，服务端先强制停止客户端，再仅重新拉起发起授权请求的应用，使其在新权限下重新连接。

```
