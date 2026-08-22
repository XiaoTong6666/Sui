# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `531`
- **Commit:** [`5791682`](https://github.com/XiaoTong6666/Sui/commit/5791682375729ff1ada7aad44999fdecaca91c92)
- **Build time:** `1m 26s`
- **SHA256:** `101beacbbd4a73ae5a0c9b92425342147ee3365153c2890c7aa731da7e28fefa`

## Message

```text
feat: 添加旧版 Shizuku Binder 广播兼容

为仍通过旧版显式广播协议请求 Shizuku Binder 的应用添加可选兼容支持。

- 在管理界面新增多语言“旧版 Shizuku 兼容”全局开关。
- 在 system_server 中拦截 IActivityManager 的 broadcastIntent / broadcastIntentWithFeature 事务，识别旧版 REQUEST_BINDER 请求。
- 通过调用方提供的回调 Binder 返回 Sui 现有服务 Binder，并复用原有权限路由及隐藏 UID 行为。
- 动态解析广播事务码和 Intent 前的 String 参数数量，以适配不同 Android 版本的 IActivityManager 接口变化。
- 兼容关闭、已安装 Shizuku、请求无效或处理失败时，继续交由 AMS 正常处理。

```
