# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `563`
- **Commit:** [`a82856c`](https://github.com/XiaoTong6666/Sui/commit/a82856cb9ea1d858437568ac930377c9df80a854)
- **Build time:** `1m 47s`
- **SHA256:** `d213e91586011f488f2f8b76142e93eb027786db638169d3529c46276dca6e13`

## Message

```text
perf: optimize legacy Shizuku Binder compatibility and Hide, Meow

为旧版 Shizuku Binder 兼容开关增加 Native 与 Java 缓存，避免每次请求都通过同步 Binder 查询全局设置。

在 Native 层提前检查兼容开关和调用方 UID，减少无关广播及 Hidden 应用进入 Java 解析流程的开销。

重构权限快照同步逻辑，统一管理 Hidden、Root、Denied、Shell 和默认权限状态，并保留原有 Java 权限复核。

为 Bridge 权限同步增加结果确认与失败重试，降低服务重连或同步失败导致的状态不一致风险。

优化旧版 Shizuku callback 处理流程，保留正常 Binder 返回功能，并阻止 Hidden 应用获取服务 Binder。

优化 BinderHook 日志计数，避免超过采样次数后仍持续执行全局原子递增。

```
