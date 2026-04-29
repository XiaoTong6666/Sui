# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `468`
- **Commit:** `d6d4cbe`

## Message

```text
fix(server): 修复权限委托回调与 Binder 资源泄漏

修复多处异常路径下的资源泄漏问题：

- 为 shell 权限委托回调增加 DeathRecipient 和超时清理，避免 UI 未返回、shell 进程死亡或请求中断时 callback 残留
- 避免 BridgeServiceClient 在重试或重注册时重复挂载 DeathRecipient
- 修复 RootBridgeDelegate 异常路径下 Parcel 未回收的问题
- 避免 Logger 重复构造时为同名 Logger 重复添加 FileHandler

同时在回调派发和异常处理路径中补充资源释放逻辑，降低 fd、handler 和 binder callback 累积风险。
```
