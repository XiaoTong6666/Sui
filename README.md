# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `487`
- **Commit:** [`0cce12d`](https://github.com/XiaoTong6666/Sui/commit/0cce12d2808483c2f702ba99be1f50ec9d4b2ceb)
- **Build time:** `3m 21s`
- **SHA256:** `278d700fa1df07a2a03fd6a3e37764fe3884f5fdd6936de0612b86ec04bce9f7`

## Message

```text
fix: 增强权限确认安全边界并修复 service 注册与 shell 路由问题

本轮改动集中收紧了 SuiService 的权限管理面，增加可信调用者校验和待确认请求追踪，
同时修复了 bridge 注册重试失效、shell 路由冲刷时序、SuiApk 半初始化对象隐患和 APatch 脚本变量错误。

- 为 requestPermissionFromShell 增加可信调用者校验（uid 0/2000/systemUiUid），
  并要求 packageName 确实归属于 reqUid，防止伪造弹窗身份与未经授权的权限请求
- dispatchPermissionConfirmationResult 移除 uid=1000 宽放 fallback，只接受 systemUiUid 回传，
  并通过 Map<String, Integer> 待确认计数机制防止同 key 并发请求被误丢与伪造回写
- 将权限确认收尾逻辑抽取为 finishPermissionConfirmation，统一正常回写和异常分支的收口，
  并支持 SystemUI 无法展示弹窗时由服务端本地完成拒绝收尾，避免请求永久挂起
- 为 BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI 新增 enforceManagerPermission，
  限制快捷方式创建仅可由管理端触发
- 新增 SuiConfigManager.syncUidsToShellFileNow 与 SuiService.flushShellRoutingState，
  在权限变更（dispatchPermissionConfirmationResult、updateFlagsForUid、dispatchPackageChanged）
  以及默认模式进出 shell 时，先同步 shell 配置文件再刷新 system_server 路由，消除 root/shell 切换竞态
- 修复 BridgeServiceClient.sendToBridge 中 Parcel.obtain 置于循环外导致重试失效的问题，
  改为每次重试均重新 obtain
- 修复 SuiApk.createForSettings 和 createForSystemUI 在类/构造器加载失败时
  仍返回半初始化对象的问题，改为直接返回 null；
  同时 ManagerProcess.showPermissionConfirmation 在加载失败时改为抛出 IllegalStateException，
  保证服务端 catch 路径能正确处理失败请求
- 修复 post-fs-data.sh APatch 分支中 kp_major_char/kp_minor_patch 未正确展开为计算变量的错误

此外，清理了 updateFlagsForUid 中未使用的 wasHidden 变量，并将多处 BridgeServiceClient.syncUids
调用抽取为 syncUidsToSystemServer 辅助方法以减少重复。

同步更新 api 子模块：
- Shizuku.pingBinder() 修复为使用局部变量 b，避免字段空指针
- ShizukuProvider 用 ContextCompat.registerReceiver 替换版本分支的 registerReceiver，provider 新增 androidx.core 依赖
- rish 的 STL 从 none 改为 c++_static，移除 libcxx 依赖与 prefab 配置

```
