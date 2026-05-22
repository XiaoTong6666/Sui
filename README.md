# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `485`
- **Commit:** [`4575090`](https://github.com/XiaoTong6666/Sui/commit/4575090d294764560d18b89079f0d7ec1dcbea52)
- **Build time:** `3m 02s`
- **SHA256:** `f194cb41bc658e7913305efa59de206c16d7d2f78ac9af2277c62bce5d058f30`

## Message

```text
refactor: 提取共享 API 组件并优化服务端与 UI 性能

清理服务端与 UI 层的重复代码，并修复部分性能和逻辑隐患：

- 将 ui 和 module 中的重复工具类合并至 api/shared，并新增 BridgeConstants 统一跨层通信常量
- 调整 ManagementViewModel 加载模型，将分批串行加载替换为基于 Dispatchers.IO 的异步并发加载
- 将 SuiConfigManager 的配置检索改为 Map 映射，并为高频配置写盘增加 200ms 防抖节流
- 修改 Bridge 中的权限状态判断，明确互斥优先级（隐藏 > 拒绝 > Root > Shell）防止权限覆盖
- 增加 Native 层的安全防护：为 Zygisk 注入添加数据长度和初始化失败检查，并将 JNI 接口表静态化

此外，修复了 SuiDatabase 的并发初始化隐患与 SuiService 中的位运算错误，并清理了 UI 层的无效判断分支。

```
