# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `507`
- **Commit:** [`c4c6f50`](https://github.com/XiaoTong6666/Sui/commit/c4c6f504f040b84849151188aac842a4ad2ef884)
- **Build time:** `3m 52s`
- **SHA256:** `29c9f109b90759d019f4a06f1b06f47fd2b08ed8d660c0ad5598b6ced5ca65a5`

## Message

```text
refactor: 移除冗余依赖以减小应用体积

- 移除 Rikkax，迁移至 AndroidX
- 移除第三方 `fastscroll` ，新增 `EdgeDragFastScroller` 作为替代
- 移除 `rikka.lifecycle.Resource`，新增本地 `Resource` 数据类
- 优化并精简 ProGuard 混淆规则
- 优化构建脚本打包逻辑

```
