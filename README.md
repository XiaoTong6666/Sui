# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `507`
- **Commit:** [`f0e506f`](https://github.com/XiaoTong6666/Sui/commit/f0e506f8beb1db552dee563411599f4be6e13e58)
- **Build time:** `2m 49s`
- **SHA256:** `14e41b99752da9ddaf9d5a3951ece5952af8a8267726827c37d7b7ea2ae5dfe6`

## Message

```text
refactor(ui/build): 移除冗余依赖以减小应用体积

- 移除 Rikkax，迁移至 AndroidX
- 移除一些第三方库，新增本地工具类作为替代
- 优化并精简 ProGuard 混淆规则
- 优化构建脚本打包逻辑

```
