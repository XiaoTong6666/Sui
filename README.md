# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `507`
- **Commit:** [`b78dc32`](https://github.com/XiaoTong6666/Sui/commit/b78dc32e69ab2508b8c77cbdd6c0be3c649ffa4b)
- **Build time:** `3m 16s`
- **SHA256:** `f663ad3e2f26c4020a3f7643115b5fd26972edb05851d1c3fdfac4e42102a34a`

## Message

```text
refactor(ui/build): 移除冗余依赖以减小应用体积

- 移除 Rikkax，迁移至 AndroidX
- 移除一些第三方库，新增本地工具类作为替代
- 优化并精简 ProGuard 混淆规则
- 优化构建脚本打包逻辑

```
