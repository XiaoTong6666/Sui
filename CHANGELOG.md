# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `471`
- **Commit:** [`21a732f`](https://github.com/XiaoTong6666/Sui/commit/21a732fd3a95c2124cece5f5765bdd4eda72497e)
- **Build time:** `4m 42s`
- **SHA256:** `ea100280b0b867732d3a754b3602793df77fae91dd5177cc2ac4a64999a87b29`

## Message

```text
ci: 重构模块构建与发布工作流

- 拆分构建、Nightly 更新、KernelSU 同步、Tag Release 和 pages 更新任务
- 新增 workflow 并发控制，避免同一分支重复运行
- 统一提取构建产物、版本信息和提交元数据
- 使用构建产物中的 module.prop 作为版本信息来源
- 上传模块 zip 与构建元数据，供后续发布任务复用
- 优化 Nightly、Tag Release 和 KernelSU 发布说明
- 更新 Gradle setup 配置并启用基础缓存
- 收紧 artifact 缺失检查和发布文件匹配校验

```
