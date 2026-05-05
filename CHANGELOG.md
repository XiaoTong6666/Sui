# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `471`
- **Commit:** [`35f0abf`](https://github.com/XiaoTong6666/Sui/commit/35f0abfce661ed4daa2ee28ce78e2a1acff88db6)
- **Build time:** `1m 21s`
- **SHA256:** `b43464917db467ba4b0a9d047a2b7d5b65e27ec07d9c30b7b01aa429bfec6665`

## Message

```text
ci(workflows): 模块化构建与发布工作流

将原本集中在 module.yml 中的构建、发布、KSU 模块仓库同步和 pages 元数据更新逻辑拆分为可复用 workflow，并由 module.yml 统一编排。

- 新增 build、release、ksu-release 和 pages 可复用 workflow
- 通过 workflow outputs 传递构建产物、版本信息和提交元数据
- 统一收集模块 zip、module.prop 版本信息、构建耗时和 SHA256
- 复用 module-zips 与 build-metadata，减少发布任务重复逻辑
- 优化 Nightly、Tag Release、KernelSU 和 pages 发布说明
- 添加并发控制，避免同一 ref 重复运行
- 收紧 artifact 缺失检查和 release 文件匹配校验1

```
