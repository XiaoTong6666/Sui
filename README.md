# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `472`
- **Commit:** [`97078a3`](https://github.com/XiaoTong6666/Sui/commit/97078a3835dc8d582f1ff3ff9ac674e5870c6d71)
- **Build time:** `1m 24s`
- **SHA256:** `efd91c4416e3503e53f51b66e3d303dcc2922221acb415509f81b46addd9b23b`

## Message

```text
ci(workflows): 统一发布流程

- 合并 nightly 与 tag release 为统一发布 job
- 使用发布参数区分 nightly 与正式 release
- 支持 tag release 同步 KSU 仓库
- 支持 tag release 更新 pages 元数据
- 复用发布说明生成逻辑

```
