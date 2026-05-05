# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `472`
- **Commit:** [`82518d4`](https://github.com/XiaoTong6666/Sui/commit/82518d482e42358215bfff9e82cddc09945eda85)
- **Build time:** `2m 59s`
- **SHA256:** `aa703568b9620939dbcd6fab49dd77608d84bf359fa84e9298463b8b27dab5dc`

## Message

```text
ci(workflows): 统一发布流程

- 合并 nightly 与 tag release 为统一发布 job
- 使用发布参数区分 nightly 与正式 release
- 支持 tag release 同步 KSU 仓库
- 支持 tag release 更新 pages 元数据
- 复用发布说明生成逻辑

```
