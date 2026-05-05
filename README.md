# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `472`
- **Commit:** [`889b033`](https://github.com/XiaoTong6666/Sui/commit/889b033819e76afd1ed87376ed4e453fd34173d4)
- **Build time:** `1m 13s`
- **SHA256:** `71b48f53438630bf705fb3f56059e80639f4a23ef30579a25d11d6411c2349bb`

## Message

```text
ci(workflows): 统一发布流程

- 合并 nightly 与 tag release 为统一发布 job
- 使用发布参数区分 nightly 与正式 release
- 支持 tag release 同步 KSU 仓库
- 支持 tag release 更新 pages 元数据
- 复用发布说明生成逻辑

```
