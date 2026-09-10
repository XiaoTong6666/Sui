# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `539`
- **Commit:** [`7fc5400`](https://github.com/XiaoTong6666/Sui/commit/7fc540036da579b1431c00052e03355d32875838)
- **Build time:** `1m 48s`
- **SHA256:** `5f0b663d1b0dc8b2baabfc715da1ecd4a2c9cccd71207b3e0f92425552ffae1b`

## Message

```text
feat(ui): add ADB Root settings

在右上角菜单新增 ADB Root 入口，提供关闭，下次启动启用一次，始终启用三种模式，复用现有 enable_adb_root_once 与 enable_adb_root 标记文件
将实际 marker 状态作为界面展示的来源，使单次标记被 post-fs-data 消费后自动回落为关闭，同时通过现有全局设置 Binder 更新选项，不改变原有 ADB Root 启动流程。

```
