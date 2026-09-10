# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `539`
- **Commit:** [`c83e85a`](https://github.com/XiaoTong6666/Sui/commit/c83e85a55482c25f517212309c20d02e52b66472)
- **Build time:** `2m 35s`
- **SHA256:** `d70652b19f863359bf05a89525f171374bdfb841c9e497d59fe08ee93eec005c`

## Message

```text
feat(ui): add ADB Root settings

在右上角菜单新增 ADB Root 入口，提供关闭，下次启动启用一次，始终启用三种模式，复用现有 enable_adb_root_once 与 enable_adb_root 标记文件
将实际 marker 状态作为界面展示的来源，使单次标记被 post-fs-data 消费后自动回落为关闭，同时通过现有全局设置 Binder 更新选项，不改变原有 ADB Root 启动流程。

```
