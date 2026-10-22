# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `569`
- **Commit:** [`8d2392a`](https://github.com/XiaoTong6666/Sui/commit/8d2392a9e4d8a079efa4badeb268c05501a48398)
- **Build time:** `2m 40s`
- **SHA256:** `00f17d6ae029be574fe714ffdcada92b003e3b56a38db65589d008a4415ec621`

## Message

```text
feat(adb): add selectable Zygisk Next injection backend, Meow

给 ADB Root 菜单加了「ZN 注入」开关，勾选走 Zygisk Next，取消就继续用 Bind Mount，选择会保存到 /data/adb/sui 的标志文件里喵（轻轻拨动开关）

通过官方 ZN API v4 给 adbd 安装 PLT Hook，保留 Root 上下文和 socket 标签处理，不再依赖替换 adbd 可执行文件喵（伸爪检查）

初始化加入状态反馈和失败回滚，后端选择不再判断 Android 版本，注入失败也不会悄悄切回 Bind Mount 喵（收好小尾巴）

```
