# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `565`
- **Commit:** [`241084a`](https://github.com/XiaoTong6666/Sui/commit/241084acc3b9a8ea4be13bff3398cc5c1e1760c6)
- **Build time:** `1m 28s`
- **SHA256:** `25131644b3c3bea4608d3cf4b7a8254eafa1598ad08cbb06b4b62ec07388408b`

## Message

```text
feat(ui): add Material 3 Expressive appearance and permission dialogs, Meow

这次给 Sui 接入了可切换的 MIUIX 和 Material 3 Expressive 界面喵。管理页新增 Material 应用卡片、Popup、二级菜单、下拉刷新和动态配色，同时保留 MIUIX 原有交互，关闭动态取色后仍使用固定配色喵

授权弹窗也支持 M3E 了喵。Root、Shell、仅一次 Root 和拒绝分别使用对应的按钮样式，并加入按压圆角动画。由于授权窗口运行在 SystemUI，界面风格改由服务端同步；全局设置新增按掩码原子更新，避免与 ADB Root 等开关互相覆盖，也修复了 Debug 主题切换和快速按压的竞态喵

```
