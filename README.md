# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `565`
- **Commit:** [`c77fe3a`](https://github.com/XiaoTong6666/Sui/commit/c77fe3a9ee03d880146378bb9c7bafb745d6c034)
- **Build time:** `4m 01s`
- **SHA256:** `17da988a57ae3021761f0a8b570adf40d225241e9dccb35321e10a9f6ad538dd`

## Message

```text
feat(ui): add Material 3 Expressive appearance and permission dialogs, Meow

这次给 Sui 接入了可切换的 MIUIX 和 Material 3 Expressive 界面喵。管理页新增 Material 应用卡片、Popup、二级菜单、下拉刷新和动态配色，同时保留 MIUIX 原有交互，关闭动态取色后仍使用固定配色喵

授权弹窗也支持 M3E 了喵。Root、Shell、仅一次 Root 和拒绝分别使用对应的按钮样式，并加入按压圆角动画。由于授权窗口运行在 SystemUI，界面风格改由服务端同步；全局设置新增按掩码原子更新，避免与 ADB Root 等开关互相覆盖，也修复了 Debug 主题切换和快速按压的竞态喵

```
