# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `492`
- **Commit:** [`11af908`](https://github.com/XiaoTong6666/Sui/commit/11af908f644018a7ce6c00baf65ce814425af94c)
- **Build time:** `3m 13s`
- **SHA256:** `3e79057035436ee82678e3586e0c33822fe558b14baf18247397f40bc7187384`

## Message

```text
fix: 兼容 Android TV settings 包名回退 #65

- 新增 SettingsPackages，统一维护 TV settings 与普通 settings 的候选包名
- 安装阶段优先解析实际存在的 settings 包，并将其应用信息写回原有 canonical 文件名
- SuiService 改为支持多个 settings 包名候选，避免仅识别 com.android.settings
- ManagerProcess 与 SuiShortcut 改为按候选包名选择 settings 目标
- Uninstaller 卸载时同时清理两个 settings 包下的动态快捷方式

```
