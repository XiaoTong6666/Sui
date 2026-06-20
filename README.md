# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `499`
- **Commit:** [`6b8083d`](https://github.com/XiaoTong6666/Sui/commit/6b8083d836aa087751fac380cad46d3a72f1d8c7)
- **Build time:** `3m 01s`
- **SHA256:** `166e9305b3e8636ea6ae55b7da3dc248d2ce3b89467e1c540d02951f25593ef2`

## Message

```text
fix: 修复权限委托回调冲突并统一 effective flags 状态

- 将 delegated permission callback key 纳入 requestCode，避免相同 uid/pid 请求互相覆盖
- 在 AppInfo 中保存实际生效权限状态，避免 UI 层重复推导权限逻辑
- 保持 Parcelable 数据兼容旧版本权限字段格式
- 同步管理页面状态更新逻辑，统一使用 effectiveFlags

```
