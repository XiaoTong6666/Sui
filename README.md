# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `499`
- **Commit:** [`5b16450`](https://github.com/XiaoTong6666/Sui/commit/5b164501e665e8102202c6ae83ab3df1a8eb278c)
- **Build time:** `1m 13s`
- **SHA256:** `23357b4fbc756167d786ddadab36d7e7d659a9a05eea6a2a4a0d8d15a34df8d1`

## Message

```text
fix: 修复权限委托回调冲突并统一 effective flags 状态

- 将 delegated permission callback key 纳入 requestCode，避免相同 uid/pid 请求互相覆盖
- 在 AppInfo 中保存实际生效权限状态，避免 UI 层重复推导权限逻辑
- 保持 Parcelable 数据兼容旧版本权限字段格式
- 同步管理页面状态更新逻辑，统一使用 effectiveFlags

```
