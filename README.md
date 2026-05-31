# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `489`
- **Commit:** [`a5c1b27`](https://github.com/XiaoTong6666/Sui/commit/a5c1b27c42b749320e1ed7591caffa268737c428)
- **Build time:** `1m 23s`
- **SHA256:** `f0e39a8eef0c0477287ebaea354da0baa0cbc00dc9be987f76c023ce24634e07`

## Message

```text
fix: 兼容 16KB 页对齐，修复反射基础类型传参，限制 label 并发

- CMakeLists：添加 -Wl,-z,max-page-size=16384 以兼容 16KB 页面大小
- AppLaunchUtils：反射调用时将基本类型参数零填充，避免 null 导致 IllegalArgumentException
- ManagementViewModel：label 加载改用 limitedParallelism(4) 并发，兼顾性能与线程压力

```
