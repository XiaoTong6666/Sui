# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `489`
- **Commit:** [`ca39e49`](https://github.com/XiaoTong6666/Sui/commit/ca39e4922c2953be7d841a0c16f462aa9d1959b2)
- **Build time:** `2m 59s`
- **SHA256:** `4aa742daea129b2b1a4b80d1c740aab0867cceb66b5ca3b5c481820029750c6b`

## Message

```text
fix: 兼容 16KB 页对齐，修复反射基础类型传参，限制 label 并发

- CMakeLists：添加 -Wl,-z,max-page-size=16384 以兼容 16KB 页面大小
- AppLaunchUtils：反射调用时将基本类型参数零填充，避免 null 导致 IllegalArgumentException
- ManagementViewModel：label 加载改用 limitedParallelism(4) 并发，兼顾性能与线程压力

```
