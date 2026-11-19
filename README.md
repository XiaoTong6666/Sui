# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `584`
- **Commit:** [`6905910`](https://github.com/XiaoTong6666/Sui/commit/69059108b81f3494f9b552f51ef1f9133ed5607c)
- **Build time:** `3m 18s`
- **SHA256:** `38a278bed0a02609884319e62a5b53cfe56b69b3bb05c1861484f62ed48e9a54`

## Message

```text
fix(build): Resolve Gradle 9.9.1 buildSrc dependencies, Meow

给 buildSrc 单独配置插件仓库，让 Kotlin DSL 插件依赖优先从 Maven Central 解析，避免插件门户暂时无法提供 Kotlin BOM 时导致 CI 在配置阶段失败喵

保留 Gradle 9.9.1，同时为 buildSrc 普通依赖添加 Maven Central；冷缓存验证和 Debug、Release 打包均通过喵

```
