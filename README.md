# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `578`
- **Commit:** [`95f3a92`](https://github.com/XiaoTong6666/Sui/commit/95f3a92dd9699ddce90ef283b9f9859ef83d3fcb)
- **Build time:** `2m 06s`
- **SHA256:** `495331fc3860b3b7e044afda377e2f82031a0b9fa7f8cb7fa38761058b03dda7`

## Message

```text
refactor(logging): unify Sui logs with a native collector, Meow

统一 Sui 自有 Java、Kotlin、Native 和 Shell 日志为 Sui Tag，并在消息中保留组件前缀，Shizuku API 和 Rish 继续使用原来的 Tag 喵

接入独立的 liblog Native 采集器，适配 Android 6–17 的解码结构与日志缓冲区，保留旧 Tag、日志轮转和升级期间的采集器互斥，不再通过 Shell logcat 读取喵

通过 Gradle 共享 Log.java，整理 Native applet 入口、安装器输出和启动脚本，清理冗余代码与重复日志前缀喵

```
