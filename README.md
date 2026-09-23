# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `552`
- **Commit:** [`8c64193`](https://github.com/XiaoTong6666/Sui/commit/8c64193b360e8e56a70637e868c0915855484d0e)
- **Build time:** `1m 53s`
- **SHA256:** `3c3c4f9bd3e73f3a4821b1a310cb8dfce01d58a77fb97e23d4b0304a54ef2a1a`

## Message

```text
fix(logging): centralize Sui logs in a single collector

统一 Sui 的持久化日志写入路径，新增由 root 启动的 logcat collector，将 Sui、SuiDaemon、SuiServer、SuiSystemServer、SuiManager、SuiSettings 以及 server-shared 等相关日志统一追加到 /data/adb/sui/sui.log，并使用 logcat 自带的轮转机制控制日志大小。通过单一写入进程避免 shell 脚本、native daemon 与 Java FileHandler 并发写入同一文件时可能出现的交叉、截断和竞争。

保留原有 logcat 行为，同时保留原先会进入 sui.log 的 stdout/stderr：native daemon 的标准输出与错误输出统一转写到 Sui tag，Installer 的完整 stdout/stderr 在安装和运行时刷新路径中统一转写到 SuiInstaller tag，再由 collector 持久化，因此早期 app_process 异常和非 Android Logger 输出也不会丢失。

同时移除 post-fs-data.sh、service.sh 对 sui.log 的直接重定向以及 Java Logger 中的 FileHandler 特殊路径，SuiService 原有 /cache/sui.log 日志重新归并到常规 LOGGER。service watchdog 会持续检查并恢复 collector，卸载时会先终止 collector；所有进程只负责写入 logd，不再直接竞争 /data/adb/sui/sui.log。

```
