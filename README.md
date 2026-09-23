# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `552`
- **Commit:** [`3013f15`](https://github.com/XiaoTong6666/Sui/commit/3013f15fbb0a900bdfbddd909425f70fd3f16240)
- **Build time:** `2m 18s`
- **SHA256:** `4de88aa2faabedbc7e304aee2085c502c062a817f76d1029f43c0b30033c9be9`

## Message

```text
fix(logging): centralize Sui logs in a single collector

统一 Sui 的持久化日志写入路径，新增由 root 启动的 logcat collector，将 Sui、SuiDaemon、SuiServer、SuiSystemServer、SuiManager、SuiSettings 以及 server-shared 等相关日志统一追加到 /data/adb/sui/sui.log，并使用 logcat 自带的轮转机制控制日志大小。通过单一写入进程避免 shell 脚本、native daemon 与 Java FileHandler 并发写入同一文件时可能出现的交叉、截断和竞争。

同时移除 post-fs-data.sh、service.sh 对 sui.log 的直接重定向以及 Java Logger 中的 FileHandler 特殊路径，SuiService 原有 /cache/sui.log 日志重新归并到常规 LOGGER。service watchdog 会持续检查并恢复 collector，卸载时会先终止 collector；Installer 新增 SuiInstaller tag，在保留安装阶段终端输出的同时也纳入统一日志。

日志仍正常写入 Android logd，collector 仅负责持久化匹配的 Sui 与共享服务日志，因此 system_server、SystemUI、Settings、root/shell server 和 UI 侧无需直接访问 /data/adb/sui。

```
