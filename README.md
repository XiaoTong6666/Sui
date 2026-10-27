# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `572`
- **Commit:** [`2aac56d`](https://github.com/XiaoTong6666/Sui/commit/2aac56dccde14c9b9d5f008c1fcc035c5d8195d3)
- **Build time:** `2m 17s`
- **SHA256:** `18eae4e6ccf885a1c6f12928a2a6a1bb3abe776fedcf0d9e089da80205262d26`

## Message

```text
fix(installer): Guard metadata and log forwarding, Meow

给日志转发加上 --，避免以 - 开头的输出被 log 当成参数喵（甩甩尾巴）

安装时检查 Installer 退出状态和元数据格式，写入后再回读核对，不让失败悄悄混过去喵（认真检查）

```
