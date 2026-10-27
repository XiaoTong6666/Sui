# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `572`
- **Commit:** [`201b29a`](https://github.com/XiaoTong6666/Sui/commit/201b29ad84aea4f6aa055140490b61db779cc79b)
- **Build time:** `0m 53s`
- **SHA256:** `e46a57aa27889de92c3dfb5e183a61ca172583876b95fb6596fde47b8477b492`

## Message

```text
fix(installer): Guard metadata and log forwarding, Meow

给日志转发加上 --，避免以 - 开头的输出被 log 当成参数喵（甩甩尾巴）

安装时检查 Installer 退出状态和元数据格式，写入后再回读核对，不让失败悄悄混过去喵（认真检查）

```
