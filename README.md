# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `571`
- **Commit:** [`af5447f`](https://github.com/XiaoTong6666/Sui/commit/af5447f4313e2abc15fc36e729ac0f296da95d2c)
- **Build time:** `2m 33s`
- **SHA256:** `fcf9ad2b3f9ff4ccee62d43bed4b6abe71ff71ddb89acbb1485148873bcb5270`

## Message

```text
fix(native): Isolate C++ exit handlers from Bionic, Meow

为 libsui.so 接入本地 __cxa_atexit/__cxa_finalize，避免将模块析构记录写入 Bionic 全局表喵（当然znlinker也会替我们处理这些了喵）

Co-authored-by: 5ec1cff <56485584+5ec1cff@users.noreply.github.com>

```
