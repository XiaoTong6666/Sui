# Nightly Build

- **Version:** `v13.5.4.3`
- **VersionCode:** `595`
- **Commit:** [`9857c07`](https://github.com/XiaoTong6666/Sui/commit/9857c07c5e21bc7c74ab20691d1e628393821ad2)
- **Build time:** `4m 22s`
- **SHA256:** `98529a5faab1fd4af2eeeb6f5ce44c416e30142a0fccc041f8920e205e305059`

## Message

```text
refactor(module): replace boot scripts with native supervisor, Meow

把原来 Shell 脚本里的启动和监控逻辑迁移到 Native Supervisor 了喵，日志采集和应用信息刷新还有 ADB Root 准备也一起接管了喵~

移除了 post-fs-data.sh，service.sh 只保留启动入口喵（终于不用维护那么多 Shell 代码啦，开心地挥挥爪子）

Root 和 Shell Server 使用独立进程组管理，Supervisor 通过文件锁保证单实例运行喵，还加上了启动超时和退避重试喵，旧进程组没完全退出之前不会启动新的 Server Pair，也不会阻塞整个监控循环喵

顺便整理了进程扫描和子进程回收逻辑，复用已有的 Helper，SystemUI 和 Settings 的应用信息发生变化时也会分别处理喵

另外...整理了模块安装和卸载流程，调整了 Root 实现识别逻辑，模块模板目录也改成了 module 喵（收拾完一大堆代码后软趴趴地摊成猫饼喵~）

```
