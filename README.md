# Nodus CLI

`Nodus-CLI`（单二进制 `nodus`）是 `Nodus-Core` 的无头 Linux 宿主，面向 VPS、软路由、NAS、树莓派及服务器环境提供命令行与守护进程入口。

## 阶段实施状态

当前已完成 **阶段 L0｜工程骨架与 Core 集成边界**（L0-01 ～ L0-04）：

- **L0-01｜Rust 工程与 Core 依赖边界**：基于 Rust Edition 2024，全 crate 强制 `unsafe_code = "forbid"`，通过 rlib 接入锁定版本 `nodus_core`，零 新增外部第三方 crate。
- **L0-02｜命令行解析、输出契约与退出码**：支持 `--config`、`--socket`、`--memory-budget`、`--connection-limit`、`--timeout`、`--json`、`-q/--quiet`、`-v/--verbose` 全局参数，实现离线 `nodus version`、`nodus config check` 与 `nodus config summary`，集中定义 `0`–`8` 确定性退出码映射并完整保留 Core 六位错误代码与行列位置。
- **L0-03｜宿主安全与密钥交付规范**：拦截命令行明文密钥参数，强制核验私有目录（`0700`）与密钥文件（`0600`、当前有效 UID 所有、`O_NOFOLLOW` 拒绝符号链接、`(dev, ino)` 防替换），支持受控环境变量读取与 `Zeroizing` 脱敏托管。
- **L0-04｜显式资源预算配置**：要求显式传入 `--memory-budget <SIZE>`（拒绝 `0`、负数、未知单位或溢出），并将预算真实交付至 Core 根预算池。

完整规范入口见 [AGENTS.md](AGENTS.md)，第三方依赖许可登记见 [LICENSE.md](LICENSE.md)。
