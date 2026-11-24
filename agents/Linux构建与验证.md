# Nodus-CLI Linux 构建与验证（MUST）

本规范负责 L0–L1 支持基线、构建环境和目标验证。各专项定义功能与成功条件，测试设计、断言及结果记录见[《测试规范》](测试规范.md)。

## 一、支持目标与证据

| 范围 | 首期要求 |
| --- | --- |
| Linux 设计基线 | 按 Core 的 GNU/glibc 基线设计，目标为 Linux Kernel 5.10、glibc 2.28，架构为 `x86_64` 与 `aarch64`。此处记录设计基线。对外承诺须依据 CLI 与锁定版本 Core 的实际联合构建和最低基线运行验证。 |
| 构建目标 | GNU Rust targets 为 `x86_64-unknown-linux-gnu` 与 `aarch64-unknown-linux-gnu`。分别记录本次实际构建及验证的目标。 |
| 开发主机 | macOS 可进行适用的格式、静态和纯逻辑检查。Linux 系统行为必须使用 Linux 验证。 |
| 后续目标 | Alpine、musl 及其他发行版或 ABI 兼容性按 [TODO.md](../TODO.md) 后续工作验证，未核验前不对外承诺。 |

1. 构建固定实际 Rust 工具链、target、Core 来源与版本、Cargo 锁文件及 features。交叉或发行构建使用与目标 GNU/glibc 基线兼容的链接器和 sysroot。记录产物架构、动态依赖和所需 GLIBC 符号版本；最低内核及运行时兼容仍须实际运行验证。
2. Rust 工程和工具链落地后，以 `cargo fmt --all -- --check` 验证格式，使用 `cargo clippy --locked --all-targets --target <target>`、`cargo build --locked --target <target>` 和 `cargo test --locked --target <target>` 运行适用检查。按实际目标补充已登记的 features、release 构建参数或 runner。交叉编译成功只能作为构建证据，目标测试需在匹配的运行环境执行。尚无工程、工具链或目标环境时如实记录。

## 二、L0–L1 按影响验证

| 变更范围 | 必须核对的可观察行为 |
| --- | --- |
| 命令与 Core 接入 | 以实际 `nodus` 入口核对帮助、参数错误、离线校验、连接失败、stdout／stderr、退出码和机器输出。区分空集合、零值和不可观测，核查 Core 原始错误码完整保留。 |
| 显式预算和配置输入 | 有效预算传到 Core，缺失、非法、溢出等输入明确失败。Core 校验和实例启动的实际结果可区分。 |
| 本地控制与并发 | 用 Linux 进程验证同 UID 访问、非授权对端拒绝、权限及状态异常的 Socket、协议不兼容、重复启动，以及断开或超时后结果可判定的行为。 |
| 生命周期及热更新 | 在 Linux 普通用户环境运行真实守护进程。验证成功与失败的配置更新、失败后旧快照和既有连接行为、信号与重载的竞争、启动失败后的回收，以及退出后 Socket 和必要资源的实际释放。 |
| 日志、诊断及用户态网络能力 | 验证各输出路径不会泄露凭据。用户态代理联调核对实际数据路径；Mesh、Tailscale／Headscale 的互通结论须使用对应真实端点及已记录版本验证。 |

验证结果及证据按[《测试规范》](测试规范.md#三结果与证据)记录。
