//! `Nodus-CLI` 宿主库入口（阶段 L0：工程骨架与 Core 集成边界）。
//!
//! 职责边界：
//! - `budget`：显式内存／连接预算解析、溢出检查与 Core 根预算交付（L0-04）；
//! - `cli`：命令行参数解析、帮助输出、全局参数优先级与命令分发（L0-02）；
//! - `core_bridge`：与 `nodus_core` 的受约束集成入口（版本溯源、离线配置校验与摘要）（L0-01）；
//! - `output`：确定性退出码映射表、Core 原始六位错误码保留、人类与 `--json` 机器输出渲染（L0-02）；
//! - `security`：私有目录与 `0600` 密钥文件权限核验、受控环境变量读取与 `Zeroizing` 凭据托管（L0-03）。

pub mod budget;
pub mod cli;
pub mod core_bridge;
pub mod output;
pub mod security;
