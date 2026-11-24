//! 显式资源预算配置与校验（L0-04）。
//!
//! 职责与不变量：
//! 1. 宿主绝不向 Core 隐式提供无限预算或静默截断超限输入；
//! 2. 解析 `--memory-budget <SIZE>`（支持字节整数与 `K`/`KB`/`KiB`、`M`/`MB`/`MiB`、`G`/`GB`/`GiB` 单位）
//!    与可选 `--connection-limit <N>`，使用 checked 算术运算严格拒绝零值、负数、非法单位和溢出；
//! 3. 明确区分两类预算边界：
//!    - `--memory-budget <SIZE>` 经 `nodus_core_set_memory_budget` 真实提交到 Core 根预算池；
//!    - `--connection-limit <N>` 在阶段 L0 由 CLI 校验正整数和平台整数范围，
//!      运行态活动连接限额在 L1 守护进程创建/管理 Core 出站会话时传入生效。

use crate::output::CliError;
use nodus_core::{
    error::{Error as CoreError, ErrorCode, ErrorInfo, NO_ERROR_CODE},
    ffi::{nodus_core_last_error_code, nodus_core_set_memory_budget},
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

/// 预算配置的显式来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetSource {
    /// 来自命令行显式参数（如 `--memory-budget` / `--connection-limit`）。
    CliFlag,
    /// 来自受控部署配置。
    DeploymentConfig,
}

/// 达到预算上限时的确定性行为（由 Core 预算池统一裁决，宿主不静默放行或降级直连）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetOverflowPolicy {
    /// 拒绝本次分配／新连接并返回结构化预算错误（如 `BudgetPoolExceeded` / `ResourceBudgetExceeded`），
    /// 保持既有已建立会话与有效配置快照不断流。
    RejectNewAllocationKeepActive,
}

/// 经宿主严格解析与边界校验的显式内存预算。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryBudget {
    /// 经过单位换算后的精确字节上限（非零，且可表示为当前目标架构 `usize`）。
    pub bytes: NonZeroU64,
    /// 计量单位固定为 `"bytes"`。
    pub unit: &'static str,
    /// 限额作用对象：进程内 Core 与网关统一根登记预算（区分于进程 RSS）。
    pub target_object: &'static str,
    /// 预算配置来源。
    pub source: BudgetSource,
    /// 超限处理策略。
    pub on_exceeded: BudgetOverflowPolicy,
}

impl MemoryBudget {
    /// 解析人类可读或字节整数形式的内存预算字符串（如 `"64M"`、`"256MiB"`、`"67108864"`）。
    /// 缺失、为空、为零、单位未知或超出 `u64` / 目标平台 `usize` 可表示范围时明确返回错误。
    pub fn parse(raw: &str, source: BudgetSource) -> Result<Self, CliError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CliError::invalid_budget(
                "内存预算 `--memory-budget` 不能为空（示例：64M、256M）",
            ));
        }
        let split_idx = trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len());
        let (num_part, unit_part) = trimmed.split_at(split_idx);
        if num_part.is_empty() {
            return Err(CliError::invalid_budget(format!(
                "内存预算 `{trimmed}` 缺少有效正整数数值"
            )));
        }
        let base: u64 = num_part.parse().map_err(|_| {
            CliError::invalid_budget(format!("内存预算数值 `{num_part}` 超出整数可表示范围"))
        })?;
        if base == 0 {
            return Err(CliError::invalid_budget(
                "内存预算 `--memory-budget` 必须大于 0（禁止使用 0 代表无限额度）",
            ));
        }

        let multiplier: u64 = match unit_part.trim() {
            "" | "B" | "b" => 1,
            "K" | "k" | "KB" | "kb" | "KiB" | "kib" => 1024,
            "M" | "m" | "MB" | "mb" | "MiB" | "mib" => 1024 * 1024,
            "G" | "g" | "GB" | "gb" | "GiB" | "gib" => 1024 * 1024 * 1024,
            other => {
                return Err(CliError::invalid_budget(format!(
                    "不支持的内存预算单位 `{other}`（支持 B、K/KiB、M/MiB、G/GiB）"
                )));
            }
        };

        let total_bytes = base.checked_mul(multiplier).ok_or_else(|| {
            CliError::invalid_budget(format!("内存预算 `{trimmed}` 换算字节时发生算术溢出"))
        })?;

        // 校验可无损转换为当前平台 usize，且不等于 usize::MAX（Core 内部以 usize::MAX 表示未设置上限）。
        let as_usize = usize::try_from(total_bytes).map_err(|_| {
            CliError::invalid_budget(format!(
                "内存预算 `{trimmed}` ({total_bytes} B) 超出当前平台地址空间上限"
            ))
        })?;
        if as_usize == usize::MAX {
            return Err(CliError::invalid_budget(
                "内存预算不能等于 usize::MAX（Core 保留该值表示未设置上限）",
            ));
        }

        let non_zero = NonZeroU64::new(total_bytes)
            .ok_or_else(|| CliError::invalid_budget("内存预算必须为非零字节数"))?;

        Ok(Self {
            bytes: non_zero,
            unit: "bytes",
            target_object: "nodus_core.root_registered_budget",
            source,
            on_exceeded: BudgetOverflowPolicy::RejectNewAllocationKeepActive,
        })
    }

    pub const fn bytes_u64(self) -> u64 {
        self.bytes.get()
    }
}

/// 显式连接数输入。L0 由 CLI 检查数量，实际连接准入及内存计量由 Core 负责。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionBudget {
    pub max_connections: NonZeroU64,
    pub unit: &'static str,
    pub target_object: &'static str,
    pub source: BudgetSource,
    pub on_exceeded: BudgetOverflowPolicy,
}

impl ConnectionBudget {
    pub fn parse(raw: &str, source: BudgetSource) -> Result<Self, CliError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CliError::invalid_budget(
                "连接数上限 `--connection-limit` 不能为空",
            ));
        }
        let count: u64 = trimmed.parse().map_err(|_| {
            CliError::invalid_budget(format!("连接数上限 `{trimmed}` 不是有效的正整数"))
        })?;
        let non_zero = NonZeroU64::new(count).ok_or_else(|| {
            CliError::invalid_budget("连接数上限 `--connection-limit` 必须大于 0")
        })?;
        usize::try_from(count).map_err(|_| {
            CliError::invalid_budget(format!("连接数上限 `{trimmed}` 超出当前平台可表示范围"))
        })?;
        Ok(Self {
            max_connections: non_zero,
            unit: "connections",
            target_object: "nodus_core.outbound_connections",
            source,
            on_exceeded: BudgetOverflowPolicy::RejectNewAllocationKeepActive,
        })
    }
}

/// 宿主校验后的预算集合，包含提交给 Core 的根内存预算和连接数输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceBudgetConfig {
    pub memory: MemoryBudget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_limit: Option<ConnectionBudget>,
}

impl ResourceBudgetConfig {
    pub fn new(memory: MemoryBudget, connection_limit: Option<ConnectionBudget>) -> Self {
        Self {
            memory,
            connection_limit,
        }
    }

    /// 将显式内存预算真实交付给 `Nodus-Core` 根预算池。
    /// 调用安全的 `nodus_core_set_memory_budget`，若 Core 返回非零错误码（如当前占用已高于新上限 `BudgetLimitBelowUsage`），
    /// 完整保留 Core 原始错误码并返回失败。
    /// L0 保留已验证的连接数输入，向 Core 提交活动连接限额属于 L1。
    pub fn apply_to_core(&self) -> Result<(), CliError> {
        let status = nodus_core_set_memory_budget(self.memory.bytes_u64());
        if status == 0 {
            return Ok(());
        }
        let raw_code = nodus_core_last_error_code();
        let code_u32 = if raw_code != NO_ERROR_CODE {
            raw_code
        } else {
            u32::try_from(status).unwrap_or(ErrorCode::Internal.value())
        };
        if let Some(code) = ErrorCode::from_value(code_u32) {
            Err(CliError::from_core_info(
                "budget-apply",
                ErrorInfo::new(code),
                None,
            ))
        } else {
            Err(CliError::from_core_error(
                "budget-apply",
                CoreError::Internal,
            ))
        }
    }
}
