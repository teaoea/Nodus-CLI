//! `nodus` 的退出码、错误分类与机器输出（`--json`）／人类可读输出契约。
//!
//! 职责与不变量：
//! 1. 集中维护 CLI 非零退出码以及 Core `ErrorCode` 到退出码的确定性映射表；
//! 2. 完整保留 Core 原始六位错误代码、`ErrorParams` 与配置诊断行列号（`CheckIssue`），
//!    禁止截断、重编号、按数字取模或解析错误消息文本猜测错误类别；
//! 3. 未知或后续新增的 Core 错误码统一走显式兜底路径（`ExitCode::CoreError = 1`）并保留原始六位代码；
//! 4. 机器模式（`--json`）在 stdout 固定输出一个 UTF-8 JSON 对象（含 `ok`、`schema_version`），
//!    空集合（`[]`）、真实零值（`0`）与暂不可观测／未启用（`null`）各自独立表达。

use nodus_core::{
    configuration::{CheckIssue, CheckIssues, SourcePosition},
    error::{Error as CoreError, ErrorCode, ErrorInfo, ErrorParams},
};
use serde::{Deserialize, Serialize};
use std::io::Write;

/// 机器可读 JSON 输出的固定 Schema 版本。
pub const JSON_SCHEMA_VERSION: u32 = 1;

/// `nodus` 命令行退出码契约（与 `CLI.md` 1.4 节及《命令行与输出契约》严格一致）。
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitCode {
    /// 命令达到其公开成功条件。
    Success = 0,
    /// Core 业务／网络运行错误或通用操作失败（附带源错误码）。
    CoreError = 1,
    /// 命令行参数或用法错误。
    UsageError = 2,
    /// 配置文件语法或语义校验失败（附带字段路径、行列位置与本地化原因）。
    ConfigInvalid = 3,
    /// 守护进程未运行或本地控制 Socket 不可达。
    DaemonUnreachable = 4,
    /// 权限拒绝（缺少 `CAP_NET_ADMIN`、Socket 对端 UID 不符、密钥或目录权限过宽等）。
    PermissionDenied = 5,
    /// 操作超时或被取消。
    TimeoutOrCancelled = 6,
    /// 当前阶段、平台或协议不支持该能力（`Unsupported` / 控制协议不兼容）。
    Unsupported = 7,
    /// 操作可能已提交但确认丢失（结果未确认，禁止据此推断未执行或自动重放有副作用请求）。
    UnconfirmedOutcome = 8,
}

impl ExitCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn process_exit_code(self) -> std::process::ExitCode {
        std::process::ExitCode::from(self as u8)
    }

    /// 集中定义的 Core `ErrorCode` → `ExitCode` 映射表。
    /// 保留源 `ErrorCode`，不按数字取模或解析文本；未单独归类的 Core 错误沿显式兜底路径映射至 `CoreError (1)`。
    pub const fn from_core_code(code: ErrorCode) -> Self {
        match code {
            // 能力不支持或协议版本不匹配
            ErrorCode::Unsupported
            | ErrorCode::IoUnsupported
            | ErrorCode::NativeNetworkUnsupported
            | ErrorCode::HandoffUnsupported
            | ErrorCode::DebugPlatformUnavailable
            | ErrorCode::DebugVersionMismatch
            | ErrorCode::CacheVersionUnsupported => Self::Unsupported,

            // 超时或取消
            ErrorCode::Cancelled
            | ErrorCode::HandoffCancelled
            | ErrorCode::HandoffDeadline
            | ErrorCode::DnsTimeout
            | ErrorCode::NetworkTimeout
            | ErrorCode::VpnPreparationTimeout
            | ErrorCode::ScriptTimeout
            | ErrorCode::GeoipDownloadTimeout
            | ErrorCode::TcpDialTimeout
            | ErrorCode::ProxyHandshakeTimeout
            | ErrorCode::TargetTlsHandshakeTimeout
            | ErrorCode::ResponseReceiveTimeout
            | ErrorCode::ConnectionReceiveTimeout
            | ErrorCode::PacketDeliverTimeout
            | ErrorCode::Http2StreamTimeout
            | ErrorCode::PublicAddressTimeout
            | ErrorCode::ProbeOutboundTimeout
            | ErrorCode::ProbeHandshakeTimeout
            | ErrorCode::ProbeRequestTimeout
            | ErrorCode::DebugProofTimeout
            | ErrorCode::LogDrainTimeout
            | ErrorCode::LogFileDrainTimeout
            | ErrorCode::LogFileReconfigureTimeout
            | ErrorCode::ConfigurationUpdateTransactionCancelled
            | ErrorCode::ConfigurationPacketsTransactionCancelled
            | ErrorCode::GatewayLanWorkerCancelled => Self::TimeoutOrCancelled,

            // 权限、信任目录或文件访问边界拒绝
            ErrorCode::IoPermissionDenied
            | ErrorCode::LogFileOwner
            | ErrorCode::LogFilePermissions
            | ErrorCode::LogFileType
            | ErrorCode::LogFileAcl
            | ErrorCode::LogFileDirectoryChanged
            | ErrorCode::LogFileChanged
            | ErrorCode::DebugIdentityRejected
            | ErrorCode::DebugUnauthorized
            | ErrorCode::DebugAuthenticationFailed
            | ErrorCode::DebugTrustDirectory
            | ErrorCode::DebugTrustFile
            | ErrorCode::IngressPolicyUserMismatch
            | ErrorCode::IngressHostLockInvalid => Self::PermissionDenied,

            // 配置语法、字段与规则语义校验失败
            ErrorCode::ConfigYamlSyntax
            | ErrorCode::ConfigUnknownField
            | ErrorCode::ConfigDuplicateField
            | ErrorCode::ConfigUnsupportedVersion
            | ErrorCode::ConfigTypeMismatch
            | ErrorCode::ConfigMissingField
            | ErrorCode::ConfigInvalidValue
            | ErrorCode::ConfigAnchorForbidden
            | ErrorCode::ConfigTagForbidden
            | ErrorCode::ConfigAliasForbidden
            | ErrorCode::ConfigUnexpectedEvent
            | ErrorCode::ConfigMultipleDocuments
            | ErrorCode::ConfigMappingKeyType
            | ErrorCode::ConfigNodeLimit
            | ErrorCode::ConfigScalarLimit
            | ErrorCode::ConfigDepthLimit
            | ErrorCode::ConfigInputSize
            | ErrorCode::ConfigCollectionLimit
            | ErrorCode::ConfigListenPortRange
            | ErrorCode::ConfigListenPortConflict
            | ErrorCode::ConfigReservedNodeName
            | ErrorCode::ConfigDuplicateNodeName
            | ErrorCode::ConfigRequiredProxyField
            | ErrorCode::ConfigAddressFamily
            | ErrorCode::ConfigDuplicateProvider
            | ErrorCode::ConfigTunMtu
            | ErrorCode::ConfigTunName
            | ErrorCode::ConfigMitmHostsMissing
            | ErrorCode::ConfigUnknownNode
            | ErrorCode::ConfigNameInvalid
            | ErrorCode::ConfigScriptName
            | ErrorCode::ConfigProviderFileName
            | ErrorCode::ConfigHttpsUrl
            | ErrorCode::ConfigDailyTime
            | ErrorCode::ConfigDnsServers
            | ErrorCode::ConfigDnsEndpoint
            | ErrorCode::ConfigDnsEcs
            | ErrorCode::ConfigDnsEcsDuplicateFamily
            | ErrorCode::ConfigDuplicateHost
            | ErrorCode::ConfigHostAddresses
            | ErrorCode::ConfigDnsAddressForbidden
            | ErrorCode::ConfigProxyCredentials
            | ErrorCode::ConfigHostPattern
            | ErrorCode::ConfigDomainRequired
            | ErrorCode::ConfigUnsupportedProxy
            | ErrorCode::ConfigUnsupportedProvider
            | ErrorCode::RuleListEmpty
            | ErrorCode::RuleFinalMissing
            | ErrorCode::RuleFinalPosition
            | ErrorCode::RuleTypeUnknown
            | ErrorCode::RuleFieldCount
            | ErrorCode::RuleProcessName
            | ErrorCode::RuleCountryCode
            | ErrorCode::RulePortSyntax
            | ErrorCode::RulePortZero
            | ErrorCode::RuleProtocolUnknown
            | ErrorCode::RuleGlobalProtocolAction
            | ErrorCode::RuleParenthesis
            | ErrorCode::RuleFieldEmpty
            | ErrorCode::GatewayInlineRuleInvalid => Self::ConfigInvalid,

            // 显式兜底路径：所有其他已登记 Core 业务、预算、会话与网络错误统一映射至 CoreError (1)
            _ => Self::CoreError,
        }
    }
}

/// 错误来源分类：区分宿主 CLI 参数／安全检查、本地 IPC 控制通道与 Core 内核错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorOrigin {
    Cli,
    Ipc,
    Core,
}

/// 宿主侧稳定机器错误标识（不与 Core 六位整数错误码混用；当来源为 Core 时，`core_code` 保存原始六位代码）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostErrorName {
    UsageError,
    InvalidBudget,
    InvalidConfig,
    SecretPolicyRejected,
    PermissionDenied,
    DaemonUnreachable,
    ProtocolIncompatible,
    TimeoutOrCancelled,
    Unsupported,
    UnconfirmedOutcome,
    CoreOperationFailed,
    IoFailure,
}

impl HostErrorName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsageError => "UsageError",
            Self::InvalidBudget => "InvalidBudget",
            Self::InvalidConfig => "InvalidConfig",
            Self::SecretPolicyRejected => "SecretPolicyRejected",
            Self::PermissionDenied => "PermissionDenied",
            Self::DaemonUnreachable => "DaemonUnreachable",
            Self::ProtocolIncompatible => "ProtocolIncompatible",
            Self::TimeoutOrCancelled => "TimeoutOrCancelled",
            Self::Unsupported => "Unsupported",
            Self::UnconfirmedOutcome => "UnconfirmedOutcome",
            Self::CoreOperationFailed => "CoreOperationFailed",
            Self::IoFailure => "IoFailure",
        }
    }
}

/// 单项配置诊断问题（完整保留 Core `ErrorInfo`、字段路径与源码行列位置）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigIssueView {
    pub code: u32,
    pub name: String,
    pub message: String,
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utf16_offset: Option<usize>,
    pub params: ErrorParams,
}

impl ConfigIssueView {
    pub fn from_core_issue(issue: &CheckIssue) -> Self {
        let contract = issue.error_info.code.contract();
        let (line, column, utf16_offset) = match &issue.position {
            Some(SourcePosition {
                line,
                column,
                utf16_offset,
            }) => (Some(*line), Some(*column), Some(*utf16_offset)),
            None => (None, None, None),
        };
        Self {
            code: issue.error_info.code.value(),
            name: contract.name.to_string(),
            message: contract.detail.to_string(),
            field: issue.field.clone(),
            line,
            column,
            utf16_offset,
            params: issue.error_info.params,
        }
    }
}

/// `CliError` 内部数据体（通过 `Box<CliErrorDetail>` 持有，保持 `Result<T, CliError>` 栈体积紧凑为 8 字节，
/// 同时允许通过 `Deref` 直接透明访问全部字段）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliErrorDetail {
    pub exit_code: ExitCode,
    pub origin: ErrorOrigin,
    pub name: String,
    pub message: String,
    pub phase: &'static str,
    pub core_code: Option<u32>,
    pub core_params: Option<ErrorParams>,
    pub issues: Vec<ConfigIssueView>,
    pub issues_truncated: bool,
    pub recovery_hint: Option<String>,
}

/// CLI 统一结构化错误：包含退出码、错误来源、Core 原始六位代码与参数、阶段标识及可选的后续查询指引。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError(Box<CliErrorDetail>);

impl std::ops::Deref for CliError {
    type Target = CliErrorDetail;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for CliError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CliError {
    fn new(detail: CliErrorDetail) -> Self {
        Self(Box::new(detail))
    }

    /// 构造命令行参数或用法错误（退出码 `2`）。
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::UsageError,
            origin: ErrorOrigin::Cli,
            name: HostErrorName::UsageError.as_str().to_string(),
            message: message.into(),
            phase: "cli-parse",
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造显式预算参数解析或边界校验失败错误（退出码 `2`）。
    pub fn invalid_budget(message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::UsageError,
            origin: ErrorOrigin::Cli,
            name: HostErrorName::InvalidBudget.as_str().to_string(),
            message: message.into(),
            phase: "budget-validate",
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造密钥文件／目录权限或敏感数据策略拒绝错误（退出码 `5`）。
    pub fn secret_policy(phase: &'static str, message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::PermissionDenied,
            origin: ErrorOrigin::Cli,
            name: HostErrorName::SecretPolicyRejected.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造权限拒绝错误（退出码 `5`）。
    pub fn permission_denied(phase: &'static str, message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::PermissionDenied,
            origin: ErrorOrigin::Cli,
            name: HostErrorName::PermissionDenied.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造守护进程未运行或本地 IPC Socket 不可达错误（退出码 `4`）。
    pub fn daemon_unreachable(phase: &'static str, message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::DaemonUnreachable,
            origin: ErrorOrigin::Ipc,
            name: HostErrorName::DaemonUnreachable.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造控制协议版本不兼容错误（退出码 `7`）。
    pub fn protocol_incompatible(phase: &'static str, message: impl Into<String>) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::Unsupported,
            origin: ErrorOrigin::Ipc,
            name: HostErrorName::ProtocolIncompatible.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造当前阶段或平台尚不支持的能力错误（退出码 `7`，保留源 Core `Unsupported` 错误码 `100023` 或宿主声明）。
    pub fn unsupported(phase: &'static str, message: impl Into<String>) -> Self {
        let code = ErrorCode::Unsupported;
        Self::new(CliErrorDetail {
            exit_code: ExitCode::Unsupported,
            origin: ErrorOrigin::Cli,
            name: HostErrorName::Unsupported.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: Some(code.value()),
            core_params: Some(ErrorParams::default()),
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 构造操作可能已提交但确认丢失的错误（退出码 `8`），并附带状态查询方式。
    pub fn unconfirmed(
        phase: &'static str,
        message: impl Into<String>,
        query_hint: impl Into<String>,
    ) -> Self {
        Self::new(CliErrorDetail {
            exit_code: ExitCode::UnconfirmedOutcome,
            origin: ErrorOrigin::Ipc,
            name: HostErrorName::UnconfirmedOutcome.as_str().to_string(),
            message: message.into(),
            phase,
            core_code: None,
            core_params: None,
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: Some(query_hint.into()),
        })
    }

    /// 从 Core `Error` 构造结构化 CLI 错误，完整保留六位 `ErrorCode` 与 `ErrorParams`。
    pub fn from_core_error(phase: &'static str, error: CoreError) -> Self {
        Self::from_core_info(phase, error.public_info(), Some(error.to_string()))
    }

    /// 从 Core `ErrorInfo` 构造结构化 CLI 错误。
    pub fn from_core_info(
        phase: &'static str,
        info: ErrorInfo,
        message_override: Option<String>,
    ) -> Self {
        let contract = info.code.contract();
        let exit_code = ExitCode::from_core_code(info.code);
        let message = message_override.unwrap_or_else(|| contract.detail.to_string());
        Self::new(CliErrorDetail {
            exit_code,
            origin: ErrorOrigin::Core,
            name: contract.name.to_string(),
            message,
            phase,
            core_code: Some(info.code.value()),
            core_params: Some(info.params),
            issues: Vec::new(),
            issues_truncated: false,
            recovery_hint: None,
        })
    }

    /// 从 Core `CheckIssues`（批量配置校验诊断）构造结构化 CLI 错误。
    pub fn from_check_issues(phase: &'static str, check: &CheckIssues) -> Self {
        let views: Vec<ConfigIssueView> = check
            .issues
            .iter()
            .map(ConfigIssueView::from_core_issue)
            .collect();
        if let Some(first) = check.issues.first() {
            let first_code = first.error_info.code;
            let contract = first_code.contract();
            // 若首个错误是文件不存在或权限被拒等 I/O 失败，按对应退出码映射；否则统一归为 ConfigInvalid (3)。
            let exit_code = if first.field == "$file" {
                match ExitCode::from_core_code(first_code) {
                    ExitCode::PermissionDenied => ExitCode::PermissionDenied,
                    _ => ExitCode::ConfigInvalid,
                }
            } else {
                ExitCode::ConfigInvalid
            };
            let loc = match &first.position {
                Some(pos) => format!("（第 {} 行，第 {} 列）", pos.line, pos.column),
                None => String::new(),
            };
            let message = format!(
                "配置校验失败：字段 `{}` {}{} [{}]",
                first.field,
                loc,
                contract.detail,
                first_code.value()
            );
            Self::new(CliErrorDetail {
                exit_code,
                origin: ErrorOrigin::Core,
                name: HostErrorName::InvalidConfig.as_str().to_string(),
                message,
                phase,
                core_code: Some(first_code.value()),
                core_params: Some(first.error_info.params),
                issues: views,
                issues_truncated: check.truncated,
                recovery_hint: None,
            })
        } else {
            Self::new(CliErrorDetail {
                exit_code: ExitCode::ConfigInvalid,
                origin: ErrorOrigin::Core,
                name: HostErrorName::InvalidConfig.as_str().to_string(),
                message: "配置校验未通过".to_string(),
                phase,
                core_code: None,
                core_params: None,
                issues: views,
                issues_truncated: check.truncated,
                recovery_hint: None,
            })
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.core_code {
            write!(f, "[{}] {} (code={})", self.phase, self.message, code)
        } else {
            write!(f, "[{}] {}", self.phase, self.message)
        }
    }
}

impl std::error::Error for CliError {}

/// `--json` 成功响应信封（遵循 `CLI.md` 1.5 节）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonSuccessEnvelope<T> {
    pub ok: bool,
    pub schema_version: u32,
    /// 当前实例配置修订代次；离线命令或未观测时为 `None`（序列化为 `null`，与 `0` 严格区分）。
    pub revision: Option<u64>,
    pub data: T,
}

impl<T> JsonSuccessEnvelope<T> {
    pub const fn new(revision: Option<u64>, data: T) -> Self {
        Self {
            ok: true,
            schema_version: JSON_SCHEMA_VERSION,
            revision,
            data,
        }
    }
}

/// `--json` 失败响应中的错误对象（遵循 `CLI.md` 1.5 节与《命令行与输出契约》）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonErrorBody {
    /// Core 原始六位错误代码；纯宿主用法或 IPC 错误无 Core 错误码时为 `null`。
    pub code: Option<u32>,
    pub name: String,
    pub message: String,
    pub phase: String,
    pub origin: ErrorOrigin,
    pub exit_code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ErrorParams>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issues: Vec<ConfigIssueView>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub issues_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hint: Option<String>,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

/// `--json` 失败响应信封。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonErrorEnvelope {
    pub ok: bool,
    pub schema_version: u32,
    pub error: JsonErrorBody,
}

impl JsonErrorEnvelope {
    pub fn from_cli_error(err: &CliError) -> Self {
        Self {
            ok: false,
            schema_version: JSON_SCHEMA_VERSION,
            error: JsonErrorBody {
                code: err.core_code,
                name: err.name.clone(),
                message: err.message.clone(),
                phase: err.phase.to_string(),
                origin: err.origin,
                exit_code: err.exit_code.as_u8(),
                params: err.core_params,
                issues: err.issues.clone(),
                issues_truncated: err.issues_truncated,
                recovery_hint: err.recovery_hint.clone(),
            },
        }
    }
}

/// 渲染成功结果到给定的 stdout 写入器。
/// - `json_mode = true`：在 `stdout` 输出单行 UTF-8 JSON；
/// - `json_mode = false`：在 `stdout` 输出人类可读文本。
pub fn write_success<T, W>(
    stdout: &mut W,
    json_mode: bool,
    quiet: bool,
    revision: Option<u64>,
    data: &T,
    human_render: impl FnOnce(&T, bool) -> String,
) -> Result<(), CliError>
where
    T: Serialize,
    W: Write,
{
    if json_mode {
        let envelope = JsonSuccessEnvelope::new(revision, data);
        let encoded = serde_json::to_string(&envelope).map_err(|_| {
            CliError::from_core_info(
                "output-encode",
                ErrorInfo::new(ErrorCode::SerializationFailed),
                None,
            )
        })?;
        writeln!(stdout, "{encoded}")
            .map_err(|e| CliError::from_core_error("output-write", CoreError::from(e)))?;
    } else {
        let text = human_render(data, quiet);
        if !text.is_empty() {
            if text.ends_with('\n') {
                write!(stdout, "{text}")
                    .map_err(|e| CliError::from_core_error("output-write", CoreError::from(e)))?;
            } else {
                writeln!(stdout, "{text}")
                    .map_err(|e| CliError::from_core_error("output-write", CoreError::from(e)))?;
            }
        }
    }
    stdout
        .flush()
        .map_err(|e| CliError::from_core_error("output-flush", CoreError::from(e)))
}

/// 渲染错误结果：
/// - `json_mode = true`：按《命令行与输出契约》第二.1 条，在 `stdout` 输出一个 UTF-8 JSON 错误对象，不污染 `stdout`；
/// - `json_mode = false`：在 `stderr` 输出人类可读错误、定位信息与恢复提示。
pub fn write_error<W1, W2>(
    stdout: &mut W1,
    stderr: &mut W2,
    json_mode: bool,
    err: &CliError,
) -> std::io::Result<()>
where
    W1: Write,
    W2: Write,
{
    if json_mode {
        let envelope = JsonErrorEnvelope::from_cli_error(err);
        let encoded = serde_json::to_string(&envelope).unwrap_or_else(|_| {
            format!(
                r#"{{"ok":false,"schema_version":{},"error":{{"code":null,"name":"SerializationFailed","message":"错误序列化失败","phase":"{}","origin":"cli","exit_code":{}}}}}"#,
                JSON_SCHEMA_VERSION,
                err.phase,
                err.exit_code.as_u8()
            )
        });
        writeln!(stdout, "{encoded}")?;
        stdout.flush()
    } else {
        if let Some(code) = err.core_code {
            writeln!(
                stderr,
                "错误 [{} | code={} | exit={}]: {}",
                err.phase,
                code,
                err.exit_code.as_u8(),
                err.message
            )?;
        } else {
            writeln!(
                stderr,
                "错误 [{} | {} | exit={}]: {}",
                err.phase,
                err.name,
                err.exit_code.as_u8(),
                err.message
            )?;
        }
        for issue in &err.issues {
            match (issue.line, issue.column) {
                (Some(line), Some(col)) => {
                    writeln!(
                        stderr,
                        "  - {} (第 {} 行, 第 {} 列): {} [code={}]",
                        issue.field, line, col, issue.message, issue.code
                    )?;
                }
                _ => {
                    writeln!(
                        stderr,
                        "  - {}: {} [code={}]",
                        issue.field, issue.message, issue.code
                    )?;
                }
            }
        }
        if err.issues_truncated {
            writeln!(stderr, "  （更多配置问题已截断，单次最多显示 64 项）")?;
        }
        if let Some(hint) = &err.recovery_hint {
            writeln!(stderr, "  提示: {hint}")?;
        }
        stderr.flush()
    }
}
