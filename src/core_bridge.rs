//! `nodus` 与 `Nodus-Core` 的受约束集成边界（L0-01 / L0-04）。
//!
//! 职责与不变量：
//! 1. 所有配置解析、摘要提取、批量诊断与资源预算设置均委派给 `nodus_core` 的公开 Rust 接口；
//! 2. CLI 不复制任何协议、路由、DNS、Mesh 或配置校验逻辑；
//! 3. 平台与构建能力矩阵诚实反映当前锁定 Core 的构建元数据与阶段实现边界。

use crate::{budget::ResourceBudgetConfig, output::CliError, security::resolve_authorized_path};
use nodus_core::{
    configuration::{Summary as CoreConfigSummary, check_file_all, check_yaml_all},
    error::diagnostics::provenance::{Build as CoreBuildInfo, build as core_build_info},
    ffi::{nodus_core_abi_version, nodus_core_capabilities},
    gateway::{
        contract::{Definition as GatewayDefinition, Summary as GatewaySummary},
        mesh::ts_identity::TailscaleProfileConfig,
    },
    storage::read_configuration,
};
use serde::Serialize;
use std::path::Path;

/// 配置校验与摘要的目标类型（对应 `nodus config check/summary --kind`）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigKind {
    #[default]
    Main,
    Gateway,
    Mesh,
    Server,
}

impl ConfigKind {
    pub fn parse(raw: &str) -> Result<Self, CliError> {
        match raw.trim() {
            "main" => Ok(Self::Main),
            "gateway" => Ok(Self::Gateway),
            "mesh" => Ok(Self::Mesh),
            "server" => Ok(Self::Server),
            other => Err(CliError::usage(format!(
                "无效的配置类型 `--kind {other}`（可选值：main、gateway、mesh、server）"
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Gateway => "gateway",
            Self::Mesh => "mesh",
            Self::Server => "server",
        }
    }
}

/// 平台与阶段能力矩阵（用于 `nodus version` 输出，严格区分 Core 能力位与 CLI 当前阶段支持态）。
#[derive(Clone, Debug, Serialize)]
pub struct PlatformCapabilities {
    pub offline_config_check: bool,
    pub explicit_memory_budget: bool,
    pub secret_file_isolation: bool,
    pub local_tun_takeover: bool,
    pub lan_transparent_gateway: bool,
    pub mesh_and_tailscale: bool,
    pub reality_server_mode: bool,
}

/// `nodus version` 返回的完整版本与构建溯源信息。
#[derive(Clone, Debug, Serialize)]
pub struct VersionReport {
    pub cli_name: &'static str,
    pub cli_version: &'static str,
    pub core_version: &'static str,
    pub core_abi_version: u32,
    pub core_capability_bits: u64,
    pub core_source_commit: Option<&'static str>,
    pub core_source_dirty: Option<bool>,
    pub core_build_id: &'static str,
    pub target_triple: &'static str,
    pub build_profile: &'static str,
    pub architecture: &'static str,
    pub host_os: &'static str,
    pub stage: &'static str,
    pub capabilities: PlatformCapabilities,
}

/// 采集当前 CLI 与锁定 Core 的真实版本与能力矩阵。
pub fn version_report() -> VersionReport {
    let CoreBuildInfo {
        core_version,
        source_commit,
        source_dirty,
        build_id,
        target,
        profile,
        architecture,
        abi,
    } = core_build_info();

    VersionReport {
        cli_name: env!("CARGO_PKG_NAME"),
        cli_version: env!("CARGO_PKG_VERSION"),
        core_version,
        core_abi_version: abi.max(nodus_core_abi_version()),
        core_capability_bits: nodus_core_capabilities(),
        core_source_commit: source_commit,
        core_source_dirty: source_dirty,
        core_build_id: build_id,
        target_triple: target,
        build_profile: profile,
        architecture,
        host_os: std::env::consts::OS,
        stage: "L0",
        capabilities: PlatformCapabilities {
            offline_config_check: true,
            explicit_memory_budget: true,
            secret_file_isolation: true,
            local_tun_takeover: false,
            lan_transparent_gateway: false,
            mesh_and_tailscale: false,
            reality_server_mode: false,
        },
    }
}

/// 统一的配置校验与摘要输出（无凭据泄漏，所有校验完全由 Core 执行）。
#[derive(Debug, Serialize)]
pub struct ConfigCheckReport {
    pub valid: bool,
    pub kind: ConfigKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_summary: Option<CoreConfigSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_summary: Option<GatewaySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_network_kind: Option<String>,
}

/// 调用 Core 离线校验指定配置文件并返回无凭据摘要。
/// 若提供了显式预算，先将预算应用到 Core 根池，再在预算约束下执行解析与语义检查。
pub fn check_config_file(
    path: &Path,
    kind: ConfigKind,
    budget: Option<&ResourceBudgetConfig>,
) -> Result<ConfigCheckReport, CliError> {
    if let Some(b) = budget {
        b.apply_to_core()?;
    }
    let resolved = resolve_authorized_path(path)?;
    let path_str = resolved
        .to_str()
        .ok_or_else(|| CliError::usage("配置文件路径不是有效的 UTF-8 字符串"))?
        .to_string();

    match kind {
        ConfigKind::Main => {
            let summary = check_file_all(&path_str)
                .map_err(|issues| CliError::from_check_issues("config-check", &issues))?;
            Ok(ConfigCheckReport {
                valid: true,
                kind,
                path: path_str,
                main_summary: Some(summary),
                gateway_summary: None,
                mesh_network_kind: None,
            })
        }
        ConfigKind::Gateway | ConfigKind::Server => {
            let text = read_file_bounded(&resolved)?;
            let definition = GatewayDefinition::from_json(&text)
                .map_err(|err| CliError::from_core_error("config-check", err))?;
            let summary = definition.summary();
            Ok(ConfigCheckReport {
                valid: true,
                kind,
                path: path_str,
                main_summary: None,
                gateway_summary: Some(summary),
                mesh_network_kind: None,
            })
        }
        ConfigKind::Mesh => {
            let text = read_file_bounded(&resolved)?;
            let profile: TailscaleProfileConfig = serde_json::from_str(&text).map_err(|_| {
                CliError::from_core_error(
                    "config-check",
                    nodus_core::error::Error::ConfigYamlSyntax,
                )
            })?;
            profile
                .validate()
                .map_err(|err| CliError::from_core_error("config-check", err))?;
            Ok(ConfigCheckReport {
                valid: true,
                kind,
                path: path_str,
                main_summary: None,
                gateway_summary: None,
                mesh_network_kind: Some(format!("{:?}", profile.network_kind)),
            })
        }
    }
}

/// 直接在内存中经 Core 校验主配置 YAML 文本（供离线校验与单元测试复用）。
pub fn check_main_yaml_str(
    yaml: &str,
    budget: Option<&ResourceBudgetConfig>,
) -> Result<CoreConfigSummary, CliError> {
    if let Some(b) = budget {
        b.apply_to_core()?;
    }
    check_yaml_all(yaml).map_err(|issues| CliError::from_check_issues("config-check", &issues))
}

/// 经 Core 受预算保护的只读入口读取主配置文本并校验。
pub fn verify_readable_main_configuration(path: &Path) -> Result<String, CliError> {
    let resolved = resolve_authorized_path(path)?;
    let path_str = resolved
        .to_str()
        .ok_or_else(|| CliError::usage("配置文件路径不是有效的 UTF-8 字符串"))?;
    let _text = read_configuration(path_str)
        .map_err(|err| CliError::from_core_error("config-load", err))?;
    Ok(path_str.to_string())
}

fn read_file_bounded(resolved: &Path) -> Result<zeroize::Zeroizing<String>, CliError> {
    use std::fs::OpenOptions;
    use std::io::Read;
    let max_bytes = nodus_core::configuration::MAX_CONFIG_BYTES;
    let before = std::fs::symlink_metadata(resolved)
        .map_err(|e| CliError::from_core_error("config-read", e.into()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(CliError::from_core_error(
            "config-read",
            nodus_core::error::Error::InvalidInput,
        ));
    }
    if before.len() > max_bytes as u64 {
        return Err(CliError::from_core_error(
            "config-read",
            nodus_core::error::Error::ResourceLimit,
        ));
    }

    // 实际打开时附加 O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK（防止符号链接穿透与 FIFO 阻塞），
    // 并对已打开的句柄复核文件类型、大小及 (dev, ino) 一致性，消除路径检查与打开之间的 TOCTOU 窗口。
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        let flags = (OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits();
        options.custom_flags(flags);
    }

    let mut file = options
        .open(resolved)
        .map_err(|e| CliError::from_core_error("config-read", e.into()))?;
    let opened = file
        .metadata()
        .map_err(|e| CliError::from_core_error("config-read", e.into()))?;
    if !opened.is_file() {
        return Err(CliError::from_core_error(
            "config-read",
            nodus_core::error::Error::InvalidInput,
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CliError::from_core_error(
                "config-read",
                nodus_core::error::Error::InvalidInput,
            ));
        }
    }
    if opened.len() > max_bytes as u64 {
        return Err(CliError::from_core_error(
            "config-read",
            nodus_core::error::Error::ResourceLimit,
        ));
    }

    let mut content = zeroize::Zeroizing::new(String::new());
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_string(&mut content)
        .map_err(|e| CliError::from_core_error("config-read", e.into()))?;
    if content.len() > max_bytes {
        return Err(CliError::from_core_error(
            "config-read",
            nodus_core::error::Error::ResourceLimit,
        ));
    }
    Ok(content)
}
