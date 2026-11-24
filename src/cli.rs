//! `nodus` 命令行解析与执行编排（L0-02）。
//!
//! 职责与不变量：
//! 1. 解析阶段优先识别 `--json`，一旦识别到有效的 `--json` 请求，后续所有参数错误、密钥拒绝与执行失败
//!    均严格以 JSON 格式在 stdout 输出，不向 stdout 混入任何人类文本或日志；
//! 2. 拦截被禁止的明文凭据命令行标志（`--auth-key`、`--private-key`、`--token` 等），返回退出码 `5`；
//! 3. 帮助信息与可用命令清单仅列出当前阶段已实际落地的命令（`version`、`config check`、`config summary`），
//!    与《命令行与输出契约》第一.1 条“尚未实现的命令不得出现在可用命令清单中”一致；
//! 4. 对尚未落地阶段的命令（L1/L2/L3），先完成显式预算、路径与密钥文件权限前置核验，再诚实返回结构化 `Unsupported`（退出码 `7`）。

use crate::{
    budget::{BudgetSource, ConnectionBudget, MemoryBudget, ResourceBudgetConfig},
    core_bridge::{
        ConfigCheckReport, ConfigKind, VersionReport, check_config_file, version_report,
    },
    output::{CliError, ExitCode, write_error, write_success},
    security::{
        open_verified_secret_file, reject_if_forbidden_secret_flag, resolve_authorized_path,
        verify_private_directory,
    },
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

/// 默认本地控制请求超时（10 秒）。
pub const DEFAULT_IPC_TIMEOUT: Duration = Duration::from_secs(10);

/// 全局命令行参数（遵循 `CLI.md` 1.1 节与《命令行与输出契约》第一.2 条）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalOptions {
    /// 全局 `--config <FILE>`（可由全局或子命令传入，显式值优先且不得静默回退）。
    pub config: Option<PathBuf>,
    /// 全局 `--socket <PATH>`（本地控制 Unix Domain Socket 端点）。
    pub socket: Option<PathBuf>,
    /// 机器可读 JSON 输出模式。
    pub json: bool,
    /// 本地 IPC 控制请求超时（默认 `10s`）。
    pub timeout: Duration,
    /// 静默模式（与 `--verbose` 互斥）。
    pub quiet: bool,
    /// 详细诊断摘要模式（与 `--quiet` 互斥，仍不输出密钥）。
    pub verbose: bool,
    /// 全局或子命令显式提供的 `--memory-budget`。
    pub memory_budget: Option<ResourceBudgetConfig>,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            config: None,
            socket: None,
            json: false,
            timeout: DEFAULT_IPC_TIMEOUT,
            quiet: false,
            verbose: false,
            memory_budget: None,
        }
    }
}

impl GlobalOptions {
    /// 获取有效控制 Socket 路径：显式 `--socket` 优先（验证合法性，无效直接报错）；
    /// 未显式指定时，root 默认 `/run/nodus/nodus.sock`，普通用户默认 `$XDG_RUNTIME_DIR/nodus/nodus.sock`。
    pub fn effective_socket_path(&self) -> Result<PathBuf, CliError> {
        if let Some(explicit) = &self.socket {
            return resolve_authorized_path(explicit);
        }
        #[cfg(unix)]
        {
            if nix::unistd::geteuid().is_root() {
                return Ok(PathBuf::from("/run/nodus/nodus.sock"));
            }
        }
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let trimmed = xdg.trim();
            if !trimmed.is_empty() {
                let base = resolve_authorized_path(Path::new(trimmed))?;
                return Ok(base.join("nodus").join("nodus.sock"));
            }
        }
        Err(CliError::usage(
            "未显式指定 `--socket <PATH>`，且环境变量 `XDG_RUNTIME_DIR` 未设置或为空",
        ))
    }
}

/// 解析后的顶层命令树。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// 显示顶层或子命令帮助。
    Help(HelpTopic),
    /// `nodus version` 或 `nodus -V / --version`。
    Version,
    /// `nodus config check <FILE> [--kind <main|gateway|mesh|server>]`。
    ConfigCheck { file: PathBuf, kind: ConfigKind },
    /// `nodus config summary <FILE> [--kind <main|gateway|mesh|server>]`。
    ConfigSummary { file: PathBuf, kind: ConfigKind },
    /// `nodus run`（L1 守护进程入口：在 L0 阶段先完整校验 `--config`、`--memory-budget`、`--connection-limit` 及目录权限，再返回 L1 未启用）。
    Run {
        config: PathBuf,
        budget: ResourceBudgetConfig,
        log_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
        enable_tun: bool,
    },
    /// 后续阶段（L1 / L2 / L3）已规划但当前 L0 尚未实现的子命令（完成参数与密钥文件权限前置检查后返回 `Unsupported` 退出码 `7`）。
    PlannedStageCommand {
        command_path: String,
        stage: &'static str,
        secret_files_to_verify: Vec<PathBuf>,
        secret_dirs_to_verify: Vec<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Version,
    Config,
}

/// 顶层解析结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInvocation {
    pub global: GlobalOptions,
    pub command: Command,
}

#[derive(Clone, Copy)]
enum OptionScope {
    Root,
    ConfigAction,
    OfflineConfig,
    Run,
    Planned,
    Other,
}

impl OptionScope {
    fn for_command(command: &str) -> Self {
        match command {
            "config" => Self::ConfigAction,
            "run" | "daemon" => Self::Run,
            "stop" | "status" | "proxy" | "route" | "node" | "conn" | "dns" | "mesh" | "logs"
            | "diag" | "tun" | "gateway" | "device" | "mitm" | "server" => Self::Planned,
            _ => Self::Other,
        }
    }

    fn accepts_local_budget(self) -> bool {
        matches!(self, Self::OfflineConfig | Self::Run)
    }

    fn takes_value(self, flag: &str) -> bool {
        if flag == "--socket" {
            return true;
        }
        match self {
            Self::Root => matches!(
                flag,
                "--config" | "--timeout" | "--memory-budget" | "--connection-limit"
            ),
            Self::OfflineConfig => matches!(
                flag,
                "--kind" | "--config" | "--memory-budget" | "--connection-limit"
            ),
            Self::Run => matches!(
                flag,
                "--config" | "--memory-budget" | "--connection-limit" | "--log-dir" | "--state-dir"
            ),
            // 规划命令仅识别当前已执行前置检查的选项。
            Self::Planned => matches!(
                flag,
                "--key-file"
                    | "--auth-key-file"
                    | "--token-file"
                    | "--cert-file"
                    | "--key-dir"
                    | "--log-dir"
                    | "--state-dir"
                    | "--memory-budget"
            ),
            Self::ConfigAction | Self::Other => false,
        }
    }
}

fn is_forwarded_global(token: &str) -> bool {
    matches!(
        token,
        "--json" | "-q" | "--quiet" | "-v" | "--verbose" | "--socket"
    ) || token.starts_with("--socket=")
}

/// 按命令位置识别选项头。错误渲染、凭据检查和子命令全局选项提取共用值与终止符边界。
fn scan_options<'a>(
    args: impl Iterator<Item = Option<&'a str>>,
    mut scope: OptionScope,
) -> impl Iterator<Item = (usize, OptionScope, &'a str, usize)> {
    let mut args = args.enumerate().peekable();
    let mut root_shortcut = false;
    std::iter::from_fn(move || {
        while let Some((index, token)) = args.next() {
            let Some(token) = token else {
                continue;
            };
            if token == "--" {
                return None;
            }

            let option_scope = scope;
            match scope {
                OptionScope::Root if matches!(token, "-h" | "--help" | "-V" | "--version") => {
                    root_shortcut = true;
                }
                OptionScope::Root if !token.starts_with('-') => {
                    scope = if root_shortcut {
                        OptionScope::Other
                    } else {
                        OptionScope::for_command(token)
                    };
                }
                OptionScope::ConfigAction if !is_forwarded_global(token) => {
                    scope = match token {
                        "check" | "summary" => OptionScope::OfflineConfig,
                        _ => OptionScope::Other,
                    };
                }
                _ => {}
            }
            if token.starts_with('-') {
                let width = if option_scope.takes_value(token)
                    && args.next_if(|(_, value)| *value != Some("--")).is_some()
                {
                    2
                } else {
                    1
                };
                return Some((index, option_scope, token, width));
            }
        }
        None
    })
    .fuse()
}

/// 在原始进程参数中识别独立的 `--json`，包括含非 UTF-8 参数的调用。
pub fn detect_json_mode_os(args: &[std::ffi::OsString]) -> bool {
    scan_options(args.iter().map(|arg| arg.to_str()), OptionScope::Root)
        .any(|(_, _, token, _)| token == "--json")
}

/// 在 UTF-8 参数中识别独立的 `--json`。
pub fn detect_json_mode(args: &[String]) -> bool {
    scan_options(args.iter().map(|arg| Some(arg.as_str())), OptionScope::Root)
        .any(|(_, _, token, _)| token == "--json")
}

/// 解析超时时间字符串（如 `"5s"`、`"500ms"`、`"1m"`）。
pub fn parse_duration_flag(flag_name: &str, raw: &str) -> Result<Duration, CliError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage(format!(
            "参数 `{flag_name}` 的时长不能为空"
        )));
    }
    let split_idx = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (num_part, unit_part) = trimmed.split_at(split_idx);
    if num_part.is_empty() {
        return Err(CliError::usage(format!(
            "参数 `{flag_name}` 的时长 `{trimmed}` 缺少有效正整数"
        )));
    }
    let value: u64 = num_part
        .parse()
        .map_err(|_| CliError::usage(format!("参数 `{flag_name}` 的时长数值 `{num_part}` 溢出")))?;
    if value == 0 {
        return Err(CliError::usage(format!(
            "参数 `{flag_name}` 的时长必须大于 0"
        )));
    }
    let millis = match unit_part.trim() {
        "ms" => value,
        "" | "s" => value
            .checked_mul(1000)
            .ok_or_else(|| CliError::usage(format!("参数 `{flag_name}` 时长溢出")))?,
        "m" => value
            .checked_mul(60_000)
            .ok_or_else(|| CliError::usage(format!("参数 `{flag_name}` 时长溢出")))?,
        other => {
            return Err(CliError::usage(format!(
                "参数 `{flag_name}` 不支持时长单位 `{other}`（支持 ms、s、m）"
            )));
        }
    };
    Ok(Duration::from_millis(millis))
}

/// 解析完整命令行参数（不含 `argv[0]` 程序名）。
///
/// 选项、参数值及参数终止符 `--` 在预扫描（`detect_json_mode`）、凭据拦截与正式解析之间严格保持同一边界：
/// - 遇到 `--` 停止选项识别，其后的全部 token 均按字面位置参数交给对应子命令；
/// - 当前命令接受的带值选项（`--flag <VAL>`）消费紧随其后的一个非终止符参数，选项值不会触发输出模式或凭据检查；
/// - 顶层 `-h/--help` 与 `-V/--version` 在完成全局选项收集与冲突校验后返回，因此 `nodus --help --json` 与 `nodus --json --help` 均以 JSON 输出帮助。
pub fn parse_cli_args(args: &[String]) -> Result<ParsedInvocation, CliError> {
    let mut global = GlobalOptions::default();
    for (_, _, token, _) in
        scan_options(args.iter().map(|arg| Some(arg.as_str())), OptionScope::Root)
    {
        reject_if_forbidden_secret_flag(token)?;
        global.json |= token == "--json";
    }

    let mut raw_memory_budget: Option<String> = None;
    let mut raw_conn_limit: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut subcommand_args: Vec<String> = Vec::new();
    let mut in_subcommand = false;
    let mut top_level_help = false;
    let mut top_level_version = false;

    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        if in_subcommand {
            subcommand_args.push(token.clone());
            i += 1;
            continue;
        }

        match token.as_str() {
            "--" => {
                // 顶层参数终止符：其后第一个 token 作为子命令名，剩余 token 原样保留在 `--` 之后传给子命令
                if i + 1 < args.len() {
                    positional.push(args[i + 1].clone());
                    if i + 2 < args.len() {
                        subcommand_args.push("--".to_string());
                        subcommand_args.extend_from_slice(&args[i + 2..]);
                    }
                }
                break;
            }
            "--json" => i += 1,
            "-q" | "--quiet" => {
                global.quiet = true;
                i += 1;
            }
            "-v" | "--verbose" => {
                global.verbose = true;
                i += 1;
            }
            "-h" | "--help" => {
                if top_level_version {
                    return Err(CliError::usage(
                        "选项 `--help (-h)` 与 `--version (-V)` 不能同时指定",
                    ));
                }
                top_level_help = true;
                i += 1;
            }
            "-V" | "--version" => {
                if top_level_help {
                    return Err(CliError::usage(
                        "选项 `--help (-h)` 与 `--version (-V)` 不能同时指定",
                    ));
                }
                top_level_version = true;
                i += 1;
            }
            "--socket" => {
                let val = next_flag_value(args, &mut i, "--socket")?;
                if val.trim().is_empty() {
                    return Err(CliError::usage("`--socket` 路径不能为空"));
                }
                let resolved = resolve_authorized_path(Path::new(&val))?;
                global.socket = Some(resolved);
                i += 1;
            }
            "--config" => {
                let val = next_flag_value(args, &mut i, "--config")?;
                if val.trim().is_empty() {
                    return Err(CliError::usage("`--config` 路径不能为空"));
                }
                let resolved = resolve_authorized_path(Path::new(&val))?;
                global.config = Some(resolved);
                i += 1;
            }
            "--timeout" => {
                let val = next_flag_value(args, &mut i, "--timeout")?;
                global.timeout = parse_duration_flag("--timeout", &val)?;
                i += 1;
            }
            "--memory-budget" => {
                let val = next_flag_value(args, &mut i, "--memory-budget")?;
                raw_memory_budget = Some(val);
                i += 1;
            }
            "--connection-limit" => {
                let val = next_flag_value(args, &mut i, "--connection-limit")?;
                raw_conn_limit = Some(val);
                i += 1;
            }
            _ if token.starts_with("--socket=") => {
                let val = &token["--socket=".len()..];
                if val.trim().is_empty() {
                    return Err(CliError::usage("`--socket` 路径不能为空"));
                }
                global.socket = Some(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            _ if token.starts_with("--config=") => {
                let val = &token["--config=".len()..];
                if val.trim().is_empty() {
                    return Err(CliError::usage("`--config` 路径不能为空"));
                }
                global.config = Some(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            _ if token.starts_with("--timeout=") => {
                let val = &token["--timeout=".len()..];
                global.timeout = parse_duration_flag("--timeout", val)?;
                i += 1;
            }
            _ if token.starts_with("--memory-budget=") => {
                let val = &token["--memory-budget=".len()..];
                raw_memory_budget = Some(val.to_string());
                i += 1;
            }
            _ if token.starts_with("--connection-limit=") => {
                let val = &token["--connection-limit=".len()..];
                raw_conn_limit = Some(val.to_string());
                i += 1;
            }
            _ if token.starts_with('-') => {
                return Err(CliError::usage(format!(
                    "未知的全局选项 `{token}`（使用 `nodus --help` 查看帮助）"
                )));
            }
            _ => {
                if top_level_version {
                    return Err(CliError::usage(format!(
                        "`nodus --version` 不接受额外子命令或参数 `{token}`"
                    )));
                }
                positional.push(token.clone());
                in_subcommand = true;
                i += 1;
            }
        }
    }

    // 只移除当前命令接受的全局选项及预算。其余选项、值和字面参数原样交给子命令。
    let scope = if top_level_help {
        OptionScope::Other
    } else {
        positional
            .first()
            .map_or(OptionScope::Other, |name| OptionScope::for_command(name))
    };
    let mut filtered_sub_args = Vec::with_capacity(subcommand_args.len());
    let mut pending = 0;
    for (index, scope, token, width) in
        scan_options(subcommand_args.iter().map(|arg| Some(arg.as_str())), scope)
    {
        let (flag, inline_value) = token
            .split_once('=')
            .map_or((token, None), |(flag, value)| (flag, Some(value)));
        let value = || match inline_value {
            Some(value) => Ok(value.to_owned()),
            None => flag_value(&subcommand_args, index, flag).cloned(),
        };

        match flag {
            "--json" if inline_value.is_none() => {}
            "-q" | "--quiet" if inline_value.is_none() => global.quiet = true,
            "-v" | "--verbose" if inline_value.is_none() => global.verbose = true,
            "--socket" => {
                let value = value()?;
                if value.trim().is_empty() {
                    return Err(CliError::usage("`--socket` 路径不能为空"));
                }
                global.socket = Some(resolve_authorized_path(Path::new(&value))?);
            }
            "--memory-budget" if scope.accepts_local_budget() => raw_memory_budget = Some(value()?),
            "--connection-limit" if scope.accepts_local_budget() => raw_conn_limit = Some(value()?),
            _ => continue,
        }
        filtered_sub_args.extend_from_slice(&subcommand_args[pending..index]);
        pending = index + width;
    }
    filtered_sub_args.extend_from_slice(&subcommand_args[pending..]);

    if global.quiet && global.verbose {
        return Err(CliError::usage(
            "选项 `--quiet (-q)` 与 `--verbose (-v)` 冲突，不能同时指定",
        ));
    }

    if let Some(ref mem_raw) = raw_memory_budget {
        let mem = MemoryBudget::parse(mem_raw, BudgetSource::CliFlag)?;
        let conn = match raw_conn_limit.as_deref() {
            Some(c) => Some(ConnectionBudget::parse(c, BudgetSource::CliFlag)?),
            None => None,
        };
        global.memory_budget = Some(ResourceBudgetConfig::new(mem, conn));
    } else if raw_conn_limit.is_some() {
        return Err(CliError::invalid_budget(
            "指定 `--connection-limit` 时必须同时提供显式 `--memory-budget <SIZE>`",
        ));
    }

    if top_level_help {
        let topic = match positional.first().map(String::as_str) {
            None | Some("help") => HelpTopic::Root,
            Some("version") => HelpTopic::Version,
            Some("config") => HelpTopic::Config,
            Some(other) => {
                return Err(CliError::usage(format!(
                    "未知的帮助主题 `{other}`（使用 `nodus --help` 查看可用命令）"
                )));
            }
        };
        return Ok(ParsedInvocation {
            global,
            command: parse_help_subcommand(&filtered_sub_args, Some(topic))?,
        });
    }

    if top_level_version {
        if let Some(extra) = positional.first() {
            return Err(CliError::usage(format!(
                "`nodus --version` 不接受额外子命令或参数 `{extra}`"
            )));
        }
        return Ok(ParsedInvocation {
            global,
            command: Command::Version,
        });
    }

    let Some(subcmd) = positional.first() else {
        return Err(CliError::usage(
            "缺少子命令（使用 `nodus --help` 查看可用命令）",
        ));
    };

    let command = match subcmd.as_str() {
        "help" => parse_help_subcommand(&filtered_sub_args, None)?,
        "version" => parse_version_subcommand(&filtered_sub_args)?,
        "config" => parse_config_subcommand(&global, &filtered_sub_args)?,
        "run" | "daemon" => parse_run_subcommand(&global, &filtered_sub_args)?,
        "stop" | "status" | "proxy" | "route" | "node" | "conn" | "dns" | "mesh" | "logs"
        | "diag" => parse_planned_subcommand(subcmd, "L1", &filtered_sub_args)?,
        "tun" => parse_planned_subcommand(subcmd, "L2", &filtered_sub_args)?,
        "gateway" | "device" | "mitm" | "server" => {
            parse_planned_subcommand(subcmd, "L3", &filtered_sub_args)?
        }
        other => {
            return Err(CliError::usage(format!(
                "未知的子命令 `{other}`（使用 `nodus --help` 查看可用命令）"
            )));
        }
    };

    Ok(ParsedInvocation { global, command })
}

fn flag_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a String, CliError> {
    args.get(index + 1)
        .filter(|value| value.as_str() != "--")
        .ok_or_else(|| CliError::usage(format!("选项 `{flag}` 缺少参数值")))
}

fn next_flag_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, CliError> {
    let value = flag_value(args, *index, flag)?;
    *index += 1;
    Ok(value.clone())
}

/// 当调用方式已确定帮助主题时，继续核验余下参数并拒绝第二个主题。
fn parse_help_subcommand(
    args: &[String],
    mut topic: Option<HelpTopic>,
) -> Result<Command, CliError> {
    let mut terminated = false;
    for token in args {
        match token.as_str() {
            "--" if !terminated => terminated = true,
            "-h" | "--help" if !terminated => {}
            "version" if topic.is_none() => topic = Some(HelpTopic::Version),
            "config" if topic.is_none() => topic = Some(HelpTopic::Config),
            other => {
                return Err(CliError::usage(format!(
                    "帮助命令收到未知主题或多余参数 `{other}`（可选主题：`version`、`config`）"
                )));
            }
        }
    }
    Ok(Command::Help(topic.unwrap_or(HelpTopic::Root)))
}

fn parse_version_subcommand(args: &[String]) -> Result<Command, CliError> {
    let mut terminated = false;
    let mut help = false;
    for arg in args {
        if !terminated && arg == "--" {
            terminated = true;
            continue;
        }
        if !terminated && matches!(arg.as_str(), "-h" | "--help") {
            help = true;
            continue;
        }
        return Err(CliError::usage(format!(
            "`nodus version` 不接受额外参数 `{arg}`"
        )));
    }
    Ok(if help {
        Command::Help(HelpTopic::Version)
    } else {
        Command::Version
    })
}

fn parse_config_subcommand(global: &GlobalOptions, args: &[String]) -> Result<Command, CliError> {
    let Some(first) = args.first() else {
        return Err(CliError::usage(
            "`nodus config` 缺少子命令（可用子命令：`check`、`summary`；使用 `nodus config --help` 查看帮助）",
        ));
    };

    let (action, start_idx, mut terminated) = if first == "--" {
        let Some(act) = args.get(1) else {
            return Err(CliError::usage(
                "`nodus config` 缺少子命令（可用子命令：`check`、`summary`；使用 `nodus config --help` 查看帮助）",
            ));
        };
        (act.as_str(), 2usize, true)
    } else {
        (first.as_str(), 1usize, false)
    };

    if !terminated && matches!(action, "-h" | "--help" | "help") {
        return parse_help_subcommand(&args[start_idx..], Some(HelpTopic::Config));
    }

    match action {
        "check" | "summary" => {
            let mut file_arg: Option<PathBuf> = None;
            let mut kind = ConfigKind::Main;
            let mut help_requested = false;
            let mut i = start_idx;
            while i < args.len() {
                let token = &args[i];
                if terminated {
                    if file_arg.is_some() {
                        return Err(CliError::usage(format!(
                            "`nodus config {action}` 多余的位置参数 `{token}`"
                        )));
                    }
                    file_arg = Some(resolve_authorized_path(Path::new(token))?);
                    i += 1;
                    continue;
                }
                match token.as_str() {
                    "--" => {
                        terminated = true;
                        i += 1;
                    }
                    "-h" | "--help" => {
                        help_requested = true;
                        i += 1;
                    }
                    "--kind" => {
                        let val = next_flag_value(args, &mut i, "--kind")?;
                        kind = ConfigKind::parse(&val)?;
                        i += 1;
                    }
                    _ if token.starts_with("--kind=") => {
                        let val = &token["--kind=".len()..];
                        kind = ConfigKind::parse(val)?;
                        i += 1;
                    }
                    "--config" => {
                        let val = next_flag_value(args, &mut i, "--config")?;
                        if file_arg.is_some() {
                            return Err(CliError::usage("不能重复指定配置文件路径"));
                        }
                        file_arg = Some(resolve_authorized_path(Path::new(&val))?);
                        i += 1;
                    }
                    _ if token.starts_with("--config=") => {
                        let val = &token["--config=".len()..];
                        if file_arg.is_some() {
                            return Err(CliError::usage("不能重复指定配置文件路径"));
                        }
                        file_arg = Some(resolve_authorized_path(Path::new(val))?);
                        i += 1;
                    }
                    _ if token.starts_with('-') => {
                        return Err(CliError::usage(format!(
                            "`nodus config {action}` 未知选项 `{token}`"
                        )));
                    }
                    _ => {
                        if file_arg.is_some() {
                            return Err(CliError::usage(format!(
                                "`nodus config {action}` 多余的位置参数 `{token}`"
                            )));
                        }
                        file_arg = Some(resolve_authorized_path(Path::new(token))?);
                        i += 1;
                    }
                }
            }

            if help_requested {
                return Ok(Command::Help(HelpTopic::Config));
            }

            let target_file = match (file_arg, global.config.clone()) {
                (Some(f), None) | (None, Some(f)) => f,
                (Some(a), Some(b)) if a == b => a,
                (Some(_), Some(_)) => {
                    return Err(CliError::usage(
                        "全局 `--config` 与子命令位置参数指定了不同的配置文件路径，存在冲突",
                    ));
                }
                (None, None) => {
                    return Err(CliError::usage(format!(
                        "`nodus config {action}` 缺少必填的 `<FILE>`（或 `--config <FILE>`）参数"
                    )));
                }
            };

            if action == "check" {
                Ok(Command::ConfigCheck {
                    file: target_file,
                    kind,
                })
            } else {
                Ok(Command::ConfigSummary {
                    file: target_file,
                    kind,
                })
            }
        }
        "apply" | "reload" | "current" => Ok(Command::PlannedStageCommand {
            command_path: format!("config {action}"),
            stage: "L1",
            secret_files_to_verify: Vec::new(),
            secret_dirs_to_verify: Vec::new(),
        }),
        other => Err(CliError::usage(format!(
            "`nodus config` 未知子命令 `{other}`（可用子命令：`check`、`summary`）"
        ))),
    }
}

fn parse_run_subcommand(global: &GlobalOptions, args: &[String]) -> Result<Command, CliError> {
    let mut config_path = global.config.clone();
    let mut log_dir: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut enable_tun = false;
    let mut terminated = false;

    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        if terminated {
            return Err(CliError::usage(format!("`nodus run` 未知参数 `{token}`")));
        }
        match token.as_str() {
            "--" => {
                terminated = true;
                i += 1;
            }
            "--config" => {
                let val = next_flag_value(args, &mut i, "--config")?;
                let resolved = resolve_authorized_path(Path::new(&val))?;
                if let Some(ref existing) = config_path
                    && existing != &resolved
                {
                    return Err(CliError::usage("不能指定多个冲突的 `--config` 路径"));
                }
                config_path = Some(resolved);
                i += 1;
            }
            _ if token.starts_with("--config=") => {
                let val = &token["--config=".len()..];
                let resolved = resolve_authorized_path(Path::new(val))?;
                if let Some(ref existing) = config_path
                    && existing != &resolved
                {
                    return Err(CliError::usage("不能指定多个冲突的 `--config` 路径"));
                }
                config_path = Some(resolved);
                i += 1;
            }
            "--log-dir" => {
                let val = next_flag_value(args, &mut i, "--log-dir")?;
                log_dir = Some(resolve_authorized_path(Path::new(&val))?);
                i += 1;
            }
            _ if token.starts_with("--log-dir=") => {
                let val = &token["--log-dir=".len()..];
                log_dir = Some(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            "--state-dir" => {
                let val = next_flag_value(args, &mut i, "--state-dir")?;
                state_dir = Some(resolve_authorized_path(Path::new(&val))?);
                i += 1;
            }
            _ if token.starts_with("--state-dir=") => {
                let val = &token["--state-dir=".len()..];
                state_dir = Some(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            "--enable-tun" => {
                enable_tun = true;
                i += 1;
            }
            other => {
                return Err(CliError::usage(format!("`nodus run` 未知参数 `{other}`")));
            }
        }
    }

    let config = config_path.ok_or_else(|| {
        CliError::usage("`nodus run` 必须显式指定 `--config <FILE>` 主配置文件路径")
    })?;

    let budget = global.memory_budget.ok_or_else(|| {
        CliError::invalid_budget(
            "`nodus run` 必须显式提供 `--memory-budget <SIZE>`（如 `--memory-budget 64M`，禁止隐式默认无限额度）",
        )
    })?;

    Ok(Command::Run {
        config,
        budget,
        log_dir,
        state_dir,
        enable_tun,
    })
}

fn parse_planned_subcommand(
    subcmd: &str,
    default_stage: &'static str,
    args: &[String],
) -> Result<Command, CliError> {
    let mut secret_files = Vec::new();
    let mut secret_dirs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        match token.as_str() {
            "--" => break,
            "--key-file" | "--auth-key-file" | "--token-file" | "--cert-file" => {
                let flag = token.clone();
                let val = next_flag_value(args, &mut i, &flag)?;
                secret_files.push(resolve_authorized_path(Path::new(&val))?);
                i += 1;
            }
            _ if token.starts_with("--key-file=")
                || token.starts_with("--auth-key-file=")
                || token.starts_with("--token-file=")
                || token.starts_with("--cert-file=") =>
            {
                let (_, val) = token.split_once('=').unwrap_or(("", ""));
                secret_files.push(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            "--key-dir" | "--log-dir" | "--state-dir" => {
                let flag = token.clone();
                let val = next_flag_value(args, &mut i, &flag)?;
                secret_dirs.push(resolve_authorized_path(Path::new(&val))?);
                i += 1;
            }
            _ if token.starts_with("--key-dir=")
                || token.starts_with("--log-dir=")
                || token.starts_with("--state-dir=") =>
            {
                let (_, val) = token.split_once('=').unwrap_or(("", ""));
                secret_dirs.push(resolve_authorized_path(Path::new(val))?);
                i += 1;
            }
            "--memory-budget" => {
                let val = next_flag_value(args, &mut i, "--memory-budget")?;
                let _ = MemoryBudget::parse(&val, BudgetSource::CliFlag)?;
                i += 1;
            }
            _ if token.starts_with("--memory-budget=") => {
                let val = &token["--memory-budget=".len()..];
                let _ = MemoryBudget::parse(val, BudgetSource::CliFlag)?;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let action_suffix = args
        .first()
        .filter(|a| !a.starts_with('-'))
        .map(|a| format!(" {a}"))
        .unwrap_or_default();

    Ok(Command::PlannedStageCommand {
        command_path: format!("{subcmd}{action_suffix}"),
        stage: default_stage,
        secret_files_to_verify: secret_files,
        secret_dirs_to_verify: secret_dirs,
    })
}

/// 从进程级 `OsString` 参数切片（不含 `argv[0]`）执行命令行调用。
///
/// 显式处理非 UTF-8 字节参数，绝不因 `std::env::args()` 在非 UTF-8 参数上 panic：
/// - 先用 `detect_json_mode_os` 在 `--` 终止符前检测是否请求了 `--json` 模式；
/// - 逐项校验 UTF-8 编码，若任一参数包含无效 UTF-8 字节，立即按用法错误（退出码 `2`）返回，
///   并在已请求 `--json` 模式时在 `stdout` 输出标准 JSON 错误信封。
pub fn execute_cli_os<W1, W2>(
    os_args: &[std::ffi::OsString],
    stdout: &mut W1,
    stderr: &mut W2,
) -> ExitCode
where
    W1: Write,
    W2: Write,
{
    let mut utf8_args = Vec::with_capacity(os_args.len());
    for (idx, os_arg) in os_args.iter().enumerate() {
        match os_arg.to_str() {
            Some(s) => utf8_args.push(s.to_owned()),
            None => {
                let err =
                    CliError::usage(format!("第 {} 个命令行参数不是有效的 UTF-8 编码", idx + 1));
                let _ = write_error(stdout, stderr, detect_json_mode_os(os_args), &err);
                return err.exit_code;
            }
        }
    }
    execute_cli(&utf8_args, stdout, stderr)
}

/// 执行一次完整的命令行调用，并将结果写入提供的 `stdout` / `stderr`，返回确定性 `ExitCode`。
pub fn execute_cli<W1, W2>(args: &[String], stdout: &mut W1, stderr: &mut W2) -> ExitCode
where
    W1: Write,
    W2: Write,
{
    let parsed = match parse_cli_args(args) {
        Ok(inv) => inv,
        Err(err) => {
            let _ = write_error(stdout, stderr, detect_json_mode(args), &err);
            return err.exit_code;
        }
    };

    let effective_json = parsed.global.json;
    let quiet = parsed.global.quiet;

    match run_command(&parsed, stdout, effective_json, quiet) {
        Ok(()) => ExitCode::Success,
        Err(err) => {
            let _ = write_error(stdout, stderr, effective_json, &err);
            err.exit_code
        }
    }
}

fn run_command<W>(
    inv: &ParsedInvocation,
    stdout: &mut W,
    json_mode: bool,
    quiet: bool,
) -> Result<(), CliError>
where
    W: Write,
{
    // 若全局显式传入了预算参数，首先向 Core 应用并校验
    if let Some(ref budget) = inv.global.memory_budget {
        budget.apply_to_core()?;
    }

    match &inv.command {
        Command::Help(topic) => {
            let text = render_help(*topic);
            if json_mode {
                #[derive(serde::Serialize)]
                struct HelpPayload<'a> {
                    topic: &'a str,
                    help: &'a str,
                }
                let topic_name = match topic {
                    HelpTopic::Root => "nodus",
                    HelpTopic::Version => "nodus version",
                    HelpTopic::Config => "nodus config",
                };
                write_success(
                    stdout,
                    true,
                    quiet,
                    None,
                    &HelpPayload {
                        topic: topic_name,
                        help: text,
                    },
                    |_, _| String::new(),
                )?;
            } else {
                write!(stdout, "{text}")
                    .and_then(|()| stdout.flush())
                    .map_err(|e| CliError::from_core_error("help-output", e.into()))?;
            }
            Ok(())
        }
        Command::Version => {
            let report = version_report();
            write_success(
                stdout,
                json_mode,
                quiet,
                None,
                &report,
                render_version_human,
            )
        }
        Command::ConfigCheck { file, kind } => {
            let report = check_config_file(file, *kind, inv.global.memory_budget.as_ref())?;
            write_success(
                stdout,
                json_mode,
                quiet,
                None,
                &report,
                render_config_check_human,
            )
        }
        Command::ConfigSummary { file, kind } => {
            let report = check_config_file(file, *kind, inv.global.memory_budget.as_ref())?;
            write_success(
                stdout,
                json_mode,
                quiet,
                None,
                &report,
                render_config_summary_human,
            )
        }
        Command::Run {
            config,
            budget,
            log_dir,
            state_dir,
            enable_tun,
        } => {
            // L0 工程边界：先对显式预算、私有目录权限和主配置文件执行真实 Core 校验，
            // 确保非法预算、权限过宽目录或错误配置按各自退出码（2 / 5 / 3）拦截；
            // 前置核验全部通过后，返回守护进程循环将在 L1 阶段启用的 Unsupported (7)。
            budget.apply_to_core()?;
            if let Some(dir) = log_dir {
                verify_private_directory(dir)?;
            }
            if let Some(dir) = state_dir {
                verify_private_directory(dir)?;
            }
            let _ = check_config_file(config, ConfigKind::Main, Some(budget))?;
            let stage_note = if *enable_tun { "L2 (Linux TUN)" } else { "L1" };
            Err(CliError::unsupported(
                "daemon-run",
                format!(
                    "配置与显式预算 ({} B) 校验通过；常驻守护进程与控制 Socket 属于阶段 {stage_note} 待实现能力",
                    budget.memory.bytes_u64()
                ),
            ))
        }
        Command::PlannedStageCommand {
            command_path,
            stage,
            secret_files_to_verify,
            secret_dirs_to_verify,
        } => {
            // 先执行密钥文件 0600 与私有目录 0700 权限核验（若权限过宽则直接返回退出码 5）
            for secret_file in secret_files_to_verify {
                let _ = open_verified_secret_file(secret_file)?;
            }
            for secret_dir in secret_dirs_to_verify {
                let _ = verify_private_directory(secret_dir)?;
            }
            Err(CliError::unsupported(
                "command-dispatch",
                format!("命令 `nodus {command_path}` 属于阶段 {stage} 能力，当前 L0 阶段尚未启用"),
            ))
        }
    }
}

fn render_version_human(report: &VersionReport, quiet: bool) -> String {
    if quiet {
        return format!("{} {}\n", report.cli_name, report.cli_version);
    }
    let commit = report.core_source_commit.unwrap_or("unknown");
    let dirty = match report.core_source_dirty {
        Some(true) => " (dirty)",
        Some(false) => " (clean)",
        None => "",
    };
    format!(
        "Nodus-CLI:       {} (stage {})\n\
         Nodus-Core:      {} (ABI v{}, commit {}{})\n\
         Core Build ID:   {}\n\
         Target / Arch:   {} ({}, {})\n\
         Capabilities:    0x{:016x} [offline-check={}, budget={}, secret-guard={}]\n",
        report.cli_version,
        report.stage,
        report.core_version,
        report.core_abi_version,
        commit,
        dirty,
        report.core_build_id,
        report.target_triple,
        report.architecture,
        report.build_profile,
        report.core_capability_bits,
        report.capabilities.offline_config_check,
        report.capabilities.explicit_memory_budget,
        report.capabilities.secret_file_isolation,
    )
}

fn render_config_check_human(report: &ConfigCheckReport, quiet: bool) -> String {
    if quiet {
        return "OK\n".to_string();
    }
    if let Some(ref s) = report.main_summary {
        format!(
            "配置校验通过 ({}): {}\n  模式: {:?} | 监听端口: {} | 节点数: {} | 规则数: {} | 规则集: {} | DNS: {}\n",
            report.kind.as_str(),
            report.path,
            s.mode,
            s.port,
            s.node_count,
            s.rule_count,
            s.rule_provider_count,
            if s.dns_enabled { "启用" } else { "关闭" }
        )
    } else if let Some(ref g) = report.gateway_summary {
        format!(
            "网关配置校验通过 ({}): {}\n  角色: {:?} | 设备数: {} | MTU: {} | DNS 端点数: {}\n",
            report.kind.as_str(),
            report.path,
            g.role,
            g.device_count,
            g.mtu,
            g.dns_endpoint_count
        )
    } else {
        format!("配置校验通过 ({}): {}\n", report.kind.as_str(), report.path)
    }
}

fn render_config_summary_human(report: &ConfigCheckReport, quiet: bool) -> String {
    if let Some(ref s) = report.main_summary {
        if quiet {
            return format!(
                "mode={:?} port={} nodes={} rules={} providers={}\n",
                s.mode, s.port, s.node_count, s.rule_count, s.rule_provider_count
            );
        }
        let mut out = format!(
            "配置摘要: {}\n\
             ----------------------------------------\n\
             路由模式:           {:?}\n\
             混合监听端口:       {}\n\
             系统代理:           {} (端口 {})\n\
             局域网共享:         {} (端口 {})\n\
             出站节点数:         {}\n\
             内联规则数:         {}\n\
             远程规则集数:       {}\n\
             内置 DNS:           {} (超时 {}s)\n\
             GeoIP 数据库:       {}\n\
             TUN 接管意图:       {} (DNS 劫持 {})\n",
            report.path,
            s.mode,
            s.port,
            if s.system_proxy_enabled {
                "启用"
            } else {
                "关闭"
            },
            s.system_proxy_port,
            if s.lan_share_enabled {
                "启用"
            } else {
                "关闭"
            },
            s.lan_share_port,
            s.node_count,
            s.rule_count,
            s.rule_provider_count,
            if s.dns_enabled { "启用" } else { "关闭" },
            s.dns_timeout_seconds,
            if s.geoip_enabled { "启用" } else { "关闭" },
            if s.tun_requested { "启用" } else { "关闭" },
            if s.tun_dns_hijack_enabled {
                "启用"
            } else {
                "关闭"
            },
        );
        if let Some(warn) = s.rewrite_warning {
            out.push_str(&format!("复写提示:           {warn:?}\n"));
        }
        out
    } else {
        render_config_check_human(report, quiet)
    }
}

/// 帮助文本（遵循《命令行与输出契约》第一.1 & 第一.2 条：只列出当前已实现的可用命令，并明确说明各参数适用场景）。
pub fn render_help(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => {
            "Nodus CLI (nodus) — Linux 节点部署与运维\n\
             \n\
             用法:\n\
               nodus [全局选项] <子命令> [子命令选项] [参数]\n\
             \n\
             当前可用子命令 (阶段 L0):\n\
               config check <FILE> [--kind <main|gateway|mesh|server>]\n\
                                 [离线] 严格校验配置文件语法与语义，定位行列号与错误码\n\
               config summary <FILE> [--kind <main|gateway|mesh|server>]\n\
                                 [离线] 输出无凭据只读配置摘要（节点数、规则数、监听端口、DNS 等）\n\
               version           [离线] 查看 CLI 版本、锁定 Core 版本、构建指纹与平台能力矩阵\n\
               help [version|config] [离线] 显示帮助信息\n\
             \n\
             全局选项:\n\
               --config <FILE>           指定配置文件路径（适用于离线 config check/summary 及守护启动）\n\
               --socket <PATH>           指定本地控制 Unix Domain Socket 路径（适用于在线 IPC 命令；显式无效时直接报错）\n\
               --memory-budget <SIZE>    显式设置 Core 根内存预算（如 64M、256M；守护启动必填，离线校验可选）\n\
               --connection-limit <N>    接受连接上限正整数（需配合 --memory-budget，活动连接限额属 L1）\n\
               --timeout <DURATION>      本地 IPC 控制请求超时（默认 10s，支持 ms/s/m）\n\
               --json                    以稳定机器可读 UTF-8 JSON 格式输出结果或错误\n\
               -q, --quiet               仅输出必要结果或错误（与 --verbose 互斥）\n\
               -v, --verbose             输出附加阶段与诊断摘要，绝不输出密钥（与 --quiet 互斥）\n\
               -h, --help [version|config] 显示全局或指定主题的帮助信息\n\
               -V, --version             显示版本信息（顶层选项）\n\
             \n\
             退出码契约:\n\
               0  成功                   4  守护进程未运行或本地 IPC 不可达\n\
               1  Core 业务/运行错误     5  权限不足或密钥文件权限过宽 (非 0600)\n\
               2  命令行参数或用法错误   6  超时或操作被取消\n\
               3  配置文件校验失败       7  当前阶段或平台不支持该能力 (Unsupported)\n\
                                         8  操作可能已提交但确认丢失 (UnconfirmedOutcome)\n"
        }
        HelpTopic::Version => {
            "用法: nodus version [--json] [-q|--quiet]\n\
             \n\
             说明:\n\
               [离线] 输出 Nodus-CLI 版本、锁定的 Nodus-Core 版本、ABI 版本、构建指纹与当前阶段能力矩阵。\n"
        }
        HelpTopic::Config => {
            "用法:\n\
               nodus config check <FILE> [--kind <main|gateway|mesh|server>] [--memory-budget <SIZE>] [--connection-limit <N>] [--json]\n\
               nodus config summary <FILE> [--kind <main|gateway|mesh|server>] [--memory-budget <SIZE>] [--connection-limit <N>] [--json]\n\
             \n\
             说明:\n\
               check    [离线] 调用 Core 严格解析并校验配置；失败返回退出码 3 及精确字段、行列号与 Core 六位错误码。\n\
               summary  [离线] 调用 Core 校验配置并输出只读无凭据摘要（路由模式、端口、节点数、规则数、DNS 状态）。\n"
        }
    }
}
