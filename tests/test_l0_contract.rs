//! 阶段 L0（工程骨架与 Core 集成边界）集成测试套件。
//!
//! 覆盖《Linux 构建与验证》与 L0-01～L0-04 的全部可观察契约：
//! 1. L0-01 / L0-02：通过实际 `nodus` 二进制入口核对帮助、版本、参数错误、离线 `config check` / `config summary`、
//!    stdout/stderr 分离、退出码映射与 `--json` 机器输出结构；保留 Core 原始六位错误代码；
//! 2. L0-03：验证密钥文件 `0600` 权限检查（拒绝 `0644` / `0640` / 符号链接 / 空文件）、私有目录 `0700` 检查、
//!    禁止命令行直接传凭据标志（返回退出码 `5`）、受控环境变量读取与 `Zeroizing` 脱敏保证；
//! 3. L0-04：验证显式内存预算（`--memory-budget`）与连接上限（`--connection-limit`）解析、
//!    拒绝 0 / 负数 / 非法单位 / 溢出，并验证预算真实交付到 `nodus_core` 根池及超限行为。

use nodus_cli::{
    budget::{BudgetSource, ConnectionBudget, MemoryBudget},
    cli::{execute_cli, parse_cli_args},
    output::{ExitCode, JSON_SCHEMA_VERSION, JsonErrorEnvelope, JsonSuccessEnvelope},
    security::{
        ControlledSecretEnv, ManagedSecretString, open_verified_secret_file,
        read_secret_file_string, read_secret_from_env, scrub_child_command_env,
        verify_private_directory,
    },
};
use nodus_core::error::ErrorCode;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("nodus-cli-test-{prefix}-{pid}-{id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("set temp dir 0700");
        }
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_in_memory(args: &[&str]) -> (ExitCode, String, String) {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = execute_cli(&owned, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).expect("stdout valid utf8"),
        String::from_utf8(err).expect("stderr valid utf8"),
    )
}

#[test]
fn test_l0_01_and_02_version_and_help_contract() {
    // 1. 人类可读帮助只列出当前阶段已实现的命令，不欺骗性列出未实现命令为已可用
    let (code, stdout, stderr) = run_in_memory(&["--help"]);
    assert_eq!(code, ExitCode::Success);
    assert!(stderr.is_empty());
    assert!(stdout.contains("config check"));
    assert!(stdout.contains("config summary"));
    assert!(stdout.contains("version"));

    // 2. JSON 模式下的 version 输出遵循固定信封结构
    let (code, stdout, stderr) = run_in_memory(&["version", "--json"]);
    assert_eq!(code, ExitCode::Success);
    assert!(stderr.is_empty());
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid version json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["schema_version"], JSON_SCHEMA_VERSION);
    // 离线命令未关联运行实例修订代次时，revision 为 null，严格区分于 0
    assert!(parsed["revision"].is_null());
    assert_eq!(parsed["data"]["cli_name"], "nodus-cli");
    assert_eq!(parsed["data"]["core_version"], "1.0.0-dev");
    assert_eq!(parsed["data"]["stage"], "L0");
    assert_eq!(parsed["data"]["capabilities"]["offline_config_check"], true);
    assert_eq!(
        parsed["data"]["capabilities"]["explicit_memory_budget"],
        true
    );
}

#[test]
fn test_l0_02_json_mode_parameter_errors_on_stdout() {
    // 解析阶段识别出 `--json` 后，即使存在未知参数或冲突参数，也必须在 stdout 输出结构化 JSON 错误且不污染 stdout
    let (code, stdout, stderr) = run_in_memory(&["--json", "--quiet", "--verbose", "version"]);
    assert_eq!(code, ExitCode::UsageError);
    assert!(stderr.is_empty());
    let env: JsonErrorEnvelope = serde_json::from_str(&stdout).expect("valid error json");
    assert!(!env.ok);
    assert_eq!(env.schema_version, JSON_SCHEMA_VERSION);
    assert_eq!(env.error.exit_code, ExitCode::UsageError.as_u8());
    assert_eq!(env.error.name, "UsageError");
    assert!(env.error.code.is_none());

    // 未知子命令在人类模式下输出到 stderr，stdout 保持为空
    let (code, stdout, stderr) = run_in_memory(&["nonexistent-subcmd"]);
    assert_eq!(code, ExitCode::UsageError);
    assert!(stdout.is_empty());
    assert!(stderr.contains("未知的子命令"));
}

#[test]
fn test_l0_01_and_02_offline_config_check_and_summary_preserves_core_codes() {
    let dir = TempDirGuard::new("config");
    let valid_path = dir.path().join("valid.yaml");
    fs::write(
        &valid_path,
        "mode: rule\nport: 7890\ndns:\n  enable: true\n  server:\n    - https://1.1.1.1/dns-query\nrules:\n  - final,direct\n",
    )
    .expect("write valid config");

    // 1. 有效配置校验通过（JSON 模式）
    let valid_str = valid_path.to_str().unwrap();
    let (code, stdout, stderr) = run_in_memory(&[
        "config",
        "check",
        valid_str,
        "--memory-budget",
        "64M",
        "--json",
    ]);
    assert_eq!(code, ExitCode::Success);
    assert!(stderr.is_empty());
    let ok_env: JsonSuccessEnvelope<serde_json::Value> =
        serde_json::from_str(&stdout).expect("valid config check json");
    assert!(ok_env.ok);
    assert_eq!(ok_env.data["valid"], true);
    assert_eq!(ok_env.data["main_summary"]["port"], 7890);
    assert_eq!(ok_env.data["main_summary"]["rule_count"], 1);
    assert_eq!(ok_env.data["main_summary"]["node_count"], 0);

    // 2. 有效配置 summary（人类可读模式）
    let (code, stdout, stderr) = run_in_memory(&["config", "summary", valid_str]);
    assert_eq!(code, ExitCode::Success);
    assert!(stderr.is_empty());
    assert!(stdout.contains("7890"));
    assert!(stdout.contains("内联规则数"));

    // 3. 无效配置（缺少 final 规则且监听端口低于 1054）：必须返回退出码 3 (ConfigInvalid)，
    // 并完整保留 Core 原始六位错误代码及行列号定位
    let invalid_path = dir.path().join("invalid.yaml");
    fs::write(
        &invalid_path,
        "port: 80\nrules:\n  - domain,example.com,direct\n",
    )
    .expect("write invalid config");
    let invalid_str = invalid_path.to_str().unwrap();

    let (code, stdout, stderr) = run_in_memory(&["config", "check", invalid_str, "--json"]);
    assert_eq!(code, ExitCode::ConfigInvalid);
    assert!(stderr.is_empty());
    let err_env: JsonErrorEnvelope =
        serde_json::from_str(&stdout).expect("valid config error json");
    assert!(!err_env.ok);
    assert_eq!(err_env.error.exit_code, ExitCode::ConfigInvalid.as_u8());
    assert_eq!(
        err_env.error.code,
        Some(ErrorCode::ConfigListenPortRange.value())
    );
    assert!(err_env.error.issues.len() >= 2);
    assert_eq!(err_env.error.issues[0].field, "port");
    assert_eq!(
        err_env.error.issues[0].code,
        ErrorCode::ConfigListenPortRange.value()
    );
    assert_eq!(err_env.error.issues[0].line, Some(1));
}

#[test]
fn test_l0_03_secret_file_permissions_and_cli_redline() {
    // 1. 禁止在命令行直接传敏感凭据标志，返回退出码 5 (PermissionDenied)
    for flag in [
        "--auth-key=tskey-123",
        "--private-key",
        "--admin-token=secret",
        "--psk=123",
    ] {
        let (code, stdout, _stderr) = run_in_memory(&["--json", flag, "version"]);
        assert_eq!(code, ExitCode::PermissionDenied);
        let env: JsonErrorEnvelope = serde_json::from_str(&stdout).expect("secret reject json");
        assert_eq!(env.error.name, "SecretPolicyRejected");
        // 错误回显绝不能包含传入的秘密值 `tskey-123` 或 `secret`
        assert!(!stdout.contains("tskey-123"));
    }

    let dir = TempDirGuard::new("secrets");
    let key_path = dir.path().join("node.key");
    fs::write(&key_path, "super-secret-private-key-material\n").expect("write secret file");

    // 2. 权限过宽（0644）的密钥文件必须被拒绝（退出码 5）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        let err = open_verified_secret_file(&key_path).expect_err("0644 must be rejected");
        assert_eq!(err.exit_code, ExitCode::PermissionDenied);

        // 0640（组可读）同样必须拒绝
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).expect("chmod 0640");
        let err = open_verified_secret_file(&key_path).expect_err("0640 must be rejected");
        assert_eq!(err.exit_code, ExitCode::PermissionDenied);

        // 0700（带可执行位）对普通密钥文件同样拒绝
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        let err = open_verified_secret_file(&key_path).expect_err("0700 file must be rejected");
        assert_eq!(err.exit_code, ExitCode::PermissionDenied);

        // 设置为 0600 后允许安全读取，且返回 ManagedSecretString 的 Debug/Display 严格脱敏
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        let secret = read_secret_file_string(&key_path).expect("0600 file must succeed");
        assert_eq!(secret.expose_str(), "super-secret-private-key-material");
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "\"[REDACTED]\"");

        // 符号链接即使指向 0600 文件也必须被 O_NOFOLLOW 拒绝
        let symlink_path = dir.path().join("link.key");
        std::os::unix::fs::symlink(&key_path, &symlink_path).expect("create symlink");
        let sym_err =
            open_verified_secret_file(&symlink_path).expect_err("symlink secret must fail");
        assert_eq!(sym_err.exit_code, ExitCode::PermissionDenied);

        // 私有目录权限检查：0755 目录必须被拒绝，0700 目录通过
        let sub_dir = dir.path().join("keys_dir");
        fs::create_dir(&sub_dir).expect("create keys_dir");
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
        let dir_err = verify_private_directory(&sub_dir).expect_err("0755 dir must fail");
        assert_eq!(dir_err.exit_code, ExitCode::PermissionDenied);

        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        verify_private_directory(&sub_dir).expect("0700 dir must pass");
    }
}

#[test]
fn test_l0_03_controlled_env_and_child_scrub() {
    let secret = ManagedSecretString::new("sensitive-token-value".to_string());
    assert!(!format!("{secret:?}").contains("sensitive-token-value"));
    assert!(!format!("{secret}").contains("sensitive-token-value"));

    // 未设置的环境变量读取失败且不泄露信息
    let err =
        read_secret_from_env(ControlledSecretEnv::AdminToken).expect_err("unset env should fail");
    assert_eq!(err.exit_code, ExitCode::PermissionDenied);

    let mut cmd = ProcessCommand::new("true");
    scrub_child_command_env(&mut cmd);
}

#[test]
fn test_l0_04_explicit_budget_parsing_and_core_enforcement() {
    // 1. 合法预算解析
    let b64m = MemoryBudget::parse("64M", BudgetSource::CliFlag).expect("64M valid");
    assert_eq!(b64m.bytes_u64(), 64 * 1024 * 1024);
    assert_eq!(b64m.unit, "bytes");

    let b256mib = MemoryBudget::parse("256MiB", BudgetSource::CliFlag).expect("256MiB valid");
    assert_eq!(b256mib.bytes_u64(), 256 * 1024 * 1024);

    // 2. 缺失、0、负数、未知单位或算术溢出必须失败
    for invalid in ["", "0", "0M", "-64M", "abc", "64T", "18446744073709551615G"] {
        let err = MemoryBudget::parse(invalid, BudgetSource::CliFlag)
            .expect_err(&format!("budget `{invalid}` must fail"));
        assert_eq!(err.exit_code, ExitCode::UsageError);
    }

    // 3. 连接数仅按正整数和平台范围校验，涵盖范围的上下端。
    for count in ["1".to_string(), usize::MAX.to_string()] {
        let budget = ConnectionBudget::parse(&count, BudgetSource::CliFlag).expect("数量在范围内");
        assert_eq!(budget.max_connections.to_string(), count);
    }
    for count in ["0", "-1", "18446744073709551616"] {
        let error = ConnectionBudget::parse(count, BudgetSource::CliFlag).unwrap_err();
        assert_eq!(error.exit_code, ExitCode::UsageError);
    }

    // 4. `nodus run` 缺失 `--memory-budget` 时明确返回错误（退出码 2）
    let dir = TempDirGuard::new("budget");
    let cfg_path = dir.path().join("router.yaml");
    fs::write(&cfg_path, "rules:\n  - final,direct\n").expect("write cfg");
    let cfg_str = cfg_path.to_str().unwrap();

    let (code, stdout, _stderr) = run_in_memory(&["run", "--config", cfg_str, "--json"]);
    assert_eq!(code, ExitCode::UsageError);
    let env: JsonErrorEnvelope = serde_json::from_str(&stdout).expect("missing budget json");
    assert_eq!(env.error.name, "InvalidBudget");

    // 5. 让独立进程接受 16B 根预算，再读取超出预算的有效配置。
    // 核对配置阶段的 Core 原码和配置问题。
    let bin = env!("CARGO_BIN_EXE_nodus");
    let tiny_out = ProcessCommand::new(bin)
        .args([
            "config",
            "check",
            cfg_str,
            "--memory-budget",
            "16B",
            "--json",
        ])
        .output()
        .expect("spawn nodus with 16B budget");
    assert!(tiny_out.stderr.is_empty());
    let tiny_err: JsonErrorEnvelope =
        serde_json::from_slice(&tiny_out.stdout).expect("budget exceeded json");
    assert_eq!(tiny_out.status.code(), Some(3));
    assert!(!tiny_err.ok);
    assert_eq!(tiny_err.error.exit_code, 3);
    assert_eq!(tiny_err.error.phase, "config-check");
    let code = ErrorCode::BudgetPoolExceeded.value();
    assert_eq!(tiny_err.error.code, Some(code));
    let issue = tiny_err
        .error
        .issues
        .first()
        .expect("Core configuration issue");
    assert_eq!(issue.code, code);
    assert_eq!(issue.field, "$file");

    // 传入充足预算（64M）时真实子进程校验成功
    let ok_out = ProcessCommand::new(bin)
        .args([
            "config",
            "check",
            cfg_str,
            "--memory-budget",
            "64M",
            "--json",
        ])
        .output()
        .expect("spawn nodus with 64M budget");
    assert_eq!(ok_out.status.code(), Some(0));
}

#[test]
fn test_real_binary_process_invocation() {
    let bin = env!("CARGO_BIN_EXE_nodus");
    let output = ProcessCommand::new(bin)
        .args(["version", "--json"])
        .output()
        .expect("spawn nodus binary");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse binary stdout json");
    assert_eq!(json["ok"], true);
    assert_eq!(json["data"]["core_version"], "1.0.0-dev");

    // 验证未实现阶段子命令在真实进程入口返回退出码 7 (Unsupported) 及 Core 错误码 100023
    let unsupported = ProcessCommand::new(bin)
        .args(["status", "--json"])
        .output()
        .expect("spawn nodus status");
    assert_eq!(unsupported.status.code(), Some(7));
    let err_json: JsonErrorEnvelope =
        serde_json::from_slice(&unsupported.stdout).expect("parse binary error json");
    assert!(!err_json.ok);
    assert_eq!(err_json.error.exit_code, 7);
    assert_eq!(err_json.error.code, Some(ErrorCode::Unsupported.value()));
}

#[cfg(unix)]
#[test]
fn test_cli_l0_01_non_utf8_os_arguments_no_panic_and_preserves_json_envelope() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let bin = env!("CARGO_BIN_EXE_nodus");
    let invalid_arg = OsString::from_vec(vec![0xff, 0xfe, b'x']);

    // 1. 人类可读模式下传入非 UTF-8 参数：不得 panic（退出码 2 而非 101），stdout 为空，stderr 输出用法错误
    let human_out = ProcessCommand::new(bin)
        .arg("version")
        .arg(&invalid_arg)
        .output()
        .expect("spawn nodus with non-utf8 arg in human mode");
    assert_eq!(
        human_out.status.code(),
        Some(ExitCode::UsageError.as_u8() as i32)
    );
    assert!(human_out.stdout.is_empty());
    let stderr_str = String::from_utf8_lossy(&human_out.stderr);
    assert!(stderr_str.contains("UTF-8"));
    assert!(!stderr_str.contains("panicked"));

    // 2. JSON 模式下传入非 UTF-8 参数：在 stdout 输出合法 JSON 错误信封，stderr 为空，退出码 2
    let json_out = ProcessCommand::new(bin)
        .arg("--json")
        .arg("version")
        .arg(&invalid_arg)
        .output()
        .expect("spawn nodus with non-utf8 arg in json mode");
    assert_eq!(
        json_out.status.code(),
        Some(ExitCode::UsageError.as_u8() as i32)
    );
    assert!(json_out.stderr.is_empty());
    let err_env: JsonErrorEnvelope =
        serde_json::from_slice(&json_out.stdout).expect("valid json error envelope for non-utf8");
    assert!(!err_env.ok);
    assert_eq!(err_env.schema_version, JSON_SCHEMA_VERSION);
    assert_eq!(err_env.error.exit_code, ExitCode::UsageError.as_u8());
    assert_eq!(err_env.error.name, "UsageError");
}

#[test]
fn test_cli_l0_02_gateway_mesh_server_config_verifies_opened_file() {
    let dir = TempDirGuard::new("kind-verify");

    // 1. 正常读取并校验 mesh JSON 配置
    let mesh_path = dir.path().join("mesh.json");
    fs::write(
        &mesh_path,
        r#"{"schema_version":1,"network_kind":"headscale","control_url":"https://hs.example.com","hostname":"node-1"}"#,
    )
    .expect("write mesh json");
    let mesh_str = mesh_path.to_str().unwrap();

    let (code, stdout, stderr) =
        run_in_memory(&["config", "summary", mesh_str, "--kind", "mesh", "--json"]);
    assert_eq!(code, ExitCode::Success);
    assert!(stderr.is_empty());
    let ok_env: JsonSuccessEnvelope<serde_json::Value> =
        serde_json::from_str(&stdout).expect("valid mesh config summary json");
    assert!(ok_env.ok);
    assert_eq!(ok_env.data["kind"], "mesh");
    assert_eq!(ok_env.data["mesh_network_kind"], "Headscale");

    // 2. 正常读取并校验 gateway / server JSON 配置（使用 RFC 7748 公开测试向量密钥）
    let gw_path = dir.path().join("gateway.json");
    fs::write(
        &gw_path,
        r#"{"schema_version":1,"transport":"wireguard","role":"server","endpoint":"127.0.0.1:51820","identity":{"public_key":"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=","private_key":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="},"devices":[{"id":"device-1","public_key":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","addresses":["10.90.0.2","fd90::2"],"destinations":["0.0.0.0/0","::/0"]}],"mtu":1500,"dns_endpoints":["10.90.0.1:53","[fd90::1]:53"]}"#,
    )
    .expect("write gateway json");
    let gw_str = gw_path.to_str().unwrap();
    for kind in ["gateway", "server"] {
        let (g_code, g_stdout, g_stderr) = run_in_memory(&[
            "config",
            "summary",
            gw_str,
            "--kind",
            kind,
            "--memory-budget",
            "64M",
            "--json",
        ]);
        assert_eq!(g_code, ExitCode::Success);
        assert!(g_stderr.is_empty());
        let g_env: JsonSuccessEnvelope<serde_json::Value> =
            serde_json::from_str(&g_stdout).expect("valid gateway summary json");
        assert!(g_env.ok);
        assert_eq!(g_env.data["kind"], kind);
        assert_eq!(g_env.data["gateway_summary"]["device_count"], 1);
    }

    // 3. 拒绝符号链接配置文件（gateway / mesh / server 均在打开前后严格拒绝符号链接与非普通文件）
    #[cfg(unix)]
    {
        let link_path = dir.path().join("mesh-link.json");
        std::os::unix::fs::symlink(&mesh_path, &link_path).expect("create config symlink");
        let link_str = link_path.to_str().unwrap();

        for kind in ["mesh", "gateway", "server"] {
            let (l_code, l_stdout, l_stderr) =
                run_in_memory(&["config", "check", link_str, "--kind", kind, "--json"]);
            assert_ne!(l_code, ExitCode::Success);
            assert!(l_stderr.is_empty());
            let err_env: JsonErrorEnvelope =
                serde_json::from_str(&l_stdout).expect("symlink reject json");
            assert!(!err_env.ok);
        }

        // 4. 拒绝目录或 FIFO 等非普通文件且不阻塞
        let dir_str = dir.path().to_str().unwrap();
        let (d_code, d_stdout, _d_stderr) =
            run_in_memory(&["config", "check", dir_str, "--kind", "gateway", "--json"]);
        assert_ne!(d_code, ExitCode::Success);
        let d_err: JsonErrorEnvelope = serde_json::from_str(&d_stdout).expect("dir reject json");
        assert!(!d_err.ok);

        let fifo_path = dir.path().join("fifo.json");
        nix::unistd::mkfifo(
            &fifo_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("create fifo");
        let fifo_str = fifo_path.to_str().unwrap();
        let (f_code, f_stdout, _f_stderr) =
            run_in_memory(&["config", "check", fifo_str, "--kind", "gateway", "--json"]);
        assert_ne!(f_code, ExitCode::Success);
        let f_err: JsonErrorEnvelope = serde_json::from_str(&f_stdout).expect("fifo reject json");
        assert!(!f_err.ok);
    }
}

#[test]
fn test_cli_l0_04_terminator_and_shortcut_json_boundary_consistency() {
    let bin = env!("CARGO_BIN_EXE_nodus");
    let dir = TempDirGuard::new("terminator");
    let valid_cfg = dir.path().join("valid.yaml");
    fs::write(&valid_cfg, "rules:\n  - final,direct\n").expect("write valid cfg");
    let valid_str = valid_cfg.to_str().unwrap();

    // 1. 帮助与版本快捷项不论与 `--json` 的先后顺序如何，均输出 JSON 信封
    for args in [
        &["--help", "--json"][..],
        &["--json", "--help"][..],
        &["--version", "--json"][..],
        &["--json", "--version"][..],
        &["config", "--help", "--json"][..],
        &["config", "check", "--help", "--json"][..],
        &["version", "--help", "--json"][..],
    ] {
        let out = ProcessCommand::new(bin)
            .args(args)
            .output()
            .expect("spawn shortcut with json");
        assert_eq!(out.status.code(), Some(0), "args={args:?}");
        assert!(out.stderr.is_empty(), "args={args:?}");
        let parsed: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("valid shortcut json");
        assert_eq!(parsed["ok"], true, "args={args:?}");
        assert_eq!(parsed["schema_version"], JSON_SCHEMA_VERSION);
    }

    for args in [
        &["version", "--port", "--json"][..],
        &["config", "--kind", "--json"][..],
        &["config", "unknown", "--kind", "--json"][..],
        &["version", "-V", "--json"][..],
        &["--version", "config", "check", "--kind", "--json"][..],
        &["--json", "help", "--", "--help"][..],
        &["--json", "version", "--help", "--", "--json"][..],
    ] {
        let out = ProcessCommand::new(bin).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args={args:?}");
        assert!(out.stderr.is_empty(), "args={args:?}");
        let env: JsonErrorEnvelope = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(env.error.name, "UsageError", "args={args:?}");
        assert_eq!(env.error.exit_code, 2);
    }

    let credentials = ProcessCommand::new(bin)
        .args(["version", "--port", "--token=fixture", "--json"])
        .output()
        .unwrap();
    assert_eq!(credentials.status.code(), Some(5));
    assert!(credentials.stderr.is_empty());
    let env: JsonErrorEnvelope = serde_json::from_slice(&credentials.stdout).unwrap();
    assert_eq!(env.error.name, "SecretPolicyRejected");
    assert_eq!(env.error.exit_code, 5);
    assert!(!String::from_utf8_lossy(&credentials.stdout).contains("fixture"));

    for literal in ["--json", "--token"] {
        fs::copy(&valid_cfg, dir.path().join(literal)).unwrap();
        for json in [false, true] {
            let mut process = ProcessCommand::new(bin);
            process
                .current_dir(dir.path())
                .args(["config", "check", "--config", literal]);
            if json {
                process.arg("--json");
            }
            let out = process.output().unwrap();
            assert_eq!(out.status.code(), Some(0));
            assert!(out.stderr.is_empty());
            if json {
                let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(envelope["ok"], true);
            } else {
                assert!(String::from_utf8_lossy(&out.stdout).contains("配置校验通过"));
            }
        }
    }

    let missing = ProcessCommand::new(bin)
        .args(["config", "check", "--config", "--", "--json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("缺少参数值"));

    // 2. 参数终止符 `--` 之后的 `--json` 只作为字面位置参数，不触发 JSON 输出模式（无论成功还是失败）
    let out_ok = ProcessCommand::new(bin)
        .current_dir(dir.path())
        .args(["config", "check", "--", "--json"])
        .output()
        .expect("spawn config check with literal --json after --");
    assert_eq!(out_ok.status.code(), Some(0));
    assert!(out_ok.stderr.is_empty());
    let out_ok_str = String::from_utf8_lossy(&out_ok.stdout);
    // 应当是人类可读模式输出，而非 JSON 信封
    assert!(out_ok_str.contains("配置校验通过"));
    assert!(!out_ok_str.trim_start().starts_with('{'));

    // 当 `--` 之后的多余字面参数包含 `--json` 导致解析错误时，同样保持人类可读错误模式（stderr 输出，stdout 为空）
    let out_err = ProcessCommand::new(bin)
        .args(["config", "check", valid_str, "--", "--json"])
        .output()
        .expect("spawn config check with extra literal --json after --");
    assert_eq!(
        out_err.status.code(),
        Some(ExitCode::UsageError.as_u8() as i32)
    );
    assert!(out_err.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out_err.stderr).contains("多余的位置参数"));
}

#[test]
fn test_cli_l0_04_help_topic_suffix_validation() {
    let bin = env!("CARGO_BIN_EXE_nodus");

    for (args, topic) in [
        (&["--help", "version", "--json"][..], "nodus version"),
        (&["--json", "--help", "--", "version"][..], "nodus version"),
        (&["--json", "-h", "config", "--"][..], "nodus config"),
        (&["help", "config", "--json"][..], "nodus config"),
        (&["config", "--help", "--json"][..], "nodus config"),
        (&["--help", "help", "--json"][..], "nodus"),
    ] {
        let out = ProcessCommand::new(bin).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "args={args:?}");
        assert!(out.stderr.is_empty(), "args={args:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(envelope["ok"], true, "args={args:?}");
        assert_eq!(envelope["data"]["topic"], topic, "args={args:?}");
    }

    for args in [
        &["--json", "--help", "version", "--", "extra"][..],
        &["--json", "version", "--help", "--", "extra"][..],
        &["--json", "--help", "--", "version", "--help"][..],
        &["--json", "--help", "version", "--", "--json"][..],
        &["--json", "help", "version", "--", "extra"][..],
        &["--json", "-h", "config", "--", "extra"][..],
        &["--json", "config", "--help", "--", "extra"][..],
        &["--help", "config", "check", "--kind", "--json"][..],
    ] {
        let out = ProcessCommand::new(bin).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args={args:?}");
        assert!(out.stderr.is_empty(), "args={args:?}");
        let envelope: JsonErrorEnvelope = serde_json::from_slice(&out.stdout).unwrap();
        assert!(!envelope.ok);
        assert_eq!(envelope.schema_version, JSON_SCHEMA_VERSION);
        assert_eq!(envelope.error.name, "UsageError");
        assert_eq!(envelope.error.exit_code, 2);
    }

    let human = ProcessCommand::new(bin)
        .args(["--help", "version", "--", "--json"])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(2));
    assert!(human.stdout.is_empty());
    assert!(String::from_utf8_lossy(&human.stderr).contains("--json"));
}

#[test]
fn test_cli_l0_06_and_07_budget_positions_and_final_values() {
    let bin = env!("CARGO_BIN_EXE_nodus");
    let dir = TempDirGuard::new("mixed-budget");
    let cfg = dir.path().join("router.yaml");
    fs::write(&cfg, "rules:\n  - final,direct\n").unwrap();
    let cfg = cfg.to_str().unwrap();

    for (command, success) in [
        (&["config", "check"][..], 0),
        (&["config", "summary"][..], 0),
        (&["run"][..], 7),
        (&["daemon"][..], 7),
    ] {
        for (before, after, count, exit) in [
            (
                &["--connection-limit", "1000000"][..],
                &["--memory-budget=64MiB"][..],
                Some(1_000_000),
                success,
            ),
            (
                &["--memory-budget", "64MiB"][..],
                &["--connection-limit=1000000"][..],
                Some(1_000_000),
                success,
            ),
            (
                &["--memory-budget=0", "--connection-limit=1000000"][..],
                &["--memory-budget", "64MiB"][..],
                Some(1_000_000),
                success,
            ),
            (
                &["--memory-budget=64MiB", "--connection-limit=0"][..],
                &["--connection-limit", "3", "--connection-limit=1000000"][..],
                Some(1_000_000),
                success,
            ),
            (
                &["--memory-budget=64MiB", "--connection-limit=1"][..],
                &["--connection-limit", "0"][..],
                None,
                2,
            ),
            (
                &["--memory-budget=64MiB"][..],
                &["--memory-budget", "0"][..],
                None,
                2,
            ),
            (&["--connection-limit=1"][..], &[][..], None, 2),
        ] {
            let args: Vec<_> = [before, command, &["--config", cfg], after, &["--json"]].concat();
            let out = ProcessCommand::new(bin).args(&args).output().unwrap();
            assert_eq!(
                out.status.code(),
                Some(exit),
                "args={args:?}, stdout={}",
                String::from_utf8_lossy(&out.stdout)
            );
            assert!(out.stderr.is_empty(), "args={args:?}");
            let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(envelope["ok"], exit == 0);
            if exit != 0 {
                assert_eq!(envelope["error"]["exit_code"], exit);
                if exit == 7 {
                    assert_eq!(envelope["error"]["code"], ErrorCode::Unsupported.value());
                    assert_eq!(envelope["error"]["phase"], "daemon-run");
                } else {
                    assert_eq!(envelope["error"]["name"], "InvalidBudget");
                    assert_eq!(envelope["error"]["phase"], "budget-validate");
                }
            }
            if let Some(count) = count {
                let invocation =
                    parse_cli_args(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                        .unwrap();
                let budget = invocation.global.memory_budget.unwrap();
                assert_eq!(budget.memory.bytes_u64(), 64 * 1024 * 1024);
                assert_eq!(
                    budget.connection_limit.unwrap().max_connections.get(),
                    count
                );
            }
        }
    }
}
