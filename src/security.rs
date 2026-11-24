//! 宿主安全、路径规范化与密钥交付边界（L0-03）。
//!
//! 职责与不变量：
//! 1. 私钥、PSK、Tailscale Auth Key、管理 API Token 及 CA 私钥仅允许从符合权限要求的私有文件（`0600`）
//!    或明确登记的受控环境变量读取；严禁通过命令行参数直接传递秘密原文；
//! 2. 秘密文件与密钥目录必须由当前进程有效 UID（`geteuid()`）所有，拒绝符号链接（`O_NOFOLLOW`），
//!    拒绝组用户或其他用户拥有任何读／写／执行权限（文件 `mode & 0o077 == 0`，目录 `mode & 0o077 == 0`），
//!    并在打开前后核验 `(dev, ino)` 与硬链接数（`nlink == 1`），消除路径替换（TOCTOU）窗口；
//! 3. 所有读入的秘密材料均由 `Zeroizing` 托管，其 `Debug` 与 `Display` 实现固定输出脱敏占位符，
//!    确保秘密原文及其可逆表示绝不进入命令行输出、日志、诊断或错误回显。

use crate::output::CliError;
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

/// 单个密钥或凭据文件的最大允许读取字节数（64 KiB，足以容纳 PEM 证书链／私钥或 Token，阻止大文件耗尽内存）。
pub const MAX_SECRET_FILE_BYTES: usize = 64 * 1024;

/// 命令行明确禁止接收秘密原文的参数名清单（用于参数解析前／解析中拦截并给出安全指引）。
pub const FORBIDDEN_SECRET_CLI_FLAGS: &[&str] = &[
    "--private-key",
    "--key",
    "--secret",
    "--psk",
    "--preshared-key",
    "--auth-key",
    "--token",
    "--admin-token",
    "--ca-key",
    "--password",
];

/// 受控敏感环境变量白名单：仅允许按名称读取已登记的宿主凭据变量。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlledSecretEnv {
    /// Tailscale / Headscale 节点注册 Auth Key（`NODUS_AUTH_KEY`）。
    AuthKey,
    /// Tailscale / Headscale 远程管理 API Token（`NODUS_ADMIN_TOKEN`）。
    AdminToken,
    /// WireGuard / 服务端私钥路径或受控密钥变量（`NODUS_PRIVATE_KEY`）。
    PrivateKey,
    /// WireGuard 预共享密钥（`NODUS_PRESHARED_KEY`）。
    PresharedKey,
}

impl ControlledSecretEnv {
    pub const fn var_name(self) -> &'static str {
        match self {
            Self::AuthKey => "NODUS_AUTH_KEY",
            Self::AdminToken => "NODUS_ADMIN_TOKEN",
            Self::PrivateKey => "NODUS_PRIVATE_KEY",
            Self::PresharedKey => "NODUS_PRESHARED_KEY",
        }
    }

    pub const fn all_names() -> &'static [&'static str] {
        &[
            "NODUS_AUTH_KEY",
            "NODUS_ADMIN_TOKEN",
            "NODUS_PRIVATE_KEY",
            "NODUS_PRESHARED_KEY",
        ]
    }
}

/// 由 `Zeroizing` 托管的敏感字符串缓冲区。
/// 不实现 `Serialize` 或 `Clone`，且 `Debug` / `Display` 始终输出 `"[REDACTED]"`。
pub struct ManagedSecretString {
    inner: Zeroizing<String>,
}

impl ManagedSecretString {
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// 仅在向 Core 受控接口交付时借用内部切片。
    pub fn expose_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for ManagedSecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"[REDACTED]\"")
    }
}

impl fmt::Display for ManagedSecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// 由 `Zeroizing` 托管的敏感字节缓冲区。
pub struct ManagedSecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl ManagedSecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    pub fn expose_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for ManagedSecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"[REDACTED_BYTES]\"")
    }
}

impl fmt::Display for ManagedSecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_BYTES]")
    }
}

/// 检查命令行 token 是否为被禁止的明文密钥参数（支持 `--auth-key` 与 `--auth-key=...` 形式）。
pub fn reject_if_forbidden_secret_flag(arg: &str) -> Result<(), CliError> {
    let flag_name = arg.split_once('=').map_or(arg, |(name, _)| name);
    if FORBIDDEN_SECRET_CLI_FLAGS.contains(&flag_name) {
        return Err(CliError::secret_policy(
            "cli-secret-guard",
            format!(
                "安全策略拒绝在命令行参数中直接传递敏感凭据 `{flag_name}`；请改用 0600 权限文件（如 `--key-file` / `--auth-key-file` / `--token-file`）或受控环境变量"
            ),
        ));
    }
    Ok(())
}

/// 将用户输入的配置或资源路径转换为已核验的规范绝对路径（不跟随最终符号链接组件，拒绝 `..`、`.`、空路径或控制字符）。
/// Core 要求宿主交付不带 `.` 或 `..` 的绝对路径。
pub fn resolve_authorized_path(raw: &Path) -> Result<PathBuf, CliError> {
    if raw.as_os_str().is_empty() {
        return Err(CliError::usage("文件路径不能为空"));
    }
    let raw_str = raw
        .to_str()
        .ok_or_else(|| CliError::usage("文件路径必须是有效的 UTF-8 编码"))?;
    if raw_str.len() > 4096 || raw_str.chars().any(char::is_control) {
        return Err(CliError::usage("文件路径长度超限或包含非法控制字符"));
    }

    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(|e| {
            CliError::permission_denied("path-resolve", format!("无法获取当前工作目录: {e}"))
        })?;
        cwd.join(raw)
    };

    // 规范化路径组件，拒绝在显式路径中使用 `..` 进行目录穿越
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(CliError::usage(format!(
                    "安全边界拒绝包含父目录引用 `..` 的路径: `{raw_str}`"
                )));
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }

    if !normalized.is_absolute() {
        return Err(CliError::usage("未能解析为绝对路径"));
    }
    Ok(normalized)
}

#[cfg(unix)]
fn current_euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// 核验私有目录（如 `--key-dir`、`--log-dir`、Socket 所在目录）：
/// 1. 必须为真实目录（拒绝符号链接）；
/// 2. 所有者 UID 必须等于当前进程有效 UID（`geteuid()`）；
/// 3. 权限掩码 `mode & 0o077 == 0`（拒绝组用户和其他用户的任何读／写／执行权限，即最高 `0700`）。
pub fn verify_private_directory(path: &Path) -> Result<PathBuf, CliError> {
    let resolved = resolve_authorized_path(path)?;
    let meta = std::fs::symlink_metadata(&resolved).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            CliError::permission_denied(
                "dir-verify",
                format!("无权访问目录 `{}`", resolved.display()),
            )
        } else {
            CliError::secret_policy(
                "dir-verify",
                format!("无法读取私有目录 `{}` 元数据: {}", resolved.display(), e),
            )
        }
    })?;

    if meta.file_type().is_symlink() {
        return Err(CliError::secret_policy(
            "dir-verify",
            format!("私有目录 `{}` 不允许为符号链接", resolved.display()),
        ));
    }
    if !meta.is_dir() {
        return Err(CliError::secret_policy(
            "dir-verify",
            format!("路径 `{}` 不是目录", resolved.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = current_euid();
        if meta.uid() != euid {
            return Err(CliError::secret_policy(
                "dir-verify",
                format!(
                    "私有目录 `{}` 所有者 UID ({}) 与当前有效 UID ({}) 不符",
                    resolved.display(),
                    meta.uid(),
                    euid
                ),
            ));
        }
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CliError::secret_policy(
                "dir-verify",
                format!(
                    "私有目录 `{}` 权限过宽 (0{:o})，必须拒绝组和其他用户访问（要求 0700）",
                    resolved.display(),
                    mode
                ),
            ));
        }
    }

    Ok(resolved)
}

/// 安全打开并核验 `0600` 私有密钥／凭据文件，返回只读 `File` 与其元数据：
/// 1. 若其父目录存在，父目录不得为组或全局可写（`mode & 0o022 == 0`）且不得为符号链接；
/// 2. 使用 `O_NOFOLLOW | O_CLOEXEC` 打开文件，拒绝符号链接、FIFO、设备文件及多重硬链接（`nlink != 1`）；
/// 3. 核验打开前后 `(dev, ino)` 一致，防止 TOCTOU 替换；
/// 4. 核验文件 UID 等于当前 `geteuid()`，且 `mode & 0o077 == 0`（组和其他用户零权限，并且拒绝可执行位 `mode & 0o177 == 0`）。
pub fn open_verified_secret_file(path: &Path) -> Result<(File, std::fs::Metadata), CliError> {
    let resolved = resolve_authorized_path(path)?;

    if let Some(parent) = resolved.parent()
        && !parent.as_os_str().is_empty()
    {
        let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| {
            CliError::secret_policy(
                "secret-file-open",
                format!("无法核验密钥文件父目录 `{}`: {}", parent.display(), e),
            )
        })?;
        if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
            return Err(CliError::secret_policy(
                "secret-file-open",
                format!(
                    "密钥文件父目录 `{}` 不能为符号链接或非目录",
                    parent.display()
                ),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let euid = current_euid();
            if parent_meta.uid() != euid && parent_meta.uid() != 0 {
                return Err(CliError::secret_policy(
                    "secret-file-open",
                    format!(
                        "密钥文件父目录 `{}` 所有者 UID ({}) 不受信任",
                        parent.display(),
                        parent_meta.uid()
                    ),
                ));
            }
            if parent_meta.mode() & 0o022 != 0 {
                return Err(CliError::secret_policy(
                    "secret-file-open",
                    format!(
                        "密钥文件父目录 `{}` 权限过宽 (0{:o})，不允许组或其他用户可写",
                        parent.display(),
                        parent_meta.mode() & 0o777
                    ),
                ));
            }
        }
    }

    let before = std::fs::symlink_metadata(&resolved).map_err(|e| {
        CliError::secret_policy(
            "secret-file-open",
            format!("无法读取密钥文件 `{}` 元数据: {}", resolved.display(), e),
        )
    })?;
    if before.file_type().is_symlink() {
        return Err(CliError::secret_policy(
            "secret-file-open",
            format!("密钥文件 `{}` 不允许为符号链接", resolved.display()),
        ));
    }
    if !before.is_file() {
        return Err(CliError::secret_policy(
            "secret-file-open",
            format!("密钥路径 `{}` 不是普通文件", resolved.display()),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        let flags = (OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits();
        options.custom_flags(flags);
    }

    let file = options.open(&resolved).map_err(|e| {
        CliError::secret_policy(
            "secret-file-open",
            format!("拒绝打开密钥文件 `{}`: {}", resolved.display(), e),
        )
    })?;
    let opened = file.metadata().map_err(|e| {
        CliError::secret_policy(
            "secret-file-open",
            format!("无法读取已打开密钥文件元数据: {e}"),
        )
    })?;

    if !opened.is_file() {
        return Err(CliError::secret_policy(
            "secret-file-open",
            format!("已打开的密钥对象 `{}` 不是普通文件", resolved.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CliError::secret_policy(
                "secret-file-open",
                format!("检测到密钥文件 `{}` 在打开期间被替换", resolved.display()),
            ));
        }
        let euid = current_euid();
        if opened.uid() != euid {
            return Err(CliError::secret_policy(
                "secret-file-open",
                format!(
                    "密钥文件 `{}` 所有者 UID ({}) 与当前有效 UID ({}) 不符",
                    resolved.display(),
                    opened.uid(),
                    euid
                ),
            ));
        }
        let mode = opened.mode() & 0o777;
        if mode & 0o177 != 0 {
            return Err(CliError::secret_policy(
                "secret-file-open",
                format!(
                    "密钥文件 `{}` 权限不合规 (0{:o})，必须为 0600（或 0400，严禁组／其他用户可读或可执行）",
                    resolved.display(),
                    mode
                ),
            ));
        }
        if opened.nlink() != 1 {
            return Err(CliError::secret_policy(
                "secret-file-open",
                format!(
                    "密钥文件 `{}` 存在多个硬链接 (nlink={})，拒绝读取",
                    resolved.display(),
                    opened.nlink()
                ),
            ));
        }
    }

    if opened.len() == 0 {
        return Err(CliError::secret_policy(
            "secret-file-open",
            format!("密钥文件 `{}` 内容为空", resolved.display()),
        ));
    }
    if opened.len() > MAX_SECRET_FILE_BYTES as u64 {
        return Err(CliError::secret_policy(
            "secret-file-open",
            format!(
                "密钥文件 `{}` 大小 ({} B) 超过安全上限 ({} B)",
                resolved.display(),
                opened.len(),
                MAX_SECRET_FILE_BYTES
            ),
        ));
    }

    Ok((file, opened))
}

/// 从 `0600` 权限私有文件读取敏感字节，使用 `Zeroizing` 托管并在读取后复核文件大小未变。
pub fn read_secret_file_bytes(path: &Path) -> Result<ManagedSecretBytes, CliError> {
    let (mut file, opened) = open_verified_secret_file(path)?;
    let expected_len = usize::try_from(opened.len()).map_err(|_| {
        CliError::secret_policy("secret-file-read", "密钥文件长度超出平台可表示范围")
    })?;

    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(expected_len + 1)
        .map_err(|_| CliError::secret_policy("secret-file-read", "密钥读取缓冲内存分配失败"))?;
    file.by_ref()
        .take((MAX_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| {
            CliError::secret_policy("secret-file-read", format!("读取密钥文件失败: {e}"))
        })?;

    let after = file.metadata().map_err(|e| {
        CliError::secret_policy("secret-file-read", format!("复核密钥文件状态失败: {e}"))
    })?;
    if buf.len() != expected_len || after.len() != opened.len() {
        return Err(CliError::secret_policy(
            "secret-file-read",
            "密钥文件在读取期间发生并发变更",
        ));
    }

    Ok(ManagedSecretBytes::new(std::mem::take(&mut *buf)))
}

/// 从 `0600` 权限私有文件读取 UTF-8 敏感字符串（自动去除首尾空白换行，内部缓冲全程 `Zeroizing` 托管）。
pub fn read_secret_file_string(path: &Path) -> Result<ManagedSecretString, CliError> {
    let raw = read_secret_file_bytes(path)?;
    let text = std::str::from_utf8(raw.expose_bytes()).map_err(|_| {
        CliError::secret_policy("secret-file-read", "密钥文件内容不是有效的 UTF-8 文本")
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CliError::secret_policy(
            "secret-file-read",
            "密钥文件去除空白后内容为空",
        ));
    }
    let mut owned = Zeroizing::new(String::new());
    owned
        .try_reserve_exact(trimmed.len())
        .map_err(|_| CliError::secret_policy("secret-file-read", "密钥字符串内存分配失败"))?;
    owned.push_str(trimmed);
    Ok(ManagedSecretString::new(std::mem::take(&mut *owned)))
}

/// 从受控环境变量读取敏感凭据并装入 `ManagedSecretString`（全程 `Zeroizing` 托管）。
/// 拒绝空值或超长输入，且错误消息只引用环境变量名，绝不回显变量值。
pub fn read_secret_from_env(var: ControlledSecretEnv) -> Result<ManagedSecretString, CliError> {
    let name = var.var_name();
    let raw = Zeroizing::new(std::env::var(name).map_err(|_| {
        CliError::secret_policy(
            "secret-env-read",
            format!("未设置受控凭据环境变量 `{name}` 或变量不是有效 UTF-8"),
        )
    })?);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::secret_policy(
            "secret-env-read",
            format!("受控凭据环境变量 `{name}` 不能为空"),
        ));
    }
    if trimmed.len() > MAX_SECRET_FILE_BYTES {
        return Err(CliError::secret_policy(
            "secret-env-read",
            format!("受控凭据环境变量 `{name}` 长度超过安全上限"),
        ));
    }
    let mut clean = Zeroizing::new(String::new());
    clean
        .try_reserve_exact(trimmed.len())
        .map_err(|_| CliError::secret_policy("secret-env-read", "凭据缓冲分配失败"))?;
    clean.push_str(trimmed);
    Ok(ManagedSecretString::new(std::mem::take(&mut *clean)))
}

/// 为将要派生的子进程清除所有受控敏感环境变量，防止凭据无意泄漏给外部子进程（《守护进程与本地控制规范》第四.1 条）。
pub fn scrub_child_command_env(cmd: &mut std::process::Command) {
    for name in ControlledSecretEnv::all_names() {
        cmd.env_remove(name);
    }
}
