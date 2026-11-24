//! `nodus` 单二进制入口。

use nodus_cli::cli::execute_cli_os;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    execute_cli_os(&args, &mut stdout, &mut stderr).process_exit_code()
}
