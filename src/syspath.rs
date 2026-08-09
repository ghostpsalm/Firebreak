//! Absolute paths for the system executables we spawn. An elevated process
//! must not resolve tool names through the PATH/CreateProcess search order —
//! a planted powershell.exe next to the binary or in a user-writable PATH
//! entry would run with admin rights.

use std::path::PathBuf;

/// %SystemRoot%, set by the session manager, not user-writable when elevated.
fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

/// Full path to a System32 tool, e.g. netsh.exe / auditpol.exe / wevtutil.exe.
pub fn system32_tool(exe_name: &str) -> PathBuf {
    system_root().join("System32").join(exe_name)
}

/// Windows PowerShell lives outside System32 proper.
pub fn powershell() -> PathBuf {
    system_root().join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// A `Command` that never flashes a console window — CREATE_NO_WINDOW.
/// All subprocess spawns go through this so the GUI stays clean.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let c = std::process::Command::new(program);
    #[cfg(windows)]
    let c = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = c;
        c.creation_flags(CREATE_NO_WINDOW);
        c
    };
    c
}
