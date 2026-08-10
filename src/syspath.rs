//! Absolute paths for the system executables we spawn. An elevated process
//! must not resolve tool names through the PATH/CreateProcess search order —
//! a planted powershell.exe next to the binary or in a user-writable PATH
//! entry would run with admin rights. The same rule holds for a root-run
//! Linux process and `ufw`/`iptables`/`nft`.

use std::path::PathBuf;

/// %SystemRoot%, set by the session manager, not user-writable when elevated.
fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

/// System directories a Linux tool may legitimately live in. Fixed list, in
/// preference order — never `$PATH`, which a caller can point anywhere.
#[cfg(unix)]
const SYSTEM_BIN_DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// Resolve a Linux system tool (`ufw`, `iptables`, `nft`, `firewall-cmd`) to
/// an absolute path under [`SYSTEM_BIN_DIRS`]. `None` when it isn't
/// installed — callers treat that as "this backend isn't present", not as an
/// error.
#[cfg(unix)]
pub fn system_tool(name: &str) -> Option<PathBuf> {
    SYSTEM_BIN_DIRS
        .iter()
        .map(|d| PathBuf::from(d).join(name))
        .find(|p| p.is_file())
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

/// A path under the system temp directory that an onlooker cannot predict.
///
/// The paths this replaces were `firebreak-<thing>-<pid>`, which anyone on
/// the box can guess: pid space is small and enumerable. That matters most
/// on exactly the path that needs it least — bundle import — because that
/// code exists to handle a file from *another* machine, and a pre-planted
/// symlink at a guessable name redirects the write. `%TEMP%` is normally
/// per-user, so this is defence in depth rather than the only barrier, but
/// it costs nothing to not rely on that.
///
/// The nonce comes from `RandomState`, whose keys the standard library seeds
/// from the OS random source. No crypto claim is made or needed here: the
/// requirement is unpredictability by another process, not secrecy.
pub fn scratch_path(stem: &str, ext: &str) -> PathBuf {
    use std::hash::{BuildHasher, Hasher};
    let nonce = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    std::env::temp_dir().join(format!(
        "firebreak-{stem}-{}-{nonce:016x}.{ext}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two calls must not collide, or a second import would land on the
    /// first one's file — and the point of the nonce is that neither is
    /// guessable from outside.
    #[test]
    fn scratch_paths_differ_every_time() {
        let a = scratch_path("import", "db");
        let b = scratch_path("import", "db");
        assert_ne!(a, b);
        assert!(a.to_string_lossy().contains("firebreak-import-"));
        assert_eq!(a.extension().unwrap(), "db");
    }
}
