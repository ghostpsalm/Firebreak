//! Elevation check via TokenElevation — everything this tool does (audit
//! policy, Security log, WFP enumeration, rule mutation) needs admin.

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Linux: root, checked by effective UID. Every read in the evidence loop
/// needs it — ufw's rule files are root-only, iptables counters come from a
/// privileged netlink socket, and `/proc/<pid>/exe` only resolves for other
/// users' processes as root. Read from /proc rather than linking libc for
/// one call; the effective UID is the second field of the `Uid:` line.
#[cfg(target_os = "linux")]
pub fn is_elevated() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .is_some_and(|euid| euid == "0")
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn is_elevated() -> bool {
    false
}

/// Relaunch this executable elevated via the UAC prompt (ShellExecute
/// "runas"). Returns true if the elevated instance was started — the
/// caller should then exit. Belt-and-braces behind the embedded
/// requireAdministrator manifest, for cases where the manifest is
/// bypassed (e.g. started by CreateProcess from another tool).
#[cfg(windows)]
pub fn relaunch_elevated() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe_w = to_wide(&exe.to_string_lossy());
    let args = std::env::args()
        .skip(1)
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let args_w = to_wide(&args);
    let verb = to_wide("runas");
    unsafe {
        let h = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(args_w.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
        // per ShellExecute contract, values > 32 mean success
        h.0 as usize > 32
    }
}

/// No Linux equivalent of the UAC prompt: a GUI process cannot ask the
/// kernel for privilege mid-run, and re-execing under pkexec/sudo from
/// inside the app would be a worse trust story than telling the user to
/// start it as root.
#[cfg(not(windows))]
pub fn relaunch_elevated() -> bool {
    false
}
