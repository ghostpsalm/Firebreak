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

#[cfg(not(windows))]
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

#[cfg(not(windows))]
pub fn relaunch_elevated() -> bool {
    false
}
