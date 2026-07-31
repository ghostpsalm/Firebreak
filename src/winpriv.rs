//! Enable a named privilege on the current process token.
//!
//! Several security APIs (AuditSetSystemPolicy, EvtSaveChannelConfig on the
//! Security channel) need a privilege that an elevated admin token *holds but
//! has disabled by default* — the command-line tools (auditpol, wevtutil)
//! enable it internally. When we call the APIs directly we must do the same.

#[cfg(windows)]
use anyhow::{bail, Result};

#[cfg(windows)]
pub fn enable_privilege(name: windows::core::PCWSTR) -> Result<()> {
    use windows::Win32::Foundation::{CloseHandle, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        let mut luid = LUID::default();
        let lookup = LookupPrivilegeValueW(windows::core::PCWSTR::null(), name, &mut luid);
        if lookup.is_err() {
            let _ = CloseHandle(token);
            bail!(
                "LookupPrivilegeValueW failed: {}",
                windows::core::Error::from_win32()
            );
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjust = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        // AdjustTokenPrivileges "succeeds" even if not all privileges were
        // assigned — GetLastError == ERROR_NOT_ALL_ASSIGNED signals the
        // token simply doesn't hold the privilege.
        let last = windows::core::Error::from_win32();
        let _ = CloseHandle(token);
        if adjust.is_err() {
            bail!("AdjustTokenPrivileges failed: {last}");
        }
        if last.code().0 as u32 == 0x0000_0514 {
            // ERROR_NOT_ALL_ASSIGNED
            bail!("the process token does not hold the required privilege (needs elevation)");
        }
        Ok(())
    }
}
