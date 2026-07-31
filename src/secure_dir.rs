//! Admin-only data directories. %ProgramData% is world-creatable: a
//! non-admin who pre-creates our predictable directory would own it and
//! could tamper with the usage DB and policy backups an admin later acts
//! on. So: directories are created with an explicit SYSTEM+Administrators
//! DACL (no inheritance from the parent), and pre-existing directories are
//! only accepted if owned by SYSTEM or Administrators.

use anyhow::Result;
use std::path::Path;

/// Full control for SYSTEM and Administrators, inherited by children,
/// protected from parent inheritance — nothing for anyone else.
#[cfg(windows)]
const ADMIN_ONLY_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[cfg(windows)]
pub fn ensure_secured_dir(path: &Path) -> Result<()> {
    use anyhow::{bail, Context};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;

    fn to_wide(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    if path.exists() {
        // accept only if owned by SYSTEM or Administrators — a directory
        // pre-created by another principal must not be trusted
        let wide = to_wide(path.as_os_str());
        unsafe {
            let mut owner = PSID::default();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let err = GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                &mut sd,
            );
            if err.is_err() {
                bail!(
                    "could not read owner of {}: error {}",
                    path.display(),
                    err.0
                );
            }
            let trusted = IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
                || IsWellKnownSid(owner, WinLocalSystemSid).as_bool();
            let _ = LocalFree(HLOCAL(sd.0));
            if !trusted {
                bail!(
                    "{} exists but is not owned by Administrators or SYSTEM — refusing to \
                     use it (possible tampering; delete it from an elevated shell or pass \
                     --db with a different location)",
                    path.display()
                );
            }
        }
        return Ok(());
    }

    // create every missing ancestor with the explicit DACL
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            ensure_secured_dir(parent)?;
        }
    }

    unsafe {
        let sddl = to_wide(std::ffi::OsStr::new(ADMIN_ONLY_SDDL));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .context("building security descriptor")?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let wide = to_wide(path.as_os_str());
        let created = CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&sa));
        let _ = LocalFree(HLOCAL(sd.0));
        created.with_context(|| format!("creating secured directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn ensure_secured_dir(path: &Path) -> Result<()> {
    // dev/preview builds only — the Windows path is the enforced one
    std::fs::create_dir_all(path)?;
    Ok(())
}
