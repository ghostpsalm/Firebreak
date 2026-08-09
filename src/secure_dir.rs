//! Admin-only data directories. %ProgramData% is world-creatable: a
//! non-admin who pre-creates our predictable directory would own it and
//! could tamper with the usage DB and policy backups an admin later acts
//! on. So: directories are created with an explicit SYSTEM+Administrators
//! DACL (no inheritance from the parent), and pre-existing directories are
//! only accepted if owned by SYSTEM or Administrators.
//!
//! Linux gets the same guarantee by its own means — created 0700, and an
//! existing directory accepted only when it is owned by the effective UID
//! (root, in any real run) and closed to group and other.

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

/// Linux: root-owned and 0700. The Windows reasoning carries over intact —
/// this directory holds the usage DB and policy backups that an
/// administrator later acts on, so a directory another user owns (or can
/// write to) must not be trusted just because it has the expected name.
#[cfg(unix)]
pub fn ensure_secured_dir(path: &Path) -> Result<()> {
    use anyhow::{bail, Context};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if path.exists() {
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if !meta.is_dir() {
            bail!("{} exists but is not a directory", path.display());
        }
        // Must be owned by us. In production "us" is root, since the tool
        // refuses to run otherwise — but stating it as the effective UID
        // keeps the check meaningful (and testable) whoever is running.
        let me = crate::elevation::effective_uid();
        if me.is_some_and(|uid| meta.uid() != uid) {
            bail!(
                "{} exists but is owned by uid {} rather than uid {} — refusing to use it \
                 (possible tampering; remove it as root, or pass --db with a different \
                 location)",
                path.display(),
                meta.uid(),
                me.unwrap_or(0)
            );
        }
        // group/other must have nothing: 0o077 covers rwx for both
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} is mode {:04o} — it must not be accessible to group or other, since it \
                 holds the usage database and policy backups. Fix with: chmod 700 {}",
                path.display(),
                mode,
                path.display()
            );
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            ensure_secured_dir(parent)?;
        }
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating secured directory {}", path.display()))?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
pub fn ensure_secured_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fb-secdir-{}-{}", std::process::id(), name))
    }

    #[test]
    fn a_group_or_world_accessible_directory_is_refused() {
        // The whole point: a predictable path another user can write to must
        // not be adopted just because the name matches.
        let dir = scratch("loose");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_secured_dir(&dir).unwrap_err().to_string();
        assert!(err.contains("group or other"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_private_directory_is_accepted_and_created_private() {
        let dir = scratch("tight");
        let _ = std::fs::remove_dir_all(&dir);
        // creation path
        ensure_secured_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "created directory must be private");
        // and re-accepting it is idempotent
        ensure_secured_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_owned_by_someone_else_is_refused() {
        // /tmp is root-owned and we are not root under `cargo test`, so it
        // stands in for the real hazard: a predictable path someone else
        // already owns.
        if crate::elevation::effective_uid() == Some(0) {
            return; // running as root: /tmp *is* ours, nothing to prove
        }
        let err = ensure_secured_dir(std::path::Path::new("/tmp"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by uid"), "{err}");
    }

    #[test]
    fn a_file_where_the_directory_should_be_is_refused() {
        let path = scratch("afile");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"x").unwrap();
        assert!(ensure_secured_dir(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
