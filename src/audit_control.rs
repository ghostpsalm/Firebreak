//! Query/enable the "Filtering Platform Connection" audit subcategory and
//! size the Security event log.
//!
//! Query goes through AuditQuerySystemPolicy (locale-independent).
//! Set shells out to auditpol.exe by subcategory GUID — auditpol handles the
//! SeSecurityPrivilege dance for us and the GUID form avoids localized
//! subcategory names.

#[cfg(windows)]
use anyhow::Context;
use anyhow::{bail, Result};

#[cfg(windows)]
use windows::core::GUID;
#[cfg(windows)]
use windows::Win32::Security::Authentication::Identity::{
    AuditFree, AuditQuerySystemPolicy, AuditSetSystemPolicy, AUDIT_POLICY_INFORMATION,
};

/// Audit subcategory: Filtering Platform Connection (events 5156/5157).
/// NOT "Filtering Platform Packet Drop" ({0CCE9225-...}) — that one is
/// per-packet volume and must stay off.
pub const FILTERING_PLATFORM_CONNECTION_GUID: &str = "{0CCE9226-69AE-11D9-BED3-505054503030}";

#[cfg(windows)]
const SUBCATEGORY: GUID = GUID::from_u128(0x0CCE9226_69AE_11D9_BED3_505054503030);

const POLICY_AUDIT_EVENT_SUCCESS: u32 = 0x1;
const POLICY_AUDIT_EVENT_FAILURE: u32 = 0x2;
#[cfg(windows)]
const POLICY_AUDIT_EVENT_NONE: u32 = 0x4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditState {
    pub success: bool,
    pub failure: bool,
}

impl AuditState {
    pub fn fully_enabled(&self) -> bool {
        self.success && self.failure
    }
}

#[cfg(windows)]
pub fn query_audit_state() -> Result<AuditState> {
    unsafe {
        let mut policy: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        let ok = AuditQuerySystemPolicy(&[SUBCATEGORY], &mut policy);
        if !ok.as_bool() || policy.is_null() {
            bail!(
                "AuditQuerySystemPolicy failed ({}); is the process elevated?",
                windows::core::Error::from_win32()
            );
        }
        let info = *policy;
        AuditFree(policy as *mut _);
        Ok(AuditState {
            success: info.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS != 0,
            failure: info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE != 0,
        })
    }
}

#[cfg(not(windows))]
pub fn query_audit_state() -> Result<AuditState> {
    bail!("audit policy query is only available on Windows")
}

/// Set Filtering Platform Connection auditing to an explicit state — used
/// both to enable collection and to restore the pre-firebreak state.
/// Note: local audit policy can be overridden by GPO on the next policy
/// refresh — if this flips back off between runs, that's the place to look.
///
/// Primary path is the AuditSetSystemPolicy API (no subprocess, so it works
/// under application-control ringfencing). Falls back to auditpol.exe only if
/// the API path fails — TODO(#7): drop the fallback once the API path is
/// confirmed on real hardware.
#[cfg(windows)]
pub fn set_auditing(state: AuditState) -> Result<()> {
    match set_auditing_api(state) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("AuditSetSystemPolicy failed ({e:#}); falling back to auditpol.exe");
            set_auditing_subprocess(state)
        }
    }
}

#[cfg(windows)]
fn set_auditing_api(state: AuditState) -> Result<()> {
    // AuditSetSystemPolicy needs SeSecurityPrivilege enabled on the token.
    crate::winpriv::enable_privilege(windows::Win32::Security::SE_SECURITY_NAME)
        .context("enabling SeSecurityPrivilege")?;

    // AuditingInformation is the complete desired state, not a delta. Zero
    // means "unchanged", so an explicit off must use POLICY_AUDIT_EVENT_NONE.
    let mut flags = 0u32;
    if state.success {
        flags |= POLICY_AUDIT_EVENT_SUCCESS;
    }
    if state.failure {
        flags |= POLICY_AUDIT_EVENT_FAILURE;
    }
    if flags == 0 {
        flags = POLICY_AUDIT_EVENT_NONE;
    }

    let info = AUDIT_POLICY_INFORMATION {
        AuditSubCategoryGuid: SUBCATEGORY,
        AuditingInformation: flags,
        AuditCategoryGuid: GUID::zeroed(),
    };
    unsafe {
        let ok = AuditSetSystemPolicy(&[info]);
        if !ok.as_bool() {
            bail!(
                "AuditSetSystemPolicy failed: {}",
                windows::core::Error::from_win32()
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_auditing_subprocess(state: AuditState) -> Result<()> {
    let onoff = |b: bool| if b { "enable" } else { "disable" };
    let out = crate::syspath::command(crate::syspath::system32_tool("auditpol.exe"))
        .args([
            "/set",
            &format!("/subcategory:{}", FILTERING_PLATFORM_CONNECTION_GUID),
            &format!("/success:{}", onoff(state.success)),
            &format!("/failure:{}", onoff(state.failure)),
        ])
        .output()
        .context("running auditpol.exe")?;
    if !out.status.success() {
        bail!(
            "auditpol /set failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_auditing(_state: AuditState) -> Result<()> {
    bail!("setting audit policy is only available on Windows")
}

pub fn enable_auditing() -> Result<()> {
    set_auditing(AuditState {
        success: true,
        failure: true,
    })
}

/// Current max size of the Security log in bytes.
/// Primary: EvtGetChannelConfigProperty; fallback: wevtutil gl.
#[cfg(windows)]
pub fn security_log_max_bytes() -> Result<u64> {
    match security_log_max_bytes_api() {
        Ok(n) => Ok(n),
        Err(e) => {
            eprintln!("EvtGetChannelConfigProperty failed ({e:#}); falling back to wevtutil");
            security_log_max_bytes_subprocess()
        }
    }
}

#[cfg(windows)]
fn security_log_max_bytes_api() -> Result<u64> {
    use windows::core::w;
    use windows::Win32::System::EventLog::{
        EvtChannelLoggingConfigMaxSize, EvtClose, EvtGetChannelConfigProperty,
        EvtOpenChannelConfig, EVT_VARIANT,
    };
    unsafe {
        let h = EvtOpenChannelConfig(None, w!("Security"), 0)
            .context("EvtOpenChannelConfig(Security)")?;
        // two-call: probe the buffer size, then read into it
        let mut used = 0u32;
        let _ =
            EvtGetChannelConfigProperty(h, EvtChannelLoggingConfigMaxSize, 0, 0, None, &mut used);
        let mut buf = vec![0u8; used.max(std::mem::size_of::<EVT_VARIANT>() as u32) as usize];
        let vptr = buf.as_mut_ptr() as *mut EVT_VARIANT;
        let ok = EvtGetChannelConfigProperty(
            h,
            EvtChannelLoggingConfigMaxSize,
            0,
            buf.len() as u32,
            Some(vptr),
            &mut used,
        );
        let val = (*vptr).Anonymous.UInt64Val;
        let _ = EvtClose(h);
        if ok.is_err() {
            bail!(
                "EvtGetChannelConfigProperty failed: {}",
                windows::core::Error::from_win32()
            );
        }
        Ok(val)
    }
}

#[cfg(windows)]
fn security_log_max_bytes_subprocess() -> Result<u64> {
    let out = crate::syspath::command(crate::syspath::system32_tool("wevtutil.exe"))
        .args(["gl", "Security"])
        .output()
        .context("running wevtutil gl Security")?;
    if !out.status.success() {
        bail!(
            "wevtutil gl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("maxSize:") {
            return rest.trim().parse::<u64>().context("parsing maxSize");
        }
    }
    bail!("maxSize not found in wevtutil output");
}

#[cfg(not(windows))]
pub fn security_log_max_bytes() -> Result<u64> {
    bail!("reading the Security log size is only available on Windows")
}

/// Set the Security log max size (bytes).
/// Primary: EvtSetChannelConfigProperty + EvtSaveChannelConfig; fallback:
/// wevtutil sl.
#[cfg(windows)]
pub fn set_security_log_max_bytes(bytes: u64) -> Result<()> {
    match set_security_log_max_bytes_api(bytes) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("EvtSetChannelConfigProperty failed ({e:#}); falling back to wevtutil");
            set_security_log_max_bytes_subprocess(bytes)
        }
    }
}

#[cfg(windows)]
fn set_security_log_max_bytes_api(bytes: u64) -> Result<()> {
    use windows::core::w;
    use windows::Win32::System::EventLog::{
        EvtChannelLoggingConfigMaxSize, EvtClose, EvtOpenChannelConfig, EvtSaveChannelConfig,
        EvtSetChannelConfigProperty, EvtVarTypeUInt64, EVT_VARIANT, EVT_VARIANT_0,
    };
    // saving the Security channel config needs SeSecurityPrivilege
    crate::winpriv::enable_privilege(windows::Win32::Security::SE_SECURITY_NAME)
        .context("enabling SeSecurityPrivilege")?;
    unsafe {
        let h = EvtOpenChannelConfig(None, w!("Security"), 0)
            .context("EvtOpenChannelConfig(Security)")?;
        let variant = EVT_VARIANT {
            Anonymous: EVT_VARIANT_0 { UInt64Val: bytes },
            Count: 0,
            Type: EvtVarTypeUInt64.0 as u32,
        };
        let set = EvtSetChannelConfigProperty(h, EvtChannelLoggingConfigMaxSize, 0, &variant);
        if set.is_err() {
            let _ = EvtClose(h);
            bail!(
                "EvtSetChannelConfigProperty failed: {}",
                windows::core::Error::from_win32()
            );
        }
        let save = EvtSaveChannelConfig(h, 0);
        let _ = EvtClose(h);
        if save.is_err() {
            bail!(
                "EvtSaveChannelConfig failed: {}",
                windows::core::Error::from_win32()
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_security_log_max_bytes_subprocess(bytes: u64) -> Result<()> {
    let out = crate::syspath::command(crate::syspath::system32_tool("wevtutil.exe"))
        .args(["sl", "Security", &format!("/ms:{}", bytes)])
        .output()
        .context("running wevtutil sl Security")?;
    if !out.status.success() {
        bail!(
            "wevtutil sl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_security_log_max_bytes(_bytes: u64) -> Result<()> {
    bail!("setting the Security log size is only available on Windows")
}

/// Default target: 512 MiB. At a few hundred bytes per 5156 event this holds
/// on the order of a million-plus connections — tune upward for busy hosts
/// or long gaps between runs.
pub const DEFAULT_SECURITY_LOG_BYTES: u64 = 512 * 1024 * 1024;
