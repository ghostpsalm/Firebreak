//! Firewall rule enumeration, mutation, and backup — via PowerShell rather
//! than the COM INetFwRule interface, deliberately: COM's INetFwRule.Name is
//! the *display* name and carries no InstanceID, while Set-NetFirewallRule
//! -Name targets the unique InstanceID we join WFP filters against. Scripts
//! are passed with -EncodedCommand to sidestep quoting entirely.

use anyhow::{bail, Context, Result};
use base64::Engine;
#[cfg(not(target_os = "linux"))]
use chrono::Utc;
use std::path::{Path, PathBuf};

use crate::model::RuleInfo;

pub(crate) fn run_powershell(script: &str) -> Result<String> {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = crate::syspath::command(crate::syspath::powershell())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .output()
        .context("spawning powershell")?;
    if !out.status.success() {
        bail!(
            "powershell failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Enumerate all firewall rules with their program/port filters joined in.
/// One PowerShell round-trip; the -All filter queries avoid a per-rule
/// association lookup, which is unusably slow across ~500 rules.
///
/// **ActiveStore, not the default.** `Get-NetFirewallRule` with no
/// `-PolicyStore` returns PersistentStore — local rules only. On a
/// domain-joined or Intune-managed machine that silently omits every rule
/// applied by Group Policy and by Windows Service Hardening, so the audit
/// would report an incomplete firewall and push traffic that matched a
/// managed rule into the unattributed bucket. ActiveStore is the resultant
/// set: local + GPO/RSOP + service stores.
///
/// `-TracePolicyStore` fills in PolicyStoreSource / PolicyStoreSourceType,
/// which is how a managed rule is told apart from one an admin made here.
/// Rules deployed by Intune live in their own MDM store and may still be
/// absent — see the verification note in docs/internals.md.
pub fn enumerate_rules() -> Result<Vec<RuleInfo>> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$apps = @{}
Get-NetFirewallApplicationFilter -All | ForEach-Object { $apps[$_.InstanceID] = $_.Program }
$ports = @{}
Get-NetFirewallPortFilter -All | ForEach-Object {
    $ports[$_.InstanceID] = @{
        Protocol   = [string]$_.Protocol
        LocalPort  = (@($_.LocalPort)  -join ',')
        RemotePort = (@($_.RemotePort) -join ',')
    }
}
$svcs = @{}
Get-NetFirewallServiceFilter -All | ForEach-Object { $svcs[$_.InstanceID] = [string]$_.Service }
$addrs = @{}
Get-NetFirewallAddressFilter -All | ForEach-Object { $addrs[$_.InstanceID] = (@($_.RemoteAddress) -join ',') }
$out = Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | ForEach-Object {
    $p = $ports[$_.InstanceID]
    [pscustomobject]@{
        Name          = $_.Name
        DisplayName   = $_.DisplayName
        Description   = $_.Description
        Enabled       = [string]$_.Enabled
        Direction     = [string]$_.Direction
        Action        = [string]$_.Action
        Profile       = [string]$_.Profile
        Group         = $_.Group
        Program       = $apps[$_.InstanceID]
        Protocol      = $p.Protocol
        LocalPort     = $p.LocalPort
        RemotePort    = $p.RemotePort
        Service       = $svcs[$_.InstanceID]
        RemoteAddress = $addrs[$_.InstanceID]
        PolicyStoreSource     = [string]$_.PolicyStoreSource
        PolicyStoreSourceType = [string]$_.PolicyStoreSourceType
    }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"#;
    let json = run_powershell(script)?;
    let rules: Vec<RuleInfo> =
        serde_json::from_str(json.trim()).context("parsing Get-NetFirewallRule JSON")?;
    Ok(rules)
}

/// Map interface index -> network profile (Domain/Private/Public) from the
/// live connection profiles. Used to give each event a profile so
/// attribution can respect a rule's profile scope and split hits per
/// profile. Reflects the *current* profile of each interface (Windows
/// doesn't record the profile in the event), which is stable in practice.
pub fn interface_profile_map() -> std::collections::HashMap<u32, crate::scope::Profile> {
    use crate::scope::Profile;
    #[derive(serde::Deserialize)]
    struct P {
        #[serde(rename = "Index")]
        index: u32,
        #[serde(rename = "Cat")]
        cat: String,
    }
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$out = Get-NetConnectionProfile | ForEach-Object {
    [pscustomobject]@{ Index = [int]$_.InterfaceIndex; Cat = [string]$_.NetworkCategory }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;
    let mut map = std::collections::HashMap::new();
    if let Ok(json) = run_powershell(script) {
        if let Ok(list) = serde_json::from_str::<Vec<P>>(json.trim()) {
            for p in list {
                let prof = match p.cat.as_str() {
                    "DomainAuthenticated" => Profile::Domain,
                    "Private" => Profile::Private,
                    "Public" => Profile::Public,
                    _ => Profile::Unknown,
                };
                map.insert(p.index, prof);
            }
        }
    }
    map
}

/// Cached rule set (JSON) for instant startup; refreshed each run. Lives
/// alongside the DB under the ACL-protected data dir.
fn rules_cache_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("firebreak").join("rules-cache.json")
}

pub fn save_rules_cache(rules: &[RuleInfo]) {
    if let Ok(json) = serde_json::to_string(rules) {
        let _ = std::fs::write(rules_cache_path(), json);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn load_rules_cache() -> Option<Vec<RuleInfo>> {
    let json = std::fs::read_to_string(rules_cache_path()).ok()?;
    serde_json::from_str(&json).ok()
}

/// Directory where backups land: %ProgramData%\firebreak\backups
#[cfg(not(target_os = "linux"))]
pub fn backup_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("firebreak").join("backups")
}

/// Export the full firewall policy before any mutation. Produces a
/// restorable .wfw (netsh advfirewall import) plus a JSON rule dump for
/// human-readable diffing. Returns the .wfw path.
#[cfg(not(target_os = "linux"))]
pub fn backup_policy(rules: &[RuleInfo]) -> Result<PathBuf> {
    let dir = backup_dir();
    crate::secure_dir::ensure_secured_dir(&dir)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let wfw = dir.join(format!("firewall-{stamp}.wfw"));
    let json = dir.join(format!("rules-{stamp}.json"));

    let out = crate::syspath::command(crate::syspath::system32_tool("netsh.exe"))
        .args(["advfirewall", "export", &wfw.to_string_lossy()])
        .output()
        .context("running netsh advfirewall export")?;
    if !out.status.success() {
        bail!(
            "netsh export failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::write(&json, serde_json::to_string_pretty(rules)?)?;
    Ok(wfw)
}

/// Names per Set-NetFirewallRule invocation: keeps the -EncodedCommand
/// well under the 32,767-char Windows command-line limit even with long
/// InstanceIDs, so a big batch can't fail wholesale after confirmation.
#[cfg(not(target_os = "linux"))]
const RULES_PER_INVOCATION: usize = 100;

/// Enable/disable a single rule by unique Name (InstanceID) — the apply
/// worker goes rule-by-rule so progress and per-rule failures are exact.
#[cfg(not(target_os = "linux"))]
pub fn set_rule_enabled(rule_name: &str, enabled: bool) -> Result<()> {
    set_rules_enabled(std::slice::from_ref(&rule_name.to_string()), enabled)
}

/// Narrow (or widen) a rule's profile scope, e.g. `-Profile Domain,Private`
/// to turn it off for Public. The rule is left enabled (you keep it active
/// on the remaining profiles). `profile_arg` is a comma-separated set or
/// "Any". Backup first — the UI's Apply flow does.
#[cfg(not(target_os = "linux"))]
pub fn set_rule_profiles(rule_name: &str, profile_arg: &str) -> Result<()> {
    let name = rule_name.replace('\'', "''");
    // profile_arg is a controlled token set (Any / Domain,Private,Public
    // combinations from ProfileSet), passed unquoted so PowerShell coerces
    // it to the Profile flags enum. Reject anything unexpected defensively.
    let prof: String = profile_arg
        .split(',')
        .map(str::trim)
        .filter(|p| matches!(*p, "Any" | "Domain" | "Private" | "Public"))
        .collect::<Vec<_>>()
        .join(",");
    if prof.is_empty() {
        bail!("no valid profiles in '{profile_arg}'");
    }
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
Set-NetFirewallRule -Name '{name}' -Profile {prof} -Enabled True
"#
    );
    run_powershell(&script)?;
    Ok(())
}

/// Enable/disable rules by unique Name (InstanceID). Backup first — this
/// module doesn't do it for you; the UI's Apply flow does. On error,
/// reports how many rules had already been applied.
#[cfg(not(target_os = "linux"))]
pub fn set_rules_enabled(rule_names: &[String], enabled: bool) -> Result<()> {
    let value = if enabled { "True" } else { "False" };
    let mut applied = 0usize;
    for chunk in rule_names.chunks(RULES_PER_INVOCATION) {
        let list = chunk
            .iter()
            .map(|n| format!("'{}'", n.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
Set-NetFirewallRule -Name @({list}) -Enabled {value}
"#
        );
        run_powershell(&script).with_context(|| {
            format!(
                "setting Enabled={value}: {applied} of {} rules were applied before this \
                 chunk failed",
                rule_names.len()
            )
        })?;
        applied += chunk.len();
    }
    Ok(())
}
