//! Offline collect/review bundles.
//!
//! A bundle is a zip carrying everything needed to audit another device's
//! firewall usage on this machine: the target's rule inventory, its
//! interface→profile map, and its filtered Security events. Produced by
//! `firebreak --collect` (or the embedded PowerShell script for hosts that
//! can't run the exe); consumed by "Import Firebreak export…" in Settings.
//!
//! Layout (schema 1):
//!   manifest.json  — schema, hostname, os, collected_at, app version
//!   context.json   — interface index → network profile map
//!   rules.json     — Vec<RuleInfo>, exactly the shape enumerate_rules parses
//!   events.evtx    — Security log filtered to 5156/5157

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::model::RuleInfo;

pub const SCHEMA: u32 = 1;

/// The PowerShell fallback collector, kept embedded so the script a user
/// hands out always matches the parser in their build.
pub const COLLECT_PS1: &str = include_str!("../assets/collect.ps1");

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub hostname: String,
    pub os: String,
    pub collected_at: String,
    pub firebreak_version: String,
    /// "exe" or "ps1" — which collector produced the bundle
    pub collector: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct BundleContext {
    /// interface index → "Domain" | "Private" | "Public" | "Unknown"
    pub iface_profiles: std::collections::HashMap<String, String>,
}

pub struct Bundle {
    pub manifest: Manifest,
    pub rules: Vec<RuleInfo>,
    pub profiles: std::collections::HashMap<u32, crate::scope::Profile>,
    /// events.evtx extracted to a temp file (EvtQuery needs a real path)
    pub events_path: PathBuf,
}

/// Default export filename next to the user's Desktop, mirroring support.rs.
pub fn default_bundle_path() -> PathBuf {
    let base = dirs_desktop();
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "host".into());
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    base.join(format!("firebreak-export-{host}-{stamp}.zip"))
}

fn dirs_desktop() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(|u| Path::new(&u).join("Desktop"))
        .unwrap_or_else(|_| std::env::temp_dir())
}

/// Produce a bundle on the target machine (Windows, elevated).
pub fn collect(out_zip: &Path, progress: &dyn Fn(&str)) -> Result<()> {
    progress("Enumerating firewall rules…");
    let rules = crate::firewall_rules::enumerate_rules().context("enumerating firewall rules")?;

    progress("Reading interface profiles…");
    let profiles = crate::firewall_rules::interface_profile_map();
    let ctx = BundleContext {
        iface_profiles: profiles
            .iter()
            .map(|(k, v)| (k.to_string(), v.label().to_string()))
            .collect(),
    };

    progress("Exporting filtered Security events (this can take a while)…");
    let tmp_evtx =
        std::env::temp_dir().join(format!("firebreak-collect-{}.evtx", std::process::id()));
    let _ = std::fs::remove_file(&tmp_evtx); // wevtutil refuses to overwrite
    let out = crate::syspath::command(crate::syspath::system32_tool("wevtutil.exe"))
        .args([
            "epl",
            "Security",
            &tmp_evtx.to_string_lossy(),
            "/q:*[System[(EventID=5156 or EventID=5157)]]",
        ])
        .output()
        .context("running wevtutil epl")?;
    if !out.status.success() {
        bail!(
            "wevtutil export failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let manifest = Manifest {
        schema: SCHEMA,
        hostname: crate::pipeline::hostname(),
        os: os_label(),
        collected_at: chrono::Utc::now().to_rfc3339(),
        firebreak_version: crate::pipeline::version_string(),
        collector: "exe".into(),
    };

    progress("Writing bundle…");
    let file = std::fs::File::create(out_zip)
        .with_context(|| format!("creating {}", out_zip.display()))?;
    let mut z = zip::ZipWriter::new(file);
    let opt = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("manifest.json", opt)?;
    z.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    z.start_file("context.json", opt)?;
    z.write_all(serde_json::to_string_pretty(&ctx)?.as_bytes())?;
    z.start_file("rules.json", opt)?;
    z.write_all(serde_json::to_string(&rules)?.as_bytes())?;
    z.start_file("events.evtx", opt)?;
    let mut ev = std::fs::File::open(&tmp_evtx).context("opening exported evtx")?;
    std::io::copy(&mut ev, &mut z)?;
    z.finish()?;
    let _ = std::fs::remove_file(&tmp_evtx);
    Ok(())
}

/// Open a bundle: parse manifest/rules/context, extract events.evtx to a
/// temp file for the event API.
pub fn read_bundle(zip_path: &Path) -> Result<Bundle> {
    let file =
        std::fs::File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut z = zip::ZipArchive::new(file).context("reading bundle zip")?;

    let manifest: Manifest = serde_json::from_str(&read_entry(&mut z, "manifest.json")?)
        .context("parsing manifest.json")?;
    if manifest.schema > SCHEMA {
        bail!(
            "bundle schema {} is newer than this build understands ({SCHEMA}) — update Firebreak",
            manifest.schema
        );
    }
    let rules: Vec<RuleInfo> =
        serde_json::from_str(&read_entry(&mut z, "rules.json")?).context("parsing rules.json")?;
    if rules.is_empty() {
        bail!("bundle contains no firewall rules");
    }
    let ctx: BundleContext =
        serde_json::from_str(&read_entry(&mut z, "context.json").unwrap_or_else(|_| "{}".into()))
            .unwrap_or_default();
    let profiles = ctx
        .iface_profiles
        .iter()
        .filter_map(|(k, v)| Some((k.parse().ok()?, crate::scope::Profile::from_label(v))))
        .collect();

    let events_path =
        std::env::temp_dir().join(format!("firebreak-import-{}.evtx", std::process::id()));
    let mut entry = z
        .by_name("events.evtx")
        .map_err(|_| anyhow!("bundle has no events.evtx"))?;
    let mut out = std::fs::File::create(&events_path).context("extracting events.evtx")?;
    std::io::copy(&mut entry, &mut out)?;

    Ok(Bundle {
        manifest,
        rules,
        profiles,
        events_path,
    })
}

fn read_entry(z: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Result<String> {
    let mut e = z
        .by_name(name)
        .map_err(|_| anyhow!("bundle has no {name}"))?;
    let mut s = String::new();
    e.read_to_string(&mut s)?;
    Ok(s)
}

fn os_label() -> String {
    #[cfg(windows)]
    {
        crate::syspath::command(crate::syspath::system32_tool("cmd.exe"))
            .args(["/c", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Windows".into())
    }
    #[cfg(not(windows))]
    {
        "non-windows".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_rule(name: &str) -> RuleInfo {
        serde_json::from_str(&format!(
            r#"{{"Name":"{name}","DisplayName":"{name}","Enabled":"True","Direction":"Inbound",
                "Action":"Allow","Profile":"Private","Protocol":"TCP","LocalPort":"22"}}"#
        ))
        .unwrap()
    }

    #[test]
    fn bundle_round_trip() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("export.zip");

        // write a bundle by hand (collect() is Windows-only)
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        let opt = zip::write::SimpleFileOptions::default();
        let manifest = Manifest {
            schema: SCHEMA,
            hostname: "TEST-PC".into(),
            os: "test".into(),
            collected_at: "2026-07-17T00:00:00Z".into(),
            firebreak_version: "0.6.0.1".into(),
            collector: "exe".into(),
        };
        z.start_file("manifest.json", opt).unwrap();
        z.write_all(serde_json::to_string(&manifest).unwrap().as_bytes())
            .unwrap();
        z.start_file("context.json", opt).unwrap();
        z.write_all(br#"{"iface_profiles":{"7":"Domain","12":"Public"}}"#)
            .unwrap();
        z.start_file("rules.json", opt).unwrap();
        z.write_all(
            serde_json::to_string(&vec![fake_rule("r1"), fake_rule("r2")])
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        z.start_file("events.evtx", opt).unwrap();
        z.write_all(b"ElfFile\0fake").unwrap();
        z.finish().unwrap();

        let b = read_bundle(&zip_path).unwrap();
        assert_eq!(b.manifest.hostname, "TEST-PC");
        assert_eq!(b.rules.len(), 2);
        assert_eq!(b.profiles.get(&7), Some(&crate::scope::Profile::Domain));
        assert_eq!(b.profiles.get(&12), Some(&crate::scope::Profile::Public));
        assert!(b.events_path.exists());
        let _ = std::fs::remove_file(&b.events_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("future.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("manifest.json", opt).unwrap();
        z.write_all(br#"{"schema":99,"hostname":"x","os":"x","collected_at":"x","firebreak_version":"x","collector":"exe"}"#).unwrap();
        z.finish().unwrap();
        let err = match read_bundle(&zip_path) {
            Ok(_) => panic!("expected a schema-too-new error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("newer"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
