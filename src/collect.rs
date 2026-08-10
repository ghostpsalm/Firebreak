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

#[cfg(any(windows, test))]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(any(windows, test))]
use crate::model::RuleInfo;

pub const SCHEMA: u32 = 1;

#[cfg(any(windows, test))]
/// Decompressed-byte ceiling for a bundle's JSON entries. Enforced against
/// bytes actually read, never against the zip's declared entry size — that
/// field lives in an attacker-controlled header (issue #8).
const JSON_ENTRY_CAP: u64 = 64 * 1024 * 1024;

#[cfg(any(windows, test))]
/// Same ceiling for events.evtx, which is a real Security log export and so
/// legitimately far larger than the JSON entries.
const EVENTS_ENTRY_CAP: u64 = 1024 * 1024 * 1024;

/// The PowerShell fallback collector, kept embedded so the script a user
/// hands out always matches the parser in their build. Only the Windows UI
/// hands it out.
#[cfg(windows)]
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

/// A bundle opened for review. Parsing one is portable and stays
/// unit-tested from any host; only *replaying* its events.evtx needs
/// EvtQuery, so nothing outside Windows calls this in a real run.
#[cfg(any(windows, test))]
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
    let tmp_evtx = crate::syspath::scratch_path("collect", "evtx");
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
#[cfg(any(windows, test))]
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
    // A bundle from an older/smaller collector may carry no context.json, and
    // an unreadable one — bad UTF-8, bad CRC, truncated stream, invalid JSON —
    // is likewise not worth failing the import over. Only an over-cap entry is
    // hard, so that is the one error the fallback must not swallow.
    let ctx: BundleContext = match read_entry_opt(&mut z, "context.json") {
        Ok(Some(s)) => serde_json::from_str(&s).unwrap_or_default(),
        Ok(None) => BundleContext::default(),
        Err(e) if e.downcast_ref::<EntryTooLarge>().is_some() => return Err(e),
        Err(_) => BundleContext::default(),
    };
    let profiles = ctx
        .iface_profiles
        .iter()
        .filter_map(|(k, v)| Some((k.parse().ok()?, crate::scope::Profile::from_label(v))))
        .collect();

    let events_path = crate::syspath::scratch_path("import", "evtx");
    let mut entry = z
        .by_name("events.evtx")
        .map_err(|_| anyhow!("bundle has no events.evtx"))?;
    // create_new: if anything already occupies this path — a pre-planted
    // symlink, a collision — fail rather than write through it. With the
    // nonce in the name (issue #10) that should be unreachable; this is the
    // check that makes "should" unnecessary.
    let mut out = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&events_path)
        .context("extracting events.evtx")?;
    // One byte past the cap: if the entry yields it, it is over.
    let extracted = std::io::copy(&mut entry.by_ref().take(EVENTS_ENTRY_CAP + 1), &mut out)
        .context("extracting events.evtx")
        .and_then(|n| {
            if n > EVENTS_ENTRY_CAP {
                bail!(
                    "events.evtx in bundle decompresses past the {} MiB limit",
                    EVENTS_ENTRY_CAP / (1024 * 1024)
                );
            }
            Ok(())
        });
    if let Err(e) = extracted {
        // A refusal must not cost the disk it refused, and the copy above has
        // already streamed its bytes to temp whichever way it ended badly —
        // over the cap, or failing the entry's own checksum part-way through a
        // tampered or bit-rotted stream. The only other remove_file for this
        // path runs on the import success path, so both failures clean up here.
        // Close the handle first (Windows will not unlink an open file), and
        // keep the removal best-effort — a cleanup failure must not mask the
        // extraction error, which is the one worth returning.
        drop(out);
        let _ = std::fs::remove_file(&events_path);
        return Err(e);
    }

    Ok(Bundle {
        manifest,
        rules,
        profiles,
        events_path,
    })
}

#[cfg(any(windows, test))]
#[cfg(any(windows, test))]
fn read_entry(z: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Result<String> {
    read_entry_opt(z, name)?.ok_or_else(|| anyhow!("bundle has no {name}"))
}

#[cfg(any(windows, test))]
/// An entry that is present but decompresses past [`JSON_ENTRY_CAP`]. Its own
/// type so a caller with a soft fallback can tell "too big to read at all"
/// apart from "read, but corrupt" — the first is a refusal, the second isn't.
#[derive(Debug)]
struct EntryTooLarge(String);

#[cfg(any(windows, test))]
impl std::fmt::Display for EntryTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in bundle decompresses past the {} MiB limit",
            self.0,
            JSON_ENTRY_CAP / (1024 * 1024)
        )
    }
}

#[cfg(any(windows, test))]
impl std::error::Error for EntryTooLarge {}

#[cfg(any(windows, test))]
/// `Ok(None)` when the entry simply isn't there; [`EntryTooLarge`] when it is
/// there but won't fit under [`JSON_ENTRY_CAP`]; any other `Err` when it is
/// there and unreadable — callers that treat a missing or corrupt entry as
/// optional must not treat an over-cap one that way.
fn read_entry_opt(z: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Result<Option<String>> {
    let Ok(mut e) = z.by_name(name) else {
        return Ok(None);
    };
    let mut s = String::new();
    // One byte past the cap: if the entry yields it, it is over.
    e.by_ref()
        .take(JSON_ENTRY_CAP + 1)
        .read_to_string(&mut s)
        .with_context(|| format!("reading {name}"))?;
    if s.len() as u64 > JSON_ENTRY_CAP {
        return Err(EntryTooLarge(name.to_string()).into());
    }
    Ok(Some(s))
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

    /// 64 MiB is the agreed decompressed-byte ceiling for the JSON entries
    /// (issue #8); these fixtures sit 1 MiB past it. Written as a repeated
    /// byte so deflate collapses the whole thing into a few KB on disk —
    /// the zip stays tiny, only the *decompressed* stream is over-cap.
    const OVER_JSON_CAP: usize = 65 * 1024 * 1024;

    /// 1 GiB is the agreed decompressed-byte ceiling for events.evtx (issue
    /// #8); this fixture sits 1 MiB past it. Same trick as the JSON entries —
    /// repeated bytes, so the zip on disk stays a few KB.
    const OVER_EVENTS_CAP: usize = 1024 * 1024 * 1024 + 1024 * 1024;

    /// Stream `head` followed by `pad` bytes of trailing whitespace into one
    /// zip entry, without ever holding it all in memory.
    ///
    /// The padding is whitespace on purpose: JSON tolerates a trailing run of
    /// it, so the entry stays *valid* however far into the padding a reader
    /// gets. An implementation that silently truncates at the cap instead of
    /// erroring therefore still parses, still returns Ok — and still fails
    /// these tests, which is the point. events.evtx is never parsed by
    /// read_bundle at all, so the same holds there for free.
    fn write_padded_entry(
        z: &mut zip::ZipWriter<std::fs::File>,
        name: &str,
        head: &[u8],
        pad: usize,
    ) {
        let opt = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(1));
        z.start_file(name, opt).unwrap();
        z.write_all(head).unwrap();
        let chunk = vec![b' '; 1024 * 1024];
        let mut left = pad;
        while left > 0 {
            let n = left.min(chunk.len());
            z.write_all(&chunk[..n]).unwrap();
            left -= n;
        }
    }

    /// Extractions no longer live at a name anyone can predict (issue #10),
    /// so a test that wants to know what a run left behind has to look for
    /// it: every `firebreak-import-<pid>-<nonce>.evtx` belonging to `pid`.
    /// Returns (path, size) for each, and removes them.
    fn sweep_extractions(pid: u32) -> Vec<(PathBuf, u64)> {
        let prefix = format!("firebreak-import-{pid}-");
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return found;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(".evtx") {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                let path = e.path();
                let _ = std::fs::remove_file(&path);
                found.push((path, size));
            }
        }
        found
    }

    fn write_manifest(z: &mut zip::ZipWriter<std::fs::File>) {
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
    }

    /// A rules.json entry that really decompresses past the 64 MiB cap must
    /// be refused, with the offending entry named. Everything else in the
    /// bundle is valid and small, so the only thing that can fail is the cap.
    #[test]
    fn oversize_rules_entry_is_refused() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("fat-rules.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("context.json", opt).unwrap();
        z.write_all(br#"{"iface_profiles":{"7":"Domain"}}"#)
            .unwrap();
        // parses cleanly at any read length — a build with no cap returns Ok.
        write_padded_entry(
            &mut z,
            "rules.json",
            br#"[{"Name":"r1","DisplayName":"r1","Enabled":"True","Direction":"Inbound","Action":"Allow","Profile":"Private"}]"#,
            OVER_JSON_CAP,
        );
        z.start_file("events.evtx", opt).unwrap();
        z.write_all(b"ElfFile\0fake").unwrap();
        z.finish().unwrap();

        let err = match read_bundle(&zip_path) {
            Ok(b) => panic!(
                "expected an over-cap error; got a bundle with {} rules",
                b.rules.len()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("rules.json"),
            "error must name the offending entry: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// context.json parse failures are deliberately soft (an old bundle
    /// without one still imports), but a size-cap breach is not a parse
    /// failure — it must not be swallowed by that fallback.
    #[test]
    fn oversize_context_entry_is_not_silently_ignored() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("fat-context.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("rules.json", opt).unwrap();
        z.write_all(
            serde_json::to_string(&vec![fake_rule("r1"), fake_rule("r2")])
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        // over-cap, yet deserialises fine — today the profile map comes out
        // populated and the import proceeds as if nothing were wrong.
        write_padded_entry(
            &mut z,
            "context.json",
            br#"{"iface_profiles":{"7":"Domain"}}"#,
            OVER_JSON_CAP,
        );
        z.start_file("events.evtx", opt).unwrap();
        z.write_all(b"ElfFile\0fake").unwrap();
        z.finish().unwrap();

        let err = match read_bundle(&zip_path) {
            Ok(b) => panic!(
                "over-cap context.json must be a hard error, not a silent fallback; \
                 got a bundle with {} interface profiles",
                b.profiles.len()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("context.json"),
            "error must name the offending entry: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the context.json contract: *only* an over-cap entry
    /// is hard. A context.json that is well under the cap but unreadable —
    /// bit rot in a bundle that has been emailed between analysts — is a
    /// parse failure, and parse failures are soft ("a malformed one is
    /// likewise not worth failing the import over"). The import must still
    /// succeed, with the default empty profile map, exactly as it does when
    /// context.json is absent altogether.
    #[test]
    fn undersized_malformed_context_entry_still_imports() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("corrupt-context.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();

        // A real context.json with one byte flipped to 0xFF. A lone 0xFF can
        // never occur in valid UTF-8, so this is a faithful stand-in for a
        // corrupted entry — and at ~46 bytes it is six orders of magnitude
        // under the cap, so the cap cannot be what fails.
        let mut corrupt = br#"{"iface_profiles":{"7":"Domain","12":"Public"}}"#.to_vec();
        let at = corrupt.iter().position(|&b| b == b'D').unwrap();
        corrupt[at] = 0xFF;
        assert!(
            std::str::from_utf8(&corrupt).is_err(),
            "fixture must really be invalid UTF-8, or this test proves nothing"
        );
        assert!(
            (corrupt.len() as u64) < JSON_ENTRY_CAP,
            "fixture must be far under the cap, or this is the over-cap test"
        );
        z.start_file("context.json", opt).unwrap();
        z.write_all(&corrupt).unwrap();

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

        let b = match read_bundle(&zip_path) {
            Ok(b) => b,
            Err(e) => panic!(
                "an under-cap unreadable context.json must fall back to the \
                 default, not fail the whole import: {e:#}"
            ),
        };
        assert!(
            b.profiles.is_empty(),
            "unreadable context.json must yield the default (empty) profile \
             map; got {} entries",
            b.profiles.len()
        );
        assert_eq!(b.rules.len(), 2, "the rest of the bundle must still import");
        // The extracted events temp path is shared with the other tests in
        // this binary (same pid), so leave it for whoever asserts on it.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// events.evtx is copied straight to a temp file rather than going through
    /// read_entry, so it needs its own coverage: a bundle whose events entry
    /// really decompresses past 1 GiB must be refused, naming the entry —
    /// not hang, not silently truncate, not succeed. Every other entry here
    /// is small and valid, so the cap is the only thing that can fail.
    #[test]
    fn oversize_events_entry_is_refused() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("fat-events.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("context.json", opt).unwrap();
        z.write_all(br#"{"iface_profiles":{"7":"Domain"}}"#)
            .unwrap();
        z.start_file("rules.json", opt).unwrap();
        z.write_all(
            serde_json::to_string(&vec![fake_rule("r1"), fake_rule("r2")])
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        // real evtx magic, then padding: read_bundle never parses this, so a
        // build that truncates at the cap still returns a "valid" bundle.
        write_padded_entry(&mut z, "events.evtx", b"ElfFile\0", OVER_EVENTS_CAP - 8);
        z.finish().unwrap();

        let got = read_bundle(&zip_path);
        let extracted = got
            .as_ref()
            .ok()
            .and_then(|b| std::fs::metadata(&b.events_path).ok())
            .map(|m| m.len());

        // Clean up *before* asserting: on a red run this test extracts a full
        // 1 GiB, and a panic would otherwise leave it behind every run. The
        // size guard means it can never delete the 12-byte file
        // bundle_round_trip is asserting on — both derive the same temp path
        // from the pid and run in parallel threads of one test binary.
        for (path, size) in sweep_extractions(std::process::id()) {
            let _ = (path, size);
        }
        let _ = std::fs::remove_dir_all(&dir);

        let err = match got {
            Ok(_) => panic!(
                "expected an over-cap error; got a bundle, with {} bytes extracted from events.evtx",
                extracted.unwrap_or(0)
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("events.evtx"),
            "error must name the offending entry: {err}"
        );
    }

    /// Refusing an over-cap events.evtx must not itself cost the machine a
    /// gigabyte. The extraction streams to a temp file *while* it reads, so by
    /// the time the cap is known to be breached that file already holds a full
    /// cap's worth of attacker-chosen bytes — and the only remove_file for it
    /// (pipeline.rs, after import) runs on the success path. Issue #8 is an
    /// availability fix ("an availability hit on an admin's machine at the
    /// moment they're doing security triage"); a refusal that leaves ~1 GiB
    /// behind per attempt just moves that denial from RAM to disk, and the
    /// attacker gets to repeat it. So the refusal must take its partial
    /// extraction with it.
    #[test]
    fn oversize_events_entry_leaves_no_partial_extraction() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("fat-events-cleanup.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("context.json", opt).unwrap();
        z.write_all(br#"{"iface_profiles":{"7":"Domain"}}"#)
            .unwrap();
        z.start_file("rules.json", opt).unwrap();
        z.write_all(
            serde_json::to_string(&vec![fake_rule("r1"), fake_rule("r2")])
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        write_padded_entry(&mut z, "events.evtx", b"ElfFile\0", OVER_EVENTS_CAP - 8);
        z.finish().unwrap();

        // The refusal runs in a *child process*, and only because read_bundle
        // names its extraction after the pid: in-process, every test in this
        // binary shares that one path, so a sibling's File::create truncation
        // or its >64 MiB sweep lands inside this window and empties the very
        // file being asserted on. Measured, not feared — the size-guard
        // version of this test passed against the leaking build under a plain
        // `cargo test`. A child has a pid of its own, so the path below is one
        // nothing else can touch and only read_bundle's own cleanup can empty.
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--ignored",
                "collect::tests::oversize_events_entry_refusal_child",
            ])
            .env("FB_OVERSIZE_BUNDLE", &zip_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("re-running this test binary as a child");
        let child_pid = child.id();
        let out = child.wait_with_output().expect("waiting for the child");

        // Sweep before asserting, as the sibling test does: on a red run a
        // panic would otherwise leave the gigabyte behind every time.
        let swept = sweep_extractions(child_pid);
        let left: u64 = swept.iter().map(|(_, n)| *n).sum();
        let where_ = swept
            .iter()
            .map(|(p, _)| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            out.status.success(),
            "the child must still refuse the over-cap bundle: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            left, 0,
            "refusing the bundle left a {left}-byte partial extraction at {} — a rejected \
             import must not cost the disk it was refused",
            where_
        );
    }

    /// The worker half of [`oversize_events_entry_leaves_no_partial_extraction`],
    /// spawned as a child process so that its extraction temp path is derived
    /// from a pid no other test shares. Deliberately does not tidy up after
    /// itself: whatever read_bundle leaves behind is the evidence, and the
    /// parent sweeps it. Ignored so a plain `cargo test` never picks it up;
    /// without the fixture env var it has nothing to say and returns.
    #[test]
    #[ignore = "spawned by oversize_events_entry_leaves_no_partial_extraction"]
    fn oversize_events_entry_refusal_child() {
        let Ok(zip) = std::env::var("FB_OVERSIZE_BUNDLE") else {
            return;
        };
        let err = match read_bundle(Path::new(&zip)) {
            Ok(b) => panic!(
                "expected an over-cap error; got a bundle extracting to {}",
                b.events_path.display()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("events.evtx"),
            "error must name the offending entry: {err}"
        );
    }

    /// Bytes the corrupt-events fixture streams before its checksum check
    /// fails. Deliberately two orders of magnitude *under* the 1 GiB cap: this
    /// is the extraction-error path, not the cap path, so nothing here may
    /// come near breaching the cap — and 32 MiB is still a real cost to leave
    /// on the disk of every machine that gets handed a bad bundle.
    const CORRUPT_EVENTS_BYTES: usize = 32 * 1024 * 1024;

    /// Invert the four little-endian CRC32 bytes at `at`, so whatever the
    /// writer stored, a reader checking it can no longer match.
    fn flip_crc32(raw: &mut [u8], at: usize) {
        for b in &mut raw[at..at + 4] {
            *b = !*b;
        }
    }

    /// Write a bundle whose events.evtx entry decompresses cleanly for
    /// [`CORRUPT_EVENTS_BYTES`] bytes and only then fails its CRC32 check: the
    /// stored checksum is flipped after the zip is written, in both the local
    /// header and the central directory, so every one of those bytes has
    /// already streamed out before the reader can tell anything is wrong.
    /// That is what a bit-rotted or deliberately tampered events entry looks
    /// like from the extraction's point of view — bytes on disk, then an
    /// error, with no cap anywhere in it.
    fn write_bad_crc_events_bundle(zip_path: &Path) {
        let file = std::fs::File::create(zip_path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        // events.evtx first, so its local header sits at offset 0 and its
        // central-directory record is the first one — the patch below can then
        // find both structurally, without scanning compressed bytes for
        // something that looks like a header signature.
        write_padded_entry(
            &mut z,
            "events.evtx",
            b"ElfFile\0",
            CORRUPT_EVENTS_BYTES - 8,
        );
        write_manifest(&mut z);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("context.json", opt).unwrap();
        z.write_all(br#"{"iface_profiles":{"7":"Domain"}}"#)
            .unwrap();
        z.start_file("rules.json", opt).unwrap();
        z.write_all(
            serde_json::to_string(&vec![fake_rule("r1"), fake_rule("r2")])
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        z.finish().unwrap();

        let mut raw = std::fs::read(zip_path).unwrap();
        let name = b"events.evtx";
        // Local file header (APPNOTE 4.3.7): signature, crc32 at +14,
        // file name at +30.
        assert_eq!(&raw[..4], b"PK\x03\x04", "fixture: no local header at 0");
        assert_eq!(
            &raw[30..30 + name.len()],
            name,
            "fixture: first entry is not events.evtx"
        );
        flip_crc32(&mut raw, 14);
        // End of central directory (APPNOTE 4.3.16): with no archive comment
        // it is exactly the last 22 bytes, and records the directory offset
        // at +16.
        let eocd = raw.len() - 22;
        assert_eq!(
            &raw[eocd..eocd + 4],
            b"PK\x05\x06",
            "fixture: no end-of-central-directory in the last 22 bytes"
        );
        let cd = u32::from_le_bytes(raw[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        // Central directory header (APPNOTE 4.3.12): signature, crc32 at +16,
        // file name at +46. This is the copy the reader actually checks.
        assert_eq!(
            &raw[cd..cd + 4],
            b"PK\x01\x02",
            "fixture: no central directory at the recorded offset"
        );
        assert_eq!(
            &raw[cd + 46..cd + 46 + name.len()],
            name,
            "fixture: first central directory record is not events.evtx"
        );
        flip_crc32(&mut raw, cd + 16);
        std::fs::write(zip_path, &raw).unwrap();
    }

    /// The cap is not the only way the events extraction can fail part-way
    /// through. The same `std::io::copy` that can run past 1 GiB can also
    /// return an error of its own — the entry's CRC32 check failing at the end
    /// of a tampered or bit-rotted stream — and by then it has written just as
    /// many attacker-chosen bytes to the same temp file. The contract is the
    /// one the over-cap refusal already answers to: a refused import must not
    /// cost the disk it was refused. Whichever way the extraction ends badly,
    /// it takes its partial extraction with it.
    #[test]
    fn corrupt_events_entry_leaves_no_partial_extraction() {
        let dir = std::env::temp_dir().join(format!("fb-bundle-test8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("bad-crc-events.zip");
        write_bad_crc_events_bundle(&zip_path);

        // A child process, for the reason the over-cap cleanup test spells out:
        // read_bundle names its extraction after the pid, so in-process every
        // test in this binary shares that one path and a sibling's File::create
        // or remove_file lands inside the window this test is asserting over —
        // which would make it pass against a leaking build. The child's pid is
        // its own, so nothing but read_bundle's own cleanup can empty the path
        // below.
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--ignored",
                "collect::tests::corrupt_events_entry_failure_child",
            ])
            .env("FB_CORRUPT_BUNDLE", &zip_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("re-running this test binary as a child");
        let child_pid = child.id();
        let out = child.wait_with_output().expect("waiting for the child");

        // Sweep before asserting: on a red run a panic would otherwise leave
        // the partial extraction behind on every run.
        let swept = sweep_extractions(child_pid);
        let left: Option<u64> = swept.iter().map(|(_, n)| *n).max();
        let where_ = swept
            .iter()
            .map(|(p, _)| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            out.status.success(),
            "the child must still refuse the corrupt bundle: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            left,
            None,
            "a failed extraction left {} bytes behind at {} — a refused import \
             must not cost the disk it was refused, however the extraction failed",
            left.unwrap_or(0),
            where_
        );
    }

    /// The worker half of [`corrupt_events_entry_leaves_no_partial_extraction`],
    /// spawned as a child process so its extraction temp path is derived from a
    /// pid no other test shares. Deliberately does not tidy up after itself:
    /// whatever read_bundle leaves behind is the evidence, and the parent
    /// sweeps it. Ignored so a plain `cargo test` never picks it up; without
    /// the fixture env var it has nothing to say and returns.
    #[test]
    #[ignore = "spawned by corrupt_events_entry_leaves_no_partial_extraction"]
    fn corrupt_events_entry_failure_child() {
        let Ok(zip) = std::env::var("FB_CORRUPT_BUNDLE") else {
            return;
        };
        let err = match read_bundle(Path::new(&zip)) {
            Ok(b) => panic!(
                "a bundle whose events.evtx fails its checksum must be refused; \
                 got one extracting to {}",
                b.events_path.display()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("events.evtx"),
            "error must name the offending entry: {err}"
        );
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
