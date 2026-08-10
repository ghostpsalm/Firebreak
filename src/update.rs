//! Self-update via GitHub Releases.
//!
//! HTTP goes through WinHTTP (see `winhttp.rs`) — no subprocess, OS TLS stack,
//! no networking crate — with a PowerShell fallback while the WinHTTP path is
//! still being verified on real hardware. The download always comes from the
//! stable "latest" URL, so a single link persists across versions; the API is
//! only consulted to learn the newest tag for comparison.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// `owner/repo` hosting the releases. Local-only today — set this to the real
/// repository when firebreak is published. Until a reachable release exists the
/// update UI degrades gracefully (it reports that it couldn't reach updates).
pub const REPO: &str = "ghostpsalm/Firebreak";

/// The asset this build updates itself from. Each platform publishes its own
/// binary to the same release, so a Linux host never downloads a .exe.
#[cfg(windows)]
pub const ASSET: &str = "firebreak.exe";
#[cfg(target_os = "linux")]
pub const ASSET: &str = "firebreak-linux-x86_64";
#[cfg(not(any(windows, target_os = "linux")))]
pub const ASSET: &str = "firebreak";

/// The single persistent download link — always resolves to the newest asset.
pub fn download_url() -> String {
    format!("https://github.com/{REPO}/releases/latest/download/{ASSET}")
}

/// Detached minisign signature published next to the asset.
pub fn signature_url() -> String {
    format!("{}.minisig", download_url())
}

/// Base64 minisign public key that release assets are signed with — the key
/// line (second line) of `signing/firebreak.pub`. Its private counterpart
/// lives git-ignored under `signing/` and signs `firebreak.exe.minisig` for
/// each release. Empty here would make `download_and_install` refuse to run
/// (fail closed), so an unverified binary is never installed with this tool's
/// elevated privileges (issue #2).
pub const TRUSTED_PUBLIC_KEY: &str = "RWQqalkBegJ2f0SS5E5JvOJX6WnuZfhaCKYiSdOrmugiiZoufxFMTplC";

/// Whether this build can verify an update (a signing key is pinned).
pub fn signing_configured() -> bool {
    !TRUSTED_PUBLIC_KEY.is_empty()
}

#[derive(Clone)]
pub struct Release {
    /// Newest published version, normalized to `major.minor.patch.build`.
    pub latest: String,
    /// The running build's version string.
    pub current: String,
    /// True when `latest` is strictly newer than `current`.
    pub newer: bool,
}

/// Ask GitHub for the latest release tag and compare it to the running build.
pub fn check() -> Result<Release> {
    let tag = latest_tag()?;
    if tag.is_empty() {
        return Err(anyhow!("no release published yet"));
    }
    let latest = normalize(&tag);
    let current = crate::pipeline::version_string();
    let newer = is_newer(&latest, &current);
    Ok(Release {
        latest,
        current,
        newer,
    })
}

/// The newest release tag.
fn latest_tag() -> Result<String> {
    let api = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = fetch_json(&api).context("asking GitHub for the latest release")?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).context("parsing releases/latest JSON")?;
    Ok(json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}

/// GitHub's API needs an Accept header; asset downloads do not.
#[cfg(windows)]
fn fetch_json(url: &str) -> Result<Vec<u8>> {
    match crate::winhttp::get(url, "Accept: application/vnd.github+json") {
        Ok(body) => Ok(body),
        Err(e) => {
            eprintln!("WinHTTP update check failed ({e:#}); falling back to PowerShell");
            latest_tag_subprocess_bytes(url)
        }
    }
}

#[cfg(not(windows))]
fn fetch_json(url: &str) -> Result<Vec<u8>> {
    fetch(url)
}

#[cfg(windows)]
fn latest_tag_subprocess_bytes(api: &str) -> Result<Vec<u8>> {
    latest_tag_subprocess(api).map(|tag| {
        // re-wrap as the minimal JSON the caller parses
        format!("{{\"tag_name\":\"{tag}\"}}").into_bytes()
    })
}

#[cfg(windows)]
fn latest_tag_subprocess(api: &str) -> Result<String> {
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         (Invoke-RestMethod -UseBasicParsing -Uri '{api}' \
           -Headers @{{'User-Agent'='firebreak';'Accept'='application/vnd.github+json'}}).tag_name"
    );
    let out = crate::syspath::command(crate::syspath::powershell())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context("launching PowerShell for the update check")?;
    if !out.status.success() {
        return Err(anyhow!(
            "couldn't reach updates: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Download the latest asset, verify its signature, and swap it in next to the
/// running exe. On success the running image has been moved to `<name>.old`
/// and the new build sits in its place; the caller then prompts a restart.
/// Returns the path to relaunch.
///
/// The download is verified against the pinned minisign key *before* it is
/// written into place and later run elevated — an unverifiable or
/// signature-mismatched artifact is refused (fail closed).
pub fn download_and_install() -> Result<PathBuf> {
    download_and_install_with(&|_| {})
}

/// What a download has moved so far. `total` is `None` when the server did
/// not say — the dialog then shows bytes rather than inventing a percentage.
#[derive(Debug, Clone, Copy, Default)]
pub struct Progress {
    pub received: u64,
    pub total: Option<u64>,
}

impl Progress {
    /// Fraction complete, if that is knowable. Clamped, because a server
    /// that under-reports its own content length must not drive a bar past
    /// its end.
    pub fn fraction(self) -> Option<f32> {
        let total = self.total.filter(|t| *t > 0)?;
        Some((self.received as f32 / total as f32).clamp(0.0, 1.0))
    }
}

/// As [`download_and_install`], reporting download progress as it goes.
pub fn download_and_install_with(progress: &(dyn Fn(Progress) + Sync)) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the running exe")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("running exe has no parent directory"))?;
    let new = dir.join(format!("{ASSET}.new"));
    let old = dir.join(format!("{ASSET}.old"));

    let bytes = fetch_with_progress(&download_url(), progress).context("downloading the update")?;
    if bytes.len() < 1024 {
        return Err(anyhow!(
            "the downloaded file looks incomplete ({} bytes)",
            bytes.len()
        ));
    }
    // authenticity gate: this binary runs elevated, so never install code we
    // can't verify came from the holder of the pinned signing key
    verify_signature(&bytes)?;

    std::fs::write(&new, &bytes).with_context(|| format!("writing {}", new.display()))?;

    // A downloaded file is not executable on Unix. Without this the swap
    // succeeds and the *next* launch fails with a permission error, which
    // looks like a corrupt update rather than a missing mode bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("making {} executable", new.display()))?;
    }

    // Neither platform lets a running image be overwritten in place, but both
    // allow it to be renamed: move the running binary aside, then swap the
    // new build into its place.
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).context("moving the running exe aside")?;
    if let Err(e) = std::fs::rename(&new, &exe) {
        let _ = std::fs::rename(&old, &exe); // roll back so the app still exists on disk
        return Err(anyhow::Error::new(e).context("installing the new exe"));
    }

    // Keep the desktop entry pointing at a binary that exists. It is written
    // against `exe`, not `current_exe()`: the swap above just moved the
    // running image to `.old`, so /proc/self/exe now names a file the next
    // run deletes. Best effort — a read-only /usr is a reason to skip the
    // launcher, never a reason to fail an update that already succeeded.
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::desktop::install_at(&exe) {
        eprintln!("update installed; the desktop entry was not refreshed: {e:#}");
    }

    Ok(exe)
}

/// Verify `bytes` against the pinned minisign public key using the detached
/// `.minisig` published next to the asset. Fails closed: no configured key,
/// an unfetchable/malformed signature, or a mismatch all refuse the install.
fn verify_signature(bytes: &[u8]) -> Result<()> {
    use minisign_verify::{PublicKey, Signature};
    if !signing_configured() {
        return Err(anyhow!(
            "self-update is unavailable in this build: no release-signing key is configured, \
             so the download cannot be verified and will not be installed"
        ));
    }
    let pk = PublicKey::from_base64(TRUSTED_PUBLIC_KEY)
        .map_err(|e| anyhow!("invalid pinned public key: {e}"))?;
    let sig_text = fetch(&signature_url())
        .context("downloading the release signature (.minisig)")
        .and_then(|b| String::from_utf8(b).context("signature is not valid UTF-8"))?;
    let sig = Signature::decode(&sig_text).map_err(|e| anyhow!("malformed signature: {e}"))?;
    pk.verify(bytes, &sig, false)
        .map_err(|e| anyhow!("signature verification failed — refusing to install: {e}"))?;
    Ok(())
}

/// Fetch a URL into memory. WinHTTP first (no subprocess); PowerShell fallback.
#[cfg(windows)]
fn fetch(url: &str) -> Result<Vec<u8>> {
    match crate::winhttp::get(url, "") {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            eprintln!("WinHTTP fetch failed ({e:#}); falling back to PowerShell");
            let dest =
                std::env::temp_dir().join(format!("firebreak-fetch-{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&dest);
            let script = format!(
                "$ErrorActionPreference='Stop'; \
                 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
                 Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{}'",
                dest.display()
            );
            let out = crate::syspath::command(crate::syspath::powershell())
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .context("launching PowerShell for the download")?;
            if !out.status.success() {
                let _ = std::fs::remove_file(&dest);
                return Err(anyhow!(
                    "download failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let bytes =
                std::fs::read(&dest).with_context(|| format!("reading {}", dest.display()))?;
            let _ = std::fs::remove_file(&dest);
            Ok(bytes)
        }
    }
}

/// Fetch a URL on Linux. curl is spawned by absolute path rather than
/// linking a TLS stack: the tool already spawns system binaries this way,
/// and adding an HTTP client would pull a second TLS implementation into a
/// binary that runs as root. HTTPS is pinned with --proto so a redirect
/// cannot downgrade the transport.
#[cfg(not(windows))]
fn fetch(url: &str) -> Result<Vec<u8>> {
    fetch_to(url, &fetch_dest())
}

/// Where curl streams a download. One path per process, so the progress
/// watcher and the fetch itself are looking at the same file.
#[cfg(not(windows))]
fn fetch_dest() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("firebreak-fetch-{}.bin", std::process::id()))
}

#[cfg(not(windows))]
fn fetch_to(url: &str, dest: &Path) -> Result<Vec<u8>> {
    let curl = crate::syspath::system_tool("curl")
        .ok_or_else(|| anyhow!("curl is not installed, so Firebreak cannot download an update"))?;
    let _ = std::fs::remove_file(dest);
    let out = crate::syspath::command(curl)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            // never let a redirect move us off HTTPS
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "120",
            "--user-agent",
            "firebreak",
            "--header",
            "Accept: application/vnd.github+json",
            "--output",
            &dest.to_string_lossy(),
            url,
        ])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        let _ = std::fs::remove_file(dest);
        return Err(anyhow!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let bytes = std::fs::read(dest).with_context(|| format!("reading {}", dest.display()))?;
    let _ = std::fs::remove_file(dest);
    Ok(bytes)
}

/// Download with progress.
///
/// On Linux curl streams to a file, so progress is the file's size as it
/// grows — watched from a second thread while curl runs. The total comes
/// from a HEAD request first; if that fails the download still proceeds and
/// the dialog shows bytes instead of a percentage. Nothing about the
/// transfer changes: this only watches it.
#[cfg(not(windows))]
fn fetch_with_progress(url: &str, progress: &(dyn Fn(Progress) + Sync)) -> Result<Vec<u8>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let total = content_length(url);
    progress(Progress { received: 0, total });

    let dest = fetch_dest();
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let watcher_done = done.clone();
        let watch = dest.clone();
        scope.spawn(move || {
            while !watcher_done.load(Ordering::Relaxed) {
                if let Ok(md) = std::fs::metadata(&watch) {
                    progress(Progress {
                        received: md.len(),
                        total,
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
        });
        let out = fetch_to(url, &dest);
        done.store(true, Ordering::Relaxed);
        out
    })
    .inspect(|bytes| {
        // land the bar on 100% rather than wherever the last poll caught it
        progress(Progress {
            received: bytes.len() as u64,
            total: total.or(Some(bytes.len() as u64)),
        });
    })
}

/// The asset's size, so the bar has an end. Best effort — a HEAD that fails
/// costs the percentage, not the download.
#[cfg(not(windows))]
fn content_length(url: &str) -> Option<u64> {
    let curl = crate::syspath::system_tool("curl")?;
    let out = crate::syspath::command(curl)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--head",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "30",
            "--user-agent",
            "firebreak",
            "--output",
            "/dev/null",
            "--write-out",
            "%{size_download}\n%{header_json}",
            url,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(text.split_once('\n')?.1).ok()?;
    json.get("content-length")?
        .as_array()?
        .first()?
        .as_str()?
        .trim()
        .parse()
        .ok()
}

#[cfg(windows)]
fn fetch_with_progress(url: &str, progress: &(dyn Fn(Progress) + Sync)) -> Result<Vec<u8>> {
    // WinHTTP reads in chunks, so bytes-so-far is free; the total is the
    // Content-Length header when the server sends one.
    match crate::winhttp::get_with_progress(url, "", &|received, total| {
        progress(Progress { received, total })
    }) {
        Ok(bytes) => Ok(bytes),
        // the PowerShell fallback writes the file in one call and reports
        // nothing on the way — the dialog stays on "Downloading…"
        Err(_) => fetch(url),
    }
}

/// Relaunch the freshly installed exe and exit this process.
pub fn restart(exe: &Path) -> ! {
    // Come back the way we were started. Relaunching bare drops whatever
    // the user ran with — and on Linux a bare launch hits the root check and
    // exits immediately, so "Restart now" would simply close the app.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let _ = crate::syspath::command(exe).args(&args).spawn();
    std::process::exit(0);
}

/// Best-effort cleanup of a leftover `.old` from a previous update. Call once at
/// startup, after the OS has released the old image.
pub fn cleanup_old() {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::remove_file(dir.join(format!("{ASSET}.old")));
        }
    }
}

fn normalize(tag: &str) -> String {
    tag.trim().trim_start_matches(['v', 'V']).to_string()
}

/// Numeric dotted-version comparison; missing trailing components count as 0.
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| {
        s.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (a, b) = (parse(latest), parse(current));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A progress bar that fills before the file arrives, or fills at all on
    /// a transfer whose size nobody stated, is worse than no bar: it says
    /// "done" while the download is still running.
    #[test]
    fn a_bar_is_only_drawn_when_the_size_is_actually_known() {
        let p = |received, total| Progress { received, total };
        assert_eq!(p(0, Some(100)).fraction(), Some(0.0));
        assert_eq!(p(50, Some(100)).fraction(), Some(0.5));
        assert_eq!(p(100, Some(100)).fraction(), Some(1.0));
        assert_eq!(p(10, None).fraction(), None, "unknown total, no fraction");
        assert_eq!(
            p(10, Some(0)).fraction(),
            None,
            "a zero total is not a size"
        );
        assert_eq!(
            p(150, Some(100)).fraction(),
            Some(1.0),
            "a server under-reporting its own length must not push the bar past its end"
        );
    }

    #[test]
    fn strips_v_prefix() {
        assert_eq!(normalize("v0.5.4.1200"), "0.5.4.1200");
        assert_eq!(normalize("0.5.4"), "0.5.4");
    }

    #[test]
    fn newer_by_component() {
        assert!(is_newer("0.5.4.10", "0.5.3.999"));
        assert!(is_newer("0.5.3.1001", "0.5.3.1000"));
        assert!(is_newer("1.0.0.0", "0.9.9.9"));
    }

    #[test]
    fn not_newer_when_equal_or_older() {
        assert!(!is_newer("0.5.3.1000", "0.5.3.1000"));
        assert!(!is_newer("0.5.3", "0.5.3.0"));
        assert!(!is_newer("0.5.2.5000", "0.5.3.1"));
    }

    #[test]
    fn pinned_public_key_is_configured_and_valid() {
        // a signing key is pinned (self-update is verified, not fail-closed)…
        assert!(signing_configured());
        // …and it is a well-formed minisign key the verifier can load, so a
        // typo'd pin fails the build's tests rather than at update time
        assert!(
            minisign_verify::PublicKey::from_base64(TRUSTED_PUBLIC_KEY).is_ok(),
            "pinned TRUSTED_PUBLIC_KEY is not a valid minisign public key"
        );
    }
}
