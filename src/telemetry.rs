//! Opt-in usage ping.
//!
//! Firebreak runs with administrator/root rights over a machine's firewall.
//! A tool in that position that quietly phones home has earned every bit of
//! suspicion it gets, so this module is built to be *auditable* rather than
//! merely disclosed:
//!
//! - **Nothing is sent until the operator says yes.** [`Consent::Unasked`] is
//!   the default and it sends nothing. The GUI asks once; a headless run
//!   cannot ask, so it never sends unless `--telemetry on` was run.
//! - **`--telemetry preview` prints the exact bytes that would be posted.**
//!   Not a description of them — the payload itself, from the same code path
//!   that sends it. Nobody should have to take this file's word for it.
//! - **The payload is a fixed, closed set of low-cardinality facts.** Every
//!   field is built here from an enumerated source; there is no pass-through
//!   of anything the host names. No hostnames, no rule names, no paths, no
//!   IPs, no serial numbers, no usernames.
//! - **It is dormant unless a build points it somewhere.** [`ENDPOINT`] is
//!   empty in a source checkout, and empty means the whole feature — prompt
//!   included — is switched off. Same fail-closed shape as the update key.
//!
//! What deliberately is *not* here: exact counters and exact ages. The
//! install ID rotates ([`ID_LIFETIME_DAYS`]), and an exact "day 412, 1,043
//! runs" would let two IDs be stitched back together across a rotation and
//! defeat the point. Ages and run counts are therefore reported as buckets.

use anyhow::Result;
use serde::Serialize;

use crate::store::Store;

/// Where the ping goes. **Empty disables the entire feature** — no prompt, no
/// state written, no request — which is what a source checkout should do.
/// Set it to your collector (see `server/README.md`) when cutting a build
/// that should report. Must be `https://`.
pub const ENDPOINT: &str = "";

/// Payload schema version. Bump when a field's meaning changes; the receiver
/// rejects a schema it does not know rather than guessing.
pub const SCHEMA: u32 = 1;

/// How often a given install may ping. A run is cheap; a ping is once a day.
const PING_INTERVAL_HOURS: i64 = 24;

/// How long an install ID lives before it is replaced with a fresh random
/// one. Long enough to measure whether people come back over a quarter,
/// short enough that the ID is not a permanent handle on a machine.
pub const ID_LIFETIME_DAYS: i64 = 90;

/// Cap on any single string that reaches the payload. DMI strings come from
/// firmware and are occasionally junk; this bounds what junk can cost.
const MAX_FIELD: usize = 64;

// ---- meta keys ----

const K_CONSENT: &str = "telemetry.consent";
const K_INSTALL_ID: &str = "telemetry.install_id";
const K_ID_ISSUED: &str = "telemetry.id_issued";
const K_ENROLLED: &str = "telemetry.enrolled";
const K_RUNS: &str = "telemetry.runs";
const K_LAST_PING: &str = "telemetry.last_ping";
/// Prefix for "this install has used feature X at least once".
const K_FEATURE: &str = "telemetry.feat.";

/// Environment escape hatch. Set to anything non-empty and Firebreak neither
/// asks nor sends, whatever is stored. For images, kiosks and CI.
pub const ENV_OPT_OUT: &str = "FIREBREAK_NO_TELEMETRY";

// ---- consent ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Never asked. Sends nothing.
    Unasked,
    Granted,
    Denied,
}

impl Consent {
    fn as_str(self) -> &'static str {
        match self {
            Consent::Unasked => "unasked",
            Consent::Granted => "granted",
            Consent::Denied => "denied",
        }
    }

    fn parse(s: &str) -> Consent {
        match s {
            "granted" => Consent::Granted,
            "denied" => Consent::Denied,
            // An unrecognised value is treated as "never asked", which sends
            // nothing. Corruption must not be able to manufacture consent.
            _ => Consent::Unasked,
        }
    }
}

/// Whether this build can report at all. False in a source checkout.
pub fn configured() -> bool {
    ENDPOINT.starts_with("https://")
}

/// Whether the environment has switched telemetry off for this run.
pub fn env_opted_out() -> bool {
    std::env::var_os(ENV_OPT_OUT).is_some_and(|v| !v.is_empty())
}

/// The answer as it sits in the database, ignoring whether this build could
/// act on it. Only `--telemetry status` wants this view; everything that
/// decides whether to send or prompt wants [`consent`].
fn stored_consent(store: &Store) -> Consent {
    store
        .get_meta(K_CONSENT)
        .ok()
        .flatten()
        .map(|v| Consent::parse(&v))
        .unwrap_or(Consent::Unasked)
}

/// The effective answer. `Unasked` when the feature is off, so a build with
/// no endpoint never shows a consent prompt and never sends.
pub fn consent(store: &Store) -> Consent {
    if !configured() {
        return Consent::Unasked;
    }
    stored_consent(store)
}

/// Plain account of what is stored and whether anything will be sent. Backs
/// `--telemetry status`; every claim it makes is read back out of the
/// database rather than assumed.
pub fn status_lines(store: &Store) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "Collector:   {}",
        if configured() {
            ENDPOINT
        } else {
            "none — this build has no endpoint and cannot send anything"
        }
    ));
    out.push(format!(
        "Consent:     {}",
        match stored_consent(store) {
            Consent::Granted => "granted — one ping a day",
            Consent::Denied => "denied — nothing is sent",
            Consent::Unasked => "not asked yet — nothing is sent",
        }
    ));
    if env_opted_out() {
        out.push(format!(
            "Environment: {ENV_OPT_OUT} is set — disabled for this run whatever the above says"
        ));
    }
    out.push(match store.get_meta(K_INSTALL_ID).ok().flatten() {
        Some(id) => format!("Install ID:  {id} (random, rotates every {ID_LIFETIME_DAYS} days)"),
        None => "Install ID:  none — nothing has identified this machine yet".into(),
    });
    out.push(match store.get_meta(K_LAST_PING).ok().flatten() {
        Some(t) => format!("Last ping:   {t}"),
        None => "Last ping:   never".into(),
    });
    if let Ok(f) = features(store) {
        out.push(format!(
            "Features:    {}",
            if f.is_empty() {
                "none recorded".to_string()
            } else {
                f.join(", ")
            }
        ));
    }
    out
}

/// Record the operator's answer. Granting starts the enrolment clock and
/// mints the first install ID; denying erases every telemetry key except the
/// answer itself, so a "no" leaves nothing behind to send later.
pub fn set_consent(
    store: &Store,
    answer: Consent,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    store.set_meta(K_CONSENT, answer.as_str())?;
    match answer {
        Consent::Granted => {
            if store.get_meta(K_ENROLLED)?.is_none() {
                store.set_meta(K_ENROLLED, &now.to_rfc3339())?;
            }
        }
        Consent::Denied | Consent::Unasked => {
            for k in [K_INSTALL_ID, K_ID_ISSUED, K_ENROLLED, K_RUNS, K_LAST_PING] {
                store.delete_meta(k)?;
            }
        }
    }
    Ok(())
}

// ---- identity ----

/// This install's current random ID, minting or rotating it as needed.
///
/// Rotation is the reason the payload's ages are buckets: a fresh ID paired
/// with an exact age would simply re-identify the machine.
fn install_id(store: &Store, now: chrono::DateTime<chrono::Utc>) -> Result<String> {
    let issued = store
        .get_meta(K_ID_ISSUED)?
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    let existing = store.get_meta(K_INSTALL_ID)?;

    let stale = match issued {
        Some(t) => (now - t).num_days() >= ID_LIFETIME_DAYS,
        None => true,
    };
    if let (false, Some(id)) = (stale, existing) {
        return Ok(id);
    }
    let id = random_hex_128();
    store.set_meta(K_INSTALL_ID, &id)?;
    store.set_meta(K_ID_ISSUED, &now.to_rfc3339())?;
    Ok(id)
}

/// 128 bits of installation identity. Not a secret and not a crypto key —
/// the requirement is that two installs do not collide and that the value
/// cannot be derived from anything about the machine.
///
/// `/dev/urandom` where there is one; elsewhere the same `RandomState`
/// source `syspath::scratch_path` relies on, mixed with the clock and the
/// pid so two IDs minted in one process cannot be near-neighbours.
fn random_hex_128() -> String {
    // read_exact, never read_to_end: /dev/urandom has no EOF.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        if f.read_exact(&mut bytes).is_ok() {
            return bytes.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    use std::hash::{BuildHasher, Hasher};
    let mix = |salt: u64| {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(salt);
        h.write_u64(std::process::id() as u64);
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.finish()
    };
    format!("{:016x}{:016x}", mix(0), mix(1))
}

// ---- feature marks ----

/// Note that this install has used a feature at least once.
///
/// A mark, not a counter: "has ever exported a bundle" answers what to
/// invest in, while an exact tally would only sharpen the fingerprint.
/// No-op unless telemetry is actually switched on, so a denied install
/// accumulates nothing.
pub fn mark(store: &Store, feature: Feature) {
    if consent(store) != Consent::Granted {
        return;
    }
    let _ = store.set_meta(&format!("{K_FEATURE}{}", feature.as_str()), "1");
}

/// The closed set of things worth knowing are used. Adding a variant is a
/// deliberate act — there is no way to record an arbitrary string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Ran with --no-ui (a report on a server, not the window)
    Headless,
    /// Exported a portable audit bundle
    Collect,
    /// Opened someone else's bundle
    Review,
    /// Applied a change to the firewall
    Apply,
    /// Installed the firewalld shadow counter table
    EnableOnly,
    /// Checked for or installed an update
    Update,
    /// Installed the desktop entry
    Desktop,
    /// Exported a support bundle
    Support,
}

impl Feature {
    fn as_str(self) -> &'static str {
        match self {
            Feature::Headless => "headless",
            Feature::Collect => "collect",
            Feature::Review => "review",
            Feature::Apply => "apply",
            Feature::EnableOnly => "enable_only",
            Feature::Update => "update",
            Feature::Desktop => "desktop",
            Feature::Support => "support",
        }
    }

    /// Every variant, so the payload's feature list can be assembled without
    /// scanning the meta table for a prefix.
    fn all() -> [Feature; 8] {
        [
            Feature::Headless,
            Feature::Collect,
            Feature::Review,
            Feature::Apply,
            Feature::EnableOnly,
            Feature::Update,
            Feature::Desktop,
            Feature::Support,
        ]
    }
}

// ---- buckets ----

/// Age in days → a coarse band. See the module note on why this is not a
/// number.
///
/// The collector validates against a copy of this list
/// (`server/receiver/src/ping.rs`), so a new band has to be deployed there
/// before a client that can emit it ships — otherwise every ping from the
/// new build is rejected. Same for [`run_bucket`] and [`Feature`].
fn age_bucket(days: i64) -> &'static str {
    match days {
        d if d <= 0 => "0",
        d if d <= 7 => "1-7",
        d if d <= 30 => "8-30",
        d if d <= 90 => "31-90",
        d if d <= 365 => "91-365",
        _ => "365+",
    }
}

/// Run count → a coarse band.
fn run_bucket(runs: u64) -> &'static str {
    match runs {
        0..=1 => "1",
        2..=5 => "2-5",
        6..=20 => "6-20",
        21..=100 => "21-100",
        _ => "100+",
    }
}

// ---- payload ----

/// Exactly what leaves the machine. Every field is documented because this
/// struct is the honest answer to "what do you send?", and `docs/telemetry.md`
/// is generated from the same list by hand — keep them in step.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Payload {
    /// Payload format version.
    pub schema: u32,
    /// Random 128-bit install ID, rotated every 90 days.
    pub install_id: String,
    /// Firebreak's own version, e.g. "0.7.81".
    pub app_version: String,
    /// "windows" or "linux".
    pub os: String,
    /// Distro or Windows family, e.g. "Fedora Linux" / "Windows 11".
    pub os_name: String,
    /// Release identifier, e.g. "44" / "26100 (24H2)".
    pub os_version: String,
    /// Target architecture of the running build, e.g. "x86_64".
    pub arch: String,
    /// Which firewall backend was in charge: wfp / ufw / firewalld /
    /// nftables / none.
    pub backend: String,
    /// Motherboard or system manufacturer from DMI, e.g. "ASUSTeK". Vendor
    /// only — model and serial are never read.
    pub board_vendor: String,
    /// Whether the DMI vendor is a known hypervisor.
    pub virtual_machine: bool,
    /// How long telemetry has been enabled here, bucketed.
    pub age: String,
    /// How many times Firebreak has run since then, bucketed.
    pub runs: String,
    /// Features used at least once, sorted. Closed vocabulary — see
    /// [`Feature`].
    pub features: Vec<String>,
}

/// Facts read from the host. Split out from [`Payload`] so the per-platform
/// probing can be tested and reviewed without the store or the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub os: String,
    pub os_name: String,
    pub os_version: String,
    pub arch: String,
    pub board_vendor: String,
    pub virtual_machine: bool,
}

/// Assemble the payload. Pure given its inputs, so a test can pin the exact
/// shape of what would be posted.
fn build(
    facts: &Facts,
    backend: &str,
    install_id: String,
    enrolled_days: i64,
    runs: u64,
    features: Vec<String>,
) -> Payload {
    Payload {
        schema: SCHEMA,
        install_id,
        app_version: crate::pipeline::version_string(),
        os: facts.os.clone(),
        os_name: facts.os_name.clone(),
        os_version: facts.os_version.clone(),
        arch: facts.arch.clone(),
        backend: clean(backend),
        board_vendor: facts.board_vendor.clone(),
        virtual_machine: facts.virtual_machine,
        age: age_bucket(enrolled_days).to_string(),
        runs: run_bucket(runs).to_string(),
        features,
    }
}

/// The payload this run would post, whatever the consent state. Backs
/// `--telemetry preview`, so it must go through exactly the same assembly
/// the sender uses — a preview that is merely a good description of the
/// payload is worth nothing.
pub fn preview(store: &Store, backend: &str) -> Result<Payload> {
    let now = chrono::Utc::now();
    let facts = facts(backend);
    let id = store
        .get_meta(K_INSTALL_ID)?
        .unwrap_or_else(|| "<minted on first ping>".into());
    Ok(build(
        &facts,
        backend,
        id,
        enrolled_days(store, now)?,
        runs(store)?,
        features(store)?,
    ))
}

fn enrolled_days(store: &Store, now: chrono::DateTime<chrono::Utc>) -> Result<i64> {
    Ok(store
        .get_meta(K_ENROLLED)?
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|t| (now - t.with_timezone(&chrono::Utc)).num_days())
        .unwrap_or(0))
}

fn runs(store: &Store) -> Result<u64> {
    Ok(store
        .get_meta(K_RUNS)?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

fn features(store: &Store) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for f in Feature::all() {
        let key = format!("{K_FEATURE}{}", f.as_str());
        if store.get_meta(&key)?.is_some() {
            out.push(f.as_str().to_string());
        }
    }
    out.sort();
    Ok(out)
}

// ---- sending ----

/// A ping in flight.
///
/// Bind it to a named local (`let _ping = …`) for the whole run: waiting
/// happens on drop, so every early return is covered without a caller having
/// to remember one. `let _ = …` would drop it immediately and wait there
/// instead, which is not what anyone means.
pub struct Ping {
    done: std::sync::mpsc::Receiver<()>,
}

impl Drop for Ping {
    /// Give the request a bounded chance to land before the process exits.
    /// A ping is never worth making someone wait longer than this, and never
    /// worth failing a run over, so the timeout is silent.
    fn drop(&mut self) {
        let _ = self.done.recv_timeout(std::time::Duration::from_secs(5));
    }
}

/// Bump the run counter and post a ping if one is due.
///
/// Returns `None` — having done nothing at all — unless every one of these
/// holds: the build has an endpoint, the environment has not opted out, this
/// run has not opted out, consent was granted, and 24h have passed since the
/// last ping.
pub fn maybe_send(store: &Store, backend: &str, suppressed: bool) -> Option<Ping> {
    if !configured() || suppressed || env_opted_out() || consent(store) != Consent::Granted {
        return None;
    }
    let now = chrono::Utc::now();

    // The run happened whether or not it is reported, so count it first.
    let n = runs(store).unwrap_or(0).saturating_add(1);
    let _ = store.set_meta(K_RUNS, &n.to_string());

    if !due(store, now) {
        return None;
    }
    let payload = build(
        &facts(backend),
        backend,
        install_id(store, now).ok()?,
        enrolled_days(store, now).ok()?,
        n,
        features(store).ok()?,
    );
    let body = serde_json::to_vec(&payload).ok()?;

    // Stamped before the request, not after: a collector that is down must
    // not turn every run into a retry storm against it.
    let _ = store.set_meta(K_LAST_PING, &now.to_rfc3339());

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = post(ENDPOINT, &body);
        let _ = tx.send(());
    });
    Some(Ping { done: rx })
}

fn due(store: &Store, now: chrono::DateTime<chrono::Utc>) -> bool {
    match store.get_meta(K_LAST_PING).ok().flatten() {
        Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
            Ok(t) => (now - t.with_timezone(&chrono::Utc)).num_hours() >= PING_INTERVAL_HOURS,
            // An unparseable stamp is treated as "due" — the alternative is
            // an install that silently stops reporting forever.
            Err(_) => true,
        },
        None => true,
    }
}

/// POST the payload. Split per platform the same way `update` splits its
/// fetch: WinHTTP on Windows, curl on Linux, so no second TLS stack is
/// linked into a binary that runs elevated.
#[cfg(windows)]
fn post(url: &str, body: &[u8]) -> Result<()> {
    let status = crate::winhttp::post_json(url, body)?;
    if status >= 400 {
        anyhow::bail!("collector returned HTTP {status}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn post(url: &str, body: &[u8]) -> Result<()> {
    use anyhow::{anyhow, Context};

    let curl =
        crate::syspath::system_tool("curl").ok_or_else(|| anyhow!("curl is not installed"))?;
    let mut child = crate::syspath::command(curl)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            // never let a redirect move the payload off HTTPS
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "5",
            "--user-agent",
            "firebreak",
            "--header",
            "Content-Type: application/json",
            // read the body from stdin so it never appears in the process
            // table, where every user on the box can read it
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("running curl")?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(body);
    }
    let out = child.wait_with_output().context("waiting for curl")?;
    if !out.status.success() {
        return Err(anyhow!(
            "ping failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

// ---- host facts ----

/// Strip a firmware or OS string down to something safe and low-cardinality:
/// no control characters, collapsed whitespace, length-capped.
fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_FIELD));
    let mut n = 0usize;
    let mut space = false;
    for c in s.chars() {
        if c.is_control() {
            continue;
        }
        if c.is_whitespace() {
            space = n > 0;
            continue;
        }
        // the separator costs a slot, so it is counted before it is written
        // — otherwise a cap-length string could end on a dangling space
        let needed = if space { 2 } else { 1 };
        if n + needed > MAX_FIELD {
            break;
        }
        if space {
            out.push(' ');
            n += 1;
            space = false;
        }
        out.push(c);
        n += 1;
    }
    out
}

/// DMI vendor strings that mean "this is a guest". Used only to separate VM
/// runs from bare metal when reading the numbers.
const HYPERVISOR_VENDORS: [&str; 8] = [
    "qemu",
    "vmware",
    "innotek", // VirtualBox
    "oracle",  // VirtualBox / OCI
    "xen",
    "parallels",
    "bochs",
    "amazon ec2",
];

fn looks_virtual(vendor: &str, product: &str) -> bool {
    let v = vendor.to_ascii_lowercase();
    let p = product.to_ascii_lowercase();
    if HYPERVISOR_VENDORS.iter().any(|h| v.contains(h)) {
        return true;
    }
    // Hyper-V reports a perfectly ordinary vendor and gives itself away only
    // in the product name.
    p.contains("virtual machine") || p.contains("hvm domu")
}

/// Everything the payload knows about the host.
pub fn facts(_backend: &str) -> Facts {
    let (os_name, os_version, vendor, product) = probe();
    Facts {
        os: if cfg!(windows) { "windows" } else { "linux" }.to_string(),
        os_name: clean(&os_name),
        os_version: clean(&os_version),
        arch: std::env::consts::ARCH.to_string(),
        virtual_machine: looks_virtual(&vendor, &product),
        board_vendor: clean(&vendor),
    }
}

/// (os_name, os_version, dmi_vendor, dmi_product)
#[cfg(target_os = "linux")]
fn probe() -> (String, String, String, String) {
    let release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |key: &str| -> String {
        release
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim_matches(['"', '\'']).to_string())
            .unwrap_or_default()
    };
    // Vendor only. /sys/class/dmi/id/product_serial and board_serial sit
    // right next to these and are deliberately never read.
    let dmi = |f: &str| -> String {
        std::fs::read_to_string(format!("/sys/class/dmi/id/{f}"))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let vendor = match dmi("board_vendor") {
        v if v.is_empty() => dmi("sys_vendor"),
        v => v,
    };
    (
        field("NAME="),
        field("VERSION_ID="),
        vendor,
        dmi("product_name"),
    )
}

#[cfg(windows)]
fn probe() -> (String, String, String, String) {
    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";

    let build = reg_string(CURRENT_VERSION, "CurrentBuild").unwrap_or_default();
    let display = reg_string(CURRENT_VERSION, "DisplayVersion").unwrap_or_default();

    // ProductName still reads "Windows 10 …" on Windows 11, so the family
    // comes from the build number instead — 22000 is the 10→11 boundary.
    let family = match build.parse::<u32>() {
        Ok(b) if b >= 22000 => "Windows 11",
        Ok(_) => "Windows 10",
        Err(_) => "Windows",
    };
    let version = if display.is_empty() {
        build
    } else {
        format!("{build} ({display})")
    };
    let vendor = reg_string(BIOS, "BaseBoardManufacturer")
        .filter(|s| !s.trim().is_empty())
        .or_else(|| reg_string(BIOS, "SystemManufacturer"))
        .unwrap_or_default();
    let product = reg_string(BIOS, "SystemProductName").unwrap_or_default();
    (family.to_string(), version, vendor, product)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn probe() -> (String, String, String, String) {
    Default::default()
}

/// Read a REG_SZ under HKEY_LOCAL_MACHINE. `None` for any failure — a
/// missing value costs a payload field, never the run.
#[cfg(windows)]
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let sub = HSTRING::from(subkey);
    let val = HSTRING::from(value);
    let mut buf = [0u16; 256];
    let mut len = std::mem::size_of_val(&buf) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &sub,
            &val,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut len),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    // len is bytes including the NUL terminator
    let chars = (len as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..chars]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private directory per test — `Store::open` secures the parent, and
    /// it rightly refuses a world-writable one like /tmp itself.
    struct TempStore {
        store: Store,
        dir: std::path::PathBuf,
    }

    impl TempStore {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "firebreak-telemetry-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Store::open(&dir.join("t.db")).expect("open store");
            TempStore { store, dir }
        }
    }

    impl std::ops::Deref for TempStore {
        type Target = Store;
        fn deref(&self) -> &Store {
            &self.store
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn t(iso: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(iso)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// The whole design rests on this: an untouched install sends nothing.
    #[test]
    fn default_consent_is_unasked_and_sends_nothing() {
        let s = TempStore::new("unasked");
        assert_eq!(consent(&s), Consent::Unasked);
        assert!(maybe_send(&s, "ufw", false).is_none());
    }

    /// A source checkout must not prompt, must not send, and must not write
    /// telemetry state — the endpoint is the master switch.
    #[test]
    fn an_endpoint_less_build_is_entirely_dormant() {
        assert!(!configured(), "ENDPOINT should be empty in the repo");
        let s = TempStore::new("dormant");
        set_consent(&s, Consent::Granted, chrono::Utc::now()).unwrap();
        // consent() reports Unasked regardless of what is stored, so no
        // caller can be tricked into showing a prompt or sending.
        assert_eq!(consent(&s), Consent::Unasked);
        assert!(maybe_send(&s, "wfp", false).is_none());
    }

    /// Denying must not leave an identity behind that a later bug could send.
    #[test]
    fn denying_erases_the_install_identity() {
        let s = TempStore::new("denied");
        s.set_meta(K_INSTALL_ID, "deadbeef").unwrap();
        s.set_meta(K_RUNS, "17").unwrap();
        s.set_meta(K_ENROLLED, &chrono::Utc::now().to_rfc3339())
            .unwrap();
        set_consent(&s, Consent::Denied, chrono::Utc::now()).unwrap();
        assert_eq!(s.get_meta(K_INSTALL_ID).unwrap(), None);
        assert_eq!(s.get_meta(K_RUNS).unwrap(), None);
        assert_eq!(s.get_meta(K_ENROLLED).unwrap(), None);
        assert_eq!(
            s.get_meta(K_CONSENT).unwrap().as_deref(),
            Some("denied"),
            "the answer itself must survive, or we would ask again"
        );
    }

    /// A corrupt or unknown consent value must read as "no", never as "yes".
    #[test]
    fn unknown_consent_value_is_not_consent() {
        assert_eq!(Consent::parse("granted"), Consent::Granted);
        assert_eq!(Consent::parse("yes"), Consent::Unasked);
        assert_eq!(Consent::parse(""), Consent::Unasked);
        assert_eq!(Consent::parse("GRANTED"), Consent::Unasked);
    }

    #[test]
    fn id_is_stable_until_it_expires() {
        let s = TempStore::new("id-rotation");
        let start = t("2026-01-01T00:00:00Z");
        let first = install_id(&s, start).unwrap();
        assert_eq!(first.len(), 32);

        let later = install_id(&s, start + chrono::Duration::days(ID_LIFETIME_DAYS - 1)).unwrap();
        assert_eq!(first, later, "must not rotate early");

        let rotated = install_id(&s, start + chrono::Duration::days(ID_LIFETIME_DAYS)).unwrap();
        assert_ne!(first, rotated, "must rotate at the lifetime boundary");
    }

    #[test]
    fn ids_do_not_collide() {
        let a = random_hex_128();
        let b = random_hex_128();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ping_is_due_once_a_day() {
        let s = TempStore::new("due");
        let now = t("2026-01-02T00:00:00Z");
        assert!(due(&s, now), "never pinged → due");

        s.set_meta(K_LAST_PING, &t("2026-01-01T12:00:00Z").to_rfc3339())
            .unwrap();
        assert!(!due(&s, now), "12h ago → not due");

        s.set_meta(K_LAST_PING, &t("2026-01-01T00:00:00Z").to_rfc3339())
            .unwrap();
        assert!(due(&s, now), "24h ago → due");

        s.set_meta(K_LAST_PING, "not a timestamp").unwrap();
        assert!(due(&s, now), "unparseable → due, not never again");
    }

    /// Exact ages and counts would let a rotated ID be stitched back to its
    /// predecessor, which is the whole reason rotation exists.
    #[test]
    fn ages_and_counts_are_coarse() {
        assert_eq!(age_bucket(0), "0");
        assert_eq!(age_bucket(7), "1-7");
        assert_eq!(age_bucket(8), "8-30");
        assert_eq!(age_bucket(91), "91-365");
        assert_eq!(age_bucket(4000), "365+");
        assert_eq!(run_bucket(0), "1");
        assert_eq!(run_bucket(1), "1");
        assert_eq!(run_bucket(6), "6-20");
        assert_eq!(run_bucket(99999), "100+");
    }

    /// Firmware strings are attacker-adjacent input: they come from the
    /// board, go into JSON, and land in someone's database.
    #[test]
    fn field_strings_are_sanitised() {
        assert_eq!(
            clean("  ASUSTeK  COMPUTER   INC.  "),
            "ASUSTeK COMPUTER INC."
        );
        assert_eq!(clean("bad\u{0}\u{1}\nvendor"), "badvendor");
        assert_eq!(clean("").len(), 0);
        assert_eq!(clean(&"x".repeat(500)).chars().count(), MAX_FIELD);
        // a newline must not be able to end up in the JSON as structure
        assert!(!clean("a\r\nb").contains('\n'));
    }

    #[test]
    fn hypervisors_are_recognised_without_reading_serials() {
        assert!(looks_virtual("QEMU", ""));
        assert!(looks_virtual("innotek GmbH", ""));
        assert!(looks_virtual("VMware, Inc.", ""));
        // Hyper-V hides in the product name
        assert!(looks_virtual("Microsoft Corporation", "Virtual Machine"));
        assert!(!looks_virtual("ASUSTeK COMPUTER INC.", "PRIME B550M-A"));
        assert!(!looks_virtual("Dell Inc.", "OptiPlex 7090"));
    }

    #[test]
    fn features_are_a_closed_sorted_vocabulary() {
        let s = TempStore::new("features");
        assert_eq!(features(&s).unwrap(), Vec::<String>::new());
        s.set_meta(&format!("{K_FEATURE}review"), "1").unwrap();
        s.set_meta(&format!("{K_FEATURE}apply"), "1").unwrap();
        // not a Feature variant, so it can never reach the payload
        s.set_meta(&format!("{K_FEATURE}secret_hostname"), "1")
            .unwrap();
        assert_eq!(features(&s).unwrap(), vec!["apply", "review"]);
    }

    /// The payload is the contract with the collector and with the person
    /// who asked what we send. Pin it whole.
    #[test]
    fn payload_shape_is_pinned() {
        let facts = Facts {
            os: "linux".into(),
            os_name: "Fedora Linux".into(),
            os_version: "44".into(),
            arch: "x86_64".into(),
            board_vendor: "ASUSTeK COMPUTER INC.".into(),
            virtual_machine: false,
        };
        let p = build(
            &facts,
            "firewalld",
            "0123456789abcdef0123456789abcdef".into(),
            45,
            9,
            vec!["apply".into(), "collect".into()],
        );
        let json: serde_json::Value = serde_json::to_value(&p).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // sorted, because JSON object order carries no meaning — it is the
        // set of fields that is the promise
        assert_eq!(
            keys,
            vec![
                "age",
                "app_version",
                "arch",
                "backend",
                "board_vendor",
                "features",
                "install_id",
                "os",
                "os_name",
                "os_version",
                "runs",
                "schema",
                "virtual_machine",
            ],
            "payload gained or lost a field — update docs/telemetry.md and the \
             consent dialog to match, then update this test"
        );
        assert_eq!(json["age"], "31-90");
        assert_eq!(json["runs"], "6-20");
        assert_eq!(json["backend"], "firewalld");
    }

    /// Nothing that names the host may appear, however the fields are filled.
    #[test]
    fn payload_carries_no_host_identity() {
        let facts = facts("ufw");
        let p = build(&facts, "ufw", "x".into(), 1, 1, vec![]);
        let json = serde_json::to_string(&p).unwrap().to_lowercase();
        let host = crate::pipeline::hostname().to_lowercase();
        if host != "this host" {
            assert!(!json.contains(&host), "hostname leaked into the payload");
        }
        if let Ok(user) = std::env::var("USER") {
            if !user.is_empty() {
                assert!(!json.contains(&user.to_lowercase()), "username leaked");
            }
        }
    }
}
