//! Main window, rebuilt to the "Firebreak UI Concept" design handoff.
//! Fixed bands top-to-bottom: title bar, evidence header, (conditional)
//! warning band, filter bar, rule table (+ optional detail panel), evidence
//! drawer, (conditional) pending-changes footer. Custom row painting keeps
//! the table grid, checkbox intent states, chips, and accent edge bars exact.

use eframe::egui::{self, Align2, Color32, Rect, Stroke, Vec2};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};

use crate::listeners::Listener;
use crate::model::{BaselineFlag, RuleInfo, RuleUsage};
#[cfg(not(target_os = "linux"))]
use crate::pipeline;
use crate::pipeline::{AnalysisResult, UnmatchedRow};

#[cfg(not(target_os = "linux"))]
use crate::firewall_rules;
/// Where the UI worker gets its data. Windows ingests audit events through
/// `pipeline`; Linux reads rule counters through `linux::bridge`. Both expose
/// the same four entry points, so the worker below is written once.
#[cfg(target_os = "linux")]
use crate::linux::bridge as backend;
#[cfg(not(target_os = "linux"))]
use crate::pipeline as backend;
use crate::theme::{self as t};
use crate::time_util;

const ROW_H: f32 = 31.0;
const HEADER_H: f32 = 28.0;
const PAGE_PAD: f32 = 14.0;

pub struct RuleRow {
    pub rule: RuleInfo,
    pub usage: Option<RuleUsage>,
    pub flags: Vec<BaselineFlag>,
    pub seen_apps: Vec<String>,
    pub listening: Vec<String>,
    pub target_enabled: bool,
    /// intended scope (edited via the scope chips)
    pub target_scopes: crate::model::ScopeSet,
    pub reviewed: ReviewState,
    /// Whether this rule's traffic was actually measured. False means the
    /// backend could not count it — a firewalld rich rule, an nft rule with
    /// no counter. It must never render or filter as "zero hits", because
    /// zero invites deleting the rule and unknown does not.
    pub hits_known: bool,
}

/// User attestation state for a rule. `Stale` = it was reviewed, but the
/// rule's definition has changed since — the mark no longer applies and the
/// rule resurfaces for re-verification.
#[derive(Clone, PartialEq, Default)]
pub enum ReviewState {
    #[default]
    No,
    Stale(String),
    Yes(String),
}

impl ReviewState {
    /// Sort rank: unreviewed first, then stale, then reviewed.
    fn rank(&self) -> u8 {
        match self {
            ReviewState::No => 0,
            ReviewState::Stale(_) => 1,
            ReviewState::Yes(_) => 2,
        }
    }
}

impl RuleRow {
    pub fn total_hits(&self) -> i64 {
        self.usage
            .as_ref()
            .map(|u| u.allow_count + u.block_count)
            .unwrap_or(0)
    }
    /// A genuine disable candidate: measured, never matched, and something
    /// Firebreak could actually switch off. A rule nobody counted is not
    /// zero-hit but unknown; a WFP filter is not a rule at all, so neither
    /// belongs in the list a user works through deleting things from.
    fn is_zero_hit(&self) -> bool {
        self.hits_known && self.rule.is_editable() && self.total_hits() == 0
    }
    /// The synthetic catch-all row, which is not a rule: it must not be
    /// counted as one, staged, applied, exported or sorted among them.
    pub(crate) fn is_default_policy(&self) -> bool {
        self.rule.source() == crate::model::RuleSource::DefaultPolicy
    }
    fn orig_scopes(&self) -> crate::model::ScopeSet {
        crate::model::ScopeSet::from_rule(&self.rule, crate::model::vocabulary())
    }
    fn pending(&self) -> bool {
        self.target_enabled != self.rule.is_enabled() || self.target_scopes != self.orig_scopes()
    }
}

#[derive(Default)]
pub struct AuditContext {
    pub hostname: String,
    pub auditing_active: bool,
    pub collection_started: Option<String>,
    pub last_ingest: Option<String>,
    pub events_processed: u64,
    pub unmatched_events: u64,
    pub note: String,
    /// What the host does with inbound traffic no rule matched. `None` where
    /// it was not established — Windows does not fill this in, and a Linux
    /// backend that could not be read reports unknown rather than a deny.
    pub default_inbound: Option<DefaultInbound>,
}

/// The host's catch-all inbound verdict, phrased for each place it appears.
#[derive(Clone, Default)]
pub struct DefaultInbound {
    /// Header wording: "Rejected", "Dropped", "Allowed".
    pub headline: String,
    /// Socket-list wording, for a listener no rule matches.
    pub socket_note: String,
    /// Where it was read from, for the detail panel.
    pub detail: String,
}

// ---- workers ----

enum WorkerMsg {
    /// audit state resolved — lets the header show it before the slower
    /// rule enumeration finishes
    AuditState(bool),
    Progress(String),
    /// preliminary result from cached rules, shown instantly; a fresh
    /// Ready follows once the live enumeration completes
    Preliminary(Box<AnalysisResult>),
    NeedsEnable(Box<AnalysisResult>),
    Ready(Box<AnalysisResult>),
    Failed(String),
}

/// Where the self-update flow is, shown in the About box.
pub(crate) enum UpdateState {
    Idle,
    Checking,
    UpToDate(String),
    Available(crate::update::Release),
    Downloading,
    Ready(std::path::PathBuf),
    Error(String),
}

/// One planned firewall change, ready to apply and describe.
#[derive(Clone)]
pub(crate) struct PlannedChange {
    pub name: String,
    pub display: String,
    pub kind: ChangeKind,
}

#[derive(Clone)]
pub(crate) enum ChangeKind {
    Disable,
    Enable,
    /// narrow the rule's profile scope; still enabled afterward
    Profiles {
        arg: String,
        // captured for a future revert-to-prior-scope path; not read yet
        #[allow(dead_code)]
        was_enabled: bool,
        removed: String,
    },
}

impl PlannedChange {
    fn new(r: &RuleRow, kind: ChangeKind) -> PlannedChange {
        PlannedChange {
            name: r.rule.name.clone(),
            display: r.rule.display_name.clone(),
            kind,
        }
    }
}

fn removed_labels(orig: &crate::model::ScopeSet, target: &crate::model::ScopeSet) -> String {
    orig.removed_since(target).join(", ")
}

/// Streamed apply progress — one message per step so the footer shows
/// "2 of 3" and rows show per-rule status/failures.
enum ApplyMsg {
    BackupOk(String),
    BackupFailed(String),
    RuleStart { name: String },
    RuleDone { name: String, error: Option<String> },
    Finished,
}

#[derive(PartialEq, Clone, Copy)]
enum Phase {
    Loading,
    NeedsEnable,
    Enabling,
    Ready,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Sockets,
    Unattributed,
    Actions,
}

// ---- bonus / quick actions ----
// Curated bulk operations phrased as plain-English questions. Staging an
// action only edits the intended state (checkboxes / profile chips); the
// changes then ride the normal confirm + backup + Apply pipeline — an
// action can never touch the firewall directly.

pub(crate) enum ActionEffect {
    /// untick the enable checkbox on matching rules
    Disable,
    /// remove the Public profile from matching rules (only when another
    /// profile remains, so the rule never ends up profile-less)
    RemovePublic,
}

pub(crate) struct QuickAction {
    pub title: &'static str,
    pub explain: &'static str,
    pub effect: ActionEffect,
    pub matcher: fn(&RuleRow) -> bool,
    /// needs usage evidence — gated off while auditing is inactive
    pub needs_evidence: bool,
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(needle)
}

fn rule_text_match(r: &RuleRow, needle: &str) -> bool {
    contains_ci(&r.rule.display_name, needle)
        || r.rule
            .group
            .as_deref()
            .is_some_and(|g| contains_ci(g, needle))
}

fn udp_port(r: &RuleRow, port: &str) -> bool {
    r.rule
        .protocol
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case("udp"))
        && r.rule
            .local_port
            .as_deref()
            .is_some_and(|lp| lp.split(',').any(|p| p == port))
}

fn inbound_allow(r: &RuleRow) -> bool {
    r.rule.direction.eq_ignore_ascii_case("inbound") && r.rule.action.eq_ignore_ascii_case("allow")
}

pub(crate) fn actions_catalog() -> &'static [QuickAction] {
    &[
        QuickAction {
            title: "Disable inbound allow rules with zero observed hits?",
            explain: "The core cleanup: enabled inbound allow rules that no traffic has matched \
                      in the entire collection window. Only trustworthy once collection has \
                      covered weekly/monthly activity — check \"Collecting since\" in the header.",
            effect: ActionEffect::Disable,
            matcher: |r| inbound_allow(r) && r.total_hits() == 0,
            needs_evidence: true,
        },
        QuickAction {
            title: "Not using mDNS device discovery?",
            explain: "mDNS (UDP 5353) lets apps discover printers, Chromecasts and speakers on \
                      the local network. On servers and locked-down desktops it's usually \
                      unneeded inbound exposure.",
            effect: ActionEffect::Disable,
            matcher: |r| rule_text_match(r, "mdns") || udp_port(r, "5353"),
            needs_evidence: false,
        },
        QuickAction {
            title: "Not using UPnP / SSDP discovery?",
            explain: "SSDP (UDP 1900) advertises and discovers UPnP devices — media servers, \
                      smart TVs, routers. Rarely needed on managed machines.",
            effect: ActionEffect::Disable,
            matcher: |r| rule_text_match(r, "ssdp") || udp_port(r, "1900"),
            needs_evidence: false,
        },
        QuickAction {
            title: "Not using LLMNR name resolution?",
            explain: "LLMNR (UDP 5355) is a legacy fallback when DNS fails — and a classic \
                      credential-theft vector (responder attacks). Disable unless you rely on \
                      name resolution without DNS.",
            effect: ActionEffect::Disable,
            matcher: |r| rule_text_match(r, "llmnr") || udp_port(r, "5355"),
            needs_evidence: false,
        },
        QuickAction {
            title: "Not using Windows Remote Assistance?",
            explain: "Remote Assistance rules admit unsolicited help sessions. If your remote \
                      support runs through other tooling, these are dormant inbound doors.",
            effect: ActionEffect::Disable,
            matcher: |r| rule_text_match(r, "remote assistance"),
            needs_evidence: false,
        },
        QuickAction {
            title: "Stop file & printer sharing on Public networks?",
            explain: "Removes the Public profile from File and Printer Sharing rules, so shares \
                      stop being reachable on untrusted networks while Domain/Private keep \
                      working. Rules whose only profile is Public are left alone.",
            effect: ActionEffect::RemovePublic,
            matcher: |r| rule_text_match(r, "file and printer sharing"),
            needs_evidence: false,
        },
    ]
}

impl App {
    /// Rows the action would still change (already-staged rows drop out).
    pub(crate) fn action_pending(&self, a: &QuickAction) -> Vec<usize> {
        if a.needs_evidence && !self.ctx_info.auditing_active {
            return Vec::new();
        }
        (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                // staging something Apply can never carry out would show a
                // count of changes that then silently does nothing
                if !r.rule.is_editable() || !r.rule.is_enabled() || !(a.matcher)(r) {
                    return false;
                }
                match a.effect {
                    ActionEffect::Disable => r.target_enabled,
                    ActionEffect::RemovePublic => {
                        r.target_scopes.is_active("Public")
                            && (r.target_scopes.is_active("Domain")
                                || r.target_scopes.is_active("Private"))
                    }
                }
            })
            .collect()
    }

    /// Stage the action into intended state; Apply remains a separate,
    /// confirmed, backup-first step.
    pub(crate) fn stage_action(&mut self, a: &QuickAction) {
        for i in self.action_pending(a) {
            match a.effect {
                ActionEffect::Disable => self.rows[i].target_enabled = false,
                ActionEffect::RemovePublic => self.rows[i].target_scopes.set("Public", false),
            }
        }
    }

    /// How many catalog actions currently have something to stage.
    pub(crate) fn applicable_action_count(&self) -> usize {
        actions_catalog()
            .iter()
            .filter(|a| !self.action_pending(a).is_empty())
            .count()
    }
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum Sort {
    // no header wires this up yet; comparator exists for when one does
    #[allow(dead_code)]
    Enabled,
    Name,
    Dir,
    Action,
    Profiles,
    Scope,
    Source,
    Hits,
    LastSeen,
    Apps,
    Listening,
    Reviewed,
}

impl Sort {
    /// Text columns default to ascending (A→Z); counts/time to descending.
    fn default_ascending(self) -> bool {
        !matches!(self, Sort::Hits | Sort::LastSeen)
    }
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum DirFilter {
    In,
    Out,
    All,
}

/// User-adjustable widths for the table columns. `name` == 0 means auto
/// (Rule shares the flex with Apps); once the user drags the Rule divider it
/// becomes a fixed width and Apps alone takes the remaining flex. Dragging a
/// header divider updates these.
#[derive(Clone, Copy)]
pub(crate) struct ColWidths {
    pub name: f32,
    pub dir: f32,
    pub action: f32,
    pub profiles: f32,
    pub scope: f32,
    pub source: f32,
    pub hits: f32,
    pub last: f32,
    pub listen: f32,
    pub reviewed: f32,
}

impl Default for ColWidths {
    fn default() -> Self {
        ColWidths {
            name: 0.0,
            dir: 44.0,
            action: 54.0,
            profiles: 118.0,
            scope: 150.0,
            source: 104.0,
            hits: 100.0,
            last: 78.0,
            listen: 132.0,
            reviewed: 78.0,
        }
    }
}

struct ApplyState {
    rx: Receiver<ApplyMsg>,
    total: usize,
    done: usize,
    current: Option<String>,
    backup: Option<String>,
    backup_failed: Option<String>,
    /// per-rule outcome: name -> Ok(()) | Err(msg)
    results: std::collections::HashMap<String, Result<(), String>>,
    finished: bool,
    stop_requested: bool,
}

pub struct App {
    db_path: Option<PathBuf>,
    phase: Phase,
    rows: Vec<RuleRow>,
    unmatched: Vec<UnmatchedRow>,
    listeners: Vec<Listener>,
    ctx_info: AuditContext,
    worker_rx: Option<Receiver<WorkerMsg>>,
    progress: String,

    // filters
    filter_text: String,
    dir_filter: DirFilter,
    only_enabled: bool,
    only_zero_hit: bool,
    only_flagged: bool,
    hide_reviewed: bool,
    /// Scope filter: one entry per scope the host's backend defines, in
    /// display order. Empty on a backend without scopes (ufw), where the
    /// filter row simply does not render.
    scope_filter: Vec<(String, bool)>,
    sort: Sort,
    sort_asc: bool,
    col_w: ColWidths,

    selected: Option<usize>,
    drawer_open: bool,
    tab: Tab,
    audit_checked: bool,

    confirm_open: bool,
    apply: Option<ApplyState>,
    status: String,
    /// user acknowledged the young-evidence warning band (dismisses it)
    warning_acked: bool,
    /// persisted drawer height across frames/toggles
    drawer_height: f32,
    settings_open: bool,
    about_open: bool,
    pub(crate) dark_mode: bool,
    pub(crate) update: std::sync::Arc<std::sync::Mutex<UpdateState>>,
    /// lazily-loaded app logo for the title bar
    pub(crate) logo: Option<egui::TextureHandle>,
    /// scratch DB for the current .evtx import session (persists across
    /// "Add" imports so multiple machines can be reviewed together)
    import_db: Option<PathBuf>,
    /// When the counters were last read, for the repeating refresh.
    #[cfg(target_os = "linux")]
    last_read: std::time::Instant,
}

/// How often the open window re-reads the kernel's counters.
///
/// Linux only. A Linux refresh is a counter read costing milliseconds, so
/// the number on screen can track traffic as it arrives; a Windows refresh
/// re-ingests the Security log and re-enumerates every rule through
/// PowerShell, which is seconds of work and must stay the user's decision.
#[cfg(target_os = "linux")]
const AUTO_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether a background re-read may replace the table right now.
///
/// Each of these is a way the refresh would take something from the user:
/// `absorb` swaps every row out, so a staged change is discarded, and it
/// clears the selection, so an open drawer closes under the cursor.
#[cfg(any(target_os = "linux", test))]
fn auto_refresh_ok(
    phase: Phase,
    worker_busy: bool,
    applying: bool,
    drawer_open: bool,
    menu_open: bool,
    staged_changes: usize,
) -> bool {
    phase == Phase::Ready
        && !worker_busy
        && !applying
        && !drawer_open
        && !menu_open
        && staged_changes == 0
}

impl App {
    fn base(db_path: Option<PathBuf>) -> Self {
        App {
            db_path,
            phase: Phase::Loading,
            rows: Vec::new(),
            unmatched: Vec::new(),
            listeners: Vec::new(),
            ctx_info: AuditContext::default(),
            worker_rx: None,
            progress: "Detecting audit state…".into(),
            filter_text: String::new(),
            dir_filter: DirFilter::In, // audits start with inbound exposure
            only_enabled: true,
            only_zero_hit: false,
            only_flagged: false,
            hide_reviewed: true,
            scope_filter: crate::model::vocabulary()
                .names
                .iter()
                .map(|n| (n.clone(), true))
                .collect(),
            sort: Sort::Hits,
            sort_asc: false, // hits descending by default (design)
            col_w: ColWidths::default(),
            selected: None,
            drawer_open: false,
            tab: Tab::Sockets,
            audit_checked: false,
            confirm_open: false,
            apply: None,
            status: String::new(),
            warning_acked: false,
            drawer_height: 190.0,
            settings_open: false,
            about_open: false,
            dark_mode: false,
            update: std::sync::Arc::new(std::sync::Mutex::new(UpdateState::Idle)),
            logo: None,
            import_db: None,
            #[cfg(target_os = "linux")]
            last_read: std::time::Instant::now(),
        }
    }

    /// Load (once) and return the title-bar logo texture.
    pub(crate) fn logo_texture(&mut self, ctx: &egui::Context) -> egui::TextureHandle {
        if let Some(t) = &self.logo {
            return t.clone();
        }
        let bytes = include_bytes!("../assets/icons/firebreak-32.png");
        let (rgba, w, h) = image_rgba(bytes).unwrap_or((vec![0; 4], 1, 1));
        let img = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
        let tex = ctx.load_texture("logo", img, egui::TextureOptions::LINEAR);
        self.logo = Some(tex.clone());
        tex
    }

    fn new_live(db_path: PathBuf, egui_ctx: egui::Context) -> Self {
        let mut app = App::base(Some(db_path.clone()));
        app.spawn_detect(db_path, egui_ctx);
        app
    }

    /// Re-read the counters on a timer so the totals track traffic while the
    /// window is open. Unlike [`App::spawn_detect`] the phase stays `Ready`:
    /// the header must not flash "Reading…" every five seconds, and there is
    /// nothing to re-detect — the backend does not change under us.
    #[cfg(target_os = "linux")]
    fn spawn_recount(&mut self, db_path: PathBuf, egui_ctx: egui::Context) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let msg = match backend::recount(&db_path) {
                Ok(r) => WorkerMsg::Ready(Box::new(r)),
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
    }

    /// Fire the repeating refresh when it is due and nothing on screen would
    /// lose by it. Also keeps the frame clock alive: without a repaint
    /// request an idle egui window sleeps, and a count that only moves when
    /// the mouse does looks broken.
    #[cfg(target_os = "linux")]
    fn maybe_auto_refresh(&mut self, ctx: &egui::Context) {
        let Some(db) = self.db_path.clone() else {
            return;
        };
        let waited = self.last_read.elapsed();
        if waited < AUTO_REFRESH {
            ctx.request_repaint_after(AUTO_REFRESH - waited);
            return;
        }
        if !auto_refresh_ok(
            self.phase,
            self.worker_rx.is_some(),
            self.apply.is_some() || self.confirm_open,
            self.selected.is_some(),
            self.settings_open || self.about_open,
            self.planned_changes().len(),
        ) {
            // try again on the next tick rather than the next mouse move
            ctx.request_repaint_after(AUTO_REFRESH);
            return;
        }
        self.last_read = std::time::Instant::now();
        self.spawn_recount(db, ctx.clone());
    }

    fn spawn_detect(&mut self, db_path: PathBuf, egui_ctx: egui::Context) {
        self.audit_checked = false;
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            // audit state first — cheap, and lets the header settle before
            // the slower rule enumeration
            progress(if cfg!(target_os = "linux") {
                "Detecting firewall backend…"
            } else {
                "Checking Windows audit policy…"
            });
            let enabled = match backend::audit_enabled() {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(WorkerMsg::Failed(format!("{e:#}")));
                    egui_ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(WorkerMsg::AuditState(enabled));
            egui_ctx.request_repaint();

            if enabled {
                // instant paint from cached rules while the live query runs
                if let Some(prelim) = backend::quick_cached_result(&db_path) {
                    let _ = tx.send(WorkerMsg::Preliminary(Box::new(prelim)));
                    egui_ctx.request_repaint();
                }
                let msg = match backend::analyze(&db_path, &progress) {
                    Ok(r) => WorkerMsg::Ready(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            } else {
                let msg = match backend::rules_only(&db_path, &progress) {
                    Ok(r) => WorkerMsg::NeedsEnable(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            }
            egui_ctx.request_repaint();
        });
    }

    /// Flip a rule's reviewed mark and persist it. Reviewing records the
    /// rule's current definition fingerprint; un-reviewing (from either the
    /// reviewed or the stale state) deletes the record.
    pub(crate) fn toggle_reviewed(&mut self, ri: usize) {
        let (next, write): (ReviewState, Option<Option<(String, String)>>) = {
            let r = &self.rows[ri];
            match r.reviewed {
                ReviewState::Yes(_) => (ReviewState::No, Some(None)),
                _ => {
                    let at = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    (
                        ReviewState::Yes(at.clone()),
                        Some(Some((r.rule.fingerprint(), at))),
                    )
                }
            }
        };
        if let (Some(db), Some(op)) = (self.db_path.clone(), write) {
            let name = self.rows[ri].rule.name.clone();
            if let Ok(store) = crate::store::Store::open(&db) {
                let _ = match op {
                    Some((fp, at)) => store.set_reviewed(&name, &fp, &at),
                    None => store.clear_reviewed(&name),
                };
            }
        }
        self.rows[ri].reviewed = next;
    }

    /// Query GitHub for the latest release on a worker thread.
    pub(crate) fn spawn_update_check(&mut self, egui_ctx: egui::Context) {
        *self.update.lock().unwrap() = UpdateState::Checking;
        let slot = self.update.clone();
        std::thread::spawn(move || {
            let next = match crate::update::check() {
                Ok(rel) if rel.newer => UpdateState::Available(rel),
                Ok(rel) => UpdateState::UpToDate(rel.current),
                Err(e) => UpdateState::Error(format!("{e:#}")),
            };
            *slot.lock().unwrap() = next;
            egui_ctx.request_repaint();
        });
    }

    /// Download and stage the newest build on a worker thread.
    pub(crate) fn spawn_update_download(&mut self, egui_ctx: egui::Context) {
        *self.update.lock().unwrap() = UpdateState::Downloading;
        let slot = self.update.clone();
        std::thread::spawn(move || {
            let next = match crate::update::download_and_install() {
                Ok(exe) => UpdateState::Ready(exe),
                Err(e) => UpdateState::Error(format!("{e:#}")),
            };
            *slot.lock().unwrap() = next;
            egui_ctx.request_repaint();
        });
    }

    /// Analyze events from an imported .evtx file on a worker thread.
    /// `append` = add to the current import session; otherwise start fresh.
    #[cfg(windows)]
    fn spawn_import(&mut self, path: PathBuf, append: bool, egui_ctx: egui::Context) {
        // stable per-process import scratch DB
        let db = self.import_db.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("firebreak-import-{}.db", std::process::id()))
        });
        self.import_db = Some(db.clone());
        let reset_first = !append;
        self.phase = Phase::Loading;
        self.audit_checked = true;
        self.progress = "Importing events…".into();
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            let msg = match pipeline::import_evtx(&db, &path, reset_first, &progress) {
                Ok(r) => WorkerMsg::Ready(Box::new(r)),
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
    }

    /// Open a firebreak-export bundle (another device's rules + events) as a
    /// fresh read-only review session.
    #[cfg(windows)]
    pub(crate) fn spawn_import_bundle(&mut self, path: PathBuf, egui_ctx: egui::Context) {
        let db = std::env::temp_dir().join(format!("firebreak-import-{}.db", std::process::id()));
        self.import_db = Some(db.clone());
        self.phase = Phase::Loading;
        self.audit_checked = true;
        self.progress = "Opening bundle…".into();
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            let msg = match pipeline::import_bundle(&db, &path, true, &progress) {
                Ok(r) => WorkerMsg::Ready(Box::new(r)),
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
    }

    /// True while reviewing imported data — Apply must stay unavailable
    /// (the changes would hit THIS host's firewall, not the reviewed one).
    pub(crate) fn read_only_session(&self) -> bool {
        self.import_db.is_some()
    }

    /// Turn off Filtering Platform Connection auditing and return to the
    /// first-run (auditing-off) view. Live collection stops.
    fn stop_auditing(&mut self, egui_ctx: &egui::Context) {
        let _ = crate::audit_control::set_auditing(crate::audit_control::AuditState {
            success: false,
            failure: false,
        });
        self.import_db = None;
        if let Some(db) = self.db_path.clone() {
            self.phase = Phase::Loading;
            self.spawn_detect(db, egui_ctx.clone());
        }
    }

    fn new_ready(
        rows: Vec<RuleRow>,
        ctx_info: AuditContext,
        unmatched: Vec<UnmatchedRow>,
        listeners: Vec<Listener>,
    ) -> Self {
        let mut app = App::base(None);
        app.phase = Phase::Ready;
        app.rows = rows;
        app.ctx_info = ctx_info;
        app.unmatched = unmatched;
        app.listeners = listeners;
        app.drawer_open = false; // starts collapsed
        app.audit_checked = true;
        app.progress.clear();
        // preview-only state overrides for screenshotting non-default screens
        match std::env::var("FIREBREAK_PREVIEW_STATE").as_deref() {
            Ok("firstrun") => {
                app.phase = Phase::NeedsEnable;
                app.ctx_info.auditing_active = false;
                for r in &mut app.rows {
                    r.usage = None;
                    r.target_enabled = r.rule.is_enabled();
                }
            }
            Ok("modal") => app.confirm_open = true,
            Ok("settings") => app.settings_open = true,
            Ok("actions") => {
                app.drawer_open = true;
                app.tab = Tab::Actions;
                app.drawer_height = 300.0;
            }
            Ok("about") => app.about_open = true,
            Ok("update") => {
                app.about_open = true;
                *app.update.lock().unwrap() = UpdateState::Available(crate::update::Release {
                    latest: "0.5.4.1287".into(),
                    current: crate::pipeline::version_string(),
                    newer: true,
                });
            }
            Ok("selected") => app.selected = Some(0),
            Ok("profiles") => {
                // demo: remove Public from a multi-profile rule + a disable
                for r in app.rows.iter_mut() {
                    if r.rule.display_name.contains("File and Printer") {
                        r.target_scopes.set("Public", false);
                    }
                }
                app.confirm_open = true;
            }
            _ => {}
        }
        app
    }

    fn start_enable(&mut self, egui_ctx: &egui::Context) {
        let Some(db_path) = self.db_path.clone() else {
            self.status = "Preview mode — enable is disabled.".into();
            return;
        };
        self.phase = Phase::Enabling;
        self.progress = "Enabling connection auditing…".into();
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        let egui_ctx = egui_ctx.clone();
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            let msg = match backend::enable_collection(&db_path, &progress)
                .and_then(|()| backend::analyze(&db_path, &progress))
            {
                Ok(r) => WorkerMsg::Ready(Box::new(r)),
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
    }

    fn poll_worker(&mut self) {
        // drain into a local buffer so message handlers can take &mut self
        let mut msgs = Vec::new();
        if let Some(rx) = &self.worker_rx {
            loop {
                match rx.try_recv() {
                    Ok(m) => msgs.push(m),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.worker_rx = None;
                        break;
                    }
                }
            }
        }
        for m in msgs {
            match m {
                WorkerMsg::AuditState(b) => {
                    self.ctx_info.auditing_active = b;
                    self.audit_checked = true;
                }
                WorkerMsg::Progress(s) => self.progress = s,
                WorkerMsg::Preliminary(r) => {
                    // show cached rules immediately; phase stays Loading so
                    // the header still signals a refresh is in flight
                    self.absorb(*r);
                }
                WorkerMsg::NeedsEnable(r) => {
                    self.absorb(*r);
                    self.phase = Phase::NeedsEnable;
                    self.worker_rx = None;
                }
                WorkerMsg::Ready(r) => {
                    let ev = r.ctx.events_processed;
                    let un = r.ctx.unmatched_events;
                    self.absorb(*r);
                    // any completed read restarts the clock, so a manual
                    // refresh is not chased by an automatic one
                    #[cfg(target_os = "linux")]
                    {
                        self.last_read = std::time::Instant::now();
                    }
                    self.phase = Phase::Ready;
                    self.status = format!("Ingested {ev} events ({un} unattributed).");
                    self.worker_rx = None;
                }
                WorkerMsg::Failed(e) => {
                    self.phase = if self.phase == Phase::Enabling {
                        Phase::NeedsEnable
                    } else {
                        Phase::Ready
                    };
                    self.status = format!("Error: {e}");
                    self.worker_rx = None;
                }
            }
        }
    }

    fn absorb(&mut self, r: AnalysisResult) {
        self.rows = r.rows;
        self.ctx_info = r.ctx;
        self.unmatched = r.unmatched;
        self.listeners = r.listeners;
        self.progress.clear();
        self.selected = None;
    }

    // ---- pending / apply ----

    /// All pending changes as a concrete apply plan.
    fn planned_changes(&self) -> Vec<PlannedChange> {
        let mut out = Vec::new();
        for r in &self.rows {
            // A WFP filter is not a rule anyone can change; it appears in the
            // table only to explain traffic. It must never reach a plan.
            if !r.rule.is_editable() {
                continue;
            }
            let orig = r.orig_scopes();
            let was_enabled = r.rule.is_enabled();
            // whole-rule off wins over any profile edit
            if !r.target_enabled || r.target_scopes.is_empty() {
                if was_enabled {
                    out.push(PlannedChange::new(r, ChangeKind::Disable));
                }
                continue;
            }
            // enabled target
            if r.target_scopes != orig {
                let arg = r.target_scopes.to_arg().unwrap_or_else(|| "Any".into());
                out.push(PlannedChange::new(
                    r,
                    ChangeKind::Profiles {
                        arg,
                        was_enabled,
                        removed: removed_labels(&orig, &r.target_scopes),
                    },
                ));
            } else if !was_enabled {
                out.push(PlannedChange::new(r, ChangeKind::Enable));
            }
        }
        out
    }

    fn pending_counts(&self) -> (usize, usize, usize) {
        let mut dis = 0;
        let mut en = 0;
        let mut scope = 0;
        for c in self.planned_changes() {
            match c.kind {
                ChangeKind::Disable => dis += 1,
                ChangeKind::Enable => en += 1,
                ChangeKind::Profiles { .. } => scope += 1,
            }
        }
        (dis, en, scope)
    }

    /// Coverage/evidence-age assessment → warning band. Some(hours) when
    /// evidence is younger than the meaningful window.
    fn young_evidence_hours(&self) -> Option<f64> {
        if !self.ctx_info.auditing_active {
            return None;
        }
        let started = self.ctx_info.collection_started.as_deref()?;
        let hours = time_util::hours_since(started)?;
        if hours < 24.0 * 7.0 {
            Some(hours)
        } else {
            None
        }
    }

    fn revert_all(&mut self) {
        for r in &mut self.rows {
            r.target_enabled = r.rule.is_enabled();
            r.target_scopes =
                crate::model::ScopeSet::from_rule(&r.rule, crate::model::vocabulary());
        }
    }

    fn start_apply(&mut self, egui_ctx: &egui::Context) {
        let plan = self.planned_changes();
        if plan.is_empty() {
            return;
        }
        let total = plan.len();
        let all_rules: Vec<RuleInfo> = self.rows.iter().map(|r| r.rule.clone()).collect();
        let db_path = self.db_path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.apply = Some(ApplyState {
            rx,
            total,
            done: 0,
            current: None,
            backup: None,
            backup_failed: None,
            results: std::collections::HashMap::new(),
            finished: false,
            stop_requested: false,
        });
        let egui_ctx = egui_ctx.clone();
        std::thread::spawn(move || {
            match platform_backup(&all_rules, db_path.as_deref()) {
                Ok(path) => {
                    let _ = tx.send(ApplyMsg::BackupOk(path.display().to_string()));
                }
                Err(e) => {
                    let _ = tx.send(ApplyMsg::BackupFailed(format!("{e:#}")));
                    let _ = tx.send(ApplyMsg::Finished);
                    egui_ctx.request_repaint();
                    return;
                }
            }
            for change in plan {
                let _ = tx.send(ApplyMsg::RuleStart {
                    name: change.name.clone(),
                });
                egui_ctx.request_repaint();
                let result = platform_apply(&change);
                let _ = tx.send(ApplyMsg::RuleDone {
                    name: change.name,
                    error: result.err().map(|e| format!("{e:#}")),
                });
                egui_ctx.request_repaint();
            }
            let _ = tx.send(ApplyMsg::Finished);
            egui_ctx.request_repaint();
        });
    }

    fn poll_apply(&mut self, ctx: &egui::Context) {
        let Some(apply) = &mut self.apply else { return };
        let mut newly_committed: Vec<String> = Vec::new();
        loop {
            match apply.rx.try_recv() {
                Ok(ApplyMsg::BackupOk(p)) => apply.backup = Some(p),
                Ok(ApplyMsg::BackupFailed(e)) => apply.backup_failed = Some(e),
                Ok(ApplyMsg::RuleStart { name }) => apply.current = Some(name),
                Ok(ApplyMsg::RuleDone { name, error }) => {
                    apply.done += 1;
                    apply.current = None;
                    match error {
                        None => {
                            apply.results.insert(name.clone(), Ok(()));
                            newly_committed.push(name);
                        }
                        Some(e) => {
                            apply.results.insert(name, Err(e));
                        }
                    }
                }
                Ok(ApplyMsg::Finished) => apply.finished = true,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    apply.finished = true;
                    break;
                }
            }
        }
        // commit saved state for succeeded rules so their controls settle to
        // the applied reality (enabled state + profile scope)
        for name in newly_committed {
            if let Some(r) = self.rows.iter_mut().find(|r| r.rule.name == name) {
                let effective_enabled = r.target_enabled && !r.target_scopes.is_empty();
                r.rule.enabled = if effective_enabled { "True" } else { "False" }.into();
                r.target_enabled = effective_enabled;
                if effective_enabled {
                    r.rule.profile = r.target_scopes.to_arg().unwrap_or_else(|| "Any".into());
                }
            }
        }
        if !apply.finished {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        } else {
            // keep the ApplyState around if any failures remain (partial-
            // failure footer); otherwise clear back to normal
            let any_fail = apply.results.values().any(|r| r.is_err());
            let backup_failed = apply.backup_failed.is_some();
            if !any_fail && !backup_failed {
                let n = apply.done;
                self.apply = None;
                self.status = format!("Applied {n} change(s).");
            }
        }
    }

    fn apply_running(&self) -> bool {
        self.apply.as_ref().is_some_and(|a| !a.finished)
    }
    fn apply_partial_failure(&self) -> bool {
        self.apply.as_ref().is_some_and(|a| {
            a.finished && (a.results.values().any(|r| r.is_err()) || a.backup_failed.is_some())
        })
    }

    /// How many actual rules there are. The catch-all row is displayed among
    /// them but is not one of them, and counting it would overstate the rule
    /// set by one on every host.
    pub(crate) fn rule_count(&self) -> usize {
        self.rows.iter().filter(|r| !r.is_default_policy()).count()
    }

    // ---- filtering ----

    /// Scope names currently ticked in the filter row. An empty vocabulary
    /// yields an empty list, which `applies_to_scopes` reads as "no scope
    /// concept — show everything" rather than "nothing selected".
    fn scope_filter_selected(&self) -> Vec<String> {
        self.scope_filter
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn visible(&self) -> Vec<usize> {
        let needle = self.filter_text.to_lowercase();
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                match self.dir_filter {
                    DirFilter::In if !r.rule.direction.eq_ignore_ascii_case("inbound") => {
                        return false
                    }
                    DirFilter::Out if !r.rule.direction.eq_ignore_ascii_case("outbound") => {
                        return false
                    }
                    _ => {}
                }
                if self.only_enabled && !r.rule.is_enabled() {
                    return false;
                }
                if self.only_zero_hit && (!r.is_zero_hit() || !self.ctx_info.auditing_active) {
                    return false;
                }
                if self.only_flagged && r.flags.is_empty() {
                    return false;
                }
                if self.hide_reviewed && matches!(r.reviewed, ReviewState::Yes(_)) {
                    return false;
                }
                if !r
                    .rule
                    .applies_to_scopes(crate::model::vocabulary(), &self.scope_filter_selected())
                {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                r.rule.display_name.to_lowercase().contains(&needle)
                    || r.rule
                        .group
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || r.rule
                        .program
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || r.seen_apps
                        .iter()
                        .any(|a| a.to_lowercase().contains(&needle))
                    || r.listening
                        .iter()
                        .any(|l| l.to_lowercase().contains(&needle))
            })
            .collect();
        idx.sort_by(|&a, &b| {
            let (ra, rb) = (&self.rows[a], &self.rows[b]);
            // The catch-all sits under every rule, in every sort and either
            // direction — it is the floor, not a competitor for the top of
            // the list.
            if ra.is_default_policy() != rb.is_default_policy() {
                return ra.is_default_policy().cmp(&rb.is_default_policy());
            }
            let ord = match self.sort {
                Sort::Enabled => ra.rule.is_enabled().cmp(&rb.rule.is_enabled()),
                Sort::Name => ra
                    .rule
                    .display_name
                    .to_lowercase()
                    .cmp(&rb.rule.display_name.to_lowercase()),
                Sort::Dir => ra.rule.direction.cmp(&rb.rule.direction),
                Sort::Action => ra.rule.action.cmp(&rb.rule.action),
                Sort::Profiles => ra.rule.profile.cmp(&rb.rule.profile),
                Sort::Scope => crate::listeners::scope_summary(&ra.rule)
                    .cmp(&crate::listeners::scope_summary(&rb.rule)),
                Sort::Source => ra.rule.source_label().cmp(&rb.rule.source_label()),
                Sort::Hits => ra.total_hits().cmp(&rb.total_hits()),
                Sort::LastSeen => {
                    let la = ra.usage.as_ref().and_then(|u| u.last_seen.clone());
                    let lb = rb.usage.as_ref().and_then(|u| u.last_seen.clone());
                    la.cmp(&lb)
                }
                Sort::Apps => ra
                    .seen_apps
                    .join(",")
                    .to_lowercase()
                    .cmp(&rb.seen_apps.join(",").to_lowercase()),
                Sort::Listening => ra.listening.join(",").cmp(&rb.listening.join(",")),
                Sort::Reviewed => ra.reviewed.rank().cmp(&rb.reviewed.rank()),
            };
            if self.sort_asc {
                ord
            } else {
                ord.reverse()
            }
        });
        idx
    }
}

// ─────────────────────────────────────────────────────────────────────────
// rendering
// ─────────────────────────────────────────────────────────────────────────

mod paint;

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.poll_apply(ctx);
        #[cfg(target_os = "linux")]
        self.maybe_auto_refresh(ctx);
        paint::window(self, ctx);
    }
}

// ---- entry points ----

fn app_icon() -> egui::IconData {
    // 256px PNG embedded in the binary; decoded to RGBA for the window icon
    let bytes = include_bytes!("../assets/icons/firebreak-256.png");
    match image_rgba(bytes) {
        Some((rgba, w, h)) => egui::IconData {
            rgba,
            width: w,
            height: h,
        },
        None => egui::IconData {
            rgba: vec![0; 4],
            width: 1,
            height: 1,
        },
    }
}

/// Minimal PNG → RGBA decode (avoids pulling a full image crate).
fn image_rgba(png: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let decoder = png::Decoder::new(png);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    // ensure RGBA8
    match info.color_type {
        png::ColorType::Rgba => Some((buf, info.width, info.height)),
        png::ColorType::Rgb => {
            let rgba = buf
                .chunks(3)
                .flat_map(|c| [c[0], c[1], c[2], 255])
                .collect();
            Some((rgba, info.width, info.height))
        }
        _ => None,
    }
}

/// Render-scale for screenshot/QA runs: FIREBREAK_PPP=2 renders the whole UI
/// at 2x pixel density (window physical size scales to match). Default 1.
pub(crate) fn render_scale() -> f32 {
    std::env::var("FIREBREAK_PPP")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|p| (0.5..=4.0).contains(p))
        .unwrap_or(1.0)
}

fn native_options() -> eframe::NativeOptions {
    let s = render_scale();
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1460.0 * s, 900.0 * s])
            .with_min_inner_size([1000.0 * s, 620.0 * s])
            .with_decorations(false) // custom title bar (see paint::titlebar)
            .with_resizable(true)
            .with_icon(std::sync::Arc::new(app_icon()))
            .with_title("Firebreak"),
        ..Default::default()
    }
}

pub fn run_live(db_path: PathBuf) -> anyhow::Result<()> {
    eframe::run_native(
        "firebreak",
        native_options(),
        Box::new(move |cc| {
            cc.egui_ctx.set_pixels_per_point(render_scale());
            t::apply_style(&cc.egui_ctx);
            Ok(Box::new(App::new_live(db_path, cc.egui_ctx.clone())))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

pub fn run_preview(
    rows: Vec<RuleRow>,
    ctx_info: AuditContext,
    unmatched: Vec<UnmatchedRow>,
    listeners: Vec<Listener>,
) -> anyhow::Result<()> {
    eframe::run_native(
        "firebreak",
        native_options(),
        Box::new(move |cc| {
            cc.egui_ctx.set_pixels_per_point(render_scale());
            t::apply_style(&cc.egui_ctx);
            Ok(Box::new(App::new_ready(
                rows, ctx_info, unmatched, listeners,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

// ---- platform apply seam ----
//
// Windows toggles a flag on a rule through Set-NetFirewallRule. Linux has no
// such flag on two of its three backends, so the same button runs a
// different operation with a different blast radius — see
// `linux::apply::Reversibility` and the warning the confirm dialog shows.

/// Snapshot the whole firewall policy before anything is changed.
#[cfg(not(target_os = "linux"))]
fn platform_backup(
    rules: &[RuleInfo],
    _db_path: Option<&std::path::Path>,
) -> anyhow::Result<PathBuf> {
    firewall_rules::backup_policy(rules)
}

#[cfg(target_os = "linux")]
fn platform_backup(
    _rules: &[RuleInfo],
    db_path: Option<&std::path::Path>,
) -> anyhow::Result<PathBuf> {
    let backend = crate::linux::detect()?
        .ok_or_else(|| anyhow::anyhow!("no supported Linux firewall backend is active"))?;
    let db_path = db_path.ok_or_else(|| anyhow::anyhow!("preview mode — nothing to back up"))?;
    crate::linux::apply::backup(backend, db_path)
}

#[cfg(not(target_os = "linux"))]
fn platform_apply(change: &PlannedChange) -> anyhow::Result<()> {
    match &change.kind {
        ChangeKind::Disable => firewall_rules::set_rule_enabled(&change.name, false),
        ChangeKind::Enable => firewall_rules::set_rule_enabled(&change.name, true),
        ChangeKind::Profiles { arg, .. } => firewall_rules::set_rule_profiles(&change.name, arg),
    }
}

#[cfg(target_os = "linux")]
fn platform_apply(change: &PlannedChange) -> anyhow::Result<()> {
    let backend = crate::linux::detect()?
        .ok_or_else(|| anyhow::anyhow!("no supported Linux firewall backend is active"))?;
    match &change.kind {
        ChangeKind::Disable => crate::linux::apply::disable(backend, &change.name),
        // Only rules that exist are listed, and every one of them is live, so
        // there is nothing to re-enable. Recreating a deleted rule would mean
        // inventing its definition, which Firebreak will not do.
        ChangeKind::Enable => Err(anyhow::anyhow!(
            "re-enabling is not available on {}: a rule that was switched off here was removed, \
             so restore it from the backup instead",
            backend.label()
        )),
        ChangeKind::Profiles { arg, .. } => {
            let zones: Vec<String> = arg
                .split(',')
                .map(str::trim)
                .filter(|z| !z.is_empty() && *z != "Any")
                .map(str::to_string)
                .collect();
            crate::linux::apply::set_scopes(backend, &change.name, &zones)
        }
    }
}

// small helpers shared with the paint module

/// Colours and short label for a scope chip.
///
/// The three Windows profiles have fixed abbreviations and colours. Anything
/// else is a backend-supplied scope — a firewalld zone — and gets the neutral
/// chip with its *own* name. It must not fall back to the "ANY" chip: ANY
/// means "every scope", so labelling a single zone that way tells the reader
/// the opposite of the truth.
pub(crate) fn profile_chip(tag: &str) -> (String, Color32, Color32, Color32) {
    let owned = |(l, a, b, c): (&'static str, Color32, Color32, Color32)| (l.to_string(), a, b, c);
    match tag {
        "Domain" => owned(t::CHIP_DOM()),
        "Private" => owned(t::CHIP_PRV()),
        "Public" => owned(t::CHIP_PUB()),
        "Any" => owned(t::CHIP_ANY()),
        // A zone name is the user's own word for something, so it is shown
        // as they wrote it: uppercasing and clipping it produced chips like
        // "FEDORAWOR…", which names nothing. The chip grows to fit and the
        // column clips at its own edge like every other cell.
        zone => {
            let (_, fg, bg, border) = t::CHIP_ANY();
            (zone.to_string(), fg, bg, border)
        }
    }
}

pub(crate) use helpers::*;
mod helpers {
    use super::*;

    /// Draw text clipped to a cell, left-aligned, vertically centered.
    pub fn cell_text(
        painter: &egui::Painter,
        rect: Rect,
        text: &str,
        font: egui::FontId,
        color: Color32,
        left_pad: f32,
    ) {
        let clip = painter.with_clip_rect(rect);
        clip.text(
            egui::pos2(rect.left() + left_pad, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            font,
            color,
        );
    }

    pub fn stroke_bottom(painter: &egui::Painter, rect: Rect, color: Color32) {
        painter.hline(
            rect.x_range(),
            rect.bottom() - 0.5,
            Stroke::new(1.0_f32, color),
        );
    }

    /// Clickable profile chip. `kept` = still in the rule's target scope;
    /// when false the chip is faded and struck through (pending removal).
    /// `clip` is the cell the chip belongs to: a zone chip carries the zone's
    /// full name and so has no fixed width, and must not paint or take clicks
    /// over the column beside it.
    /// Returns (width, click response if editable).
    pub fn interactive_chip(
        ui: &mut egui::Ui,
        top_left: egui::Pos2,
        clip: Rect,
        tag: &str,
        kept: bool,
        editable: bool,
        id_src: (usize, u8),
    ) -> (f32, Option<egui::Response>) {
        let (short, fg, bg, border) = profile_chip(tag);
        let font = t::semibold(9.5);
        let (fg, bg, border) = if kept {
            (fg, bg, border)
        } else {
            (
                t::DISABLED(),
                egui::Color32::from_rgb(0xF2, 0xF3, 0xF5),
                t::HAIRLINE_TEXT(),
            )
        };
        let painter = ui.painter().with_clip_rect(clip.intersect(ui.clip_rect()));
        let galley = painter.layout_no_wrap(short.to_string(), font.clone(), fg);
        let w = galley.size().x + 10.0;
        let h = 15.0;
        let r = Rect::from_min_size(top_left, Vec2::new(w, h));
        painter.rect(r, 0.0, bg, Stroke::new(1.0_f32, border));
        painter.galley(
            egui::pos2(r.left() + 5.0, r.center().y - galley.size().y / 2.0),
            galley,
            fg,
        );
        if !kept {
            // strike-through
            painter.hline(
                r.left() + 3.0..=r.right() - 3.0,
                r.center().y,
                Stroke::new(1.0_f32, t::DISABLED()),
            );
        }
        let hit = r.intersect(clip);
        let resp = if editable && hit.width() > 0.0 {
            let re = ui.interact(
                hit,
                ui.id().with(("prof", id_src.0, id_src.1)),
                egui::Sense::click(),
            );
            if re.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                painter.rect_stroke(r, 0.0, Stroke::new(1.0_f32, t::ACCENT()));
            }
            Some(re)
        } else {
            None
        };
        (w + 3.0, resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repeating refresh replaces every row, so anything the user is
    /// part-way through must hold it off. Each case below is a way real work
    /// would otherwise vanish between one tick and the next.
    #[test]
    fn auto_refresh_waits_for_the_user_to_finish() {
        let idle = || auto_refresh_ok(Phase::Ready, false, false, false, false, 0);
        assert!(idle(), "an idle, settled window is exactly when to refresh");

        // a staged disable is unsaved work; absorbing new rows discards it
        assert!(!auto_refresh_ok(
            Phase::Ready,
            false,
            false,
            false,
            false,
            1
        ));
        // drawer open: absorb clears the selection and it would shut
        assert!(!auto_refresh_ok(Phase::Ready, false, false, true, false, 0));
        // a menu closes the moment the table under it is rebuilt
        assert!(!auto_refresh_ok(Phase::Ready, false, false, false, true, 0));
        // never two reads at once, and never over an apply in flight
        assert!(!auto_refresh_ok(Phase::Ready, true, false, false, false, 0));
        assert!(!auto_refresh_ok(Phase::Ready, false, true, false, false, 0));
        // and not before the first read has landed
        assert!(!auto_refresh_ok(
            Phase::Loading,
            false,
            false,
            false,
            false,
            0
        ));
        assert!(!auto_refresh_ok(
            Phase::NeedsEnable,
            false,
            false,
            false,
            false,
            0
        ));
    }
}
