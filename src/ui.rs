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
use crate::pipeline::{self, AnalysisResult, UnmatchedRow};
use crate::theme::{self as t};
use crate::{firewall_rules, time_util};

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
    /// intended profile scope (edited via the profile chips)
    pub target_profiles: crate::model::ProfileSet,
    pub reviewed: ReviewState,
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
    fn is_zero_hit(&self) -> bool {
        self.total_hits() == 0
    }
    fn orig_profiles(&self) -> crate::model::ProfileSet {
        crate::model::ProfileSet::from_rule(&self.rule)
    }
    fn pending(&self) -> bool {
        self.target_enabled != self.rule.is_enabled()
            || self.target_profiles != self.orig_profiles()
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

fn removed_labels(orig: crate::model::ProfileSet, target: crate::model::ProfileSet) -> String {
    let mut removed = Vec::new();
    if orig.domain && !target.domain {
        removed.push("Domain");
    }
    if orig.private && !target.private {
        removed.push("Private");
    }
    if orig.public && !target.public {
        removed.push("Public");
    }
    removed.join(", ")
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
                if !r.rule.is_enabled() || !(a.matcher)(r) {
                    return false;
                }
                match a.effect {
                    ActionEffect::Disable => r.target_enabled,
                    ActionEffect::RemovePublic => {
                        r.target_profiles.public
                            && (r.target_profiles.domain || r.target_profiles.private)
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
                ActionEffect::RemovePublic => self.rows[i].target_profiles.public = false,
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
    show_domain: bool,
    show_private: bool,
    show_public: bool,
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
            show_domain: true,
            show_private: true,
            show_public: true,
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
            progress("Checking Windows audit policy…");
            let enabled = match pipeline::audit_enabled() {
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
                if let Some(prelim) = pipeline::quick_cached_result(&db_path) {
                    let _ = tx.send(WorkerMsg::Preliminary(Box::new(prelim)));
                    egui_ctx.request_repaint();
                }
                let msg = match pipeline::analyze(&db_path, &progress) {
                    Ok(r) => WorkerMsg::Ready(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            } else {
                let msg = match pipeline::rules_only(&progress) {
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
                        r.target_profiles.public = false;
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
            let msg = match pipeline::enable_collection(&db_path, &progress)
                .and_then(|()| pipeline::analyze(&db_path, &progress))
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
            let orig = r.orig_profiles();
            let was_enabled = r.rule.is_enabled();
            // whole-rule off wins over any profile edit
            if !r.target_enabled || r.target_profiles.is_empty() {
                if was_enabled {
                    out.push(PlannedChange::new(r, ChangeKind::Disable));
                }
                continue;
            }
            // enabled target
            if r.target_profiles != orig {
                let arg = r
                    .target_profiles
                    .to_profile_arg()
                    .unwrap_or_else(|| "Any".into());
                out.push(PlannedChange::new(
                    r,
                    ChangeKind::Profiles {
                        arg,
                        was_enabled,
                        removed: removed_labels(orig, r.target_profiles),
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
            r.target_profiles = crate::model::ProfileSet::from_rule(&r.rule);
        }
    }

    fn start_apply(&mut self, egui_ctx: &egui::Context) {
        let plan = self.planned_changes();
        if plan.is_empty() {
            return;
        }
        let total = plan.len();
        let all_rules: Vec<RuleInfo> = self.rows.iter().map(|r| r.rule.clone()).collect();
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
            match firewall_rules::backup_policy(&all_rules) {
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
                let result = match &change.kind {
                    ChangeKind::Disable => firewall_rules::set_rule_enabled(&change.name, false),
                    ChangeKind::Enable => firewall_rules::set_rule_enabled(&change.name, true),
                    ChangeKind::Profiles { arg, .. } => {
                        firewall_rules::set_rule_profiles(&change.name, arg)
                    }
                };
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
                let effective_enabled = r.target_enabled && !r.target_profiles.is_empty();
                r.rule.enabled = if effective_enabled { "True" } else { "False" }.into();
                r.target_enabled = effective_enabled;
                if effective_enabled {
                    r.rule.profile = r
                        .target_profiles
                        .to_profile_arg()
                        .unwrap_or_else(|| "Any".into());
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

    // ---- filtering ----

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
                    .applies_to_profile(self.show_domain, self.show_private, self.show_public)
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

// small helpers shared with the paint module
pub(crate) fn profile_chip(tag: &str) -> (&'static str, Color32, Color32, Color32) {
    match tag {
        "Domain" => t::CHIP_DOM(),
        "Private" => t::CHIP_PRV(),
        "Public" => t::CHIP_PUB(),
        _ => t::CHIP_ANY(),
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
        painter.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, color));
    }

    /// Clickable profile chip. `kept` = still in the rule's target scope;
    /// when false the chip is faded and struck through (pending removal).
    /// Returns (width, click response if editable).
    pub fn interactive_chip(
        ui: &mut egui::Ui,
        top_left: egui::Pos2,
        tag: &str,
        kept: bool,
        editable: bool,
        id_src: (usize, u8),
    ) -> (f32, Option<egui::Response>) {
        let (label, fg, bg, border) = profile_chip(match tag {
            "Domain" => "Domain",
            "Private" => "Private",
            "Public" => "Public",
            _ => "Any",
        });
        let short = &label; // DOM/PRV/PUB from profile_chip
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
        let galley = ui
            .painter()
            .layout_no_wrap(short.to_string(), font.clone(), fg);
        let w = galley.size().x + 10.0;
        let h = 15.0;
        let r = Rect::from_min_size(top_left, Vec2::new(w, h));
        ui.painter().rect(r, 0.0, bg, Stroke::new(1.0, border));
        ui.painter().galley(
            egui::pos2(r.left() + 5.0, r.center().y - galley.size().y / 2.0),
            galley,
            fg,
        );
        if !kept {
            // strike-through
            ui.painter().hline(
                r.left() + 3.0..=r.right() - 3.0,
                r.center().y,
                Stroke::new(1.0, t::DISABLED()),
            );
        }
        let resp = if editable {
            let re = ui.interact(
                r,
                ui.id().with(("prof", id_src.0, id_src.1)),
                egui::Sense::click(),
            );
            if re.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                ui.painter()
                    .rect_stroke(r, 0.0, Stroke::new(1.0, t::ACCENT()));
            }
            Some(re)
        } else {
            None
        };
        (w + 3.0, resp)
    }
}
