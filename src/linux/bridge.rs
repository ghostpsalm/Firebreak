//! Adapts a Linux backend's [`super::Report`] to the shape the shared UI
//! renders, so the same table, filters, drawer and CSV export serve both
//! platforms.
//!
//! It mirrors the handful of `pipeline` entry points the UI worker calls, so
//! `ui.rs` picks a module at compile time rather than branching on the OS at
//! every call site.
//!
//! One mapping deserves stating plainly. Windows ingests *events*: a rule
//! with no hits was measured and found idle. Linux reads *counters*, and a
//! rule the backend could not count has no hits for an entirely different
//! reason. Both would arrive at the UI as `usage: None`, so
//! [`crate::ui::RuleRow::hits_known`] carries the distinction through —
//! without it, every unmeasurable rule would appear in the zero-hit filter,
//! which is the list the user works through deleting things.

use anyhow::Result;
use std::path::Path;

use crate::pipeline::AnalysisResult;
use crate::ui::{self, AuditContext, RuleRow};

/// Is collection already running? For a backend the kernel counts for free
/// this is always true; for one that needs instrumenting it asks whether the
/// instrumentation is actually in place.
pub fn audit_enabled() -> Result<bool> {
    let Some(backend) = super::detect()? else {
        return Ok(false);
    };
    Ok(!backend.needs_instrumentation() || super::collection_active(backend))
}

/// No cached fast path on Linux: reading counters *is* the fast path. The
/// UI treats `None` as "nothing to paint yet" and waits for `analyze`.
pub fn quick_cached_result(_db_path: &Path) -> Option<AnalysisResult> {
    None
}

/// The rule table while collection is off — the first-run screen, and the
/// screen you get back after stopping.
///
/// It still loads the banked counter totals. "Not counting now" and "never
/// counted anything" are different states, and a run that had collected for
/// a week before someone stopped it must not present as an empty first run.
pub fn rules_only(db_path: &Path, progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    let backend = require_backend()?;
    progress("Reading firewall rules…");
    let prior = crate::store::Store::open(db_path)
        .and_then(|s| s.load_counter_state())
        .unwrap_or_default();
    let (report, _) = super::analyze(backend, &prior)?;
    let reviewed = crate::store::Store::open(db_path)
        .and_then(|s| s.load_reviewed())
        .unwrap_or_default();
    Ok(to_result(
        backend,
        report,
        false,
        &reviewed,
        super::default_policy::read(backend),
    ))
}

/// A full run: read counters, fold them into the running totals, persist.
pub fn analyze(db_path: &Path, progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    let backend = require_backend()?;
    progress(&format!("Reading {} rules…", backend.label()));
    let store = crate::store::Store::open(db_path)?;
    let prior = store.load_counter_state()?;
    progress("Reading rule counters…");
    let (report, next) = super::analyze(backend, &prior)?;
    store.save_counter_state(&next)?;
    // A review attests to a rule's definition and is a user artifact, not
    // derived data — it has to survive every refresh, or ticking a rule off
    // appears to work and silently resets on the next read.
    let reviewed = store.load_reviewed().unwrap_or_default();
    Ok(to_result(
        backend,
        report,
        true,
        &reviewed,
        super::default_policy::read(backend),
    ))
}

/// Start collecting — installs whatever the backend needs.
pub fn enable_collection(db_path: &Path, progress: &dyn Fn(&str)) -> Result<()> {
    let backend = require_backend()?;
    progress("Enabling collection…");
    let message = super::enable_collection(backend, db_path)?;
    progress(&message);
    Ok(())
}

/// Stop collecting — removes whatever [`enable_collection`] installed.
/// Collected totals stay in the store; this stops counting, it does not
/// discard evidence.
pub fn stop_collection(db_path: &Path) -> Result<String> {
    let backend = require_backend()?;
    super::stop_collection(backend, db_path)
}

fn require_backend() -> Result<super::Backend> {
    super::detect()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no supported Linux firewall backend is active (Firebreak supports ufw, \
             firewalld and raw nftables)"
        )
    })
}

/// A repeating refresh: the same fold as [`analyze`], but reusing the rule
/// vocabulary the last full pass read. Cheap enough to run on a timer —
/// see [`super::recount`] for what it deliberately does not re-read.
pub fn recount(db_path: &Path) -> Result<AnalysisResult> {
    let backend = require_backend()?;
    let store = crate::store::Store::open(db_path)?;
    let prior = store.load_counter_state()?;
    let (report, next) = super::recount(backend, &prior)?;
    store.save_counter_state(&next)?;
    let reviewed = store.load_reviewed().unwrap_or_default();
    Ok(to_result(
        backend,
        report,
        true,
        &reviewed,
        super::default_policy::read(backend),
    ))
}

/// Fold a backend report into the shared result type.
type Reviewed = std::collections::HashMap<String, (String, String)>;

fn to_result(
    backend: super::Backend,
    report: super::Report,
    collecting: bool,
    reviewed: &Reviewed,
    stance: Option<super::default_policy::DefaultInbound>,
) -> AnalysisResult {
    let measured: i64 = report.rows.iter().filter_map(|r| r.hits).sum();
    let unmeasurable = report.unmeasurable.len() as u64;

    let mut note = report.note.clone().unwrap_or_default();
    if unmeasurable > 0 {
        note = format!(
            "{unmeasurable} rule(s) could not be counted and are listed under \
             Not measurable — they are active, not unused. {note}"
        );
    }

    let mut rows = report
        .rows
        .into_iter()
        .map(|r| row_from(r, reviewed))
        .collect::<Vec<_>>();
    if let Some(s) = &stance {
        rows.push(default_policy_row(backend, s));
    }
    let unmatched = report
        .unmeasurable
        .into_iter()
        .map(|(name, why)| crate::pipeline::UnmatchedRow {
            filter_name: format!("{name} — {why}"),
            usage: crate::model::RuleUsage::default(),
        })
        .collect();

    AnalysisResult {
        rows,
        ctx: AuditContext {
            hostname: format!("{} ({})", crate::pipeline::hostname(), backend.label()),
            auditing_active: collecting,
            collection_started: None,
            last_ingest: Some(crate::pipeline::now_iso()),
            // Counters are totals, not a per-run event stream: this is
            // everything counted so far, not what this run ingested.
            events_processed: measured.max(0) as u64,
            unmatched_events: unmeasurable,
            note: note.trim().to_string(),
            default_inbound: stance.map(|s| ui::DefaultInbound {
                headline: s.verdict.headline().to_string(),
                socket_note: s.verdict.socket_note().to_string(),
                source: format!("{} default", backend.label()),
                detail: s.detail.clone(),
            }),
        },
        unmatched,
        listeners: super::proc::enumerate_listeners(),
    }
}

/// The catch-all verdict as a row in the rule table. Shape and guarantees
/// are the shared ones — see [`crate::default_policy::row`]; what differs
/// per platform is only what had to be read to know the verdict.
fn default_policy_row(
    backend: super::Backend,
    stance: &super::default_policy::DefaultInbound,
) -> RuleRow {
    crate::default_policy::row(
        stance.verdict,
        // no Linux backend scopes its catch-all: it is the floor for every
        // zone at once
        "Any",
        &stance.detail,
        format!(
            "Inbound traffic matching none of the rules above. Read from {}, not configured \
             by Firebreak. Traffic on a connection this host started is accepted before this \
             is reached.",
            backend.label()
        ),
    )
}

fn row_from(row: super::RuleUsageRow, reviewed: &Reviewed) -> RuleRow {
    let hits_known = row.hits.is_some();
    // A counter counts packets the rule matched; whether that is traffic
    // allowed or traffic blocked is the rule's own verdict.
    let blocks = row.rule.action.eq_ignore_ascii_case("block");
    let usage = row.hits.map(|hits| crate::model::RuleUsage {
        rule_id: row.rule.name.clone(),
        allow_count: if blocks { 0 } else { hits },
        block_count: if blocks { hits } else { 0 },
        // Counters carry no timestamps: we know a rule was matched, never
        // when. Left empty rather than invented.
        first_seen: None,
        last_seen: None,
        apps: Vec::new(),
        distinct_peers: 0,
        by_profile: Vec::new(),
    });
    let target_scopes = crate::model::ScopeSet::from_rule(&row.rule, crate::model::vocabulary());
    RuleRow {
        flags: crate::baseline_checks::flags_for(&row.rule),
        target_enabled: row.rule.is_enabled(),
        target_scopes,
        seen_apps: Vec::new(),
        listening: row.listening,
        // a review names a fingerprint; if the rule's definition moved, the
        // mark goes stale rather than silently still applying
        reviewed: match reviewed.get(&row.rule.name) {
            Some((fp, at)) if *fp == row.rule.fingerprint() => ui::ReviewState::Yes(at.clone()),
            Some((_, at)) => ui::ReviewState::Stale(at.clone()),
            None => ui::ReviewState::No,
        },
        rule: row.rule,
        usage,
        hits_known,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_from_test(r: super::super::RuleUsageRow) -> RuleRow {
        row_from(r, &Default::default())
    }

    fn default_row(verdict: super::super::default_policy::Verdict) -> RuleRow {
        default_policy_row(
            super::super::Backend::Firewalld,
            &super::super::default_policy::DefaultInbound {
                verdict,
                detail: "a chain tail".into(),
            },
        )
    }

    /// The catch-all is displayed among the rules but is not one, and every
    /// path that acts on a rule has to agree — a checkbox, a plan or a
    /// zero-hit listing on it would each be a way to "disable" the host's
    /// default deny, which Firebreak cannot do and must not offer.
    #[test]
    fn the_default_policy_row_is_never_treated_as_a_rule() {
        use super::super::default_policy::Verdict;
        let r = default_row(Verdict::Reject);
        assert!(r.is_default_policy());
        assert!(!r.rule.is_editable(), "nothing here can be changed");
        assert!(
            !r.hits_known,
            "counters sit after the verdict and never see rejected traffic, so its \
             hits are unknown — not zero, which would list it as a disable candidate"
        );
        assert_eq!(r.usage.as_ref().map(|u| u.allow_count), None);
        assert_eq!(r.rule.action, "Reject");
    }

    /// An open host must read as open. Reporting a deny that is not there
    /// would tell someone an exposed port is closed.
    #[test]
    fn an_accept_default_is_shown_as_allow() {
        use super::super::default_policy::Verdict;
        assert_eq!(default_row(Verdict::Accept).rule.action, "Allow");
        assert_eq!(default_row(Verdict::Drop).rule.action, "Block");
    }

    fn row(name: &str, action: &str, hits: Option<i64>) -> super::super::RuleUsageRow {
        super::super::RuleUsageRow {
            listening: Vec::new(),
            hits,
            rule: crate::model::RuleInfo {
                name: name.into(),
                display_name: name.into(),
                description: None,
                enabled: "True".into(),
                direction: "Inbound".into(),
                action: action.into(),
                profile: "Any".into(),
                group: None,
                program: None,
                protocol: None,
                local_port: None,
                remote_port: None,
                service: None,
                remote_address: None,
                policy_source: None,
                policy_source_type: None,
            },
        }
    }

    #[test]
    fn an_uncounted_rule_is_not_a_zero_hit_rule() {
        // The whole reason hits_known exists. Both of these reach the UI
        // with usage: None; only one of them is a disable candidate.
        let unknown = row_from_test(row("a", "Allow", None));
        let idle = row_from_test(row("b", "Allow", Some(0)));
        assert!(!unknown.hits_known);
        assert!(idle.hits_known);
        assert_eq!(unknown.total_hits(), 0);
        assert_eq!(idle.total_hits(), 0);
    }

    #[test]
    fn a_blocking_rules_counter_is_blocked_traffic() {
        let allow = row_from_test(row("a", "Allow", Some(7)));
        let block = row_from_test(row("b", "Block", Some(7)));
        assert_eq!(allow.usage.as_ref().unwrap().allow_count, 7);
        assert_eq!(allow.usage.as_ref().unwrap().block_count, 0);
        assert_eq!(block.usage.as_ref().unwrap().block_count, 7);
        assert_eq!(block.usage.as_ref().unwrap().allow_count, 0);
    }

    #[test]
    fn counters_carry_no_timestamps_so_none_are_invented() {
        let r = row_from_test(row("a", "Allow", Some(3)));
        let u = r.usage.unwrap();
        assert_eq!(u.first_seen, None);
        assert_eq!(u.last_seen, None);
    }

    #[test]
    fn unmeasurable_rules_are_surfaced_in_the_report_context() {
        let report = super::super::Report {
            rows: vec![row("a", "Allow", Some(1)), row("b", "Allow", None)],
            note: None,
            unmeasurable: vec![("b".into(), "no counter".into())],
        };
        let result = to_result(
            super::super::Backend::Ufw,
            report,
            true,
            &Default::default(),
            None,
        );
        assert_eq!(result.ctx.unmatched_events, 1);
        assert!(
            result.ctx.note.contains("not unused"),
            "{}",
            result.ctx.note
        );
        assert_eq!(result.unmatched.len(), 1);
        assert!(result.unmatched[0].filter_name.contains("no counter"));
    }

    #[test]
    fn totals_reflect_everything_counted_so_far() {
        let report = super::super::Report {
            rows: vec![row("a", "Allow", Some(4)), row("b", "Block", Some(6))],
            note: None,
            unmeasurable: vec![],
        };
        let result = to_result(
            super::super::Backend::Ufw,
            report,
            true,
            &Default::default(),
            None,
        );
        assert_eq!(result.ctx.events_processed, 10);
        assert_eq!(result.rows.len(), 2);
        assert!(result.ctx.default_inbound.is_none());
    }

    #[test]
    fn a_known_default_stance_appends_the_synthetic_row() {
        let report = super::super::Report {
            rows: vec![row("a", "Allow", Some(4))],
            note: None,
            unmeasurable: vec![],
        };
        let result = to_result(
            super::super::Backend::Ufw,
            report,
            true,
            &Default::default(),
            Some(super::super::default_policy::DefaultInbound {
                verdict: crate::default_policy::Verdict::Drop,
                detail: "DEFAULT_INPUT_POLICY=\"DROP\"".into(),
            }),
        );
        // The synthetic catch-all rides along with the user's rules, and the
        // totals still count only what the backend actually measured.
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.ctx.events_processed, 4);
        assert!(result.ctx.default_inbound.is_some());
    }
}
