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

/// The rule table with no usage data — the first-run screen, before the
/// user has opted into collection.
pub fn rules_only(progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    let backend = require_backend()?;
    progress("Reading firewall rules…");
    let (report, _) = super::analyze(backend, &super::PriorState::default())?;
    Ok(to_result(backend, report, false, &Default::default()))
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
    Ok(to_result(backend, report, true, &reviewed))
}

/// Start collecting — installs whatever the backend needs.
pub fn enable_collection(db_path: &Path, progress: &dyn Fn(&str)) -> Result<()> {
    let backend = require_backend()?;
    progress("Enabling collection…");
    let message = super::enable_collection(backend, db_path)?;
    progress(&message);
    Ok(())
}

fn require_backend() -> Result<super::Backend> {
    super::detect()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no supported Linux firewall backend is active (Firebreak supports ufw, \
             firewalld and raw nftables)"
        )
    })
}

/// Fold a backend report into the shared result type.
type Reviewed = std::collections::HashMap<String, (String, String)>;

fn to_result(
    backend: super::Backend,
    report: super::Report,
    collecting: bool,
    reviewed: &Reviewed,
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

    let rows = report
        .rows
        .into_iter()
        .map(|r| row_from(r, reviewed))
        .collect::<Vec<_>>();
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
        },
        unmatched,
        listeners: super::proc::enumerate_listeners(),
    }
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
        );
        assert_eq!(result.ctx.events_processed, 10);
        assert_eq!(result.rows.len(), 2);
    }
}
