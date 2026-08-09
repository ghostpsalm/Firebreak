//! Linux firewall backends.
//!
//! Windows has one firewall with one rule vocabulary. Linux has three in
//! common use, and they differ in what a "rule" even is and in how — or
//! whether — the kernel will tell you it was matched:
//!
//! | backend   | rule identity                | evidence                          |
//! |-----------|------------------------------|-----------------------------------|
//! | ufw       | `### tuple ###` line         | iptables counters, always on      |
//! | firewalld | zone + service/port entry    | shadow counter table (its own     |
//! |           |                              | nft table is `flags owner`)       |
//! | nftables  | table/chain/handle           | counters, if the admin added them |
//!
//! The seam below is what the shared pipeline talks to. The one method that
//! is not cosmetic is [`Backend::needs_instrumentation`]: it is false for
//! ufw, and that collapses Firebreak's three run modes into one, because
//! there is no collection clock to start and no waiting period before the
//! first useful answer.

pub mod apply;
pub mod bridge;
pub mod counters;
pub mod firewalld;
pub mod nftables;
pub mod proc;
pub mod ufw;

use anyhow::{Context, Result};

/// Which firewall manager owns this host's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ufw,
    Firewalld,
    Nftables,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::Ufw => "ufw",
            Backend::Firewalld => "firewalld",
            Backend::Nftables => "nftables",
        }
    }

    /// How this backend gets its evidence, for the report header.
    pub fn evidence_summary(self) -> &'static str {
        match self {
            Backend::Ufw => "iptables counters, always on — nothing to enable",
            Backend::Firewalld => {
                "Firebreak's own shadow counter table (firewalld's is owner-locked)"
            }
            Backend::Nftables => "each rule's own nftables counter — exact, nothing reconstructed",
        }
    }

    /// Whether Firebreak must turn something on before evidence accrues.
    /// False means the kernel is already counting and the first run has a
    /// real answer.
    pub fn needs_instrumentation(self) -> bool {
        match self {
            Backend::Ufw => false,
            // firewalld's own table is owner-locked and carries no counters,
            // so Firebreak must install a shadow table before anything is
            // measured — and then wait for traffic.
            Backend::Firewalld => true,
            // A raw ruleset may already carry counters, in which case the
            // first run answers. Rules without one need a counter adding,
            // which edits the live firewall and is therefore opt-in.
            Backend::Nftables => true,
        }
    }

    /// How this backend divides rules into scopes. ufw does not: every rule
    /// applies unconditionally, so the scope column and filter disappear
    /// rather than showing three Windows profiles that mean nothing here.
    pub fn scope_vocabulary(self) -> crate::model::ScopeVocabulary {
        match self {
            Backend::Ufw => crate::model::ScopeVocabulary::none(),
            // zones are firewalld's scopes, and there can be any number
            Backend::Firewalld => crate::model::ScopeVocabulary {
                names: firewalld::read_zones().map(|z| z.names).unwrap_or_default(),
                any_token: "Any".into(),
            },
            // raw nftables has no zone or profile concept
            Backend::Nftables => crate::model::ScopeVocabulary::none(),
        }
    }
}

/// Work out which backend is in charge.
///
/// Presence is not enough — a host can have ufw installed but inactive
/// while firewalld actually runs the show. Only an *active* manager counts,
/// because an inactive one's rules sit on disk but not in the kernel, and
/// reading its counters would report every rule as unused.
///
/// Three outcomes, deliberately distinct: `Ok(Some)` means use this backend,
/// `Ok(None)` means nothing supported is running here, and `Err` means a
/// backend looks present but could not be interrogated — which is a problem
/// the user needs told about, not one to silently treat as absence.
pub fn detect() -> Result<Option<Backend>> {
    if crate::syspath::system_tool("ufw").is_some() {
        let active = ufw::status().context("checking whether ufw is active")?;
        if active {
            return Ok(Some(Backend::Ufw));
        }
    }
    if crate::syspath::system_tool("firewall-cmd").is_some() && firewalld::is_running() {
        return Ok(Some(Backend::Firewalld));
    }
    // Last: a hand-written ruleset with no manager in front of it. Checked
    // only after the others, since both of them *are* nftables underneath —
    // auditing their generated rules directly would report a vocabulary the
    // user never wrote.
    if crate::syspath::system_tool("nft").is_some() && nftables::has_ruleset() {
        return Ok(Some(Backend::Nftables));
    }
    Ok(None)
}

/// Everything one run learned about a rule.
#[derive(Debug, Clone)]
pub struct RuleUsageRow {
    pub rule: crate::model::RuleInfo,
    /// Processes currently listening behind the ports this rule opens, as
    /// "name:port". Inference from the live listener set, not per-connection
    /// attribution — see [`proc`].
    pub listening: Vec<String>,
    /// Total packets matched across counter resets, or `None` when the
    /// rule's counters could not be read. `None` is not zero: zero means
    /// "never used, consider removing it" and `None` means "we do not know",
    /// and conflating them is how a tool talks someone into deleting a rule
    /// that is load-bearing.
    pub hits: Option<i64>,
}

/// A backend's report for one run.
#[derive(Debug, Default)]
pub struct Report {
    pub rows: Vec<RuleUsageRow>,
    /// A caveat about how this backend collects, shown with the report.
    pub note: Option<String>,
    /// Rules that exist but cannot be measured, with the reason. Kept apart
    /// from `rows` so nothing unmeasurable is ever rendered as unused.
    pub unmeasurable: Vec<(String, String)>,
}

impl Report {
    /// Rules that are definitely never matched — the disable candidates.
    /// Excludes anything whose hits are unknown.
    pub fn unused(&self) -> Vec<&RuleUsageRow> {
        self.rows.iter().filter(|r| r.hits == Some(0)).collect()
    }
}

/// Counter bookkeeping carried between runs, as read from (and written back
/// to) the store.
#[derive(Debug, Default, Clone)]
pub struct PriorState {
    /// The counter lifetime the stored readings belong to. `None` on a first
    /// run — which is *not* treated as a reset, or every first run would
    /// bank a phantom lifetime.
    pub generation: Option<String>,
    pub counters: std::collections::BTreeMap<String, counters::CounterState>,
}

/// Collect one run's evidence from whichever backend is active. Returns the
/// report plus the state the caller must persist for the next run.
pub fn analyze(backend: Backend, prior: &PriorState) -> Result<(Report, PriorState)> {
    match backend {
        Backend::Ufw => analyze_ufw(prior),
        Backend::Firewalld => analyze_firewalld(prior),
        Backend::Nftables => analyze_nftables(prior),
    }
}

/// Is this backend's instrumentation currently in place? Meaningless for a
/// backend that needs none, which reports true.
pub fn collection_active(backend: Backend) -> bool {
    match backend {
        Backend::Ufw => true,
        Backend::Firewalld => firewalld::table_exists(),
        // Partial by nature: some rules may carry counters the admin wrote.
        // "Active" here means Firebreak has something to read at all.
        Backend::Nftables => nftables::read_rules()
            .map(|rules| rules.iter().any(|r| r.counter.is_some()))
            .unwrap_or(false),
    }
}

/// Start collecting on a backend that needs instrumentation. No-op where the
/// kernel already counts.
pub fn enable_collection(backend: Backend, db_path: &std::path::Path) -> Result<String> {
    match backend {
        Backend::Ufw => Ok("ufw counters are always running — nothing to enable.".into()),
        Backend::Nftables => nftables::add_counters(db_path),
        Backend::Firewalld => {
            let zones = firewalld::read_zones()?;
            firewalld::install(&zones.rules)?;
            Ok(format!(
                "Installed the shadow counter table for {} rule(s) across {} zone(s). \n{}",
                zones.rules.len(),
                zones.names.len(),
                firewalld::REBOOT_CAVEAT
            ))
        }
    }
}

/// Undo whatever `enable_collection` installed. Collected totals in the
/// store are kept — this stops counting, it does not discard evidence.
pub fn stop_collection(backend: Backend, db_path: &std::path::Path) -> Result<String> {
    match backend {
        Backend::Ufw => Ok("ufw needed no instrumentation, so there is nothing to remove.".into()),
        Backend::Nftables => nftables::remove_counters(db_path),
        Backend::Firewalld => {
            firewalld::teardown()?;
            Ok(format!(
                "Removed the `{}` counter table. Collected totals are kept.",
                firewalld::SHADOW_TABLE
            ))
        }
    }
}

fn analyze_firewalld(prior: &PriorState) -> Result<(Report, PriorState)> {
    use std::collections::BTreeMap;

    let zones = firewalld::read_zones()?;
    let live_listeners = proc::enumerate_listeners();
    let mut report = Report::default();
    report.unmeasurable.extend(zones.unmeasurable.clone());
    report
        .unmeasurable
        .extend(firewalld::unexpressible(&zones.rules));

    let ids: Vec<String> = zones.rules.iter().map(firewalld::FwdRule::id).collect();
    let generation = counters::generation(&ids);
    let generation_changed = prior.generation.as_deref().is_some_and(|g| g != generation);

    // Firebreak does not instrument a host that has not asked for it. This
    // backend *writes* to the kernel firewall to collect, which Windows
    // never does, so installing the shadow table is an explicit decision
    // (--enable-only) exactly as enabling audit policy is on Windows.
    if !firewalld::table_exists() {
        let mut report = report;
        report.note = Some(format!(
            "Collection is not enabled on this host, so there are no counts yet. Run \
             `firebreak --enable-only` to install the shadow counter table, leave it to \
             gather traffic, then run again. {}",
            firewalld::REBOOT_CAVEAT
        ));
        for rule in &zones.rules {
            let info = rule.to_rule_info();
            report.rows.push(RuleUsageRow {
                listening: crate::listeners::listeners_for_rule(&info, &live_listeners),
                rule: info,
                hits: None,
            });
        }
        return Ok((report, prior.clone()));
    }

    // The table must describe the rules as they are *now*. A changed rule
    // set means a new table and therefore new counters, which the generation
    // token turns into a banked lifetime rather than a decrease.
    if generation_changed {
        firewalld::install(&zones.rules)?;
    }

    let live = firewalld::read_counters()?;
    let mut next = PriorState {
        generation: Some(generation),
        counters: BTreeMap::new(),
    };

    for (i, rule) in zones.rules.iter().enumerate() {
        let id = rule.id();
        let hits = if firewalld::match_expr(rule).is_none() {
            // already reported as unmeasurable above
            None
        } else {
            match live.get(&i) {
                Some(raw) => {
                    let state = prior
                        .counters
                        .get(&id)
                        .copied()
                        .unwrap_or_default()
                        .observe(*raw, generation_changed);
                    next.counters.insert(id.clone(), state);
                    Some(state.total())
                }
                None => {
                    report.unmeasurable.push((
                        id.clone(),
                        "The shadow counter table has no entry for this rule, so it could \
                         not be counted."
                            .into(),
                    ));
                    None
                }
            }
        };
        let info = rule.to_rule_info();
        report.rows.push(RuleUsageRow {
            listening: crate::listeners::listeners_for_rule(&info, &live_listeners),
            rule: info,
            hits,
        });
    }
    report.note = Some(firewalld::REBOOT_CAVEAT.to_string());
    Ok((report, next))
}

fn analyze_ufw(prior: &PriorState) -> Result<(Report, PriorState)> {
    use std::collections::BTreeMap;

    let parsed = ufw::read_rules()?;
    let live_listeners = proc::enumerate_listeners();
    let mut report = Report::default();

    for (tuple, reason) in &parsed.unreadable {
        report.unmeasurable.push((
            format!("ufw:{tuple}"),
            format!("{reason}. The rule is still active in the firewall."),
        ));
    }

    // one counter read per (family, chain) rather than per rule
    let mut chains: BTreeMap<(ufw::Family, String), BTreeMap<usize, i64>> = BTreeMap::new();
    for rule in &parsed.rules {
        let key = (rule.family, rule.chain.clone());
        if let std::collections::btree_map::Entry::Vacant(slot) = chains.entry(key) {
            slot.insert(ufw::read_counters(rule.family, &rule.chain)?);
        }
    }

    let ids: Vec<String> = parsed.rules.iter().map(ufw::UfwRule::id).collect();
    let generation = counters::generation(&ids);
    // A first run has nothing banked, so nothing can have been lost to a
    // reset — only a *changed* generation means the counters restarted.
    let generation_changed = prior.generation.as_deref().is_some_and(|g| g != generation);

    let mut next = PriorState {
        generation: Some(generation),
        counters: BTreeMap::new(),
    };

    for rule in &parsed.rules {
        let id = rule.id();
        if parsed.untrustworthy_chains.contains(&rule.chain) {
            report.unmeasurable.push((
                id,
                format!(
                    "{} is loaded with inserts as well as appends, so Firebreak cannot tell \
                     which live counter belongs to which rule.",
                    rule.chain
                ),
            ));
            continue;
        }
        let raw = chains
            .get(&(rule.family, rule.chain.clone()))
            .and_then(|c| ufw::hits_for(rule, c));
        let hits = match raw {
            Some(raw) => {
                let state = prior
                    .counters
                    .get(&id)
                    .copied()
                    .unwrap_or_default()
                    .observe(raw, generation_changed);
                next.counters.insert(id.clone(), state);
                Some(state.total())
            }
            None => {
                report.unmeasurable.push((
                    id.clone(),
                    "The live firewall chain no longer matches ufw's rule file, so this \
                     rule's counter could not be identified."
                        .into(),
                ));
                None
            }
        };
        let info = rule.to_rule_info();
        report.rows.push(RuleUsageRow {
            listening: crate::listeners::listeners_for_rule(&info, &live_listeners),
            rule: info,
            hits,
        });
    }
    Ok((report, next))
}

/// Raw nftables: read whatever counters the ruleset already carries.
///
/// This is the only backend whose evidence is exact rather than inferred —
/// the counter belongs to the rule itself. Rules without one are reported as
/// unmeasurable with an actionable reason, never as zero-hit, because
/// "nobody ever counted this" and "this is never used" are opposite
/// conclusions and only one of them justifies deleting a rule.
fn analyze_nftables(prior: &PriorState) -> Result<(Report, PriorState)> {
    use std::collections::BTreeMap;

    let rules = nftables::read_rules()?;
    let live_listeners = proc::enumerate_listeners();
    let mut report = Report::default();

    let ids: Vec<String> = rules.iter().map(nftables::NftRule::id).collect();
    let generation = counters::generation(&ids);
    let generation_changed = prior.generation.as_deref().is_some_and(|g| g != generation);
    let mut next = PriorState {
        generation: Some(generation),
        counters: BTreeMap::new(),
    };

    let uncounted = rules.iter().filter(|r| r.counter.is_none()).count();
    for rule in &rules {
        let id = rule.id();
        let hits = match rule.counter {
            Some(raw) => {
                let state = prior
                    .counters
                    .get(&id)
                    .copied()
                    .unwrap_or_default()
                    .observe(raw, generation_changed);
                next.counters.insert(id.clone(), state);
                Some(state.total())
            }
            None => {
                // Name the rule as the admin wrote it. Its identity is a
                // digest, which tells a reader nothing about which rule of
                // theirs is going uncounted.
                report.unmeasurable.push((
                    format!("{} {} — {}", rule.table, rule.chain, rule.text),
                    "This rule carries no counter, so the kernel is not counting it. Run \
                     `firebreak --enable-only` to add one (the ruleset is backed up first \
                     and every edit is verified)."
                        .into(),
                ));
                None
            }
        };
        let info = rule.to_rule_info();
        report.rows.push(RuleUsageRow {
            listening: crate::listeners::listeners_for_rule(&info, &live_listeners),
            rule: info,
            hits,
        });
    }

    if uncounted > 0 {
        report.note = Some(format!(
            "{uncounted} of {} rule(s) carry no counter and are listed as not measurable. \
             Counters also reset on reboot or a ruleset reload; Firebreak banks the old total.",
            rules.len()
        ));
    }
    Ok((report, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufw_needs_no_instrumentation() {
        // The whole reason ufw is the first backend: nothing to enable, no
        // waiting period, an answer on the first run.
        assert!(!Backend::Ufw.needs_instrumentation());
    }

    #[test]
    fn unused_excludes_rules_whose_hits_are_unknown() {
        let mk = |name: &str, hits: Option<i64>| RuleUsageRow {
            listening: Vec::new(),
            rule: crate::model::RuleInfo {
                name: name.into(),
                display_name: name.into(),
                description: None,
                enabled: "True".into(),
                direction: "Inbound".into(),
                action: "Allow".into(),
                profile: "Any".into(),
                group: None,
                program: None,
                protocol: None,
                local_port: None,
                remote_port: None,
                service: None,
                remote_address: None,
            },
            hits,
        };
        let report = Report {
            rows: vec![mk("a", Some(0)), mk("b", None), mk("c", Some(5))],
            note: None,
            unmeasurable: vec![],
        };
        let unused: Vec<&str> = report
            .unused()
            .iter()
            .map(|r| r.rule.name.as_str())
            .collect();
        assert_eq!(unused, vec!["a"], "unknown must never read as unused");
    }

    #[test]
    fn a_first_run_is_not_mistaken_for_a_counter_reset() {
        // With no stored generation there is nothing banked, so treating the
        // run as a reset would add a phantom lifetime to every total.
        let prior = PriorState::default();
        let changed = prior.generation.as_deref().is_some_and(|g| g != "boot-a:1");
        assert!(!changed);
    }
}
