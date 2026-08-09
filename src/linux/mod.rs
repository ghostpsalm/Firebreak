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

pub mod counters;
pub mod ufw;

use anyhow::{Context, Result};

/// Which firewall manager owns this host's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ufw,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::Ufw => "ufw",
        }
    }

    /// Whether Firebreak must turn something on before evidence accrues.
    /// False means the kernel is already counting and the first run has a
    /// real answer.
    pub fn needs_instrumentation(self) -> bool {
        match self {
            Backend::Ufw => false,
        }
    }

    /// How this backend divides rules into scopes. ufw does not: every rule
    /// applies unconditionally, so the scope column and filter disappear
    /// rather than showing three Windows profiles that mean nothing here.
    pub fn scope_vocabulary(self) -> crate::model::ScopeVocabulary {
        match self {
            Backend::Ufw => crate::model::ScopeVocabulary::none(),
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
    Ok(None)
}

/// Everything one run learned about a rule.
#[derive(Debug, Clone)]
pub struct RuleUsageRow {
    pub rule: crate::model::RuleInfo,
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
    }
}

fn analyze_ufw(prior: &PriorState) -> Result<(Report, PriorState)> {
    use std::collections::BTreeMap;

    let parsed = ufw::read_rules()?;
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
        report.rows.push(RuleUsageRow {
            rule: rule.to_rule_info(),
            hits,
        });
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
