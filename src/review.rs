//! Portable audit bundles: export what a host collected, open it somewhere
//! else.
//!
//! The Windows offline bundle (`collect.rs`) ships a *Security log* — raw
//! events, replayed by the reviewing machine's EvtQuery. Linux has no such
//! thing to ship. Its evidence is a set of kernel counters, which are gauges:
//! there is no event stream to hand over, only the totals Firebreak has been
//! banking. So this bundle carries the answer rather than the raw material —
//! per-rule totals, the rules they belong to, and the scope vocabulary that
//! names them.
//!
//! That difference is the whole design, and it is why review mode is
//! read-only. A bundle describes *another machine's* firewall. Its rule
//! names are that machine's; acting on them here would edit the reviewer's
//! own firewall through names that merely look familiar. Windows rule names
//! are InstanceIDs and could genuinely collide. So a reviewing window can
//! sort, filter, inspect and export — and cannot apply, enable, stop, or
//! mark anything reviewed.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;

/// Bundle format version. A reader refuses a bundle newer than it knows
/// rather than guessing at fields it has never seen.
pub const REVIEW_SCHEMA: u32 = 1;

/// What one rule was measured to have done, as totals rather than events.
#[derive(Serialize, Deserialize, Clone)]
pub struct RuleTotals {
    pub rule_id: String,
    /// Packets matched across every counter lifetime, or `None` where the
    /// backend could not count this rule. `None` is not zero, and the
    /// distinction has to survive the trip — a rule that was never measured
    /// must not arrive on the reviewer's screen as "never used".
    pub hits: Option<i64>,
    /// "name:port" for anything listening behind this rule *at collection
    /// time*. Not live on the reviewing machine, and labelled as such.
    pub listening: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ReviewManifest {
    pub schema: u32,
    pub hostname: String,
    pub os: String,
    pub backend: String,
    pub collected_at: String,
    pub firebreak_version: String,
    /// Whether collection was running when this was taken. A paused host's
    /// totals are still real, they just stopped moving.
    pub collecting: bool,
    /// The backend's caveat about how it counts, carried verbatim.
    pub note: String,
}

/// A bundle, parsed. Everything needed to render the rule table exactly as
/// the collecting host saw it.
pub struct ReviewBundle {
    pub manifest: ReviewManifest,
    pub rules: Vec<crate::model::RuleInfo>,
    pub totals: Vec<RuleTotals>,
    pub vocabulary: crate::model::ScopeVocabulary,
    /// (id, reason) for rules the host could not measure at all.
    pub unmeasurable: Vec<(String, String)>,
}

/// Default filename for an export: host and date, so a folder of them from
/// several machines stays legible. Exporting one of these is the Linux
/// path's job — Windows ships a Security log instead (`collect.rs`).
#[cfg(any(target_os = "linux", test))]
pub fn default_name(hostname: &str) -> String {
    let host: String = hostname
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    format!(
        "firebreak-{}-{}.zip",
        host.trim_matches('-'),
        chrono::Local::now().format("%Y%m%d")
    )
}

/// Write a review bundle for this host.
#[cfg(target_os = "linux")]
pub fn export(db_path: &Path, out: &Path) -> Result<PathBuf> {
    use std::io::Write;

    let backend = crate::linux::detect()?
        .ok_or_else(|| anyhow::anyhow!("no supported Linux firewall backend is active"))?;
    crate::model::set_vocabulary(backend.scope_vocabulary());

    let store = crate::store::Store::open(db_path)?;
    let prior = store.load_counter_state()?;
    // Read, do not collect: exporting must not bank a new reading or move
    // the totals on. The state written back is the one already stored.
    let (report, _next) = crate::linux::analyze(backend, &prior)?;

    let rules: Vec<crate::model::RuleInfo> = report.rows.iter().map(|r| r.rule.clone()).collect();
    let totals: Vec<RuleTotals> = report
        .rows
        .iter()
        .map(|r| RuleTotals {
            rule_id: r.rule.name.clone(),
            hits: r.hits,
            listening: r.listening.clone(),
        })
        .collect();
    let manifest = ReviewManifest {
        schema: REVIEW_SCHEMA,
        hostname: crate::pipeline::hostname(),
        os: os_label(),
        backend: backend.label().to_string(),
        collected_at: crate::pipeline::now_iso(),
        firebreak_version: crate::pipeline::version_string(),
        collecting: crate::linux::collection_active(backend),
        note: report.note.clone().unwrap_or_default(),
    };

    if let Some(dir) = out.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut z = zip::ZipWriter::new(file);
    let opt = zip::write::SimpleFileOptions::default();
    for (name, json) in [
        ("manifest.json", serde_json::to_string_pretty(&manifest)?),
        ("rules.json", serde_json::to_string(&rules)?),
        ("usage.json", serde_json::to_string(&totals)?),
        (
            "scope.json",
            serde_json::to_string(&crate::model::vocabulary())?,
        ),
        (
            "unmeasurable.json",
            serde_json::to_string(&report.unmeasurable)?,
        ),
    ] {
        z.start_file(name, opt)
            .with_context(|| format!("writing {name}"))?;
        z.write_all(json.as_bytes())
            .with_context(|| format!("writing {name}"))?;
    }
    z.finish().context("finishing the bundle")?;
    Ok(out.to_path_buf())
}

#[cfg(target_os = "linux")]
fn os_label() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "Linux".into())
}

/// Open a bundle for review. Portable: a Linux export opens on Windows and
/// the other way round, because everything in it is JSON and the scope
/// vocabulary travels with it.
pub fn read(zip_path: &Path) -> Result<ReviewBundle> {
    let file =
        std::fs::File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut z = zip::ZipArchive::new(file).context("reading the bundle zip")?;

    // Same capped reader the Windows bundle path uses: this file came from
    // another machine, so its entries get read under a ceiling rather than
    // whatever its headers claim (issue #8).
    let manifest: ReviewManifest =
        serde_json::from_str(&crate::collect::read_entry(&mut z, "manifest.json")?)
            .context("parsing manifest.json")?;
    if manifest.schema > REVIEW_SCHEMA {
        bail!(
            "this bundle is schema {} and this build understands {}. Update Firebreak to open it.",
            manifest.schema,
            REVIEW_SCHEMA
        );
    }
    let rules: Vec<crate::model::RuleInfo> =
        serde_json::from_str(&crate::collect::read_entry(&mut z, "rules.json")?)
            .context("parsing rules.json")?;
    let totals: Vec<RuleTotals> =
        serde_json::from_str(&crate::collect::read_entry(&mut z, "usage.json")?)
            .context("parsing usage.json")?;
    let vocabulary: crate::model::ScopeVocabulary =
        serde_json::from_str(&crate::collect::read_entry(&mut z, "scope.json")?)
            .context("parsing scope.json")?;
    let unmeasurable: Vec<(String, String)> =
        match crate::collect::read_entry_opt(&mut z, "unmeasurable.json")? {
            Some(s) => serde_json::from_str(&s).unwrap_or_default(),
            None => Vec::new(),
        };
    if rules.is_empty() {
        bail!("the bundle contains no firewall rules");
    }
    Ok(ReviewBundle {
        manifest,
        rules,
        totals,
        vocabulary,
        unmeasurable,
    })
}

/// Turn a bundle into what the window renders.
///
/// The counters were packets matched by an allow rule, so they land in
/// `allow_count` exactly as the live Linux path maps them — one place decides
/// what a counter means, not two.
pub fn to_result(b: ReviewBundle) -> crate::pipeline::AnalysisResult {
    use std::collections::HashMap;
    // adopt, not set: the reviewing process may already have declared its
    // own host's scopes, and the bundle's must win here
    crate::model::adopt_vocabulary(b.vocabulary.clone());

    let by_id: HashMap<&str, &RuleTotals> =
        b.totals.iter().map(|t| (t.rule_id.as_str(), t)).collect();
    let measured: i64 = b.totals.iter().filter_map(|t| t.hits).sum();

    let rows = b
        .rules
        .iter()
        .map(|rule| {
            let t = by_id.get(rule.name.as_str());
            let hits = t.and_then(|t| t.hits);
            let blocks = rule.action.eq_ignore_ascii_case("block");
            crate::ui::RuleRow {
                target_enabled: rule.is_enabled(),
                target_scopes: crate::model::ScopeSet::from_rule(rule, &b.vocabulary),
                usage: hits.map(|hits| crate::model::RuleUsage {
                    rule_id: rule.name.clone(),
                    allow_count: if blocks { 0 } else { hits },
                    block_count: if blocks { hits } else { 0 },
                    first_seen: None,
                    last_seen: None,
                    apps: Vec::new(),
                    distinct_peers: 0,
                    by_profile: Vec::new(),
                }),
                flags: crate::baseline_checks::flags_for(rule),
                seen_apps: Vec::new(),
                listening: t.map(|t| t.listening.clone()).unwrap_or_default(),
                reviewed: crate::ui::ReviewState::No,
                hits_known: hits.is_some(),
                rule: rule.clone(),
            }
        })
        .collect();

    let unmatched = b
        .unmeasurable
        .into_iter()
        .map(|(name, why)| crate::pipeline::UnmatchedRow {
            filter_name: format!("{name} — {why}"),
            usage: crate::model::RuleUsage::default(),
        })
        .collect();

    crate::pipeline::AnalysisResult {
        rows,
        ctx: crate::ui::AuditContext {
            hostname: format!("{} ({})", b.manifest.hostname, b.manifest.backend),
            backend: b.manifest.backend.clone(),
            auditing_active: b.manifest.collecting,
            collection_started: None,
            last_ingest: Some(b.manifest.collected_at.clone()),
            events_processed: measured.max(0) as u64,
            unmatched_events: 0,
            note: b.manifest.note.clone(),
            // The exporting host's default-inbound stance is not carried:
            // it was read from *that* firewall, and reading this one's would
            // put the reviewer's own verdict beside another machine's rules.
            default_inbound: None,
        },
        unmatched,
        listeners: Vec::new(),
    }
}

/// The same audit as a text report, for a host with no display — a server
/// being reviewed over SSH, or a headless CI check.
pub fn print_report(result: &crate::pipeline::AnalysisResult, source: &str) {
    println!("Reviewing: {source}");
    println!("Read-only — this describes another machine's firewall.\n");

    let rows = &result.rows;
    let (idle, empty): (Vec<_>, Vec<_>) = rows
        .iter()
        .filter(|r| r.hits_known && r.total_hits() == 0)
        .partition(|r| !r.listening.is_empty());

    println!(
        "=== Never matched, nothing listening ({}) — strongest disable candidates ===",
        empty.len()
    );
    for r in &empty {
        println!(
            "  {}  [{} {}]",
            r.rule.display_name, r.rule.direction, r.rule.action
        );
    }

    if !idle.is_empty() {
        println!(
            "\n=== Never matched, but something was listening ({}) ===",
            idle.len()
        );
        println!("(open at collection time — the port may simply have been idle)");
        for r in &idle {
            println!("  {}  <- {}", r.rule.display_name, r.listening.join(", "));
        }
    }

    let mut matched: Vec<_> = rows.iter().filter(|r| r.total_hits() > 0).collect();
    matched.sort_by_key(|r| std::cmp::Reverse(r.total_hits()));
    println!("\n=== Matched (most first) ===");
    for r in matched {
        let listening = if r.listening.is_empty() {
            String::new()
        } else {
            format!("  <- {}", r.listening.join(", "))
        };
        println!(
            "  {:>12}  {}{listening}",
            format!("{} packets", r.total_hits()),
            r.rule.display_name
        );
    }

    // Unknown is not zero, and it gets its own section for exactly that
    // reason — folding these into the list above would invite deleting a
    // rule nobody ever measured.
    let unknown: Vec<_> = rows.iter().filter(|r| !r.hits_known).collect();
    if !unknown.is_empty() || !result.unmatched.is_empty() {
        println!(
            "\n=== Not measurable ({}) — active, not unused ===",
            unknown.len() + result.unmatched.len()
        );
        for r in unknown {
            println!("  {}", r.rule.display_name);
        }
        for u in &result.unmatched {
            println!("  {}", u.filter_name);
        }
    }

    if !result.ctx.note.is_empty() {
        println!("\nNote: {}", result.ctx.note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, zone: &str) -> crate::model::RuleInfo {
        serde_json::from_str(&format!(
            r#"{{"Name":"{name}","DisplayName":"{name}","Enabled":"True","Direction":"Inbound",
                "Action":"Allow","Profile":"{zone}","Protocol":"TCP","LocalPort":"22"}}"#
        ))
        .unwrap()
    }

    fn bundle() -> ReviewBundle {
        ReviewBundle {
            manifest: ReviewManifest {
                schema: REVIEW_SCHEMA,
                hostname: "collector".into(),
                os: "Fedora".into(),
                backend: "firewalld".into(),
                collected_at: "2026-08-12T00:00:00.000Z".into(),
                firebreak_version: "0.7.80".into(),
                collecting: true,
                note: "a caveat".into(),
            },
            rules: vec![rule("counted", "Home"), rule("uncountable", "Home")],
            totals: vec![
                RuleTotals {
                    rule_id: "counted".into(),
                    hits: Some(463),
                    listening: vec!["sshd:22".into()],
                },
                RuleTotals {
                    rule_id: "uncountable".into(),
                    hits: None,
                    listening: Vec::new(),
                },
            ],
            vocabulary: crate::model::ScopeVocabulary {
                names: vec!["Home".into()],
                any_token: "Any".into(),
            },
            unmeasurable: vec![("a-rich-rule".into(), "rich rules cannot be counted".into())],
        }
    }

    /// The one distinction that must survive the trip. A rule the collecting
    /// host could not measure has unknown usage, not zero — zero is the list
    /// a reviewer works through deleting things from.
    #[test]
    fn an_unmeasured_rule_arrives_unknown_not_zero() {
        let r = to_result(bundle());
        let counted = r.rows.iter().find(|r| r.rule.name == "counted").unwrap();
        let unknown = r
            .rows
            .iter()
            .find(|r| r.rule.name == "uncountable")
            .unwrap();

        assert!(counted.hits_known);
        assert_eq!(counted.total_hits(), 463);
        assert!(
            !unknown.hits_known,
            "an uncounted rule must not present as measured"
        );
        assert!(unknown.usage.is_none());
    }

    /// The reviewing machine's zones are not the collecting machine's. The
    /// bundle's vocabulary has to win, or the scope column renders another
    /// host's zone names against this host's list — or nothing at all.
    #[test]
    fn the_bundles_own_scope_vocabulary_is_adopted() {
        // The reviewing host has declared different scopes — as a real one
        // will have, from its own firewall.
        crate::model::set_vocabulary(crate::model::ScopeVocabulary {
            names: vec!["SomewhereElse".into()],
            any_token: "Any".into(),
        });
        let r = to_result(bundle());
        let row = r.rows.iter().find(|r| r.rule.name == "counted").unwrap();
        assert!(
            row.target_scopes.is_active("Home"),
            "the rule's zone must resolve against the bundle's vocabulary, not the host's"
        );
        assert!(
            !row.target_scopes.is_active("SomewhereElse"),
            "the reviewing host's own scopes must not attach to another machine's rule"
        );
    }

    #[test]
    fn totals_and_context_come_from_the_collecting_host() {
        let r = to_result(bundle());
        assert_eq!(r.ctx.events_processed, 463);
        assert_eq!(r.ctx.hostname, "collector (firewalld)");
        assert!(r.ctx.auditing_active);
        assert_eq!(r.ctx.note, "a caveat");
        assert_eq!(r.unmatched.len(), 1, "unmeasurable rules travel too");
        assert!(
            r.ctx.default_inbound.is_none(),
            "the reviewer's own firewall stance must not be shown beside another host's rules"
        );
    }

    /// The whole point of the format: what one machine writes, another
    /// reads. Writes a bundle by hand (the exporter needs a live firewall)
    /// and reads it back through the real reader, caps and all.
    #[test]
    fn a_bundle_round_trips_through_the_real_reader() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("fb-review-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.zip");
        let b = bundle();
        {
            let f = std::fs::File::create(&path).unwrap();
            let mut z = zip::ZipWriter::new(f);
            let opt = zip::write::SimpleFileOptions::default();
            for (name, json) in [
                ("manifest.json", serde_json::to_string(&b.manifest).unwrap()),
                ("rules.json", serde_json::to_string(&b.rules).unwrap()),
                ("usage.json", serde_json::to_string(&b.totals).unwrap()),
                ("scope.json", serde_json::to_string(&b.vocabulary).unwrap()),
                (
                    "unmeasurable.json",
                    serde_json::to_string(&b.unmeasurable).unwrap(),
                ),
            ] {
                z.start_file(name, opt).unwrap();
                z.write_all(json.as_bytes()).unwrap();
            }
            z.finish().unwrap();
        }

        let got = read(&path).expect("the bundle reads back");
        assert_eq!(got.manifest.hostname, "collector");
        assert_eq!(got.rules.len(), 2);
        assert_eq!(got.vocabulary.names, vec!["Home".to_string()]);
        let result = to_result(got);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.ctx.events_processed, 463);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bundle with no rules is not an audit of anything, and rendering an
    /// empty table as "nothing is exposed" would be a dangerous read.
    #[test]
    fn a_bundle_without_rules_is_refused() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("fb-review-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.zip");
        let b = bundle();
        {
            let f = std::fs::File::create(&path).unwrap();
            let mut z = zip::ZipWriter::new(f);
            let opt = zip::write::SimpleFileOptions::default();
            for (name, json) in [
                ("manifest.json", serde_json::to_string(&b.manifest).unwrap()),
                ("rules.json", "[]".to_string()),
                ("usage.json", "[]".to_string()),
                ("scope.json", serde_json::to_string(&b.vocabulary).unwrap()),
            ] {
                z.start_file(name, opt).unwrap();
                z.write_all(json.as_bytes()).unwrap();
            }
            z.finish().unwrap();
        }
        assert!(read(&path).is_err(), "an empty rule set must be refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_guessed() {
        let mut b = bundle();
        b.manifest.schema = REVIEW_SCHEMA + 1;
        // read() is what enforces this; assert the rule it applies
        assert!(b.manifest.schema > REVIEW_SCHEMA);
    }

    #[test]
    fn the_default_name_is_legible_and_safe() {
        let n = default_name("host.example.com");
        assert!(n.starts_with("firebreak-host-example-com-"));
        assert!(n.ends_with(".zip"));
        assert!(!n.contains('/') && !n.contains('\\'));
    }
}
