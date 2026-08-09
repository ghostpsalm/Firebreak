//! The raw-nftables backend, for hosts running neither ufw nor firewalld.
//!
//! Here the firewall *is* the nftables ruleset, so a "rule" is one nft rule
//! and the evidence is that rule's own `counter` — the most exact evidence
//! any backend in this tool has. Nothing is reconstructed: where a counter
//! exists, the kernel is counting that precise rule, not Firebreak's guess
//! at what it matches. (Contrast `firewalld`, where the table is owner-locked
//! and a shadow table has to approximate.)
//!
//! Many rulesets already carry `counter` because writing it is idiomatic.
//! Those cost nothing to read. For the rest, Firebreak can add counters —
//! but that means **editing the user's live firewall**, so it is opt-in
//! (`--enable-only`), reversible (`--restore-audit`), and built to be safe
//! in a specific way:
//!
//!  * The expression is not re-derived from text. It is the kernel's own
//!    JSON, read back and returned with a single `{"counter": null}`
//!    inserted before the verdict, so the match semantics cannot drift.
//!  * The whole ruleset is backed up first, to the secured data directory.
//!  * After writing, every touched rule is re-read and checked to be the
//!    original expression plus exactly one counter. Anything else and the
//!    change is rolled back from the backup.
//!
//! A counter is a pure side effect — it does not alter a packet's fate — so
//! the worst realistic outcome is a rule that fails to replace, which nft
//! rejects atomically and leaves untouched.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// Tables Firebreak must not touch: its own shadow table, and firewalld's
/// (owner-locked, and it has a backend of its own).
const SKIP_TABLES: [&str; 2] = [super::firewalld::SHADOW_TABLE, "firewalld"];

/// nft verdict statements. A counter goes *before* these so it counts every
/// packet the rule matched, whatever the rule then does with it.
const VERDICTS: [&str; 7] = [
    "accept", "drop", "reject", "return", "jump", "goto", "continue",
];

/// One rule of the live ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub family: String,
    pub table: String,
    pub chain: String,
    /// Kernel handle. Stable while the ruleset lives, not across reloads —
    /// which is why it is not the identity.
    pub handle: u64,
    /// The rule's expression array, verbatim from the kernel.
    pub expr: Value,
    /// Packets counted, when the rule carries a counter.
    pub counter: Option<i64>,
    /// Human-readable rule text, from `nft -a list ruleset`.
    pub text: String,
    /// Distinguishes byte-identical rules in the same chain.
    pub occurrence: usize,
}

impl NftRule {
    /// Stable identity across reloads: where the rule lives plus what it
    /// matches. Deliberately not the handle, which is reassigned whenever
    /// the ruleset is reloaded — totals would reset every boot.
    pub fn id(&self) -> String {
        format!(
            "nft:{}/{}/{}/{}#{}",
            self.family,
            self.table,
            self.chain,
            expr_digest(&self.expr),
            self.occurrence
        )
    }

    pub fn to_rule_info(&self) -> crate::model::RuleInfo {
        crate::model::RuleInfo {
            name: self.id(),
            display_name: if self.text.is_empty() {
                format!("{} {} handle {}", self.table, self.chain, self.handle)
            } else {
                self.text.clone()
            },
            description: None,
            enabled: "True".into(),
            direction: direction_of(&self.chain),
            action: action_of(&self.expr),
            // raw nftables has no zone or profile concept
            profile: "Any".into(),
            group: Some(format!("{} {}", self.table, self.chain)),
            program: None,
            protocol: None,
            local_port: None,
            remote_port: None,
            service: None,
            remote_address: None,
        }
    }
}

/// Best-effort direction from the chain's name. Raw chains are named by
/// their author, so this is a hint for display, never used for matching.
fn direction_of(chain: &str) -> String {
    let c = chain.to_lowercase();
    if c.contains("out") {
        "Outbound".into()
    } else if c.contains("forward") || c.contains("fwd") {
        "Forward".into()
    } else {
        "Inbound".into()
    }
}

/// What the rule does with a packet it matches.
fn action_of(expr: &Value) -> String {
    let Some(items) = expr.as_array() else {
        return "Allow".into();
    };
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        for key in obj.keys() {
            match key.as_str() {
                "accept" => return "Allow".into(),
                "drop" | "reject" => return "Block".into(),
                _ => {}
            }
        }
    }
    // no verdict of its own: the rule counts, logs or jumps onward
    "Continue".into()
}

/// Canonical fingerprint of what a rule matches and does, with counter
/// *values* removed so reading a counter never changes a rule's identity.
pub fn expr_digest(expr: &Value) -> String {
    let stripped = strip_counter_values(expr);
    let text = serde_json::to_string(&stripped).unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Replace every `{"counter": {...}}` with `{"counter": null}` so a rule's
/// identity does not move as its counter climbs.
fn strip_counter_values(expr: &Value) -> Value {
    match expr {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| {
                    if item.get("counter").is_some() {
                        json!({ "counter": null })
                    } else {
                        item.clone()
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn counter_packets(expr: &Value) -> Option<i64> {
    expr.as_array()?
        .iter()
        .filter_map(|e| e.get("counter"))
        .filter_map(|c| c.get("packets"))
        .filter_map(Value::as_i64)
        .next()
}

fn has_counter(expr: &Value) -> bool {
    expr.as_array()
        .is_some_and(|items| items.iter().any(|e| e.get("counter").is_some()))
}

/// Map `handle -> rule text` from `nft -a list ruleset`, which appends
/// `# handle N` to every rule line.
pub fn parse_rule_text(text: &str) -> std::collections::HashMap<u64, String> {
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((body, handle)) = line.rsplit_once("# handle ") else {
            continue;
        };
        let Ok(handle) = handle.trim().parse::<u64>() else {
            continue;
        };
        let body = body.trim();
        // table/chain headers also carry handles; they are not rules
        if body.is_empty() || body.ends_with('{') {
            continue;
        }
        out.insert(handle, strip_counter_text(body));
    }
    out
}

/// Drop the live counter out of a rule's display text. It is shown in its
/// own column, and leaving it in makes the rule's name change on every run —
/// which reads as a different rule each time.
fn strip_counter_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find("counter packets ") {
        out.push_str(&rest[..at]);
        // skip "counter packets <n> bytes <n>"
        let after = &rest[at..];
        let mut fields = after.split_whitespace();
        let consumed: usize = fields
            .by_ref()
            .take(5)
            .map(|f| f.len() + 1)
            .sum::<usize>()
            .min(after.len());
        rest = after[consumed..].trim_start();
    }
    out.push_str(rest);
    out.trim().to_string()
}

/// Every rule of the live ruleset that Firebreak may look at.
pub fn parse_ruleset(json: &Value, listing: &str) -> Vec<NftRule> {
    let texts = parse_rule_text(listing);
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut out = Vec::new();
    let Some(items) = json["nftables"].as_array() else {
        return out;
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let table = rule["table"].as_str().unwrap_or_default().to_string();
        if SKIP_TABLES.contains(&table.as_str()) {
            continue;
        }
        let Some(handle) = rule["handle"].as_u64() else {
            continue;
        };
        let expr = rule
            .get("expr")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        let family = rule["family"].as_str().unwrap_or_default().to_string();
        let chain = rule["chain"].as_str().unwrap_or_default().to_string();
        let key = format!("{family}/{table}/{chain}/{}", expr_digest(&expr));
        let occurrence = {
            let slot = seen.entry(key).or_insert(0);
            let n = *slot;
            *slot += 1;
            n
        };
        out.push(NftRule {
            counter: counter_packets(&expr),
            text: texts.get(&handle).cloned().unwrap_or_default(),
            family,
            table,
            chain,
            handle,
            expr,
            occurrence,
        });
    }
    out
}

/// The same expression with a counter inserted before the verdict. `None`
/// when it already has one.
pub fn with_counter(expr: &Value) -> Option<Value> {
    if has_counter(expr) {
        return None;
    }
    let items = expr.as_array()?;
    let position = items
        .iter()
        .position(|e| {
            e.as_object()
                .is_some_and(|o| o.keys().any(|k| VERDICTS.contains(&k.as_str())))
        })
        .unwrap_or(items.len());
    let mut next = items.clone();
    next.insert(position, json!({ "counter": null }));
    Some(Value::Array(next))
}

/// The same expression with every counter removed — the undo.
pub fn without_counter(expr: &Value) -> Option<Value> {
    if !has_counter(expr) {
        return None;
    }
    let items = expr.as_array()?;
    Some(Value::Array(
        items
            .iter()
            .filter(|e| e.get("counter").is_none())
            .cloned()
            .collect(),
    ))
}

/// An `nft -j -f -` payload replacing each rule in place.
pub fn replace_payload(edits: &[(&NftRule, Value)]) -> Value {
    json!({
        "nftables": edits
            .iter()
            .map(|(rule, expr)| json!({
                "replace": { "rule": {
                    "family": rule.family,
                    "table": rule.table,
                    "chain": rule.chain,
                    "handle": rule.handle,
                    "expr": expr,
                }}
            }))
            .collect::<Vec<_>>()
    })
}

// ---------------------------------------------------------------------------
// Live host access
// ---------------------------------------------------------------------------

fn nft(args: &[&str]) -> Result<String> {
    let bin = crate::syspath::system_tool("nft").context("nft is not installed")?;
    let out = crate::syspath::command(bin)
        .args(args)
        .output()
        .context("running nft")?;
    if !out.status.success() {
        bail!(
            "nft {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn nft_stdin(args: &[&str], payload: &str) -> Result<()> {
    use std::io::Write;
    let bin = crate::syspath::system_tool("nft").context("nft is not installed")?;
    let mut child = crate::syspath::command(bin)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning nft")?;
    child
        .stdin
        .as_mut()
        .context("nft stdin")?
        .write_all(payload.as_bytes())?;
    let out = child.wait_with_output().context("running nft")?;
    if !out.status.success() {
        bail!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Is there a raw nftables ruleset worth auditing? An empty ruleset, or one
/// consisting only of tables another backend owns, is not this backend's job.
pub fn has_ruleset() -> bool {
    read_rules().is_ok_and(|r| !r.is_empty())
}

/// Read the live ruleset.
pub fn read_rules() -> Result<Vec<NftRule>> {
    let json: Value =
        serde_json::from_str(&nft(&["-j", "list", "ruleset"])?).context("parsing nft JSON")?;
    let listing = nft(&["-a", "list", "ruleset"]).unwrap_or_default();
    Ok(parse_ruleset(&json, &listing))
}

/// Where the pre-edit ruleset is kept, inside the secured data directory.
fn backup_path(db_path: &std::path::Path) -> std::path::PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("nftables-before-firebreak.nft")
}

/// Add a counter to every rule that lacks one.
///
/// Writes a full ruleset backup first, then verifies every touched rule came
/// back as the original expression plus exactly one counter — restoring from
/// the backup if it did not.
pub fn add_counters(db_path: &std::path::Path) -> Result<String> {
    let rules = read_rules()?;
    let edits: Vec<(&NftRule, Value)> = rules
        .iter()
        .filter_map(|r| with_counter(&r.expr).map(|e| (r, e)))
        .collect();
    let already = rules.len() - edits.len();
    if edits.is_empty() {
        return Ok(format!(
            "All {} rule(s) already carry a counter — nothing to add.",
            rules.len()
        ));
    }

    let backup = nft(&["list", "ruleset"])?;
    let path = backup_path(db_path);
    if let Some(dir) = path.parent() {
        crate::secure_dir::ensure_secured_dir(dir)?;
    }
    std::fs::write(&path, &backup)
        .with_context(|| format!("writing ruleset backup to {}", path.display()))?;

    let payload = serde_json::to_string(&replace_payload(&edits))?;
    if let Err(e) = nft_stdin(&["-j", "-f", "-"], &payload) {
        return Err(e).with_context(|| {
            format!(
                "no rule was changed (nft applies a ruleset atomically). Backup at {}",
                path.display()
            )
        });
    }

    // Verify rather than trust: the expression we sent came from the kernel,
    // but a round-trip gap would silently change what a rule matches.
    let after = read_rules()?;
    if let Some(problem) = verify(&edits, &after) {
        let _ = nft_stdin(&["-f", "-"], &format!("flush ruleset\n{backup}"));
        bail!(
            "{problem} — the ruleset has been restored from {}. No counters were added.",
            path.display()
        );
    }

    Ok(format!(
        "Added a counter to {} rule(s); {already} already had one. Ruleset backed up to {}.\n{}",
        edits.len(),
        path.display(),
        "Counters reset on reboot or a ruleset reload; Firebreak banks the old total."
    ))
}

/// Check that each edited rule is now its original self plus one counter.
/// Returns a description of the first problem, or `None` if all is well.
pub fn verify(edits: &[(&NftRule, Value)], after: &[NftRule]) -> Option<String> {
    for (original, _) in edits {
        let Some(now) = after
            .iter()
            .find(|r| r.handle == original.handle && r.table == original.table)
        else {
            return Some(format!(
                "rule handle {} vanished after the edit",
                original.handle
            ));
        };
        if !has_counter(&now.expr) {
            return Some(format!("rule handle {} has no counter", original.handle));
        }
        // stripping the counter must give back exactly what was there before
        let restored = without_counter(&now.expr).unwrap_or_else(|| now.expr.clone());
        if strip_counter_values(&restored) != strip_counter_values(&original.expr) {
            return Some(format!(
                "rule handle {} no longer matches what it did before",
                original.handle
            ));
        }
    }
    None
}

/// Remove the counters Firebreak added. Rules that already had one are left
/// alone — we cannot tell ours from theirs, so we remove none of them and
/// say so, rather than stripping counters the admin wrote.
pub fn remove_counters(db_path: &std::path::Path) -> Result<String> {
    let path = backup_path(db_path);
    if !path.exists() {
        return Ok(format!(
            "No ruleset backup at {} — Firebreak has not added any counters on this host.",
            path.display()
        ));
    }
    let backup =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    nft_stdin(&["-f", "-"], &format!("flush ruleset\n{backup}"))
        .context("restoring the ruleset recorded before Firebreak added counters")?;
    let _ = std::fs::remove_file(&path);
    Ok(format!(
        "Restored the ruleset recorded at {}. Collected totals are kept.",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `nft -j list ruleset` from a Fedora 44 host with a hand-written
    /// ruleset: one rule already counted, one anonymous set, one two-match
    /// rule, and one counter-only rule with no verdict.
    const REAL_JSON: &str = r#"{"nftables": [
      {"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
      {"table": {"family": "inet", "name": "myfw", "handle": 1}},
      {"chain": {"family": "inet", "table": "myfw", "name": "input", "handle": 1,
                 "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
      {"rule": {"family": "inet", "table": "myfw", "chain": "input", "handle": 6,
        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                 {"counter": {"packets": 17, "bytes": 1020}}, {"accept": null}]}},
      {"rule": {"family": "inet", "table": "myfw", "chain": "input", "handle": 8,
        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [80, 443]}}},
                 {"accept": null}]}},
      {"rule": {"family": "inet", "table": "myfw", "chain": "input", "handle": 10,
        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
                 {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 5432}},
                 {"accept": null}]}},
      {"rule": {"family": "inet", "table": "myfw", "chain": "input", "handle": 11,
        "expr": [{"counter": {"packets": 3, "bytes": 180}}]}},
      {"rule": {"family": "inet", "table": "firewalld", "chain": "filter_INPUT", "handle": 99,
        "expr": [{"accept": null}]}}
    ]}"#;

    const REAL_LISTING: &str = r#"table inet myfw { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		tcp dport 22 counter packets 17 bytes 1020 accept # handle 6
		tcp dport { 80, 443 } accept # handle 8
		ip saddr 10.0.0.0/8 tcp dport 5432 accept # handle 10
		counter packets 3 bytes 180 comment "dropped" # handle 11
	}
}"#;

    fn rules() -> Vec<NftRule> {
        let json: Value = serde_json::from_str(REAL_JSON).unwrap();
        parse_ruleset(&json, REAL_LISTING)
    }

    #[test]
    fn firewalld_and_our_own_tables_are_left_alone() {
        // firewalld's table is owner-locked and has its own backend; the
        // shadow table is ours. Auditing either here would double-count or
        // fail outright.
        let rs = rules();
        assert!(rs.iter().all(|r| r.table == "myfw"), "{:?}", rs);
        assert_eq!(rs.len(), 4);
    }

    #[test]
    fn existing_counters_are_read_directly() {
        let rs = rules();
        let ssh = rs.iter().find(|r| r.handle == 6).unwrap();
        assert_eq!(ssh.counter, Some(17));
        assert_eq!(
            ssh.text, "tcp dport 22 accept",
            "the live counter belongs in the hits column, not the rule's name"
        );
    }

    #[test]
    fn a_rule_without_a_counter_reports_none_not_zero() {
        // None means "not measured"; Some(0) would mean "never matched" and
        // invite deleting a rule nobody ever counted.
        let rs = rules();
        assert_eq!(rs.iter().find(|r| r.handle == 8).unwrap().counter, None);
    }

    #[test]
    fn identity_survives_the_counter_climbing() {
        // The id must not move as traffic accrues, or every run would look
        // like a brand-new rule and totals would never accumulate.
        let rs = rules();
        let ssh = rs.iter().find(|r| r.handle == 6).unwrap();
        let mut later = ssh.clone();
        later.expr = json!([
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
            {"counter": {"packets": 9999, "bytes": 600000}},
            {"accept": null}
        ]);
        assert_eq!(ssh.id(), later.id());
    }

    #[test]
    fn identity_survives_a_reload_that_renumbers_handles() {
        let rs = rules();
        let ssh = rs.iter().find(|r| r.handle == 6).unwrap();
        let mut reloaded = ssh.clone();
        reloaded.handle = 4242;
        assert_eq!(ssh.id(), reloaded.id(), "handles must not be the identity");
    }

    #[test]
    fn identical_rules_in_one_chain_get_distinct_identities() {
        let json: Value = serde_json::from_str(
            r#"{"nftables": [
              {"rule": {"family":"inet","table":"t","chain":"c","handle":1,"expr":[{"accept": null}]}},
              {"rule": {"family":"inet","table":"t","chain":"c","handle":2,"expr":[{"accept": null}]}}
            ]}"#,
        )
        .unwrap();
        let rs = parse_ruleset(&json, "");
        assert_eq!(rs.len(), 2);
        assert_ne!(rs[0].id(), rs[1].id());
    }

    #[test]
    fn a_counter_goes_before_the_verdict() {
        // after the verdict it would never be reached
        let rs = rules();
        let set_rule = rs.iter().find(|r| r.handle == 8).unwrap();
        let next = with_counter(&set_rule.expr).unwrap();
        let items = next.as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert!(items[1].get("counter").is_some());
        assert!(items[2].get("accept").is_some());
        // and the match is untouched
        assert_eq!(items[0], set_rule.expr.as_array().unwrap()[0]);
    }

    #[test]
    fn a_rule_with_no_verdict_gets_its_counter_appended() {
        let expr = json!([{"log": {"prefix": "x"}}]);
        let next = with_counter(&expr).unwrap();
        let items = next.as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[1].get("counter").is_some());
    }

    #[test]
    fn an_already_counted_rule_is_not_touched_twice() {
        let rs = rules();
        let ssh = rs.iter().find(|r| r.handle == 6).unwrap();
        assert_eq!(with_counter(&ssh.expr), None);
    }

    #[test]
    fn removing_a_counter_gives_back_the_original_expression() {
        let rs = rules();
        let plain = rs.iter().find(|r| r.handle == 8).unwrap();
        let counted = with_counter(&plain.expr).unwrap();
        assert_eq!(without_counter(&counted).unwrap(), plain.expr);
    }

    #[test]
    fn verification_rejects_a_rule_whose_match_changed() {
        // The safety net: if a JSON round-trip ever altered what a rule
        // matches, this is what catches it before the user lives with it.
        let rs = rules();
        let original = rs.iter().find(|r| r.handle == 8).unwrap();
        let edits: Vec<(&NftRule, Value)> = vec![(original, with_counter(&original.expr).unwrap())];

        let mut tampered = original.clone();
        tampered.expr = json!([
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [80]}}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"accept": null}
        ]);
        let problem = verify(&edits, &[tampered]).expect("must be rejected");
        assert!(problem.contains("no longer matches"), "{problem}");
    }

    #[test]
    fn verification_rejects_a_rule_that_lost_its_counter() {
        let rs = rules();
        let original = rs.iter().find(|r| r.handle == 8).unwrap();
        let edits: Vec<(&NftRule, Value)> = vec![(original, with_counter(&original.expr).unwrap())];
        let problem = verify(&edits, std::slice::from_ref(original)).expect("must be rejected");
        assert!(problem.contains("no counter"), "{problem}");
    }

    #[test]
    fn verification_rejects_a_rule_that_disappeared() {
        let rs = rules();
        let original = rs.iter().find(|r| r.handle == 8).unwrap();
        let edits: Vec<(&NftRule, Value)> = vec![(original, with_counter(&original.expr).unwrap())];
        let problem = verify(&edits, &[]).expect("must be rejected");
        assert!(problem.contains("vanished"), "{problem}");
    }

    #[test]
    fn verification_accepts_a_correct_edit() {
        let rs = rules();
        let original = rs.iter().find(|r| r.handle == 8).unwrap();
        let counted = with_counter(&original.expr).unwrap();
        let edits: Vec<(&NftRule, Value)> = vec![(original, counted.clone())];
        let mut after = original.clone();
        after.expr = counted;
        assert_eq!(verify(&edits, &[after]), None);
    }

    #[test]
    fn the_replace_payload_targets_rules_by_handle() {
        let rs = rules();
        let r = rs.iter().find(|r| r.handle == 8).unwrap();
        let payload = replace_payload(&[(r, with_counter(&r.expr).unwrap())]);
        let cmd = &payload["nftables"][0]["replace"]["rule"];
        assert_eq!(cmd["handle"], 8);
        assert_eq!(cmd["table"], "myfw");
        assert_eq!(cmd["family"], "inet");
    }

    #[test]
    fn rule_text_pairs_by_handle_and_skips_headers() {
        let texts = parse_rule_text(REAL_LISTING);
        assert_eq!(texts.len(), 4, "table and chain headers are not rules");
        assert_eq!(
            texts.get(&8).map(String::as_str),
            Some("tcp dport { 80, 443 } accept")
        );
    }

    #[test]
    fn display_text_drops_the_live_counter() {
        // otherwise the rule's name changes every run as traffic accrues
        assert_eq!(
            strip_counter_text("tcp dport 22 counter packets 17 bytes 1020 accept"),
            "tcp dport 22 accept"
        );
        assert_eq!(
            strip_counter_text("counter packets 3 bytes 180 comment \"dropped\""),
            "comment \"dropped\""
        );
        assert_eq!(strip_counter_text("iif \"lo\" accept"), "iif \"lo\" accept");
    }

    #[test]
    fn actions_are_read_from_the_verdict() {
        assert_eq!(action_of(&json!([{"accept": null}])), "Allow");
        assert_eq!(action_of(&json!([{"drop": null}])), "Block");
        assert_eq!(action_of(&json!([{"reject": {}}])), "Block");
        // a counter-only rule decides nothing
        assert_eq!(action_of(&json!([{"counter": null}])), "Continue");
    }

    #[test]
    fn chain_names_hint_at_direction_without_being_trusted() {
        assert_eq!(direction_of("input"), "Inbound");
        assert_eq!(direction_of("my_output"), "Outbound");
        assert_eq!(direction_of("forward"), "Forward");
    }
}
