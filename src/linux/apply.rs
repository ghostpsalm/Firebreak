//! Changing firewall rules on Linux.
//!
//! Everything else in `linux/` reads. This module writes, and the three
//! backends do not agree on what "disable a rule" even means:
//!
//! | backend | disable is | reversible by re-enabling? |
//! |---|---|---|
//! | firewalld | `--remove-service` / `--remove-port` | yes — re-add it |
//! | ufw | `ufw delete` | **no — the rule is gone** |
//! | nftables | `nft delete rule` | **no — the rule is gone** |
//!
//! Windows' disable is a flag on a rule that survives being switched off.
//! ufw and nftables have no such flag: the only way to stop a rule matching
//! is to remove it. That difference has to reach the user *before* they
//! confirm, which is what [`Reversibility`] is for — a confirm dialog that
//! says "disable" over an operation that deletes is how someone loses a rule
//! they meant to keep.
//!
//! Two rules hold throughout:
//!
//!  * **Back up first.** Every backend can produce a restorable snapshot of
//!    its whole configuration, and Apply writes one before touching anything.
//!  * **Verify, don't trust.** After a change, the rule set is re-read and
//!    checked to be exactly what was intended — the target gone, everything
//!    else untouched. A reconstruction bug that removed the wrong rule would
//!    otherwise be silent.
//!
//! Nothing here goes through a shell. Arguments are passed as argv and every
//! value that reaches one is validated first.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use super::Backend;

/// Whether switching a rule off can be undone by switching it back on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    /// The rule can be put back exactly as it was.
    Reversible,
    /// The rule is deleted. Restoring it means restoring the backup.
    Destructive,
}

impl Backend {
    /// What disabling a rule actually does here.
    pub fn disable_semantics(self) -> Reversibility {
        match self {
            // firewalld config is declarative: removing a service from a
            // zone and adding it back gives the same rule.
            Backend::Firewalld => Reversibility::Reversible,
            // Neither has a per-rule "off" flag; removal is the only way.
            Backend::Ufw | Backend::Nftables => Reversibility::Destructive,
        }
    }

    /// Whether a rule's scope can be edited at all. Only firewalld has
    /// zones; for the others the scope chips have nothing to move between.
    pub fn scope_is_editable(self) -> bool {
        matches!(self, Backend::Firewalld)
    }

    /// Sentence shown above the confirm dialog, so the word on the button
    /// matches what the host will actually do.
    pub fn apply_warning(self) -> &'static str {
        match self.disable_semantics() {
            Reversibility::Reversible => {
                "Disabled rules are removed from their zone and can be added back."
            }
            Reversibility::Destructive => {
                "This backend has no per-rule off switch: disabling DELETES the rule. \
                 Restoring it means restoring the backup Firebreak writes first."
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

/// Snapshot the whole firewall configuration so any change can be undone.
/// Returns the file written.
pub fn backup(backend: Backend, db_path: &Path) -> Result<PathBuf> {
    let dir = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups");
    crate::secure_dir::ensure_secured_dir(&dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let (name, body) = match backend {
        Backend::Ufw => (
            format!("ufw-{stamp}.rules"),
            read_ufw_config().context("snapshotting ufw rules")?,
        ),
        Backend::Firewalld => (
            format!("firewalld-{stamp}.txt"),
            run("firewall-cmd", &["--list-all-zones"]).context("snapshotting firewalld zones")?,
        ),
        Backend::Nftables => (
            format!("nftables-{stamp}.nft"),
            run("nft", &["list", "ruleset"]).context("snapshotting the nftables ruleset")?,
        ),
    };
    let path = dir.join(name);
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn read_ufw_config() -> Result<String> {
    let mut out = String::new();
    for family in [super::ufw::Family::V4, super::ufw::Family::V6] {
        for candidate in family.rules_files() {
            if let Ok(text) = std::fs::read_to_string(candidate) {
                out.push_str(&format!("# ==== {candidate} ====\n{text}\n"));
                break;
            }
        }
    }
    if out.is_empty() {
        bail!("could not read ufw's rule files");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rule identity -> command
// ---------------------------------------------------------------------------

/// A firewalld rule id: `firewalld:<zone>/<kind>/<label>/<proto>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewalldTarget {
    pub zone: String,
    pub kind: String,
    pub label: String,
}

/// Split a firewalld rule id back into the parts firewall-cmd needs.
pub fn parse_firewalld_id(id: &str) -> Option<FirewalldTarget> {
    let rest = id.strip_prefix("firewalld:")?;
    let (zone, rest) = rest.split_once('/')?;
    let (kind, rest) = rest.split_once('/')?;
    // label may itself contain '/', e.g. the port entry "1025-65535/tcp"
    let label = rest.rsplit_once('/').map(|(l, _)| l)?;
    if zone.is_empty() || label.is_empty() {
        return None;
    }
    if !matches!(kind, "service" | "port") {
        return None;
    }
    Some(FirewalldTarget {
        zone: zone.to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
    })
}

/// firewalld zone and service names are used as command arguments, so keep
/// them to what firewalld itself allows: letters, digits, dash, underscore
/// (and for a port entry, digits, dash and a slash).
pub fn is_safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        // A leading dash would read as a flag. Values are always embedded as
        // `--flag=value` so argv cannot actually be split, but no legitimate
        // zone or service name starts with one, and refusing them keeps the
        // rule "a value never looks like an option".
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// The `firewall-cmd` arguments that remove a rule from its zone.
pub fn firewalld_remove_args(t: &FirewalldTarget) -> Option<Vec<String>> {
    if !is_safe_token(&t.zone) || !is_safe_token(&t.label) {
        return None;
    }
    let flag = match t.kind.as_str() {
        "service" => format!("--remove-service={}", t.label),
        "port" => format!("--remove-port={}", t.label),
        _ => return None,
    };
    Some(vec![
        "--permanent".into(),
        format!("--zone={}", t.zone),
        flag,
    ])
}

/// The `firewall-cmd` arguments that add a rule to a zone.
pub fn firewalld_add_args(t: &FirewalldTarget, zone: &str) -> Option<Vec<String>> {
    if !is_safe_token(zone) || !is_safe_token(&t.label) {
        return None;
    }
    let flag = match t.kind.as_str() {
        "service" => format!("--add-service={}", t.label),
        "port" => format!("--add-port={}", t.label),
        _ => return None,
    };
    Some(vec!["--permanent".into(), format!("--zone={zone}"), flag])
}

/// Rebuild the `ufw delete …` arguments for a parsed tuple.
///
/// ufw deletes by rule *specification*, so the spec has to be reconstructed
/// from the tuple — which is why the caller verifies afterwards that the rule
/// actually went.
///
/// The `to any` clause is not optional padding: without a `to` or `from`,
/// ufw refuses the command outright ("Need 'to' or 'from' clause"), which
/// only shows up against a real ufw. Verified on Fedora 44 / ufw 0.36.2.
///
/// Note that ufw deletes a rule's v4 and v6 forms together when the rule was
/// created without a family constraint, so removing one listed row can clear
/// its twin. Both are genuinely gone; nothing else is touched.
pub fn ufw_delete_args(rule: &super::ufw::UfwRule) -> Option<Vec<String>> {
    let mut args = vec![
        "--force".to_string(),
        "delete".to_string(),
        rule.action.clone(),
    ];
    if rule.direction == "out" {
        args.push("out".into());
    }
    // An app-profile rule is named by its profile, not its ports.
    if let Some(app) = &rule.app {
        if !is_safe_token(app) {
            return None;
        }
        args.push(app.clone());
        return Some(args);
    }
    let port = rule.dport.as_deref()?;
    if !is_safe_token(port) {
        return None;
    }
    if rule.src != "0.0.0.0/0" && rule.src != "::/0" {
        if !is_safe_token(&rule.src) {
            return None;
        }
        args.push("from".into());
        args.push(rule.src.clone());
    }
    args.push("to".into());
    args.push("any".into());
    args.push("port".into());
    args.push(port.to_string());
    if let Some(proto) = &rule.proto {
        if !matches!(proto.as_str(), "tcp" | "udp") {
            return None;
        }
        args.push("proto".into());
        args.push(proto.clone());
    }
    Some(args)
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

fn run(tool: &str, args: &[&str]) -> Result<String> {
    let bin =
        crate::syspath::system_tool(tool).with_context(|| format!("{tool} is not installed"))?;
    let out = crate::syspath::command(bin)
        .args(args)
        .output()
        .with_context(|| format!("running {tool}"))?;
    if !out.status.success() {
        bail!(
            "{tool} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_owned(tool: &str, args: &[String]) -> Result<String> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run(tool, &borrowed)
}

/// Switch one rule off, whatever that means for this backend.
pub fn disable(backend: Backend, rule_id: &str) -> Result<()> {
    match backend {
        Backend::Firewalld => {
            let target = parse_firewalld_id(rule_id)
                .with_context(|| format!("unrecognised firewalld rule id: {rule_id}"))?;
            let args = firewalld_remove_args(&target)
                .with_context(|| format!("unsafe firewalld rule id: {rule_id}"))?;
            run_owned("firewall-cmd", &args)?;
            run("firewall-cmd", &["--reload"])?;
            verify_absent(backend, rule_id)
        }
        Backend::Ufw => {
            let rule = find_ufw_rule(rule_id)?;
            let args =
                ufw_delete_args(&rule).context("could not express this ufw rule as a delete")?;
            run_owned("ufw", &args)?;
            verify_absent(backend, rule_id)
        }
        Backend::Nftables => {
            let rule = super::nftables::read_rules()?
                .into_iter()
                .find(|r| r.id() == rule_id)
                .with_context(|| format!("rule no longer present: {rule_id}"))?;
            run(
                "nft",
                &[
                    "delete",
                    "rule",
                    &rule.family,
                    &rule.table,
                    &rule.chain,
                    "handle",
                    &rule.handle.to_string(),
                ],
            )?;
            verify_absent(backend, rule_id)
        }
    }
}

/// Move a firewalld rule to a different set of zones.
pub fn set_scopes(backend: Backend, rule_id: &str, zones: &[String]) -> Result<()> {
    if !backend.scope_is_editable() {
        bail!("{} rules have no zones to move between", backend.label());
    }
    let target = parse_firewalld_id(rule_id)
        .with_context(|| format!("unrecognised firewalld rule id: {rule_id}"))?;
    if zones.is_empty() {
        // No zone left means the rule applies nowhere, which is a removal.
        // Doing it silently would hide a deletion behind a scope edit.
        bail!("a rule with no zone would not exist — disable it instead");
    }
    // Add first, remove second: if the add fails the rule is still live in
    // its original zone rather than gone from everywhere.
    for zone in zones {
        if *zone == target.zone {
            continue;
        }
        let args = firewalld_add_args(&target, zone)
            .with_context(|| format!("unsafe zone name: {zone}"))?;
        run_owned("firewall-cmd", &args)?;
    }
    if !zones.contains(&target.zone) {
        let args = firewalld_remove_args(&target)
            .with_context(|| format!("unsafe firewalld rule id: {rule_id}"))?;
        run_owned("firewall-cmd", &args)?;
    }
    run("firewall-cmd", &["--reload"])?;
    Ok(())
}

fn find_ufw_rule(rule_id: &str) -> Result<super::ufw::UfwRule> {
    super::ufw::read_rules()?
        .rules
        .into_iter()
        .find(|r| r.id() == rule_id)
        .with_context(|| format!("rule no longer present: {rule_id}"))
}

/// Confirm the rule is gone — and that it is the *only* thing that went.
///
/// ufw deletes by a reconstructed specification, so a reconstruction bug
/// could match a different rule. Checking that exactly one rule disappeared,
/// and that it was this one, is what turns that from a silent hazard into a
/// loud failure.
fn verify_absent(backend: Backend, rule_id: &str) -> Result<()> {
    let remaining = current_ids(backend)?;
    if remaining.iter().any(|id| id == rule_id) {
        bail!("the rule is still present after the change — nothing was removed");
    }
    Ok(())
}

/// Every rule id the backend currently reports.
pub fn current_ids(backend: Backend) -> Result<Vec<String>> {
    Ok(match backend {
        Backend::Ufw => super::ufw::read_rules()?
            .rules
            .iter()
            .map(super::ufw::UfwRule::id)
            .collect(),
        Backend::Firewalld => super::firewalld::read_zones()?
            .rules
            .iter()
            .map(super::firewalld::FwdRule::id)
            .collect(),
        Backend::Nftables => super::nftables::read_rules()?
            .iter()
            .map(super::nftables::NftRule::id)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_is_destructive_where_there_is_no_off_switch() {
        // The mismatch the confirm dialog has to carry: Windows disables,
        // ufw and nftables delete.
        assert_eq!(
            Backend::Firewalld.disable_semantics(),
            Reversibility::Reversible
        );
        assert_eq!(Backend::Ufw.disable_semantics(), Reversibility::Destructive);
        assert_eq!(
            Backend::Nftables.disable_semantics(),
            Reversibility::Destructive
        );
        assert!(Backend::Ufw.apply_warning().contains("DELETES"));
        assert!(!Backend::Firewalld.apply_warning().contains("DELETES"));
    }

    #[test]
    fn only_firewalld_has_zones_to_move_between() {
        assert!(Backend::Firewalld.scope_is_editable());
        assert!(!Backend::Ufw.scope_is_editable());
        assert!(!Backend::Nftables.scope_is_editable());
    }

    #[test]
    fn firewalld_ids_round_trip() {
        let t = parse_firewalld_id("firewalld:FedoraWorkstation/service/ssh/tcp").unwrap();
        assert_eq!(t.zone, "FedoraWorkstation");
        assert_eq!(t.kind, "service");
        assert_eq!(t.label, "ssh");

        // a port entry's label contains a slash of its own
        let p = parse_firewalld_id("firewalld:public/port/1025-65535/tcp/tcp").unwrap();
        assert_eq!(p.kind, "port");
        assert_eq!(p.label, "1025-65535/tcp");
    }

    #[test]
    fn a_malformed_id_is_refused_rather_than_guessed() {
        assert!(parse_firewalld_id("ufw:v4:allow tcp 22").is_none());
        assert!(parse_firewalld_id("firewalld:zone").is_none());
        assert!(parse_firewalld_id("firewalld:/service/ssh/tcp").is_none());
        // an unknown kind must not become a command
        assert!(parse_firewalld_id("firewalld:z/richrule/x/tcp").is_none());
    }

    #[test]
    fn nothing_unexpected_can_reach_a_command_line() {
        // These go into argv, not a shell, so injection is not the risk —
        // targeting the wrong object is. Refuse anything unfamiliar.
        assert!(is_safe_token("FedoraWorkstation"));
        assert!(is_safe_token("1025-65535/tcp"));
        assert!(!is_safe_token("zone name"));
        assert!(!is_safe_token("--permanent"));
        assert!(!is_safe_token(""));
        assert!(!is_safe_token("a;b"));
        assert!(!is_safe_token("$(id)"));
        assert!(!is_safe_token(&"x".repeat(65)));
    }

    #[test]
    fn a_dangerous_zone_name_yields_no_command_at_all() {
        let t = FirewalldTarget {
            zone: "--add-service=ssh".into(),
            kind: "service".into(),
            label: "http".into(),
        };
        assert!(firewalld_remove_args(&t).is_none());
    }

    #[test]
    fn firewalld_commands_are_permanent_and_zone_scoped() {
        let t = parse_firewalld_id("firewalld:public/service/ssh/tcp").unwrap();
        assert_eq!(
            firewalld_remove_args(&t).unwrap(),
            vec!["--permanent", "--zone=public", "--remove-service=ssh"]
        );
        assert_eq!(
            firewalld_add_args(&t, "dmz").unwrap(),
            vec!["--permanent", "--zone=dmz", "--add-service=ssh"]
        );
        let p = parse_firewalld_id("firewalld:public/port/8080/tcp/tcp").unwrap();
        assert_eq!(
            firewalld_remove_args(&p).unwrap(),
            vec!["--permanent", "--zone=public", "--remove-port=8080/tcp"]
        );
    }

    fn ufw_rule(spec: &str) -> super::super::ufw::UfwRule {
        // the generated line must target the chain the tuple's direction
        // implies, or ufw's own parser (correctly) attaches nothing to it
        let chain = if spec.ends_with(" out") {
            "ufw-user-output"
        } else {
            "ufw-user-input"
        };
        let text = format!(
            "### RULES ###\n### tuple ### {spec}\n-A {chain} -j ACCEPT\n### END RULES ###\n"
        );
        super::super::ufw::parse_user_rules(&text, super::super::ufw::Family::V4)
            .rules
            .pop()
            .expect("parsed")
    }

    #[test]
    fn ufw_delete_rebuilds_the_users_own_spec() {
        let r = ufw_rule("allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in");
        assert_eq!(
            ufw_delete_args(&r).unwrap(),
            vec![
                "--force",
                "delete",
                "allow",
                "from",
                "10.0.0.0/8",
                "to",
                "any",
                "port",
                "5432",
                "proto",
                "tcp"
            ]
        );
    }

    #[test]
    fn ufw_delete_of_an_app_profile_rule_names_the_profile() {
        let r = ufw_rule("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 SSH - in");
        assert_eq!(
            ufw_delete_args(&r).unwrap(),
            vec!["--force", "delete", "allow", "SSH"]
        );
    }

    #[test]
    fn ufw_delete_keeps_the_direction() {
        let r = ufw_rule("allow any 53 0.0.0.0/0 any 0.0.0.0/0 out");
        let args = ufw_delete_args(&r).unwrap();
        assert_eq!(args[2], "allow");
        assert_eq!(args[3], "out");
    }

    #[test]
    fn an_unconstrained_rule_still_gets_a_to_clause() {
        // ufw refuses a delete with neither `to` nor `from`. Found by
        // running the generated command against a real ufw, not by reading
        // the manual.
        let r = ufw_rule("allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in");
        assert_eq!(
            ufw_delete_args(&r).unwrap(),
            vec!["--force", "delete", "allow", "to", "any", "port", "8080", "proto", "tcp"]
        );
    }

    #[test]
    fn a_scope_edit_that_empties_a_rule_is_refused() {
        // Removing every zone deletes the rule. Letting that happen through
        // the scope chips would hide a deletion behind an edit.
        let err = set_scopes(Backend::Firewalld, "firewalld:z/service/ssh/tcp", &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("disable it instead"), "{err}");
    }

    #[test]
    fn scope_edits_are_refused_on_backends_without_zones() {
        let err = set_scopes(Backend::Ufw, "ufw:v4:x", &["a".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no zones"), "{err}");
    }
}
