//! The firewalld backend.
//!
//! firewalld is the hard one. Its nftables table carries `flags owner`, so
//! the kernel refuses to let any other process add a counter to it — not a
//! permissions problem, and `sudo` does not help:
//!
//! ```text
//! $ nft replace rule inet firewalld filter_IN_FedoraWorkstation_allow \
//!       handle 163 udp dport 137 counter accept
//! Error: Could not process rule: Operation not permitted
//! ```
//!
//! firewalld emits no counters of its own either, so there is nothing to
//! read. Firebreak therefore installs a **shadow table** of its own: same
//! traffic, counters only, no verdicts.
//!
//! Placement is the whole design. The shadow chain sits in the input hook at
//! priority 300 — *after* firewalld's filter at priority 0 — so a packet only
//! reaches it if firewalld already accepted it. A hit therefore means
//! "allowed via this rule", not "would have matched if it got here". The
//! chain's policy is `accept` and its rules carry no verdict, so it cannot
//! change any packet's fate; it can only count.
//!
//! Two consequences the caller must carry honestly:
//!
//!  * The shadow rules are a *reconstruction* of firewalld's semantics, not
//!    firewalld's own rules. Anything not expressible as a tcp/udp port match
//!    — rich rules, ipsets, icmp-blocks, protocol-only entries — is reported
//!    as **unmeasurable**, never as zero-hit. Mistaking "cannot count this"
//!    for "never used" is how a tool talks someone into deleting a rule that
//!    is load-bearing.
//!  * nftables tables do not survive a reboot. Collection therefore stops at
//!    every reboot until Firebreak next runs — unlike Windows, where the
//!    audit policy persists. [`REBOOT_CAVEAT`] is the text shown to the user.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

use crate::model::RuleInfo;

/// Our own table. Named, versioned and never shared with firewalld's.
pub const SHADOW_TABLE: &str = "firebreak_shadow";

/// Input-hook priority. firewalld's filter runs at 0, so 300 is after its
/// verdict: we see accepted traffic only.
const SHADOW_PRIORITY: i32 = 300;

pub const REBOOT_CAVEAT: &str = "nftables tables do not survive a reboot, so counting stops at \
     every reboot until Firebreak runs again. Totals already collected are kept.";

/// One firewalld entry, as the user configured it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwdRule {
    pub zone: String,
    /// "service" or "port"
    pub kind: String,
    /// service name, or the port spec for a bare port entry
    pub label: String,
    pub proto: String,
    /// comma-separated ports/ranges
    pub ports: String,
}

impl FwdRule {
    pub fn id(&self) -> String {
        format!(
            "firewalld:{}/{}/{}/{}",
            self.zone, self.kind, self.label, self.proto
        )
    }

    pub fn to_rule_info(&self) -> RuleInfo {
        RuleInfo {
            name: self.id(),
            display_name: format!("{} ({})", self.label, self.zone),
            description: None,
            enabled: "True".into(),
            // Zone services and ports admit inbound traffic.
            direction: "Inbound".into(),
            action: "Allow".into(),
            // the zone *is* the scope; the vocabulary is the zone list
            profile: self.zone.clone(),
            group: Some(self.kind.clone()),
            program: None,
            protocol: Some(self.proto.clone()),
            local_port: Some(self.ports.clone()),
            remote_port: None,
            service: (self.kind == "service").then(|| self.label.clone()),
            remote_address: None,
            // Linux has no policy store; the owning manager is the source.
            policy_source: Some("firewalld".into()),
            policy_source_type: Some(crate::model::RuleInfo::SOURCE_TYPE_PLATFORM.into()),
        }
    }
}

/// What a zone contains, split into what Firebreak can and cannot count.
#[derive(Debug, Default)]
pub struct Zones {
    pub rules: Vec<FwdRule>,
    /// (id, reason) for configuration that exists but cannot be measured.
    pub unmeasurable: Vec<(String, String)>,
    /// Active zone names, in the order firewalld reports them — this becomes
    /// the scope vocabulary.
    pub names: Vec<String>,
}

fn firewall_cmd(args: &[&str]) -> Result<String> {
    let bin =
        crate::syspath::system_tool("firewall-cmd").context("firewall-cmd is not installed")?;
    let out = crate::syspath::command(bin)
        .args(args)
        .output()
        .context("running firewall-cmd")?;
    if !out.status.success() {
        bail!(
            "firewall-cmd {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn is_running() -> bool {
    firewall_cmd(&["--state"]).is_ok_and(|s| s.trim() == "running")
}

/// Active zone names. `--get-active-zones` prints the zone name on its own
/// line followed by indented detail, and marks the default with a suffix.
pub fn active_zones(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && !l.trim().is_empty())
        // "FedoraWorkstation (default)" -> "FedoraWorkstation"
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Parse `firewall-cmd --info-service=<name>` into (proto, port) pairs and
/// the services it includes.
pub fn parse_service(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut ports = Vec::new();
    let mut includes = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("ports:") {
            for tok in rest.split_whitespace() {
                if let Some((port, proto)) = tok.split_once('/') {
                    ports.push((proto.to_string(), port.to_string()));
                }
            }
        } else if let Some(rest) = l.strip_prefix("includes:") {
            includes.extend(rest.split_whitespace().map(str::to_string));
        }
    }
    (ports, includes)
}

/// Expand a service into every (proto, port) it opens, following `includes`.
///
/// firewalld services compose: `samba-client` declares only 138/udp but
/// includes `netbios-ns`, which adds 137/udp. Not following includes makes a
/// rule look narrower than it is — the one direction of error this tool must
/// never make. Depth-capped and cycle-guarded, because the include graph is
/// user-editable.
fn service_ports(name: &str) -> Vec<(String, String)> {
    fn walk(
        name: &str,
        seen: &mut std::collections::HashSet<String>,
        out: &mut Vec<(String, String)>,
        depth: usize,
    ) {
        if depth > 8 || !seen.insert(name.to_string()) {
            return;
        }
        let Ok(text) = firewall_cmd(&[&format!("--info-service={name}")]) else {
            return;
        };
        let (ports, includes) = parse_service(&text);
        out.extend(ports);
        for inc in includes {
            walk(&inc, seen, out, depth + 1);
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    walk(name, &mut seen, &mut out, 0);
    out.sort();
    out.dedup();
    out
}

/// Turn one zone's `--info-zone` output into rules plus a list of everything
/// in it Firebreak cannot count.
pub fn parse_zone(zone: &str, text: &str, expand: &dyn Fn(&str) -> Vec<(String, String)>) -> Zones {
    let mut z = Zones::default();
    let mut unmeasurable = |what: &str, detail: &str, why: &str| {
        z.unmeasurable
            .push((format!("firewalld:{zone}/{what}/{detail}"), why.to_string()));
    };

    // firewalld prints most fields inline ("services: ssh mdns") but puts
    // rich rules and forward-ports on *tab-indented continuation lines*
    // under an otherwise-empty key. Treating a blank value as "nothing here"
    // therefore drops every rich rule silently — the exact failure this
    // backend exists to avoid.
    let mut current_key = String::new();
    for line in text.lines() {
        let (key, rest) = if line.starts_with('\t') {
            (current_key.clone(), line.trim().to_string())
        } else {
            let Some((k, v)) = line.trim().split_once(':') else {
                continue;
            };
            current_key = k.to_string();
            (k.to_string(), v.trim().to_string())
        };
        let (key, rest) = (key.as_str(), rest.as_str());
        if rest.is_empty() {
            continue;
        }
        match key {
            "services" => {
                for svc in rest.split_whitespace() {
                    let mut by_proto: BTreeMap<String, Vec<String>> = BTreeMap::new();
                    for (proto, port) in expand(svc) {
                        by_proto.entry(proto).or_default().push(port);
                    }
                    if by_proto.is_empty() {
                        unmeasurable(
                            "service",
                            svc,
                            "This service opens no tcp/udp port that Firebreak can count \
                             (it may use a protocol or kernel helper instead).",
                        );
                        continue;
                    }
                    for (proto, ports) in by_proto {
                        z.rules.push(FwdRule {
                            zone: zone.to_string(),
                            kind: "service".into(),
                            label: svc.to_string(),
                            proto,
                            ports: ports.join(","),
                        });
                    }
                }
            }
            "ports" => {
                for tok in rest.split_whitespace() {
                    let Some((port, proto)) = tok.split_once('/') else {
                        continue;
                    };
                    if !matches!(proto, "tcp" | "udp") {
                        unmeasurable(
                            "port",
                            tok,
                            "Only tcp and udp ports can be counted by the shadow table.",
                        );
                        continue;
                    }
                    z.rules.push(FwdRule {
                        zone: zone.to_string(),
                        kind: "port".into(),
                        label: tok.to_string(),
                        proto: proto.to_string(),
                        ports: port.to_string(),
                    });
                }
            }
            // Everything below is real, active configuration that the shadow
            // table cannot express. It is listed so the user sees it exists,
            // rather than silently getting a shorter rule list.
            "rich rules" => unmeasurable(
                "rich-rule",
                rest,
                "Rich rules can match on source, ipset, logging and rate limits; Firebreak \
                 cannot reconstruct them as a counter, so this rule has no hit count.",
            ),
            "protocols" => unmeasurable(
                "protocol",
                rest,
                "Protocol-level entries (esp, ah, gre …) have no port to count.",
            ),
            "source-ports" => unmeasurable(
                "source-port",
                rest,
                "Source-port entries are not reconstructed by the shadow table.",
            ),
            "icmp-blocks" => unmeasurable(
                "icmp-block",
                rest,
                "ICMP block entries have no port to count.",
            ),
            "forward-ports" => unmeasurable(
                "forward-port",
                rest,
                "Forwarded ports are redirected before the shadow chain sees them.",
            ),
            _ => {}
        }
    }
    z
}

/// Read every active zone.
pub fn read_zones() -> Result<Zones> {
    let mut all = Zones {
        names: active_zones(&firewall_cmd(&["--get-active-zones"])?),
        ..Zones::default()
    };
    for zone in &all.names {
        let text = firewall_cmd(&[&format!("--info-zone={zone}")])?;
        let z = parse_zone(zone, &text, &service_ports);
        all.rules.extend(z.rules);
        all.unmeasurable.extend(z.unmeasurable);
    }
    if all.rules.is_empty() && all.unmeasurable.is_empty() {
        bail!("no firewalld zone configuration found");
    }
    Ok(all)
}

/// Short, comment-safe id for a rule's counter. nft comments are capped, and
/// the position in `rules` is what the reader joins on.
fn slot(index: usize) -> String {
    format!("fb{index}")
}

/// The nft match expression that recognises a rule's traffic.
pub fn match_expr(rule: &FwdRule) -> Option<String> {
    if !matches!(rule.proto.as_str(), "tcp" | "udp") {
        return None;
    }
    let parts: Vec<&str> = rule.ports.split(',').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    // reject anything that is not a bare port or a lo-hi range, so nothing
    // unexpected is ever spliced into a ruleset we hand to the kernel
    for p in &parts {
        let ok = match p.split_once('-') {
            Some((a, b)) => {
                a.parse::<u16>().is_ok_and(|a| a > 0) && b.parse::<u16>().is_ok_and(|b| b > 0)
            }
            None => p.parse::<u16>().is_ok_and(|p| p > 0),
        };
        if !ok {
            return None;
        }
    }
    Some(if parts.len() == 1 {
        format!("{} dport {}", rule.proto, parts[0])
    } else {
        format!("{} dport {{ {} }}", rule.proto, parts.join(", "))
    })
}

/// Build the full shadow ruleset. Counters only, policy accept, no verdicts:
/// this table can count traffic but cannot change what happens to it.
pub fn shadow_ruleset(rules: &[FwdRule]) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {SHADOW_TABLE} {{\n"));
    s.push_str("  chain shadow_in {\n");
    s.push_str(&format!(
        "    type filter hook input priority {SHADOW_PRIORITY}; policy accept;\n"
    ));
    // ct state new makes this per-connection rather than per-packet, which is
    // the same granularity Windows event 5156 reports.
    s.push_str("    ct state new jump shadow_match\n");
    s.push_str("  }\n");
    s.push_str("  chain shadow_match {\n");
    for (i, rule) in rules.iter().enumerate() {
        if let Some(expr) = match_expr(rule) {
            s.push_str(&format!("    {expr} counter comment \"{}\"\n", slot(i)));
        }
    }
    s.push_str("  }\n}\n");
    s
}

/// Which rules the shadow table cannot express.
pub fn unexpressible(rules: &[FwdRule]) -> Vec<(String, String)> {
    rules
        .iter()
        .filter(|r| match_expr(r).is_none())
        .map(|r| {
            (
                r.id(),
                "Firebreak could not express this rule as a port counter, so it has no hit \
                 count. It is still active in the firewall."
                    .to_string(),
            )
        })
        .collect()
}

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

/// Load a ruleset via `nft -f -`.
fn nft_load(ruleset: &str) -> Result<()> {
    use std::io::Write;
    let bin = crate::syspath::system_tool("nft").context("nft is not installed")?;
    let mut child = crate::syspath::command(bin)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning nft")?;
    child
        .stdin
        .as_mut()
        .context("nft stdin")?
        .write_all(ruleset.as_bytes())?;
    let out = child.wait_with_output().context("running nft -f -")?;
    if !out.status.success() {
        bail!(
            "installing the shadow counter table failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn table_exists() -> bool {
    nft(&["list", "table", "inet", SHADOW_TABLE]).is_ok()
}

/// Remove the shadow table. Safe to call when it is not there.
pub fn teardown() -> Result<()> {
    if !table_exists() {
        return Ok(());
    }
    nft(&["delete", "table", "inet", SHADOW_TABLE])?;
    Ok(())
}

/// Install (or replace) the shadow table so it matches `rules`.
///
/// Replacing resets the counters, which is why the caller folds a generation
/// token over the rule set: a changed rule set means a new counter lifetime,
/// and the old readings must be banked rather than treated as a decrease.
pub fn install(rules: &[FwdRule]) -> Result<()> {
    let _ = teardown();
    nft_load(&shadow_ruleset(rules))
}

/// Read the shadow table's counters, keyed by rule index.
pub fn read_counters() -> Result<BTreeMap<usize, i64>> {
    let json = nft(&["-j", "list", "table", "inet", SHADOW_TABLE])?;
    let v: serde_json::Value = serde_json::from_str(&json).context("parsing nft JSON output")?;
    Ok(parse_counters(&v))
}

/// Extract `comment -> packets` from `nft -j list table` output.
pub fn parse_counters(v: &serde_json::Value) -> BTreeMap<usize, i64> {
    let mut out = BTreeMap::new();
    let Some(items) = v["nftables"].as_array() else {
        return out;
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let Some(comment) = rule.get("comment").and_then(|c| c.as_str()) else {
            continue;
        };
        let Some(index) = comment
            .strip_prefix("fb")
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        let packets = rule["expr"]
            .as_array()
            .map(|exprs| {
                exprs
                    .iter()
                    .filter_map(|e| e.get("counter"))
                    .filter_map(|c| c.get("packets"))
                    .filter_map(serde_json::Value::as_i64)
                    .sum::<i64>()
            })
            .unwrap_or(0);
        out.insert(index, packets);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `firewall-cmd --info-zone=FedoraWorkstation` from the Fedora
    /// 44 host this was developed on. Note `ports: 1025-65535/*`, which is
    /// what Fedora Workstation ships open by default.
    const REAL_ZONE: &str = r#"FedoraWorkstation (active)
  target: default
  ingress-priority: 0
  icmp-block-inversion: no
  interfaces: eno2 wlo1
  sources:
  services: dhcpv6-client samba-client ssh
  ports: 1025-65535/udp 1025-65535/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
"#;

    fn fake_expand(svc: &str) -> Vec<(String, String)> {
        match svc {
            "ssh" => vec![("tcp".into(), "22".into())],
            "dhcpv6-client" => vec![("udp".into(), "546".into())],
            // samba-client declares 138/udp and includes netbios-ns (137/udp)
            "samba-client" => vec![("udp".into(), "137".into()), ("udp".into(), "138".into())],
            _ => vec![],
        }
    }

    fn zone() -> Zones {
        parse_zone("FedoraWorkstation", REAL_ZONE, &fake_expand)
    }

    #[test]
    fn a_real_zone_yields_its_services_and_ports() {
        let z = zone();
        let ids: Vec<String> = z.rules.iter().map(|r| r.id()).collect();
        assert!(ids.contains(&"firewalld:FedoraWorkstation/service/ssh/tcp".to_string()));
        assert!(ids.contains(&"firewalld:FedoraWorkstation/port/1025-65535/tcp/tcp".to_string()));
        assert_eq!(z.rules.len(), 5, "{ids:?}");
    }

    #[test]
    fn a_composed_service_reports_every_port_it_opens() {
        // samba-client looks like one port and is really two. Under-reporting
        // here makes a rule look narrower than it is.
        let z = zone();
        let samba = z
            .rules
            .iter()
            .find(|r| r.label == "samba-client")
            .expect("samba-client present");
        assert_eq!(samba.ports, "137,138");
    }

    #[test]
    fn empty_zone_fields_add_nothing() {
        // "protocols:" with no value must not become an unmeasurable entry
        let z = zone();
        assert!(z.unmeasurable.is_empty(), "{:?}", z.unmeasurable);
    }

    /// Verbatim `firewall-cmd --info-zone=public` from a Fedora 44 host
    /// configured with rich rules, a protocol, an icmp-block and a
    /// forward-port. The tab-indented continuation lines under `rich rules:`
    /// and `forward-ports:` are exactly how firewalld prints them.
    const REAL_ZONE_WITH_RICH_RULES: &str = "public (default)\n  \
        target: default\n  \
        icmp-block-inversion: no\n  \
        interfaces: \n  \
        services: dhcpv6-client mdns ssh\n  \
        ports: \n  \
        protocols: esp\n  \
        forward: yes\n  \
        masquerade: no\n  \
        forward-ports: \n\
        \tport=80:proto=tcp:toport=8080:toaddr=\n  \
        source-ports: \n  \
        icmp-blocks: echo-request\n  \
        rich rules: \n\
        \trule service name=\"ssh\" log prefix=\"ssh\" level=\"info\" limit value=\"3/m\" accept\n\
        \trule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"5432\" protocol=\"tcp\" accept\n";

    #[test]
    fn rich_rules_on_continuation_lines_are_not_silently_dropped() {
        // firewalld prints "rich rules:" with an empty value and the rules
        // themselves on tab-indented lines below. Reading only the inline
        // value loses every rich rule on the host — the user would be told
        // their firewall is simpler than it is.
        let z = parse_zone("public", REAL_ZONE_WITH_RICH_RULES, &fake_expand);
        let rich: Vec<&(String, String)> = z
            .unmeasurable
            .iter()
            .filter(|(id, _)| id.contains("rich-rule"))
            .collect();
        assert_eq!(
            rich.len(),
            2,
            "both rich rules must surface: {:?}",
            z.unmeasurable
        );
        assert!(rich.iter().any(|(id, _)| id.contains("10.0.0.0/8")));
        assert!(rich.iter().any(|(id, _)| id.contains("ssh")));
    }

    #[test]
    fn every_uncountable_zone_feature_is_listed() {
        let z = parse_zone("public", REAL_ZONE_WITH_RICH_RULES, &fake_expand);
        let ids: Vec<&str> = z.unmeasurable.iter().map(|(i, _)| i.as_str()).collect();
        assert!(ids.iter().any(|i| i.contains("protocol/esp")), "{ids:?}");
        assert!(ids.iter().any(|i| i.contains("icmp-block")), "{ids:?}");
        assert!(ids.iter().any(|i| i.contains("forward-port")), "{ids:?}");
        // and the countable services still come through
        assert!(z.rules.iter().any(|r| r.label == "ssh"));
    }

    #[test]
    fn active_zone_names_drop_the_default_marker() {
        let text =
            "FedoraWorkstation (default)\n  interfaces: eno2 wlo1\npublic\n  interfaces: tun0\n";
        assert_eq!(active_zones(text), vec!["FedoraWorkstation", "public"]);
    }

    #[test]
    fn service_includes_are_parsed() {
        let text = "samba-client\n  ports: 138/udp\n  protocols:\n  includes: netbios-ns\n";
        let (ports, includes) = parse_service(text);
        assert_eq!(ports, vec![("udp".to_string(), "138".to_string())]);
        assert_eq!(includes, vec!["netbios-ns"]);
    }

    #[test]
    fn match_expressions_cover_single_ports_ranges_and_sets() {
        let mk = |proto: &str, ports: &str| FwdRule {
            zone: "z".into(),
            kind: "port".into(),
            label: "l".into(),
            proto: proto.into(),
            ports: ports.into(),
        };
        assert_eq!(
            match_expr(&mk("tcp", "22")).as_deref(),
            Some("tcp dport 22")
        );
        assert_eq!(
            match_expr(&mk("tcp", "1025-65535")).as_deref(),
            Some("tcp dport 1025-65535")
        );
        assert_eq!(
            match_expr(&mk("udp", "137,138")).as_deref(),
            Some("udp dport { 137, 138 }")
        );
    }

    #[test]
    fn nothing_unexpected_reaches_the_kernel_ruleset() {
        // The ruleset is handed to nft as text, so a port field that is not
        // a number must be refused outright rather than interpolated.
        let mk = |ports: &str| FwdRule {
            zone: "z".into(),
            kind: "port".into(),
            label: "l".into(),
            proto: "tcp".into(),
            ports: ports.into(),
        };
        assert_eq!(match_expr(&mk("22; drop")), None);
        assert_eq!(match_expr(&mk("}")), None);
        assert_eq!(match_expr(&mk("")), None);
        assert_eq!(match_expr(&mk("0")), None);
        assert_eq!(match_expr(&mk("99999")), None);
    }

    #[test]
    fn the_shadow_table_can_count_but_never_decide() {
        let z = zone();
        let rs = shadow_ruleset(&z.rules);
        assert!(rs.contains("policy accept"));
        assert!(rs.contains("priority 300"), "must sit after firewalld");
        assert!(
            rs.contains("ct state new"),
            "per-connection, not per-packet"
        );
        for verdict in ["drop", "reject", "accept\n"] {
            assert!(
                !rs.contains(&format!(" {verdict}")),
                "shadow rules must carry no verdict: {rs}"
            );
        }
        // one counter per expressible rule
        assert_eq!(rs.matches("counter comment").count(), z.rules.len());
    }

    #[test]
    fn unexpressible_rules_are_named_so_they_cannot_read_as_unused() {
        let rules = vec![FwdRule {
            zone: "z".into(),
            kind: "service".into(),
            label: "weird".into(),
            proto: "esp".into(),
            ports: "".into(),
        }];
        let out = unexpressible(&rules);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.contains("still active"));
    }

    #[test]
    fn counters_are_read_back_by_slot() {
        let json = serde_json::json!({
            "nftables": [
                {"metainfo": {"version": "1.1.6"}},
                {"rule": {"comment": "fb0", "expr": [
                    {"match": {}}, {"counter": {"packets": 9, "bytes": 540}}]}},
                {"rule": {"comment": "fb2", "expr": [
                    {"counter": {"packets": 0, "bytes": 0}}]}},
                {"rule": {"expr": [{"counter": {"packets": 5}}]}}
            ]
        });
        let c = parse_counters(&json);
        assert_eq!(c.get(&0), Some(&9));
        assert_eq!(c.get(&2), Some(&0));
        assert_eq!(c.len(), 2, "a rule with no comment is not ours");
    }

    #[test]
    fn zone_scope_is_the_rules_scope() {
        let z = zone();
        let info = z.rules[0].to_rule_info();
        assert_eq!(info.profile, "FedoraWorkstation");
        assert_eq!(info.direction, "Inbound");
    }
}
