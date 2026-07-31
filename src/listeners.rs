//! Current listening sockets (netstat-style), enumerated via
//! Get-NetTCPConnection/-NetUDPEndpoint with owning-process resolution, and
//! cross-referenced against inbound rules so the table can show which
//! process is actually bound to a rule's ports right now.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::RuleInfo;

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    #[serde(rename = "Proto")]
    pub proto: String,
    #[serde(rename = "LocalAddress")]
    pub local_address: String,
    #[serde(rename = "LocalPort")]
    pub local_port: u32,
    #[serde(rename = "Pid")]
    pub pid: u32,
    #[serde(rename = "ProcessName", default)]
    pub process_name: String,
    #[serde(rename = "ProcessPath", default)]
    pub process_path: String,
}

pub fn enumerate_listeners() -> Result<Vec<Listener>> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path } }
$out = @()
Get-NetTCPConnection -State Listen | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $out += [pscustomobject]@{
        Proto = 'TCP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort
        Pid = [int]$_.OwningProcess; ProcessName = [string]$p.Name; ProcessPath = [string]$p.Path
    }
}
Get-NetUDPEndpoint | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $out += [pscustomobject]@{
        Proto = 'UDP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort
        Pid = [int]$_.OwningProcess; ProcessName = [string]$p.Name; ProcessPath = [string]$p.Path
    }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;
    let json = crate::firewall_rules::run_powershell(script)?;
    let listeners: Vec<Listener> =
        serde_json::from_str(json.trim()).context("parsing listener JSON")?;
    Ok(listeners)
}

/// Expand the couple of env-var forms Windows rules commonly use in Program
/// paths, enough for basename comparison.
fn expand_program_path(p: &str) -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    p.replace("%SystemRoot%", &system_root)
        .replace("%systemroot%", &system_root)
        .replace("%windir%", &system_root)
        .to_lowercase()
}

fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Parse a firewall LocalPort spec ("80", "5000-5020", "137,138,139",
/// mixed) into inclusive ranges. Symbolic tokens (RPC, RPCEPMap,
/// PlayToDiscovery, …) are unresolvable here and yield nothing — better no
/// listener claim than a wrong one.
pub(crate) fn parse_port_ranges(spec: &str) -> Vec<(u32, u32)> {
    spec.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if let Some((a, b)) = entry.split_once('-') {
                match (a.trim().parse(), b.trim().parse()) {
                    (Ok(a), Ok(b)) if a <= b => Some((a, b)),
                    _ => None,
                }
            } else {
                entry.parse().ok().map(|p| (p, p))
            }
        })
        .collect()
}

/// Which current listeners fall under an inbound rule's scope. A firewall
/// rule only admits traffic satisfying ALL of its conditions, so listener
/// matching is a conjunction too: protocol AND local port (when specified,
/// including ranges) AND program (when specified). A rule with neither
/// ports nor program ("Any") claims no listeners — the Scope column
/// already says Any, and listing every socket would be noise.
pub fn listeners_for_rule(rule: &RuleInfo, listeners: &[Listener]) -> Vec<String> {
    if !rule.direction.eq_ignore_ascii_case("inbound") {
        return Vec::new();
    }
    let rule_proto = rule.protocol.as_deref().unwrap_or("Any");
    let port_spec = rule
        .local_port
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"));
    let port_ranges = port_spec.map(parse_port_ranges);
    let program = rule
        .program
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
        .map(expand_program_path);

    // nothing to scope on, or a port spec we can't resolve (symbolic like
    // RPC): claim nothing rather than over-claim
    if port_spec.is_none() && program.is_none() {
        return Vec::new();
    }
    if matches!(&port_ranges, Some(r) if r.is_empty()) {
        return Vec::new();
    }

    let mut out = Vec::new();
    for l in listeners {
        let proto_ok =
            rule_proto.eq_ignore_ascii_case("any") || rule_proto.eq_ignore_ascii_case(&l.proto);
        if !proto_ok {
            continue;
        }
        let port_ok = match &port_ranges {
            Some(ranges) => ranges
                .iter()
                .any(|&(a, b)| l.local_port >= a && l.local_port <= b),
            None => true, // no port condition on the rule
        };
        let program_ok = match &program {
            Some(prog) => {
                let lp = l.process_path.to_lowercase();
                !lp.is_empty() && (lp == *prog || basename(&lp) == basename(prog))
            }
            None => true, // no program condition on the rule
        };
        if port_ok && program_ok {
            let name = if l.process_name.is_empty() {
                format!("pid{}", l.pid)
            } else {
                l.process_name.clone()
            };
            // design chip format: process:port
            let entry = format!("{}:{}", name, l.local_port);
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    out
}

/// Compact scope string for the table column, design format:
/// "TCP 3389 · svchost", "TCP any · anydesk.exe", "UDP 53 · svchost".
/// "Any" scope renders as "Any". Full path is detail-panel material.
pub fn scope_summary(rule: &RuleInfo) -> String {
    let proto = rule
        .protocol
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"));
    let ports = rule
        .local_port
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"));
    let prog = rule
        .program
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
        .map(basename);

    let net = match (proto, ports) {
        (Some(pr), Some(po)) => Some(format!("{pr} {po}")),
        (Some(pr), None) => Some(format!("{pr} any")),
        (None, Some(po)) => Some(po.to_string()),
        (None, None) => None,
    };
    match (net, prog) {
        (Some(n), Some(p)) => format!("{n} · {p}"),
        (Some(n), None) => n,
        (None, Some(p)) => p.to_string(),
        (None, None) => "Any".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        dir: &str,
        proto: Option<&str>,
        lport: Option<&str>,
        program: Option<&str>,
    ) -> RuleInfo {
        RuleInfo {
            name: "{id}".into(),
            display_name: "r".into(),
            description: None,
            enabled: "True".into(),
            direction: dir.into(),
            action: "Allow".into(),
            profile: "Any".into(),
            group: None,
            program: program.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: None,
            service: None,
            remote_address: None,
        }
    }

    fn listener(proto: &str, port: u32, name: &str, path: &str) -> Listener {
        Listener {
            proto: proto.into(),
            local_address: "0.0.0.0".into(),
            local_port: port,
            pid: 1234,
            process_name: name.into(),
            process_path: path.into(),
        }
    }

    #[test]
    fn port_scoped_rule_matches_listener_on_port_and_proto() {
        let ls = vec![
            listener("TCP", 3389, "svchost", r"C:\Windows\System32\svchost.exe"),
            listener("UDP", 3389, "other", ""),
        ];
        let r = rule("Inbound", Some("TCP"), Some("3389"), None);
        assert_eq!(listeners_for_rule(&r, &ls), vec!["svchost:3389"]);
    }

    #[test]
    fn program_and_port_rule_requires_both_to_match() {
        // regression: an svchost rule scoped to 5000-5020 must not claim
        // every port svchost listens on
        let svchost = r"C:\Windows\System32\svchost.exe";
        let ls = vec![
            listener("TCP", 135, "svchost", svchost),
            listener("TCP", 5010, "svchost", svchost),
            listener("TCP", 5010, "other", r"C:\other.exe"),
        ];
        let r = rule("Inbound", Some("TCP"), Some("5000-5020"), Some(svchost));
        assert_eq!(listeners_for_rule(&r, &ls), vec!["svchost:5010"]);
    }

    #[test]
    fn port_ranges_and_lists_parse() {
        assert_eq!(parse_port_ranges("5000-5020"), vec![(5000, 5020)]);
        assert_eq!(
            parse_port_ranges("137,138,139"),
            vec![(137, 137), (138, 138), (139, 139)]
        );
        assert_eq!(
            parse_port_ranges("80,8000-8080"),
            vec![(80, 80), (8000, 8080)]
        );
        assert!(parse_port_ranges("RPC").is_empty());
    }

    #[test]
    fn symbolic_port_spec_claims_no_listeners() {
        let svchost = r"C:\Windows\System32\svchost.exe";
        let ls = vec![listener("TCP", 135, "svchost", svchost)];
        let r = rule("Inbound", Some("TCP"), Some("RPC"), Some(svchost));
        assert!(listeners_for_rule(&r, &ls).is_empty());
    }

    #[test]
    fn program_rule_without_ports_matches_by_process() {
        let ls = vec![listener(
            "UDP",
            5353,
            "chrome",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )];
        let r = rule(
            "Inbound",
            Some("UDP"),
            None,
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        );
        assert_eq!(listeners_for_rule(&r, &ls), vec!["chrome:5353"]);
    }

    #[test]
    fn outbound_rules_have_no_listeners() {
        let ls = vec![listener("TCP", 443, "x", "")];
        let r = rule("Outbound", Some("TCP"), Some("443"), None);
        assert!(listeners_for_rule(&r, &ls).is_empty());
    }

    #[test]
    fn scope_summary_is_compact() {
        assert_eq!(
            scope_summary(&rule("Inbound", Some("TCP"), Some("3389"), None)),
            "TCP 3389"
        );
        assert_eq!(
            scope_summary(&rule(
                "Inbound",
                Some("UDP"),
                Some("5353"),
                Some(r"C:\x\chrome.exe")
            )),
            "UDP 5353 · chrome.exe"
        );
        assert_eq!(
            scope_summary(&rule(
                "Inbound",
                Some("TCP"),
                None,
                Some(r"C:\x\anydesk.exe")
            )),
            "TCP any · anydesk.exe"
        );
        assert_eq!(scope_summary(&rule("Inbound", None, None, None)), "Any");
        assert_eq!(
            scope_summary(&rule("Outbound", None, None, Some(r"C:\y\spotify.exe"))),
            "spotify.exe"
        );
    }
}
