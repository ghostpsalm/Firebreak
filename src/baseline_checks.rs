//! Static advisory layer, independent of usage data. These are prompts for
//! review, not verdicts — several of these protocols are load-bearing on
//! networks that use AirPlay/Chromecast/network printers/etc. The list
//! should be reconciled against a current Microsoft Security Compliance
//! Toolkit / CIS benchmark before being treated as authoritative.

use crate::model::{BaselineFlag, RuleInfo};

struct Check {
    /// substrings matched case-insensitively against DisplayName or Group
    name_hints: &'static [&'static str],
    /// (protocol, local port) match as fallback when names don't hit
    port_hint: Option<(&'static str, &'static str)>,
    inbound_only: bool,
    flag: BaselineFlag,
}

const CHECKS: &[Check] = &[
    Check {
        name_hints: &["mdns"],
        port_hint: Some(("UDP", "5353")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "mDNS",
            advice: "Multicast discovery (AirPlay/Chromecast/printers). Commonly disabled on hardened/domain profiles; keep if local device discovery is needed.",
        },
    },
    Check {
        name_hints: &["ssdp"],
        port_hint: Some(("UDP", "1900")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "SSDP/UPnP",
            advice: "UPnP discovery. Frequent hardening target; disable unless UPnP device discovery is actually used.",
        },
    },
    Check {
        name_hints: &["llmnr", "link-local multicast"],
        port_hint: Some(("UDP", "5355")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "LLMNR",
            advice: "Legacy name resolution, credential-relay attack surface. Microsoft/CIS baselines recommend disabling (also via GPO, not just firewall).",
        },
    },
    Check {
        name_hints: &["netbios", "nb-"],
        port_hint: Some(("UDP", "137")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "NetBIOS",
            advice: "Legacy name service (137-139). Disable unless legacy SMB/browsing on the LAN requires it.",
        },
    },
    Check {
        name_hints: &["wsd", "ws-discovery", "function discovery"],
        port_hint: Some(("UDP", "3702")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "WS-Discovery",
            advice: "Device discovery (printers/scanners). Review on anything not needing plug-and-play network devices.",
        },
    },
    Check {
        name_hints: &["remote desktop", "rdp"],
        port_hint: Some(("TCP", "3389")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "RDP",
            advice: "Remote Desktop inbound. If used, restrict RemoteAddress scope; if unused, disable — top lateral-movement target.",
        },
    },
    Check {
        name_hints: &["file and printer sharing (smb"],
        port_hint: Some(("TCP", "445")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "SMB inbound",
            advice: "Inbound file sharing. Workstations rarely need to *serve* SMB; disable inbound 445 unless this host shares files/printers.",
        },
    },
    Check {
        name_hints: &["remote assistance"],
        port_hint: None,
        inbound_only: true,
        flag: BaselineFlag {
            title: "Remote Assistance",
            advice: "Commonly disabled by baseline unless the org actively uses solicited Remote Assistance.",
        },
    },
];

pub fn flags_for(rule: &RuleInfo) -> Vec<BaselineFlag> {
    let mut out = Vec::new();

    // A rule applied by Group Policy or another management system is not
    // this machine's to change: switching it off here lasts until the next
    // policy refresh puts it back. Saying so stops someone "fixing" the same
    // rule every week and wondering why it returns.
    if rule.is_managed() {
        out.push(BaselineFlag {
            title: "Managed centrally",
            advice: "This rule comes from Group Policy or device management, not from this \
                     machine. Disabling it here is undone at the next policy refresh — change \
                     it where it is defined.",
        });
    }
    let name = rule.display_name.to_lowercase();
    let group = rule.group.as_deref().unwrap_or("").to_lowercase();
    let inbound = rule.direction.eq_ignore_ascii_case("inbound");

    for check in CHECKS {
        if check.inbound_only && !inbound {
            continue;
        }
        let name_hit = check
            .name_hints
            .iter()
            .any(|h| name.contains(h) || group.contains(h));
        let port_hit = match (&check.port_hint, &rule.protocol, &rule.local_port) {
            (Some((proto, port)), Some(rp), Some(rport)) => {
                rp.eq_ignore_ascii_case(proto) && rport.split(',').any(|p| p == *port)
            }
            _ => false,
        };
        if name_hit || port_hit {
            out.push(check.flag.clone());
        }
    }

    // structural check: enabled Allow rule with no program and no port
    // restriction is maximally broad
    if rule.is_enabled()
        && rule.action.eq_ignore_ascii_case("allow")
        && rule
            .program
            .as_deref()
            .is_none_or(|p| p.is_empty() || p == "Any")
        && rule
            .local_port
            .as_deref()
            .is_none_or(|p| p.is_empty() || p == "Any")
        && inbound
    {
        out.push(BaselineFlag {
            title: "Broad inbound allow",
            advice: "Inbound allow with no program and no port restriction — vet scope (RemoteAddress, profile) or tighten.",
        });
    } else if inbound && rule.is_enabled() && rule.action.eq_ignore_ascii_case("allow") {
        // A rule *with* a port restriction can still be enormous. Fedora
        // Workstation ships 1025-65535/tcp open by default: 64,511 ports,
        // which the "no port restriction" test above sails straight past
        // while being the broadest rule on the host.
        if let Some(spec) = rule.local_port.as_deref() {
            let span = port_span(spec);
            if span > WIDE_PORT_SPAN {
                out.push(BaselineFlag {
                    title: "Very wide port range",
                    advice: "This inbound allow covers thousands of ports, so anything that binds \
                             one of them is reachable — check the Listening column for what is \
                             actually behind it, and narrow the range if you can.",
                });
            }
        }
    }
    out
}

/// More ports than any single service needs. Chosen to sit just above the
/// privileged range so "all high ports" trips it and a legitimate multi-port
/// service does not.
const WIDE_PORT_SPAN: u32 = 1024;

/// Total number of ports a rule's port spec admits.
fn port_span(spec: &str) -> u32 {
    crate::listeners::parse_port_ranges(spec)
        .iter()
        .map(|(a, b)| b.saturating_sub(*a).saturating_add(1))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_rule(port: &str) -> RuleInfo {
        RuleInfo {
            name: "r".into(),
            display_name: "r".into(),
            description: None,
            enabled: "True".into(),
            direction: "Inbound".into(),
            action: "Allow".into(),
            profile: "Any".into(),
            group: None,
            program: None,
            protocol: Some("tcp".into()),
            local_port: Some(port.into()),
            remote_port: None,
            service: None,
            remote_address: None,
            policy_source: None,
            policy_source_type: None,
        }
    }

    #[test]
    fn a_huge_port_range_is_flagged_even_though_it_is_a_restriction() {
        // Fedora Workstation's default. The "no port restriction" test does
        // not fire here, so without this the broadest rule on the host is
        // the one rule nothing flags.
        let flags = flags_for(&wide_rule("1025-65535"));
        assert!(
            flags.iter().any(|f| f.title == "Very wide port range"),
            "{flags:?}"
        );
    }

    #[test]
    fn an_ordinary_multi_port_service_is_not_flagged() {
        for spec in ["80,443", "137,138,139", "8000-8080", "22"] {
            let flags = flags_for(&wide_rule(spec));
            assert!(
                !flags.iter().any(|f| f.title == "Very wide port range"),
                "{spec} should not be flagged: {flags:?}"
            );
        }
    }

    #[test]
    fn port_spans_are_counted_across_ranges_and_lists() {
        assert_eq!(port_span("22"), 1);
        assert_eq!(port_span("80,443"), 2);
        assert_eq!(port_span("1025-65535"), 64511);
        assert_eq!(port_span("RPC"), 0);
    }

    fn rule(
        display: &str,
        dir: &str,
        action: &str,
        proto: Option<&str>,
        lport: Option<&str>,
        program: Option<&str>,
    ) -> RuleInfo {
        RuleInfo {
            name: "{id}".into(),
            display_name: display.into(),
            description: None,
            enabled: "True".into(),
            direction: dir.into(),
            action: action.into(),
            profile: "Any".into(),
            group: None,
            program: program.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: None,
            service: None,
            remote_address: None,
            policy_source: None,
            policy_source_type: None,
        }
    }

    fn titles(r: &RuleInfo) -> Vec<&'static str> {
        flags_for(r).into_iter().map(|f| f.title).collect()
    }

    #[test]
    fn mdns_flagged_by_name_or_port() {
        let by_name = rule(
            "Something (mDNS-In)",
            "Inbound",
            "Allow",
            None,
            None,
            Some("x.exe"),
        );
        assert!(titles(&by_name).contains(&"mDNS"));
        let by_port = rule(
            "Custom rule",
            "Inbound",
            "Allow",
            Some("UDP"),
            Some("5353"),
            Some("x.exe"),
        );
        assert!(titles(&by_port).contains(&"mDNS"));
    }

    #[test]
    fn inbound_only_checks_skip_outbound_rules() {
        let outbound = rule(
            "mDNS thing",
            "Outbound",
            "Allow",
            Some("UDP"),
            Some("5353"),
            Some("x.exe"),
        );
        assert!(!titles(&outbound).contains(&"mDNS"));
    }

    #[test]
    fn broad_inbound_allow_is_structural() {
        let broad = rule("My Server", "Inbound", "Allow", None, None, None);
        assert!(titles(&broad).contains(&"Broad inbound allow"));
        // a program restriction defuses it
        let scoped = rule(
            "My Server",
            "Inbound",
            "Allow",
            None,
            None,
            Some(r"C:\srv.exe"),
        );
        assert!(!titles(&scoped).contains(&"Broad inbound allow"));
        // block rules are never "broad allows"
        let block = rule("Block all", "Inbound", "Block", None, None, None);
        assert!(!titles(&block).contains(&"Broad inbound allow"));
    }

    #[test]
    fn rdp_flagged_by_port() {
        let r = rule(
            "Custom remote thing",
            "Inbound",
            "Allow",
            Some("TCP"),
            Some("3389"),
            Some("x.exe"),
        );
        assert!(titles(&r).contains(&"RDP"));
    }

    #[test]
    fn multi_port_lists_match_individual_ports() {
        let r = rule(
            "Custom",
            "Inbound",
            "Allow",
            Some("UDP"),
            Some("137,138,139"),
            Some("x.exe"),
        );
        assert!(titles(&r).contains(&"NetBIOS"));
    }
}
