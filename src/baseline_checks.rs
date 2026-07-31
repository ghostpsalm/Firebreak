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
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
