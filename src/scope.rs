//! Scope-based attribution: which firewall rules' criteria a given
//! connection satisfies. Windows' FilterOrigin names the *decisive* filter,
//! which for allowed traffic is frequently a system default (e.g. mDNS on
//! UDP 5353 is admitted by an interface pre-filter, FilterOrigin
//! "Unknown"), never the user's mDNS rule. For a usage audit the question
//! is "did traffic matching this rule's scope occur?" — so we credit every
//! enabled/relevant rule whose direction + protocol + local/remote port +
//! program the connection matches. One connection can credit several rules
//! (overlapping scopes); that is correct — each is "exercised".

use std::collections::{HashMap, HashSet};

use crate::listeners::parse_port_ranges;
use crate::model::{EventRecord, RuleInfo};

/// Windows Firewall network profile. `Unknown` = interface not resolvable to
/// a profile (loopback, transient); it matches any rule profile rather than
/// being dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Domain,
    Private,
    Public,
    Unknown,
}

impl Profile {
    pub fn label(self) -> &'static str {
        match self {
            Profile::Domain => "Domain",
            Profile::Private => "Private",
            Profile::Public => "Public",
            Profile::Unknown => "Unknown",
        }
    }

    /// Inverse of label(); NetworkCategory spellings also accepted.
    pub fn from_label(s: &str) -> Profile {
        match s.trim() {
            "Domain" | "DomainAuthenticated" => Profile::Domain,
            "Private" => Profile::Private,
            "Public" => Profile::Public,
            _ => Profile::Unknown,
        }
    }
}

/// IANA protocol numbers as they appear in 5156/5157 events.
fn proto_to_num(s: &str) -> Option<u32> {
    match s.trim().to_ascii_uppercase().as_str() {
        "ICMPV4" | "ICMP" => Some(1),
        "IGMP" => Some(2),
        "TCP" => Some(6),
        "UDP" => Some(17),
        "IPV6-ICMP" | "ICMPV6" => Some(58),
        other => other.parse().ok(),
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Expand the couple of env-var forms Windows rules use in Program paths,
/// enough for basename comparison.
fn expand_program(p: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    p.replace("%SystemRoot%", &root)
        .replace("%systemroot%", &root)
        .replace("%windir%", &root)
}

fn in_ranges(port: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|&(a, b)| port >= a && port <= b)
}

/// One rule's match criteria. `None` on a field means "Any" (unconstrained).
struct RuleScope {
    rule_name: String,
    dir_in: bool,
    protocols: Option<HashSet<u32>>,
    local_ports: Option<Vec<(u32, u32)>>,
    remote_ports: Option<Vec<(u32, u32)>>,
    program_base: Option<String>,
    /// which profiles the rule applies to; None = Any
    profiles: Option<HashSet<Profile>>,
}

impl RuleScope {
    fn from_rule(r: &RuleInfo) -> Option<RuleScope> {
        // A disabled rule is never loaded into WFP, so it cannot decide any
        // connection — crediting it with a hit would be a false attribution.
        // Exclude it from the index entirely (matches the module doc: we
        // credit every *enabled* rule whose scope a connection satisfies).
        if !r.is_enabled() {
            return None;
        }
        let dir_in = if r.direction.eq_ignore_ascii_case("inbound") {
            true
        } else if r.direction.eq_ignore_ascii_case("outbound") {
            false
        } else {
            return None;
        };
        let protocols = match r.protocol.as_deref() {
            Some(p) if !p.is_empty() && !p.eq_ignore_ascii_case("any") => {
                let set: HashSet<u32> = p.split(',').filter_map(proto_to_num).collect();
                (!set.is_empty()).then_some(set)
            }
            _ => None,
        };
        let ports = |spec: Option<&str>| -> Option<Vec<(u32, u32)>> {
            spec.map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("any"))
                .map(parse_port_ranges)
        };
        let program_base = r
            .program
            .as_deref()
            .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
            .map(|p| basename(&expand_program(p)).to_lowercase());
        let tags = r.profile_tags();
        let profiles = if tags == ["Any"] {
            None
        } else {
            let set: HashSet<Profile> = tags
                .iter()
                .filter_map(|t| match *t {
                    "Domain" => Some(Profile::Domain),
                    "Private" => Some(Profile::Private),
                    "Public" => Some(Profile::Public),
                    _ => None,
                })
                .collect();
            (!set.is_empty()).then_some(set)
        };
        Some(RuleScope {
            rule_name: r.name.clone(),
            dir_in,
            protocols,
            local_ports: ports(r.local_port.as_deref()),
            remote_ports: ports(r.remote_port.as_deref()),
            program_base,
            profiles,
        })
    }

    /// A rule is only scope-attributable if it constrains protocol, port, or
    /// program. A rule that constrains none of these (Any/Any/Any — e.g. a
    /// Store-app rule whose real restriction is an AppContainer package we
    /// can't see, or a broad allow-all) would match every connection in its
    /// direction, which is noise rather than a "this rule was exercised"
    /// signal, so it is excluded from per-connection crediting.
    fn is_attributable(&self) -> bool {
        self.protocols.is_some()
            || self.local_ports.is_some()
            || self.remote_ports.is_some()
            || self.program_base.is_some()
    }

    fn matches(&self, c: &Conn) -> bool {
        if self.dir_in != c.dir_in {
            return false;
        }
        // profile gate — a Domain-only rule can't be exercised by Public
        // traffic. Unknown-profile connections match anything.
        if let Some(ps) = &self.profiles {
            if c.profile != Profile::Unknown && !ps.contains(&c.profile) {
                return false;
            }
        }
        if let Some(ps) = &self.protocols {
            if !ps.contains(&c.proto) {
                return false;
            }
        }
        // a symbolic/unresolved port spec parses to an empty range list —
        // treat as "cannot confirm", i.e. don't match on ports alone
        if let Some(lp) = &self.local_ports {
            if lp.is_empty() || !in_ranges(c.local_port, lp) {
                return false;
            }
        }
        if let Some(rp) = &self.remote_ports {
            if rp.is_empty() || !in_ranges(c.remote_port, rp) {
                return false;
            }
        }
        if let Some(pb) = &self.program_base {
            if c.app_base.is_empty() || &c.app_base != pb {
                return false;
            }
        }
        true
    }
}

/// A connection reduced to its match-relevant fields.
pub struct Conn {
    pub dir_in: bool,
    pub proto: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub app_base: String,
    pub profile: Profile,
}

impl Conn {
    /// Build from an event. Local endpoint = dest for inbound, source for
    /// outbound; remote is the other side. `profiles` maps interface index
    /// to network profile.
    pub fn from_event(
        ev: &EventRecord,
        normalized_app: &str,
        profiles: &HashMap<u32, Profile>,
    ) -> Conn {
        let dir_in = ev.direction.eq_ignore_ascii_case("inbound");
        let dp: u32 = ev.dest_port.trim().parse().unwrap_or(0);
        let sp: u32 = ev.source_port.trim().parse().unwrap_or(0);
        let (local_port, remote_port) = if dir_in { (dp, sp) } else { (sp, dp) };
        Conn {
            dir_in,
            proto: ev.protocol,
            local_port,
            remote_port,
            app_base: basename(normalized_app).to_lowercase(),
            profile: profiles.get(&ev.interface_index).copied().unwrap_or(Profile::Unknown),
        }
    }
}

/// Rule scopes indexed by (direction, protocol) for fast candidate lookup.
pub struct ScopeIndex {
    scopes: Vec<RuleScope>,
    // direction -> protocol -> rule indices; plus per-direction any-protocol
    by_proto: HashMap<(bool, u32), Vec<usize>>,
    any_proto: HashMap<bool, Vec<usize>>,
}

impl ScopeIndex {
    pub fn build(rules: &[RuleInfo]) -> ScopeIndex {
        let mut scopes = Vec::new();
        let mut by_proto: HashMap<(bool, u32), Vec<usize>> = HashMap::new();
        let mut any_proto: HashMap<bool, Vec<usize>> = HashMap::new();
        for r in rules {
            if let Some(s) = RuleScope::from_rule(r) {
                if !s.is_attributable() {
                    continue; // Any/Any/Any rule — would match everything
                }
                let idx = scopes.len();
                match &s.protocols {
                    Some(ps) => {
                        for &p in ps {
                            by_proto.entry((s.dir_in, p)).or_default().push(idx);
                        }
                    }
                    None => any_proto.entry(s.dir_in).or_default().push(idx),
                }
                scopes.push(s);
            }
        }
        ScopeIndex { scopes, by_proto, any_proto }
    }

    /// Names of all rules whose scope this connection matches.
    pub fn matching_rules(&self, c: &Conn) -> Vec<&str> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let candidates = self
            .by_proto
            .get(&(c.dir_in, c.proto))
            .into_iter()
            .flatten()
            .chain(self.any_proto.get(&c.dir_in).into_iter().flatten());
        for &idx in candidates {
            if seen.insert(idx) && self.scopes[idx].matches(c) {
                out.push(self.scopes[idx].rule_name.as_str());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, dir: &str, proto: Option<&str>, lport: Option<&str>, rport: Option<&str>, prog: Option<&str>) -> RuleInfo {
        RuleInfo {
            name: name.into(),
            display_name: name.into(),
            description: None,
            enabled: "True".into(),
            direction: dir.into(),
            action: "Allow".into(),
            profile: "Any".into(),
            group: None,
            program: prog.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: rport.map(Into::into),
            service: None,
            remote_address: None,
        }
    }

    fn ev(dir: &str, proto: u32, sp: &str, dp: &str, app: &str) -> EventRecord {
        EventRecord {
            event_id: 5156,
            record_id: 1,
            time_created: "t".into(),
            filter_rtid: 0,
            application: app.into(),
            direction: dir.into(),
            filter_origin: Some("Unknown".into()),
            protocol: proto,
            dest_address: "d".into(),
            dest_port: dp.into(),
            source_address: "s".into(),
            source_port: sp.into(),
            interface_index: 0,
        }
    }

    fn conn(e: &EventRecord, app: &str) -> Conn {
        Conn::from_event(e, app, &HashMap::new())
    }

    #[test]
    fn mdns_inbound_credits_the_5353_rule() {
        // the exact case from the field: UDP 5353 inbound, FilterOrigin Unknown
        let rules = vec![
            rule("mDNS", "Inbound", Some("UDP"), Some("5353"), None, None),
            rule("RDP", "Inbound", Some("TCP"), Some("3389"), None, None),
        ];
        let idx = ScopeIndex::build(&rules);
        let e = ev("Inbound", 17, "5353", "5353", r"\device\hd\svchost.exe");
        let c = conn(&e, r"C:\windows\system32\svchost.exe");
        assert_eq!(idx.matching_rules(&c), vec!["mDNS"]);
    }

    #[test]
    fn unconstrained_rule_is_excluded() {
        // Any/Any/Any inbound rule (a Store-app rule) must not match every
        // connection — regression for the 30-identical-rows bug
        let rules = vec![rule("Windows Camera", "Inbound", None, None, None, None)];
        let idx = ScopeIndex::build(&rules);
        let c = conn(&ev("Inbound", 6, "40000", "443", "chrome.exe"), "chrome.exe");
        assert!(idx.matching_rules(&c).is_empty());
    }

    #[test]
    fn disabled_rule_is_excluded() {
        // a disabled rule is not loaded into WFP and must never be credited,
        // even when its scope matches the connection exactly (regression: F1)
        let mut r = rule("Old RDP", "Inbound", Some("TCP"), Some("3389"), None, None);
        r.enabled = "False".into();
        let idx = ScopeIndex::build(&[r]);
        let c = conn(&ev("Inbound", 6, "40000", "3389", "svchost.exe"), "svchost.exe");
        assert!(idx.matching_rules(&c).is_empty());
        // the same rule, enabled, does match — proving exclusion is the state,
        // not the scope
        let mut r2 = rule("RDP", "Inbound", Some("TCP"), Some("3389"), None, None);
        r2.enabled = "True".into();
        let idx2 = ScopeIndex::build(&[r2]);
        assert_eq!(idx2.matching_rules(&c), vec!["RDP"]);
    }

    #[test]
    fn icmp_ping_credits_protocol_only_rule() {
        let rules = vec![rule("Echo Request v4", "Inbound", Some("ICMPv4"), None, None, None)];
        let idx = ScopeIndex::build(&rules);
        let c = conn(&ev("Inbound", 1, "0", "0", "System"), "System");
        assert_eq!(idx.matching_rules(&c), vec!["Echo Request v4"]);
    }

    #[test]
    fn program_and_port_both_required() {
        let rules = vec![rule("svc5000", "Inbound", Some("TCP"), Some("5000-5020"), None, Some(r"C:\x\svchost.exe"))];
        let idx = ScopeIndex::build(&rules);
        let miss = conn(&ev("Inbound", 6, "40000", "135", "svchost.exe"), r"C:\x\svchost.exe");
        assert!(idx.matching_rules(&miss).is_empty());
        let hit = conn(&ev("Inbound", 6, "40000", "5010", "svchost.exe"), r"C:\x\svchost.exe");
        assert_eq!(idx.matching_rules(&hit), vec!["svc5000"]);
    }

    #[test]
    fn outbound_matches_on_remote_port() {
        let rules = vec![rule("DNS out", "Outbound", Some("UDP"), None, Some("53"), None)];
        let idx = ScopeIndex::build(&rules);
        let c = conn(&ev("Outbound", 17, "50000", "53", "svchost.exe"), "svchost.exe");
        assert_eq!(idx.matching_rules(&c), vec!["DNS out"]);
    }

    #[test]
    fn profile_gate_excludes_wrong_profile() {
        let mut r = rule("RDP Domain", "Inbound", Some("TCP"), Some("3389"), None, None);
        r.profile = "Domain".into();
        let idx = ScopeIndex::build(&[r]);
        let mut e = ev("Inbound", 6, "40000", "3389", "svchost.exe");
        e.interface_index = 5;
        // interface 5 is Public → Domain-only rule must not match
        let map = HashMap::from([(5u32, Profile::Public)]);
        let c = Conn::from_event(&e, "svchost.exe", &map);
        assert!(idx.matching_rules(&c).is_empty());
        // interface 5 is Domain → matches
        let map = HashMap::from([(5u32, Profile::Domain)]);
        let c = Conn::from_event(&e, "svchost.exe", &map);
        assert_eq!(idx.matching_rules(&c), vec!["RDP Domain"]);
    }

    #[test]
    fn direction_and_protocol_gate() {
        let rules = vec![rule("mDNS in", "Inbound", Some("UDP"), Some("5353"), None, None)];
        let idx = ScopeIndex::build(&rules);
        let c = conn(&ev("Outbound", 17, "5353", "5353", "svchost.exe"), "svchost.exe");
        assert!(idx.matching_rules(&c).is_empty());
        let c2 = conn(&ev("Inbound", 6, "5353", "5353", "svchost.exe"), "svchost.exe");
        assert!(idx.matching_rules(&c2).is_empty());
    }
}
