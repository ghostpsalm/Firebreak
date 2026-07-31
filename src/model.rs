use serde::{Deserialize, Serialize};

/// A firewall rule as enumerated via PowerShell (Get-NetFirewallRule joined
/// with its application/port filters). `name` is the InstanceID-style unique
/// name; `display_name` is what the GUI shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "Enabled")]
    pub enabled: String,
    #[serde(rename = "Direction")]
    pub direction: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Profile")]
    pub profile: String,
    #[serde(rename = "Group", default)]
    pub group: Option<String>,
    #[serde(rename = "Program", default)]
    pub program: Option<String>,
    #[serde(rename = "Protocol", default)]
    pub protocol: Option<String>,
    #[serde(rename = "LocalPort", default)]
    pub local_port: Option<String>,
    #[serde(rename = "RemotePort", default)]
    pub remote_port: Option<String>,
    #[serde(rename = "Service", default)]
    pub service: Option<String>,
    #[serde(rename = "RemoteAddress", default)]
    pub remote_address: Option<String>,
}

impl RuleInfo {
    pub fn is_enabled(&self) -> bool {
        self.enabled.eq_ignore_ascii_case("true")
    }

    /// Security-relevant definition of the rule, as a stable string. Backs
    /// the "Reviewed" mark: a review attests to THIS definition, so any
    /// change here invalidates it. Deliberately excludes the enabled state
    /// (disabling a reviewed rule — e.g. via firebreak itself — is not a
    /// definition change) and cosmetic fields (display name, description,
    /// group).
    pub fn fingerprint(&self) -> String {
        let f = |o: &Option<String>| o.as_deref().unwrap_or("").to_string();
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.direction,
            self.action,
            self.profile,
            f(&self.program),
            f(&self.protocol),
            f(&self.local_port),
            f(&self.remote_port),
            f(&self.service),
            f(&self.remote_address),
        )
    }

    /// Profile tags for display: ["Domain"], ["Private", "Public"], … or
    /// ["Any"]. Unknown/NotApplicable values render as-is so nothing is
    /// silently hidden.
    pub fn profile_tags(&self) -> Vec<&'static str> {
        let p = self.profile.to_lowercase();
        if p.contains("any") {
            return vec!["Any"];
        }
        let mut tags = Vec::new();
        if p.contains("domain") {
            tags.push("Domain");
        }
        if p.contains("private") {
            tags.push("Private");
        }
        if p.contains("public") {
            tags.push("Public");
        }
        tags
    }

    /// Whether this rule is active in at least one of the selected profiles.
    /// "Any" (and unrecognized values like NotApplicable) match whenever at
    /// least one profile is selected — filtering must never hide a rule
    /// whose scope we couldn't parse.
    pub fn applies_to_profile(&self, domain: bool, private: bool, public: bool) -> bool {
        if !(domain || private || public) {
            return false;
        }
        let tags = self.profile_tags();
        if tags.is_empty() || tags == ["Any"] {
            return true;
        }
        (domain && tags.contains(&"Domain"))
            || (private && tags.contains(&"Private"))
            || (public && tags.contains(&"Public"))
    }
}

/// One parsed 5156/5157 event. Several fields aren't consumed by the
/// aggregation yet but are parsed for future per-connection detail views.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EventRecord {
    pub event_id: u32,
    /// EventRecordID: monotonic per-channel cursor, the ingestion checkpoint
    pub record_id: u64,
    /// ISO8601 UTC
    pub time_created: String,
    pub filter_rtid: u64,
    /// Raw application path as logged (\device\harddiskvolumeN\... form)
    pub application: String,
    /// "Inbound" / "Outbound" / raw token if unrecognized
    pub direction: String,
    /// Newer Windows 10/11 builds embed the filter's origin directly in
    /// the event: a firewall rule ID, or a policy origin like "Stealth",
    /// "Boot Time Default", "Query User Default", "WSH Default". When it
    /// names a rule, it's the most authoritative attribution available.
    pub filter_origin: Option<String>,
    pub protocol: u32,
    pub dest_address: String,
    pub dest_port: String,
    pub source_address: String,
    pub source_port: String,
    /// interface the connection used; maps to a network profile
    /// (Domain/Private/Public) for profile-aware attribution
    pub interface_index: u32,
}

impl EventRecord {
    pub fn is_allow(&self) -> bool {
        self.event_id == 5156
    }
}

/// One WFP filter from FwpmFilterEnum0, with everything potentially useful
/// for mapping back to a firewall rule.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FilterInfo {
    pub filter_id: u64,
    pub name: String,
    pub description: String,
    /// providerData blob decoded as UTF-16LE (lossy); for MPSSVC firewall
    /// filters this is expected to carry the rule identity — verify on a
    /// real box with --dump-filters.
    pub provider_data_utf16: String,
    /// providerData blob as hex, for diagnosis when UTF-16 decode is garbage
    pub provider_data_hex: String,
    pub provider_context_key: String,
    pub layer_key: String,
}

/// Aggregated usage for one rule (or one unmatched filter), as read back
/// from the store for reporting.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct RuleUsage {
    pub rule_id: String,
    pub allow_count: i64,
    pub block_count: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// distinct application paths seen hitting this rule, with per-app hits
    pub apps: Vec<(String, i64)>,
    /// distinct remote peer addresses observed (source for inbound,
    /// destination for outbound)
    pub distinct_peers: i64,
    /// per-profile split: (profile, allow, block)
    pub by_profile: Vec<(String, i64, i64)>,
}

/// A static baseline advisory attached to a rule by pattern matching.
#[derive(Debug, Clone)]
pub struct BaselineFlag {
    pub title: &'static str,
    pub advice: &'static str,
}

/// The set of network profiles a rule applies to — the editable scope behind
/// the clickable profile chips. "Any" expands to all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSet {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

impl ProfileSet {
    pub fn from_rule(r: &RuleInfo) -> ProfileSet {
        let tags = r.profile_tags();
        if tags == ["Any"] {
            ProfileSet {
                domain: true,
                private: true,
                public: true,
            }
        } else {
            ProfileSet {
                domain: tags.contains(&"Domain"),
                private: tags.contains(&"Private"),
                public: tags.contains(&"Public"),
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.domain && !self.private && !self.public
    }

    pub fn is_all(&self) -> bool {
        self.domain && self.private && self.public
    }

    /// The `-Profile` argument for Set-NetFirewallRule; None when empty
    /// (caller should disable the rule instead).
    pub fn to_profile_arg(self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        if self.is_all() {
            return Some("Any".into());
        }
        let mut v = Vec::new();
        if self.domain {
            v.push("Domain");
        }
        if self.private {
            v.push("Private");
        }
        if self.public {
            v.push("Public");
        }
        Some(v.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_with_profile(profile: &str) -> RuleInfo {
        RuleInfo {
            name: "{id}".into(),
            display_name: "r".into(),
            description: None,
            enabled: "True".into(),
            direction: "Inbound".into(),
            action: "Allow".into(),
            profile: profile.into(),
            group: None,
            program: None,
            protocol: None,
            local_port: None,
            remote_port: None,
            service: None,
            remote_address: None,
        }
    }

    #[test]
    fn profile_tags_parse_combinations() {
        assert_eq!(rule_with_profile("Any").profile_tags(), vec!["Any"]);
        assert_eq!(
            rule_with_profile("Domain, Public").profile_tags(),
            vec!["Domain", "Public"]
        );
        assert_eq!(rule_with_profile("Private").profile_tags(), vec!["Private"]);
    }

    #[test]
    fn profile_filter_matches_selected_sets() {
        let dp = rule_with_profile("Domain, Private");
        assert!(dp.applies_to_profile(true, false, false));
        assert!(dp.applies_to_profile(false, true, false));
        assert!(!dp.applies_to_profile(false, false, true));
        // Any matches whenever something is selected, never when nothing is
        let any = rule_with_profile("Any");
        assert!(any.applies_to_profile(false, false, true));
        assert!(!any.applies_to_profile(false, false, false));
        // unparseable scope must stay visible rather than silently vanish
        let odd = rule_with_profile("NotApplicable");
        assert!(odd.applies_to_profile(true, false, false));
    }
}
