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
    /// Where the rule came from — a GPO name, or empty for a local rule.
    /// Windows only; populated by -TracePolicyStore.
    #[serde(rename = "PolicyStoreSource", default)]
    pub policy_source: Option<String>,
    /// Local / GroupPolicy / Dynamic / Generated / Hardcoded. A rule that is
    /// not Local was applied by policy, so disabling it here is temporary —
    /// the next policy refresh puts it back.
    #[serde(rename = "PolicyStoreSourceType", default)]
    pub policy_source_type: Option<String>,
}

/// Where a rule is defined — which decides what changing it here achieves,
/// and whether it can be changed here at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// Made on this machine. Fully editable, changes stick.
    Local,
    /// From a Group Policy Object. Editable, but a policy refresh puts it
    /// back — so a local change is temporary, not a fix.
    GroupPolicy,
    /// Deployed by Intune or another MDM. Same caveat as Group Policy.
    Mdm,
    /// Windows Service Hardening. Ships with the OS and is not a user rule.
    ServiceHardening,
    /// The Linux firewall manager that owns the rule (ufw / firewalld /
    /// nftables). Editable through that manager, which is what Apply does.
    Platform,
    /// The chain's catch-all verdict — what happens to inbound traffic that
    /// matched no rule at all. Not a rule anyone wrote and not one anyone can
    /// edit; it is shown because a rule list that omits it invites the reader
    /// to assume the gaps are open when they are usually closed.
    DefaultPolicy,
    /// A Windows Filtering Platform filter that is *not* a firewall rule —
    /// Defender network protection, a VPN client, third-party security
    /// software. It filters traffic but no firewall rule describes it, so it
    /// is shown to explain blocks and can never be edited from here.
    WfpFilter,
}

impl RuleInfo {
    /// Synthetic `policy_source_type` marking a rule that came from a
    /// non-firewall WFP filter rather than the rule store.
    pub const SOURCE_TYPE_WFP: &'static str = "WfpFilter";
    /// Synthetic marker for a Linux backend's own rules.
    pub const SOURCE_TYPE_PLATFORM: &'static str = "Platform";
    /// Synthetic marker for the catch-all verdict row.
    pub const SOURCE_TYPE_DEFAULT: &'static str = "DefaultPolicy";

    pub fn source(&self) -> RuleSource {
        match self.policy_source_type.as_deref().unwrap_or("") {
            t if t.eq_ignore_ascii_case(Self::SOURCE_TYPE_WFP) => RuleSource::WfpFilter,
            t if t.eq_ignore_ascii_case(Self::SOURCE_TYPE_DEFAULT) => RuleSource::DefaultPolicy,
            t if t.eq_ignore_ascii_case(Self::SOURCE_TYPE_PLATFORM) => RuleSource::Platform,
            t if t.eq_ignore_ascii_case("GroupPolicy") => RuleSource::GroupPolicy,
            t if t.eq_ignore_ascii_case("MDM") => RuleSource::Mdm,
            // Windows reports service-hardening rules under several names;
            // none of them is something a user authored.
            "StaticServiceStore" | "ConfigurableServiceStore" | "Hardcoded" | "Generated" => {
                RuleSource::ServiceHardening
            }
            _ => RuleSource::Local,
        }
    }

    /// True when the rule is defined somewhere else, so switching it off
    /// here lasts only until the next policy refresh. Deliberately false for
    /// Platform: a ufw rule is managed by ufw, but Apply really does change
    /// it, and warning about a refresh that never comes would be noise.
    pub fn is_managed(&self) -> bool {
        matches!(self.source(), RuleSource::GroupPolicy | RuleSource::Mdm)
    }

    /// Whether Firebreak can change this rule at all. A WFP filter is
    /// something else's enforcement showing through; there is no rule to
    /// edit, so it must never present a checkbox.
    pub fn is_editable(&self) -> bool {
        !matches!(
            self.source(),
            RuleSource::WfpFilter | RuleSource::DefaultPolicy
        )
    }

    /// Short label for the Source column.
    pub fn source_label(&self) -> String {
        match self.source() {
            RuleSource::Local => "Local".into(),
            RuleSource::GroupPolicy => "Group Policy".into(),
            RuleSource::Mdm => "Intune/MDM".into(),
            RuleSource::ServiceHardening => "Service hardening".into(),
            RuleSource::DefaultPolicy => "Chain default".into(),
            // the owning subsystem is the useful part: "ufw", "firewalld"
            RuleSource::Platform | RuleSource::WfpFilter => self
                .policy_source
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "Kernel".into()),
        }
    }

    /// Longer explanation for the detail panel and tooltips.
    pub fn source_detail(&self) -> String {
        match self.source() {
            RuleSource::Local => "Created on this machine.".into(),
            RuleSource::GroupPolicy => format!(
                "Applied by Group Policy{}. Disabling it here is undone at the next policy \
                 refresh — change it where it is defined.",
                self.policy_source
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            ),
            RuleSource::Mdm => "Deployed by Intune or another MDM. Disabling it here is undone \
                 at the next policy sync."
                .into(),
            RuleSource::ServiceHardening => {
                "A Windows Service Hardening rule that ships with the OS.".into()
            }
            RuleSource::Platform => format!("Managed by {}.", self.source_label()),
            // `policy_source` carries where this was read from, verbatim, so
            // the claim can be checked against the host rather than believed.
            RuleSource::DefaultPolicy => format!(
                "Not a rule: what inbound traffic meets when no rule matched it. Firebreak \
                 reads it, never changes it{}",
                self.policy_source
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" — {s}."))
                    .unwrap_or_else(|| ".".into())
            ),
            RuleSource::WfpFilter => format!(
                "Not a firewall rule: a {} packet filter. It can block or permit traffic that \
                 no firewall rule explains, and Firebreak cannot change it.",
                self.source_label()
            ),
        }
    }
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

    /// Scope tags for display: ["Domain"], ["Private", "Public"], … or
    /// ["Any"]. Names come from the host's vocabulary, so on firewalld these
    /// are zones. Unrecognised values (Windows' "NotApplicable", an unknown
    /// zone) yield no tags, which callers must treat as "scope unknown" —
    /// never as "scope empty".
    pub fn scope_tags(&self, vocab: &ScopeVocabulary) -> Vec<String> {
        let raw = self.profile.to_lowercase();
        if vocab.is_empty() {
            return Vec::new();
        }
        if raw.contains(&vocab.any_token.to_lowercase()) {
            return vec![vocab.any_token.clone()];
        }
        vocab
            .names
            .iter()
            .filter(|n| raw.contains(&n.to_lowercase()))
            .cloned()
            .collect()
    }

    /// Whether this rule is active in at least one of the selected scopes.
    /// "Any", an unparseable scope, and a backend with no scope concept at
    /// all each match whenever *something* is selected: a filter must never
    /// hide a rule whose scope could not be read, or the user audits a
    /// firewall while a rule they cannot see is letting traffic through.
    pub fn applies_to_scopes(&self, vocab: &ScopeVocabulary, selected: &[String]) -> bool {
        if vocab.is_empty() {
            return true;
        }
        if selected.is_empty() {
            return false;
        }
        let tags = self.scope_tags(vocab);
        if tags.is_empty() || tags == [vocab.any_token.clone()] {
            return true;
        }
        tags.iter().any(|t| selected.contains(t))
    }
}

/// The scopes a firewall backend divides its rules into.
///
/// Windows has exactly three network profiles. firewalld has a user-defined
/// list of zones, of any length. ufw has no such concept at all — every rule
/// simply applies. Nothing shared can therefore hardcode three names, so the
/// names are data supplied by whichever backend is in charge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeVocabulary {
    /// Scope names in display order. Empty = this backend has no scopes.
    pub names: Vec<String>,
    /// The token a rule uses to mean "all scopes".
    pub any_token: String,
}

impl ScopeVocabulary {
    /// Windows Firewall's network profiles.
    pub fn windows_profiles() -> Self {
        ScopeVocabulary {
            names: vec!["Domain".into(), "Private".into(), "Public".into()],
            any_token: "Any".into(),
        }
    }

    /// A backend without scopes, e.g. ufw.
    pub fn none() -> Self {
        ScopeVocabulary::default()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// The host's scope vocabulary. It is a property of the machine Firebreak is
/// auditing — fixed for the life of the process — so it is set once at
/// startup rather than threaded through every rule-rendering call.
static VOCABULARY: std::sync::OnceLock<ScopeVocabulary> = std::sync::OnceLock::new();

/// Declare the host's vocabulary. First call wins; later calls are ignored,
/// so a backend cannot silently redefine scopes mid-run.
pub fn set_vocabulary(vocab: ScopeVocabulary) {
    let _ = VOCABULARY.set(vocab);
}

pub fn vocabulary() -> &'static ScopeVocabulary {
    VOCABULARY.get_or_init(|| {
        if cfg!(windows) {
            ScopeVocabulary::windows_profiles()
        } else {
            ScopeVocabulary::none()
        }
    })
}

/// Which of the host vocabulary's scopes a rule is active in — the editable
/// scope behind the clickable chips. Ordered to match the vocabulary so the
/// UI renders scopes in a stable order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet {
    entries: Vec<(String, bool)>,
    /// Carried so the set can render itself back to rule text without
    /// needing the vocabulary again.
    any_token: String,
}

impl ScopeSet {
    pub fn from_rule(r: &RuleInfo, vocab: &ScopeVocabulary) -> ScopeSet {
        let tags = r.scope_tags(vocab);
        // "Any" and an unreadable scope both expand to every scope: the rule
        // is live everywhere until proven otherwise.
        let all = tags.is_empty() || tags == [vocab.any_token.clone()];
        ScopeSet {
            entries: vocab
                .names
                .iter()
                .map(|n| (n.clone(), all || tags.contains(n)))
                .collect(),
            any_token: vocab.any_token.clone(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, bool)> {
        self.entries.iter().map(|(n, a)| (n.as_str(), *a))
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, a)| n == name && *a)
    }

    pub fn set(&mut self, name: &str, active: bool) {
        for (n, a) in self.entries.iter_mut() {
            if n == name {
                *a = active;
            }
        }
    }

    pub fn toggle(&mut self, name: &str) {
        let now = self.is_active(name);
        self.set(name, !now);
    }

    /// No scope selected. For a backend with no scopes this is false — an
    /// empty vocabulary means "always applies", not "applies nowhere".
    pub fn is_empty(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|(_, a)| !*a)
    }

    pub fn is_all(&self) -> bool {
        self.entries.iter().all(|(_, a)| *a)
    }

    /// The backend's rule-text form, e.g. Windows' `-Profile Domain,Private`.
    /// None when nothing is selected — the caller should disable the rule
    /// instead of narrowing it to nothing.
    pub fn to_arg(&self) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        if self.is_empty() {
            return None;
        }
        if self.is_all() {
            return Some(self.any_token.clone());
        }
        Some(
            self.entries
                .iter()
                .filter(|(_, a)| *a)
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    /// Scopes present in `self` but dropped in `other` — what an edit removes.
    pub fn removed_since(&self, other: &ScopeSet) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(n, a)| *a && !other.is_active(n))
            .map(|(n, _)| n.as_str())
            .collect()
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
    /// The filter's provider GUID as a string, or empty when it has none.
    /// This is how a Windows Firewall filter is told apart from Defender
    /// network protection, a VPN client, or third-party security software.
    pub provider_key: String,
    /// The provider's display name, resolved from the provider table.
    pub provider_name: String,
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
            policy_source: None,
            policy_source_type: None,
        }
    }

    fn sel(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_group_policy_rule_is_recognised_as_managed() {
        // Disabling a centrally-managed rule lasts until the next policy
        // refresh. Treating it as local is how someone ends up "fixing" the
        // same rule every week.
        let mut r = rule_with_profile("Any");
        r.policy_source_type = Some("GroupPolicy".into());
        r.policy_source = Some("Corp-Baseline".into());
        assert!(r.is_managed());
        assert_eq!(r.source_label(), "Group Policy");
    }

    #[test]
    fn a_local_rule_is_not_managed() {
        let mut r = rule_with_profile("Any");
        assert!(!r.is_managed(), "no policy info means local");
        assert_eq!(r.source_label(), "Local");
        r.policy_source_type = Some("Local".into());
        assert!(!r.is_managed());
        r.policy_source_type = Some(String::new());
        assert!(!r.is_managed(), "an empty type is not a management system");
    }

    #[test]
    fn scope_tags_parse_combinations() {
        let v = ScopeVocabulary::windows_profiles();
        assert_eq!(rule_with_profile("Any").scope_tags(&v), vec!["Any"]);
        assert_eq!(
            rule_with_profile("Domain, Public").scope_tags(&v),
            vec!["Domain", "Public"]
        );
        assert_eq!(rule_with_profile("Private").scope_tags(&v), vec!["Private"]);
    }

    #[test]
    fn scope_filter_matches_selected_sets() {
        let v = ScopeVocabulary::windows_profiles();
        let dp = rule_with_profile("Domain, Private");
        assert!(dp.applies_to_scopes(&v, &sel(&["Domain"])));
        assert!(dp.applies_to_scopes(&v, &sel(&["Private"])));
        assert!(!dp.applies_to_scopes(&v, &sel(&["Public"])));
        // Any matches whenever something is selected, never when nothing is
        let any = rule_with_profile("Any");
        assert!(any.applies_to_scopes(&v, &sel(&["Public"])));
        assert!(!any.applies_to_scopes(&v, &sel(&[])));
    }

    #[test]
    fn an_unreadable_scope_stays_visible() {
        // A rule whose scope Firebreak cannot parse is still a live rule.
        // Hiding it would let the user audit a firewall to "clean" while
        // something they never saw is admitting traffic.
        let v = ScopeVocabulary::windows_profiles();
        let odd = rule_with_profile("NotApplicable");
        assert!(odd.applies_to_scopes(&v, &sel(&["Domain"])));
    }

    #[test]
    fn a_backend_without_scopes_shows_every_rule() {
        // ufw has no zones or profiles at all. An empty vocabulary must mean
        // "always applies", not "applies nowhere" — the latter would render
        // an entire Linux firewall invisible.
        let v = ScopeVocabulary::none();
        let r = rule_with_profile("Any");
        assert!(r.applies_to_scopes(&v, &sel(&[])));
        assert!(r.scope_tags(&v).is_empty());
    }

    #[test]
    fn an_arbitrary_zone_vocabulary_works() {
        // firewalld zones are user-defined and there can be any number.
        let v = ScopeVocabulary {
            names: vec!["FedoraWorkstation".into(), "public".into(), "dmz".into()],
            any_token: "Any".into(),
        };
        let r = rule_with_profile("FedoraWorkstation");
        assert_eq!(r.scope_tags(&v), vec!["FedoraWorkstation"]);
        assert!(r.applies_to_scopes(&v, &sel(&["FedoraWorkstation"])));
        assert!(!r.applies_to_scopes(&v, &sel(&["dmz"])));
    }

    #[test]
    fn scope_set_round_trips_through_the_rule_text_form() {
        let v = ScopeVocabulary::windows_profiles();
        let mut s = ScopeSet::from_rule(&rule_with_profile("Any"), &v);
        assert!(s.is_all());
        assert_eq!(s.to_arg().as_deref(), Some("Any"));
        s.set("Public", false);
        assert_eq!(s.to_arg().as_deref(), Some("Domain,Private"));
    }

    #[test]
    fn narrowing_to_nothing_has_no_rule_text_form() {
        // An empty scope is not "Any". Writing it back as Any would widen a
        // rule the user was trying to switch off — the caller must disable
        // the rule instead.
        let v = ScopeVocabulary::windows_profiles();
        let mut s = ScopeSet::from_rule(&rule_with_profile("Any"), &v);
        for name in ["Domain", "Private", "Public"] {
            s.set(name, false);
        }
        assert!(s.is_empty());
        assert_eq!(s.to_arg(), None);
    }

    #[test]
    fn removed_since_reports_what_an_edit_drops() {
        let v = ScopeVocabulary::windows_profiles();
        let orig = ScopeSet::from_rule(&rule_with_profile("Any"), &v);
        let mut target = orig.clone();
        target.set("Public", false);
        assert_eq!(orig.removed_since(&target), vec!["Public"]);
        assert!(target.removed_since(&orig).is_empty());
    }

    #[test]
    fn a_no_scope_backend_has_an_empty_editable_set() {
        // ufw: nothing to render as chips, and nothing to write back.
        let v = ScopeVocabulary::none();
        let s = ScopeSet::from_rule(&rule_with_profile("Any"), &v);
        assert_eq!(s.iter().count(), 0);
        assert!(!s.is_empty(), "no scopes is not the same as none selected");
        assert_eq!(s.to_arg(), None);
    }

    #[test]
    fn an_unreadable_scope_expands_to_every_scope_not_none() {
        // A rule whose scope will not parse is live somewhere. Treating it
        // as empty would render it as "applies nowhere" and, worse, let an
        // apply narrow it to nothing.
        let v = ScopeVocabulary::windows_profiles();
        let s = ScopeSet::from_rule(&rule_with_profile("NotApplicable"), &v);
        assert!(s.is_all());
    }

    #[test]
    fn zones_of_any_length_round_trip() {
        let v = ScopeVocabulary {
            names: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            any_token: "Any".into(),
        };
        let mut s = ScopeSet::from_rule(&rule_with_profile("b, d"), &v);
        assert_eq!(s.to_arg().as_deref(), Some("b,d"));
        s.toggle("a");
        assert_eq!(s.to_arg().as_deref(), Some("a,b,d"));
    }
}
