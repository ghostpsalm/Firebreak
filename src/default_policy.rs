//! What happens to inbound traffic that matched no rule at all — the
//! verdict in the gaps between the rules.
//!
//! Shared vocabulary plus the Windows reader. The Linux readers live in
//! [`crate::linux::default_policy`], because what has to be read differs
//! completely: Linux reads a chain tail or a chain policy, Windows reads
//! three profiles that can disagree with each other.
//!
//! Both platforms answer the same question, and it is one a rule list alone
//! cannot: every rule is an *exception*, so a listening socket with no rule
//! beside it is unexplained until you know the default. It is read from the
//! host on both, never assumed, because on either platform it can genuinely
//! be open — a raw nftables `policy accept`, or a Windows profile whose
//! firewall is simply switched off.

/// The verdict for traffic that matched no rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Refused, and the sender is told (ICMP admin-prohibited, TCP reset).
    /// Linux only: Windows Firewall's block drops in silence and has no
    /// reject to configure, so the variant does not exist there.
    #[cfg(any(target_os = "linux", test))]
    Reject,
    /// Discarded in silence. Windows' default inbound block behaves this
    /// way, which is why it is not reported as a reject.
    Drop,
    /// Allowed through. Not a misconfiguration to report — some hosts are
    /// deliberately open and filter elsewhere — but it inverts what an
    /// unmatched listening socket means.
    Accept,
}

impl Verdict {
    /// How the rule table's Action column names it, in that column's
    /// vocabulary.
    pub fn action_label(self) -> &'static str {
        match self {
            #[cfg(any(target_os = "linux", test))]
            Verdict::Reject => "Reject",
            Verdict::Drop => "Block",
            Verdict::Accept => "Allow",
        }
    }

    /// One word for the evidence header.
    pub fn headline(self) -> &'static str {
        match self {
            #[cfg(any(target_os = "linux", test))]
            Verdict::Reject => "Rejected",
            Verdict::Drop => "Blocked",
            Verdict::Accept => "Allowed",
        }
    }

    /// What a listening socket with no matching rule can expect. Phrased for
    /// the socket list, where the reader is asking "is this exposed?".
    pub fn socket_note(self) -> &'static str {
        match self {
            #[cfg(any(target_os = "linux", test))]
            Verdict::Reject => "no rule — unsolicited inbound rejected",
            Verdict::Drop => "no rule — unsolicited inbound blocked",
            Verdict::Accept => "no rule — but the default is allow, so this is reachable",
        }
    }
}

/// A host's default inbound verdict and where it was read from. The Linux
/// readers produce this; Windows produces a [`WindowsStance`] instead,
/// because there is one verdict per profile and they need not agree.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
pub struct DefaultInbound {
    pub verdict: Verdict,
    /// Verbatim enough that the claim can be checked against the host
    /// instead of believed.
    pub detail: String,
}

// ---- the synthetic table row ----

/// Rule-name prefix of the synthetic catch-all row(s). Contains a NUL, so it
/// can never collide with a name any firewall can produce.
pub const ROW_ID_PREFIX: &str = "\u{0}firebreak-default-inbound";

/// The catch-all verdict as a row in the rule table.
///
/// It is not a rule, and everything about it says so: no checkbox, no review
/// circle, no hits (unknown, not zero — nothing counts traffic the firewall
/// refused), and a source of `DefaultPolicy`, which is what keeps it out of
/// plans, quick actions, the zero-hit list, the CSV export and the rule
/// count. It sorts last, under the rules it is the floor beneath.
///
/// `profile` is the scope this verdict applies to in the host's own
/// vocabulary — "Any" where the backend has no scopes, "Domain,Private"
/// where two Windows profiles agree and the third does not.
pub fn row(
    verdict: Verdict,
    profile: &str,
    detail: &str,
    description: String,
) -> crate::ui::RuleRow {
    let rule = crate::model::RuleInfo {
        name: format!("{ROW_ID_PREFIX}:{profile}"),
        display_name: "(default) everything else".into(),
        description: Some(description),
        enabled: "True".into(),
        direction: "Inbound".into(),
        action: verdict.action_label().to_string(),
        profile: profile.to_string(),
        group: None,
        program: None,
        protocol: None,
        local_port: None,
        remote_port: None,
        service: None,
        remote_address: None,
        // where it was read from, shown in the detail panel
        policy_source: Some(detail.to_string()),
        policy_source_type: Some(crate::model::RuleInfo::SOURCE_TYPE_DEFAULT.to_string()),
    };
    crate::ui::RuleRow {
        target_enabled: true,
        target_scopes: crate::model::ScopeSet::from_rule(&rule, &crate::model::vocabulary()),
        rule,
        usage: None,
        flags: Vec::new(),
        seen_apps: Vec::new(),
        listening: Vec::new(),
        reviewed: crate::ui::ReviewState::No,
        // never "zero hits": nothing counts traffic the firewall refused
        hits_known: false,
    }
}

// ---- Windows ----

/// One Windows firewall profile's stance, as reported by
/// `Get-NetFirewallProfile`.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProfileStance {
    #[serde(rename = "Name")]
    pub name: String,
    /// "True"/"False" — a profile whose firewall is switched off has no
    /// default deny at all.
    #[serde(rename = "Enabled")]
    pub enabled: String,
    /// "Block", "Allow", or "NotConfigured".
    #[serde(rename = "Inbound")]
    pub inbound: String,
}

/// The three profiles' stances, which need not agree — and when they don't,
/// saying only the strictest of them would describe a host that is more
/// closed than it is.
#[cfg(any(windows, test))]
#[derive(Debug, Clone)]
pub struct WindowsStance {
    /// (profile, verdict, why) in the order Windows reported them.
    pub per_profile: Vec<(String, Verdict, String)>,
}

#[cfg(any(windows, test))]
impl WindowsStance {
    /// The distinct verdicts, each with the profiles that hold it, in the
    /// order first seen. One synthetic table row per entry.
    pub fn grouped(&self) -> Vec<(Verdict, Vec<String>)> {
        let mut out: Vec<(Verdict, Vec<String>)> = Vec::new();
        for (profile, verdict, _) in &self.per_profile {
            match out.iter_mut().find(|(v, _)| v == verdict) {
                Some((_, profiles)) => profiles.push(profile.clone()),
                None => out.push((*verdict, vec![profile.clone()])),
            }
        }
        out
    }

    /// Header wording. A single verdict is named; profiles that disagree are
    /// reported as disagreeing rather than averaged into one claim.
    pub fn headline(&self) -> String {
        match self.grouped().as_slice() {
            [(v, _)] => v.headline().to_string(),
            _ => "Varies by profile".to_string(),
        }
    }

    /// Socket-list wording for a listener no rule matches.
    pub fn socket_note(&self) -> String {
        match self.grouped().as_slice() {
            [(v, _)] => v.socket_note().to_string(),
            groups => {
                let open: Vec<&str> = groups
                    .iter()
                    .filter(|(v, _)| *v == Verdict::Accept)
                    .flat_map(|(_, p)| p.iter().map(String::as_str))
                    .collect();
                if open.is_empty() {
                    "no rule — unsolicited inbound blocked".to_string()
                } else {
                    format!(
                        "no rule — reachable on {}, blocked on the other profiles",
                        open.join(", ")
                    )
                }
            }
        }
    }

    /// Where each verdict came from, for the header caption and the row's
    /// detail panel.
    pub fn detail(&self) -> String {
        self.per_profile
            .iter()
            .map(|(p, _, why)| format!("{p}: {why}"))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// Read the host's per-profile default inbound action.
#[cfg(windows)]
pub fn read_windows() -> Option<WindowsStance> {
    // Properties are selected by name, so this does not depend on the
    // display language the way parsing `netsh` output would.
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$out = Get-NetFirewallProfile | ForEach-Object {
    [pscustomobject]@{
        Name = [string]$_.Name
        Enabled = [string]$_.Enabled
        Inbound = [string]$_.DefaultInboundAction
    }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;
    let json = crate::firewall_rules::run_powershell(script).ok()?;
    let profiles: Vec<ProfileStance> = serde_json::from_str(json.trim()).ok()?;
    interpret_windows(&profiles)
}

/// Turn what Windows reported into a verdict per profile.
///
/// Two cases decide more than they look like they do. A profile whose
/// firewall is **off** has no default deny — inbound is allowed there, and
/// reporting the configured `DefaultInboundAction` would describe a
/// protection that is not running. And `NotConfigured` is not unknown: it is
/// Windows' shipped default, which is to block.
#[cfg(any(windows, test))]
pub fn interpret_windows(profiles: &[ProfileStance]) -> Option<WindowsStance> {
    let mut per_profile = Vec::new();
    for p in profiles {
        if p.name.trim().is_empty() {
            continue;
        }
        let enabled = p.enabled.eq_ignore_ascii_case("true");
        let (verdict, why) = if !enabled {
            (
                Verdict::Accept,
                "the firewall is off for this profile, so nothing blocks unmatched inbound"
                    .to_string(),
            )
        } else {
            match p.inbound.to_ascii_lowercase().as_str() {
                "block" => (Verdict::Drop, "DefaultInboundAction is Block".to_string()),
                "allow" => (Verdict::Accept, "DefaultInboundAction is Allow".to_string()),
                // Windows' own default when nothing set it
                "notconfigured" | "" => (
                    Verdict::Drop,
                    "DefaultInboundAction is NotConfigured, which Windows treats as Block"
                        .to_string(),
                ),
                other => return other_is_unknown(other),
            }
        };
        per_profile.push((p.name.clone(), verdict, why));
    }
    (!per_profile.is_empty()).then_some(WindowsStance { per_profile })
}

/// An action Windows reported that this code does not know. Reported as
/// unreadable rather than guessed — a wrong guess here is a claim about
/// whether the host is exposed.
#[cfg(any(windows, test))]
fn other_is_unknown(_action: &str) -> Option<WindowsStance> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, enabled: &str, inbound: &str) -> ProfileStance {
        ProfileStance {
            name: name.into(),
            enabled: enabled.into(),
            inbound: inbound.into(),
        }
    }

    /// The shipped Windows configuration: all three profiles on, inbound
    /// blocked. One verdict, so one row and a plain headline.
    #[test]
    fn the_normal_windows_host_blocks_on_every_profile() {
        let s = interpret_windows(&[
            p("Domain", "True", "Block"),
            p("Private", "True", "Block"),
            p("Public", "True", "NotConfigured"),
        ])
        .expect("a stance");
        assert_eq!(s.headline(), "Blocked");
        let groups = s.grouped();
        assert_eq!(groups.len(), 1, "one verdict shared by three profiles");
        assert_eq!(groups[0].0, Verdict::Drop);
        assert_eq!(groups[0].1, ["Domain", "Private", "Public"]);
        assert!(s
            .detail()
            .contains("NotConfigured, which Windows treats as Block"));
    }

    /// A profile with the firewall switched off is open, whatever its
    /// configured action says. Reporting "Blocked" here would tell someone
    /// an exposed machine is protected.
    #[test]
    fn a_disabled_profile_is_open_whatever_its_configured_action() {
        let s = interpret_windows(&[
            p("Domain", "True", "Block"),
            p("Private", "True", "Block"),
            p("Public", "False", "Block"),
        ])
        .expect("a stance");
        assert_eq!(s.headline(), "Varies by profile");
        assert_eq!(s.grouped().len(), 2, "a row each for blocked and allowed");
        assert!(
            s.socket_note().contains("reachable on Public"),
            "the socket list must name the profile that is open, got: {}",
            s.socket_note()
        );
        assert!(s.detail().contains("the firewall is off for this profile"));
    }

    #[test]
    fn an_explicit_allow_is_reported_as_allow() {
        let s = interpret_windows(&[p("Public", "True", "Allow")]).expect("a stance");
        assert_eq!(s.grouped()[0].0, Verdict::Accept);
        assert_eq!(s.headline(), "Allowed");
    }

    /// Anything unrecognised is unreadable, not a guess in either direction.
    #[test]
    fn an_unknown_action_is_not_guessed() {
        assert!(interpret_windows(&[p("Domain", "True", "Sideways")]).is_none());
        assert!(interpret_windows(&[]).is_none());
    }

    /// The JSON shape the PowerShell reader emits, so a change to either
    /// side has to change both.
    #[test]
    fn the_profile_json_deserializes() {
        let list: Vec<ProfileStance> = serde_json::from_str(
            r#"[{"Name":"Domain","Enabled":"True","Inbound":"Block"},
                {"Name":"Public","Enabled":"False","Inbound":"NotConfigured"}]"#,
        )
        .expect("parses");
        let s = interpret_windows(&list).expect("a stance");
        assert_eq!(s.per_profile.len(), 2);
        assert_eq!(s.per_profile[1].1, Verdict::Accept);
    }
}
