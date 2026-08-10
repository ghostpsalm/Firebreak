//! What happens to inbound traffic that matched no rule at all.
//!
//! A rule list read on its own invites a wrong conclusion. Every rule the
//! user wrote is an *exception*; the interesting part is the verdict in the
//! gaps between them, and on a normal Linux host that verdict is a reject or
//! a drop — which is why a listening socket with no rule beside it is
//! usually unreachable rather than exposed.
//!
//! It is read from the host, never assumed, because the three backends do
//! not agree and one of them can genuinely be open:
//!
//! - **firewalld** ends its `filter_INPUT` base chain with a catch-all
//!   verdict (`reject with icmpx admin-prohibited` by default).
//! - **ufw** sets `DEFAULT_INPUT_POLICY` in `/etc/default/ufw`, normally
//!   `DROP`.
//! - **raw nftables** is whatever the administrator wrote. `policy accept`
//!   on the input chain is common, and there "no rule" means *allowed* — the
//!   exact opposite. Hardcoding a deny would be a lie on that backend.
//!
//! Conntrack sits in front of all of this: `ct state {established, related}
//! accept` means replies to traffic the host itself started are allowed
//! whatever the default is, which is why a DHCP client works with no rule
//! naming it.

use serde_json::Value;

pub use crate::default_policy::{DefaultInbound, Verdict};

/// Read the active backend's default inbound verdict. `None` means it could
/// not be read — which is reported as unknown, never as a deny.
pub fn read(backend: super::Backend) -> Option<DefaultInbound> {
    match backend {
        super::Backend::Firewalld => {
            parse_firewalld_input_chain(&super::firewalld::input_chain_text().ok()?)
        }
        super::Backend::Ufw => {
            let text = ["/etc/default/ufw", "/etc/ufw/ufw.conf"]
                .iter()
                .find_map(|p| std::fs::read_to_string(p).ok())?;
            parse_ufw_defaults(&text)
        }
        super::Backend::Nftables => parse_nft_input_policy(&super::nftables::ruleset_json().ok()?),
    }
}

/// The tail of firewalld's `filter_INPUT` chain is the catch-all. If the
/// chain ends in a jump instead, the chain's own policy decides.
pub(crate) fn parse_firewalld_input_chain(text: &str) -> Option<DefaultInbound> {
    let mut policy = None;
    let mut tail = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line == "}" || line.starts_with('{') || line.starts_with("table ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("chain ") {
            let _ = rest;
            continue;
        }
        if line.starts_with("type ") {
            policy = line
                .split("policy ")
                .nth(1)
                .map(|p| p.trim_end_matches(';').trim().to_string());
            continue;
        }
        tail = Some(line.to_string());
    }
    let tail = tail?;
    let verdict = verdict_of(&tail).or_else(|| verdict_of(policy.as_deref()?))?;
    Some(DefaultInbound {
        verdict,
        detail: format!("firewalld's filter_INPUT chain ends in `{tail}`"),
    })
}

/// `DEFAULT_INPUT_POLICY="DROP"` in ufw's defaults file.
pub(crate) fn parse_ufw_defaults(text: &str) -> Option<DefaultInbound> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "DEFAULT_INPUT_POLICY" {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        let verdict = verdict_of(value)?;
        return Some(DefaultInbound {
            verdict,
            detail: format!("ufw's DEFAULT_INPUT_POLICY is {}", value.to_uppercase()),
        });
    }
    None
}

/// Base chains hooked into `input` carry the policy. Several may exist, and
/// a packet traverses all of them, so one `drop` decides the outcome
/// whatever the others say.
pub(crate) fn parse_nft_input_policy(json: &Value) -> Option<DefaultInbound> {
    let mut chains: Vec<(String, Verdict)> = Vec::new();
    for item in json.get("nftables")?.as_array()? {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        if chain.get("hook").and_then(Value::as_str) != Some("input") {
            continue;
        }
        let Some(verdict) = chain
            .get("policy")
            .and_then(Value::as_str)
            .and_then(verdict_of)
        else {
            continue;
        };
        let name = chain
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("input")
            .to_string();
        chains.push((name, verdict));
    }
    if chains.is_empty() {
        return None;
    }
    // most restrictive wins: a drop anywhere on the path ends the packet
    let decisive = chains
        .iter()
        .find(|(_, v)| *v == Verdict::Drop)
        .or_else(|| chains.iter().find(|(_, v)| *v == Verdict::Reject))
        .unwrap_or(&chains[0])
        .clone();
    Some(DefaultInbound {
        verdict: decisive.1,
        detail: format!(
            "the input chain `{}` has policy {}",
            decisive.0,
            match decisive.1 {
                Verdict::Drop => "drop",
                Verdict::Reject => "reject",
                Verdict::Accept => "accept",
            }
        ),
    })
}

/// The first verdict word in a line of nft/ufw syntax, if there is one.
fn verdict_of(text: &str) -> Option<Verdict> {
    let first = text.split_whitespace().next()?.to_ascii_lowercase();
    match first.as_str() {
        "reject" => Some(Verdict::Reject),
        "drop" => Some(Verdict::Drop),
        "accept" => Some(Verdict::Accept),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `nft list chain inet firewalld filter_INPUT` from a Fedora 44
    /// workstation running firewalld 2.x.
    const FEDORA_INPUT_CHAIN: &str = r#"table inet firewalld {
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state { established, related } accept
		ct status dnat accept
		iifname "lo" accept
		ct state invalid drop
		jump filter_INPUT_POLICIES
		reject with icmpx admin-prohibited
	}
}"#;

    #[test]
    fn firewalld_default_is_the_chain_tail_not_the_chain_policy() {
        let d = parse_firewalld_input_chain(FEDORA_INPUT_CHAIN).expect("a verdict");
        // `policy accept` is on the chain, but the last rule rejects, so
        // reading the policy would report the host as open when it is not
        assert_eq!(d.verdict, Verdict::Reject);
        assert!(d.detail.contains("reject with icmpx admin-prohibited"));
    }

    #[test]
    fn a_chain_ending_in_a_jump_falls_back_to_its_policy() {
        let text = "table inet x {\n\tchain input {\n\t\ttype filter hook input priority 0; \
                    policy drop;\n\t\tjump elsewhere\n\t}\n}";
        assert_eq!(
            parse_firewalld_input_chain(text).map(|d| d.verdict),
            Some(Verdict::Drop)
        );
    }

    #[test]
    fn ufw_default_input_policy_is_read_from_the_defaults_file() {
        let text = "# /etc/default/ufw\nIPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n\
                    DEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n";
        let d = parse_ufw_defaults(text).expect("a verdict");
        assert_eq!(d.verdict, Verdict::Drop);
        // the *output* policy is accept; reading the wrong one would report
        // an open host
        assert!(d.detail.contains("DROP"));
    }

    #[test]
    fn a_raw_nftables_host_may_genuinely_be_open() {
        let json: Value = serde_json::from_str(
            r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input",
                "type":"filter","hook":"input","prio":0,"policy":"accept"}}]}"#,
        )
        .unwrap();
        let d = parse_nft_input_policy(&json).expect("a verdict");
        assert_eq!(
            d.verdict,
            Verdict::Accept,
            "an accept policy must be reported as accept — claiming a deny here \
             would tell the user an exposed port is closed"
        );
    }

    #[test]
    fn a_drop_on_any_input_chain_decides() {
        let json: Value = serde_json::from_str(
            r#"{"nftables":[
                {"chain":{"name":"input","hook":"input","policy":"accept"}},
                {"chain":{"name":"guard","hook":"input","policy":"drop"}},
                {"chain":{"name":"fwd","hook":"forward","policy":"accept"}}]}"#,
        )
        .unwrap();
        let d = parse_nft_input_policy(&json).expect("a verdict");
        assert_eq!(d.verdict, Verdict::Drop);
        assert!(d.detail.contains("guard"));
    }

    #[test]
    fn no_input_chain_is_unknown_rather_than_a_guess() {
        let json: Value =
            serde_json::from_str(r#"{"nftables":[{"chain":{"name":"out","hook":"output"}}]}"#)
                .unwrap();
        assert!(parse_nft_input_policy(&json).is_none());
        assert!(parse_ufw_defaults("IPV6=yes\n").is_none());
    }
}
