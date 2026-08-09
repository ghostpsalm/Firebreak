//! The ufw backend.
//!
//! ufw is the easiest firewall Firebreak has to audit, and by some distance:
//! `iptables-nft` puts a packet counter on every rule automatically, so the
//! "which rules are unused" question is answerable read-only, with nothing
//! enabled and no waiting period. There is no collection clock to start —
//! see [`super::Backend::needs_instrumentation`].
//!
//! Rule identity comes from the `### tuple ###` lines in
//! `/etc/ufw/user.rules`, which are ufw's own machine-readable record of
//! what the user asked for and map 1:1 onto `ufw status numbered`. Each
//! tuple is followed by the iptables rules ufw generated from it, in the
//! order they are loaded — so the Nth `-A <chain>` line in the file is the
//! Nth rule of that live chain, and that positional join is how a tuple gets
//! its counter.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::model::RuleInfo;

/// IP family — ufw keeps v4 and v6 rules in separate files and separate
/// kernel tables, and the same tuple text can appear in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn tag(self) -> &'static str {
        match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }

    /// Candidate rule-file locations, in order. Distros disagree: Debian and
    /// Ubuntu keep them under `/etc/ufw`, Fedora under `/var/lib/ufw`.
    fn rules_files(self) -> [&'static str; 2] {
        match self {
            Family::V4 => ["/etc/ufw/user.rules", "/var/lib/ufw/user.rules"],
            Family::V6 => ["/etc/ufw/user6.rules", "/var/lib/ufw/user6.rules"],
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    /// ufw's user chains, which are named per family: `ufw-user-input` for
    /// v4 but `ufw6-user-input` for v6. Reading v6 rules against the v4
    /// chain names finds nothing, which looks exactly like a firewall with
    /// no IPv6 rules — a silent half-blind audit on any dual-stack host.
    fn user_chains(self) -> [&'static str; 3] {
        match self {
            Family::V4 => ["ufw-user-input", "ufw-user-output", "ufw-user-forward"],
            Family::V6 => ["ufw6-user-input", "ufw6-user-output", "ufw6-user-forward"],
        }
    }

    fn chain_for(self, direction: &str) -> &'static str {
        let chains = self.user_chains();
        match direction {
            "out" => chains[1],
            "fwd" => chains[2],
            _ => chains[0],
        }
    }
}

/// One generated iptables rule belonging to a tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based position within its chain, as iptables numbers them.
    pub position: usize,
    /// The traffic this entry matches, ignoring what it *does* about it.
    /// Entries sharing a signature see the same packets; entries with
    /// different signatures see disjoint packets. Everything about counting
    /// a tuple's hits correctly turns on this distinction.
    pub signature: String,
}

/// One ufw rule, as the user wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfwRule {
    /// The raw tuple text — ufw's own identity for the rule, and ours.
    pub tuple: String,
    pub family: Family,
    /// allow / deny / reject / limit
    pub action: String,
    pub proto: Option<String>,
    pub dport: Option<String>,
    pub sport: Option<String>,
    pub src: String,
    pub dst: String,
    /// Destination application profile (`ufw allow SSH`), when the rule came
    /// from one. It names the rule far better than its port does.
    pub app: Option<String>,
    /// in / out / fwd
    pub direction: String,
    pub iface: Option<String>,
    pub comment: Option<String>,
    pub chain: String,
    pub entries: Vec<Entry>,
}

/// What a parse of one rules file produced. Tuples we could not read are
/// carried out explicitly rather than dropped: a rule that silently vanishes
/// here would look like a rule that does not exist, and the whole point of
/// the tool is to tell the user what their firewall actually allows.
#[derive(Debug, Default)]
pub struct ParsedRules {
    pub rules: Vec<UfwRule>,
    /// Rules that exist but cannot be counted, as (tuple text, reason).
    /// Two distinct causes, kept distinguishable because they need
    /// different fixes: a tuple shape this parser does not understand, and
    /// a tuple that generated no iptables rules at all.
    pub unreadable: Vec<(String, &'static str)>,
    /// Chains whose positional join is untrustworthy because the file
    /// inserts (`-I`) into them rather than only appending.
    pub untrustworthy_chains: Vec<String>,
}

/// Parse a `user.rules` / `user6.rules` file.
pub fn parse_user_rules(text: &str, family: Family) -> ParsedRules {
    let mut out = ParsedRules::default();
    // running per-chain rule position, mirroring how iptables-restore loads
    let mut next_position: BTreeMap<&str, usize> = BTreeMap::new();
    let mut current: Option<UfwRule> = None;
    let mut in_rules = false;

    for raw in text.lines() {
        let line = raw.trim();

        if line == "### RULES ###" {
            in_rules = true;
            continue;
        }
        if line == "### END RULES ###" {
            if let Some(r) = current.take() {
                push_rule(&mut out, r);
            }
            in_rules = false;
            continue;
        }

        if let Some(spec) = line.strip_prefix("### tuple ### ") {
            if let Some(r) = current.take() {
                push_rule(&mut out, r);
            }
            match parse_tuple(spec, family) {
                Some(r) => current = Some(r),
                None => out.unreadable.push((
                    spec.to_string(),
                    "Firebreak does not understand this rule's format",
                )),
            }
            continue;
        }

        // Positional joining assumes append-only load order. An insert into
        // a user chain would shift every later position, so refuse to trust
        // that chain's counters rather than report shifted numbers.
        if let Some(rest) = line.strip_prefix("-I ") {
            if let Some(chain) = rest.split_whitespace().next() {
                if family.user_chains().contains(&chain)
                    && !out.untrustworthy_chains.iter().any(|c| c == chain)
                {
                    out.untrustworthy_chains.push(chain.to_string());
                }
            }
            continue;
        }

        let Some(rest) = line.strip_prefix("-A ") else {
            continue;
        };
        let Some(chain) = rest.split_whitespace().next() else {
            continue;
        };
        // every -A advances that chain's position, whether or not it belongs
        // to a tuple — the live chain numbers them all
        let slot = next_position.entry(chain_key(family, chain)).or_insert(1);
        let position = *slot;
        *slot += 1;

        if !in_rules {
            continue;
        }
        if let Some(rule) = current.as_mut() {
            if rule.chain == chain {
                rule.entries.push(Entry {
                    position,
                    signature: match_signature(rest),
                });
            }
        }
    }
    if let Some(r) = current.take() {
        push_rule(&mut out, r);
    }
    out
}

/// Chain names are interned to `&'static str` where known so the position
/// map can key on them; unknown chains share one bucket, which is harmless
/// because only user chains are ever joined to counters.
fn chain_key(family: Family, chain: &str) -> &'static str {
    family
        .user_chains()
        .iter()
        .find(|c| **c == chain)
        .copied()
        .unwrap_or("other")
}

fn push_rule(out: &mut ParsedRules, rule: UfwRule) {
    // A tuple with no generated entries has nothing to count; surface it
    // rather than reporting it as a zero-hit (i.e. unused) rule.
    if rule.entries.is_empty() {
        out.unreadable.push((
            rule.tuple,
            "ufw recorded this rule but generated no firewall entry for it",
        ));
        return;
    }
    out.rules.push(rule);
}

/// `### tuple ###` payload:
/// `<action> <proto> <dport> <dst> <sport> <src> [<dapp> <sapp>] [<dir>]
///  [comment=<hex>]`
///
/// The application-profile fields are the trap here. A rule created from an
/// app profile (`ufw allow SSH`) writes two extra tokens before the
/// direction — `allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 SSH - in` — so the
/// direction is not at a fixed index. It is found by matching from the end
/// instead, which is also what makes the field count self-describing.
/// Fedora's default install ships such rules, so this is the common case,
/// not an exotic one.
///
/// `action` may also carry a logging suffix (`allow_log`, `deny_log-all`)
/// and `dir` an interface (`in_eth0`).
fn parse_tuple(spec: &str, family: Family) -> Option<UfwRule> {
    let mut tokens: Vec<&str> = spec.split_whitespace().collect();

    let mut comment = None;
    if let Some(pos) = tokens.iter().position(|t| t.starts_with("comment=")) {
        comment = decode_hex_comment(&tokens[pos]["comment=".len()..]);
        tokens.remove(pos);
    }

    if tokens.len() < 6 {
        return None;
    }

    // A trailing direction token is optional; without one, inbound is the
    // implied default (ufw omitted it on older rules).
    let mut direction = "in".to_string();
    let mut iface = None;
    if tokens.len() > 6 {
        if let Some((d, i)) = split_direction(tokens[tokens.len() - 1]) {
            direction = d;
            iface = i;
            tokens.pop();
        }
    }

    // Whatever is left past the six fixed fields must be the app-profile
    // pair. Anything else is a shape this parser does not understand, and
    // guessing would silently mis-describe a live rule.
    let dapp = match tokens.len() {
        6 => None,
        8 => Some(tokens[6]).filter(|t| *t != "-"),
        _ => return None,
    };

    let action = tokens[0].split('_').next().unwrap_or(tokens[0]).to_string();
    if !matches!(action.as_str(), "allow" | "deny" | "reject" | "limit") {
        return None;
    }

    let any = |s: &str| -> Option<String> {
        if s.eq_ignore_ascii_case("any") {
            None
        } else {
            Some(s.to_string())
        }
    };

    Some(UfwRule {
        tuple: spec.to_string(),
        family,
        action,
        proto: any(tokens[1]),
        dport: any(tokens[2]),
        dst: tokens[3].to_string(),
        sport: any(tokens[4]),
        src: tokens[5].to_string(),
        app: dapp.map(str::to_string),
        chain: family.chain_for(&direction).to_string(),
        direction,
        iface,
        comment,
        entries: Vec::new(),
    })
}

fn split_direction(token: &str) -> Option<(String, Option<String>)> {
    let (dir, iface) = match token.split_once('_') {
        Some((d, i)) => (d, Some(i.to_string())),
        None => (token, None),
    };
    match dir {
        "in" | "out" | "fwd" => Some((dir.to_string(), iface)),
        _ => None,
    }
}

/// ufw hex-encodes rule comments. A comment that will not decode is dropped
/// (it is cosmetic), never allowed to fail the rule.
fn decode_hex_comment(hex: &str) -> Option<String> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// Which packets an `-A` spec matches, ignoring the verdict. Only the match
/// options count — `-j`, `-m recent …`, `-m conntrack …` and friends
/// describe what happens to the packet, not which packets are seen.
fn match_signature(spec: &str) -> String {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let mut keys: BTreeMap<&str, &str> = BTreeMap::new();
    let mut i = 0;
    while i < tokens.len() {
        let key = tokens[i];
        let is_match_key = matches!(
            key,
            "-p" | "--dport" | "--sport" | "-s" | "-d" | "-i" | "-o"
        );
        if is_match_key {
            if let Some(value) = tokens.get(i + 1) {
                keys.insert(key, value);
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    keys.into_iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Hits for one tuple, given its chain's live counters indexed by position.
///
/// A tuple can expand into several iptables rules, and they fall into two
/// kinds that must be combined differently:
///
///  * **Same signature** — one traffic class inspected several times, as
///    `limit` does (`recent --set`, then `recent --update -j ufw-user-limit`,
///    then `-j ufw-user-limit-accept`). Summing would report three hits per
///    connection, so take the maximum: the rule that saw every packet.
///  * **Different signatures** — disjoint traffic, as `proto any` does by
///    expanding to one tcp rule and one udp rule. Neither sees the other's
///    packets, so these must be summed or half the evidence is lost.
///
/// Returns `None` when any of the tuple's positions has no counter, which
/// means the live chain no longer matches the file. Reporting nothing is
/// correct there; reporting a partial sum would look like a lightly-used
/// rule and invite the user to delete it.
pub fn hits_for(rule: &UfwRule, counters: &BTreeMap<usize, i64>) -> Option<i64> {
    let mut by_signature: BTreeMap<&str, i64> = BTreeMap::new();
    for entry in &rule.entries {
        let value = *counters.get(&entry.position)?;
        let slot = by_signature.entry(entry.signature.as_str()).or_insert(0);
        *slot = (*slot).max(value);
    }
    Some(by_signature.values().sum())
}

/// Parse `iptables -L <chain> -v -n -x --line-numbers` into position -> packets.
pub fn parse_chain_counters(text: &str) -> BTreeMap<usize, i64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(num), Some(pkts)) = (fields.next(), fields.next()) else {
            continue;
        };
        // header lines ("Chain …", "num pkts bytes …") fail these parses
        let (Ok(num), Ok(pkts)) = (num.parse::<usize>(), pkts.parse::<i64>()) else {
            continue;
        };
        out.insert(num, pkts);
    }
    out
}

/// Human-facing rule name, close to what `ufw status` shows.
fn display_name(rule: &UfwRule) -> String {
    let port = match (&rule.app, &rule.dport, &rule.proto) {
        // an app profile is the name the user chose; prefer it to the port
        (Some(app), _, _) => app.clone(),
        (None, Some(p), Some(proto)) => format!("{p}/{proto}"),
        (None, Some(p), None) => p.clone(),
        (None, None, Some(proto)) => proto.clone(),
        (None, None, None) => "any".to_string(),
    };
    let mut s = format!("{} {}", rule.action.to_uppercase(), port);
    if rule.dst != "0.0.0.0/0" && rule.dst != "::/0" {
        s.push_str(&format!(" to {}", rule.dst));
    }
    if rule.src != "0.0.0.0/0" && rule.src != "::/0" {
        s.push_str(&format!(" from {}", rule.src));
    }
    if let Some(iface) = &rule.iface {
        s.push_str(&format!(" on {iface}"));
    }
    if rule.family == Family::V6 {
        s.push_str(" (v6)");
    }
    if let Some(c) = &rule.comment {
        s.push_str(&format!(" — {c}"));
    }
    s
}

impl UfwRule {
    /// Stable identity: family plus ufw's own tuple text. Survives
    /// reordering, unlike a chain position.
    pub fn id(&self) -> String {
        format!("ufw:{}:{}", self.family.tag(), self.tuple)
    }

    pub fn to_rule_info(&self) -> RuleInfo {
        RuleInfo {
            name: self.id(),
            display_name: display_name(self),
            description: self.comment.clone(),
            enabled: "True".into(),
            direction: match self.direction.as_str() {
                "out" => "Outbound".into(),
                "fwd" => "Forward".into(),
                _ => "Inbound".into(),
            },
            action: match self.action.as_str() {
                // `limit` allows, with a rate cap — it is not a block
                "allow" | "limit" => "Allow".into(),
                _ => "Block".into(),
            },
            // ufw has no zones or profiles; every rule is unconditionally in
            // scope. The generalised scope label lands with the firewalld
            // backend, which is the one that actually has zones.
            profile: "Any".into(),
            group: Some(format!("ufw {}", self.direction)),
            program: None,
            protocol: self.proto.clone(),
            local_port: self.dport.clone(),
            remote_port: self.sport.clone(),
            service: None,
            remote_address: Some(self.src.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Live host access
// ---------------------------------------------------------------------------

/// Is ufw installed and active? An inactive ufw still has rules on disk but
/// nothing loaded in the kernel, so its counters would all read zero — which
/// would report every rule as unused. Refuse rather than mislead.
pub fn status() -> Result<bool> {
    let ufw = crate::syspath::system_tool("ufw").context("ufw is not installed")?;
    let out = crate::syspath::command(ufw)
        .arg("status")
        .output()
        .context("running ufw status")?;
    if !out.status.success() {
        bail!(
            "ufw status failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case("Status: active")))
}

/// Read and parse both rules files.
pub fn read_rules() -> Result<ParsedRules> {
    let mut all = ParsedRules::default();
    let mut looked_in: Vec<&str> = Vec::new();
    for family in [Family::V4, Family::V6] {
        let Some(path) = family
            .rules_files()
            .into_iter()
            .inspect(|p| looked_in.push(p))
            .map(Path::new)
            .find(|p| p.exists())
        else {
            continue;
        };
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "reading {} (Firebreak needs root to read ufw's rule files)",
                path.display()
            )
        })?;
        let parsed = parse_user_rules(&text, family);
        all.rules.extend(parsed.rules);
        all.unreadable.extend(parsed.unreadable);
        all.untrustworthy_chains.extend(parsed.untrustworthy_chains);
    }
    if all.rules.is_empty() && all.unreadable.is_empty() {
        bail!("no ufw rules found (looked in {})", looked_in.join(", "));
    }
    Ok(all)
}

/// Live counters for one chain.
pub fn read_counters(family: Family, chain: &str) -> Result<BTreeMap<usize, i64>> {
    let tool = crate::syspath::system_tool(family.tool())
        .with_context(|| format!("{} is not installed", family.tool()))?;
    let out = crate::syspath::command(tool)
        // -x is not optional: without it iptables rounds counts to "1234K"
        // and every large number becomes a lie
        .args(["-L", chain, "-v", "-n", "-x", "--line-numbers"])
        .output()
        .with_context(|| format!("reading {} counters for {chain}", family.tool()))?;
    if !out.status.success() {
        bail!(
            "{} -L {chain} failed: {}",
            family.tool(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_chain_counters(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `/etc/ufw/user.rules` from a real Ubuntu 24.04 host with
    /// ufw 0.36.2, after: `ufw limit ssh`, `ufw allow from 10.0.0.0/8 to any
    /// port 5432 proto tcp comment "postgres from lan"`, `ufw deny 23`,
    /// `ufw allow out 53`, `ufw allow in on eth0 to any port 8080 proto tcp`.
    const REAL_USER_RULES: &str = r#"*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit
-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept

### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=706f7374677265732066726f6d206c616e
-A ufw-user-input -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT

### tuple ### deny any 23 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 23 -j DROP
-A ufw-user-input -p udp --dport 23 -j DROP

### tuple ### allow any 53 0.0.0.0/0 any 0.0.0.0/0 out
-A ufw-user-output -p tcp --dport 53 -j ACCEPT
-A ufw-user-output -p udp --dport 53 -j ACCEPT

### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in_eth0
-A ufw-user-input -i eth0 -p tcp --dport 8080 -j ACCEPT

### END RULES ###

### LOGGING ###
-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
### END LOGGING ###

### RATE LIMITING ###
-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
### END RATE LIMITING ###
COMMIT
"#;

    /// Verbatim `iptables -L ufw-user-input -v -n -x --line-numbers` for the
    /// same host, with counters edited in to exercise the arithmetic.
    const REAL_INPUT_COUNTERS: &str = r#"Chain ufw-user-input (1 references)
num      pkts      bytes target     prot opt in     out     source               destination
1         900    54000            6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 ctstate NEW recent: SET
2          12      720 ufw-user-limit  6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 ctstate NEW recent: UPDATE
3         888    53280 ufw-user-limit-accept  6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
4          17     1020 ACCEPT     6    --  *      *       10.0.0.0/8           0.0.0.0/0            tcp dpt:5432
5           5      300 DROP       6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:23
6           3      180 DROP       17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:23
7           0        0 ACCEPT     6    --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080
"#;

    /// Verbatim `/var/lib/ufw/user.rules` from a real Fedora 44 host — a
    /// different distro with a different rule-file location and, critically,
    /// application-profile rules in the *default* install. The two extra
    /// tuple fields these carry (`SSH -`) shift the direction token.
    const FEDORA_USER_RULES: &str = r#"### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 SSH - in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT -m comment --comment 'dapp_SSH'

### tuple ### allow udp 5353 224.0.0.251 any 0.0.0.0/0 mDNS - in
-A ufw-user-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT -m comment --comment 'dapp_mDNS'

### END RULES ###
"#;

    fn parsed() -> ParsedRules {
        parse_user_rules(REAL_USER_RULES, Family::V4)
    }

    #[test]
    fn application_profile_rules_parse_despite_the_shifted_direction() {
        let p = parse_user_rules(FEDORA_USER_RULES, Family::V4);
        assert!(p.unreadable.is_empty(), "{:?}", p.unreadable);
        assert_eq!(p.rules.len(), 2);

        let ssh = &p.rules[0];
        assert_eq!(ssh.app.as_deref(), Some("SSH"));
        assert_eq!(ssh.dport.as_deref(), Some("22"));
        assert_eq!(ssh.direction, "in", "'SSH' must not be read as a direction");
        assert_eq!(ssh.chain, "ufw-user-input");

        let mdns = &p.rules[1];
        assert_eq!(mdns.app.as_deref(), Some("mDNS"));
        assert_eq!(mdns.dst, "224.0.0.251");
        assert_eq!(mdns.proto.as_deref(), Some("udp"));
    }

    #[test]
    fn an_app_profile_names_the_rule_better_than_its_port_does() {
        let p = parse_user_rules(FEDORA_USER_RULES, Family::V4);
        assert_eq!(display_name(&p.rules[0]), "ALLOW SSH");
        assert_eq!(display_name(&p.rules[1]), "ALLOW mDNS to 224.0.0.251");
    }

    #[test]
    fn a_source_app_profile_placeholder_is_not_mistaken_for_a_profile() {
        let p = parse_user_rules(FEDORA_USER_RULES, Family::V4);
        // "-" is ufw's "no source app profile" placeholder
        assert_eq!(p.rules[0].app.as_deref(), Some("SSH"));
    }

    /// Verbatim `/var/lib/ufw/user6.rules` from the same Fedora host. Note
    /// the chain names: ufw uses `ufw6-user-input` for IPv6.
    const FEDORA_USER6_RULES: &str = r#"### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 SSH - in
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT -m comment --comment 'dapp_SSH'

### tuple ### deny any 23 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 23 -j DROP
-A ufw6-user-input -p udp --dport 23 -j DROP

### END RULES ###
"#;

    #[test]
    fn ipv6_rules_bind_to_the_ufw6_chains() {
        // Parsing v6 rules against the v4 chain names attaches no entries,
        // which renders every IPv6 rule unmeasurable — indistinguishable
        // from a host with no IPv6 rules at all. Half-blind, silently.
        let p = parse_user_rules(FEDORA_USER6_RULES, Family::V6);
        assert!(p.unreadable.is_empty(), "{:?}", p.unreadable);
        assert_eq!(p.rules.len(), 2);
        assert!(p.rules.iter().all(|r| r.chain == "ufw6-user-input"));
        assert!(p.rules.iter().all(|r| !r.entries.is_empty()));
        // and v6 positions are counted in their own chain, from 1
        assert_eq!(
            p.rules[1]
                .entries
                .iter()
                .map(|e| e.position)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn an_unrecognised_field_count_is_reported_rather_than_guessed() {
        // seven tokens with no trailing direction is a shape we do not
        // understand; inventing a reading would mis-describe a live rule
        let text = "### RULES ###\n\
                    ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 mystery\n\
                    -A ufw-user-input -p tcp --dport 22 -j ACCEPT\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert!(p.rules.is_empty());
        assert_eq!(p.unreadable.len(), 1);
    }

    fn rule(tuple_starts_with: &str) -> UfwRule {
        parsed()
            .rules
            .into_iter()
            .find(|r| r.tuple.starts_with(tuple_starts_with))
            .expect("rule present")
    }

    #[test]
    fn parses_every_tuple_in_a_real_rules_file() {
        let p = parsed();
        assert_eq!(p.rules.len(), 5, "{:?}", p.rules);
        assert!(p.unreadable.is_empty(), "{:?}", p.unreadable);
        assert!(p.untrustworthy_chains.is_empty());
    }

    #[test]
    fn tuple_fields_map_to_the_users_intent() {
        let r = rule("allow tcp 5432");
        assert_eq!(r.action, "allow");
        assert_eq!(r.proto.as_deref(), Some("tcp"));
        assert_eq!(r.dport.as_deref(), Some("5432"));
        assert_eq!(r.src, "10.0.0.0/8");
        assert_eq!(r.sport, None, "'any' sport must not become a constraint");
        assert_eq!(r.direction, "in");
        assert_eq!(r.comment.as_deref(), Some("postgres from lan"));
        assert_eq!(r.chain, "ufw-user-input");
    }

    #[test]
    fn interface_qualified_direction_is_split_out() {
        let r = rule("allow tcp 8080");
        assert_eq!(r.direction, "in");
        assert_eq!(r.iface.as_deref(), Some("eth0"));
        assert_eq!(r.chain, "ufw-user-input");
    }

    #[test]
    fn outbound_rules_land_in_the_output_chain_with_their_own_positions() {
        let r = rule("allow any 53");
        assert_eq!(r.chain, "ufw-user-output");
        // positions restart per chain — an outbound rule is not position 8
        assert_eq!(
            r.entries.iter().map(|e| e.position).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn positions_follow_the_live_chain_ordering() {
        assert_eq!(
            rule("limit tcp 22")
                .entries
                .iter()
                .map(|e| e.position)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            rule("allow tcp 5432")
                .entries
                .iter()
                .map(|e| e.position)
                .collect::<Vec<_>>(),
            vec![4]
        );
        assert_eq!(
            rule("allow tcp 8080")
                .entries
                .iter()
                .map(|e| e.position)
                .collect::<Vec<_>>(),
            vec![7]
        );
    }

    #[test]
    fn rate_limit_expansion_is_not_multiplied() {
        // `limit` inspects the same connection three times. Summing would
        // report 1800 hits for 900 connections.
        let counters = parse_chain_counters(REAL_INPUT_COUNTERS);
        assert_eq!(hits_for(&rule("limit tcp 22"), &counters), Some(900));
    }

    #[test]
    fn protocol_expansion_is_summed_not_maxed() {
        // `deny any 23` becomes disjoint tcp and udp rules: 5 + 3.
        // Taking the max here would silently discard the udp evidence.
        let counters = parse_chain_counters(REAL_INPUT_COUNTERS);
        assert_eq!(hits_for(&rule("deny any 23"), &counters), Some(8));
    }

    #[test]
    fn a_simple_rule_reports_its_own_counter() {
        let counters = parse_chain_counters(REAL_INPUT_COUNTERS);
        assert_eq!(hits_for(&rule("allow tcp 5432"), &counters), Some(17));
        assert_eq!(hits_for(&rule("allow tcp 8080"), &counters), Some(0));
    }

    #[test]
    fn a_missing_counter_reports_nothing_rather_than_a_partial_sum() {
        // live chain shorter than the file: the join is broken, and a
        // partial total would read as "barely used — safe to delete"
        let mut counters = parse_chain_counters(REAL_INPUT_COUNTERS);
        counters.remove(&6);
        assert_eq!(hits_for(&rule("deny any 23"), &counters), None);
    }

    #[test]
    fn counter_parsing_ignores_headers_and_keeps_exact_numbers() {
        let counters = parse_chain_counters(REAL_INPUT_COUNTERS);
        assert_eq!(counters.len(), 7);
        assert_eq!(counters.get(&1), Some(&900));
        assert_eq!(counters.get(&4), Some(&17));
    }

    #[test]
    fn match_signature_ignores_verdicts_and_stateful_matches() {
        // the three `limit` entries differ only in what they do
        let a = match_signature(
            "ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set",
        );
        let b = match_signature("ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept");
        assert_eq!(a, b);
        // but a different protocol is genuinely different traffic
        let c = match_signature("ufw-user-input -p udp --dport 22 -j ACCEPT");
        assert_ne!(a, c);
        // ...as is a different interface
        let d = match_signature("ufw-user-input -i eth0 -p tcp --dport 22 -j ACCEPT");
        assert_ne!(a, d);
    }

    #[test]
    fn an_unparseable_tuple_is_reported_not_dropped() {
        let text = "### RULES ###\n\
                    ### tuple ### nonsense\n\
                    -A ufw-user-input -j ACCEPT\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert!(p.rules.is_empty());
        assert_eq!(p.unreadable.len(), 1);
        assert_eq!(p.unreadable[0].0, "nonsense");
        assert!(p.unreadable[0].1.contains("format"));
    }

    #[test]
    fn a_tuple_with_no_generated_rules_is_reported_not_counted_as_unused() {
        let text = "### RULES ###\n\
                    ### tuple ### allow tcp 99 0.0.0.0/0 any 0.0.0.0/0 in\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert!(p.rules.is_empty());
        assert_eq!(p.unreadable.len(), 1);
    }

    #[test]
    fn an_insert_into_a_user_chain_invalidates_that_chains_positions() {
        let text = "### RULES ###\n\
                    ### tuple ### allow tcp 99 0.0.0.0/0 any 0.0.0.0/0 in\n\
                    -A ufw-user-input -p tcp --dport 99 -j ACCEPT\n\
                    -I ufw-user-input -p tcp --dport 1 -j ACCEPT\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert_eq!(p.untrustworthy_chains, vec!["ufw-user-input".to_string()]);
    }

    #[test]
    fn logging_action_variants_keep_their_base_action() {
        let text = "### RULES ###\n\
                    ### tuple ### deny_log-all any 25 0.0.0.0/0 any 0.0.0.0/0 in\n\
                    -A ufw-user-input -p tcp --dport 25 -j DROP\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert_eq!(p.rules[0].action, "deny");
        assert_eq!(p.rules[0].to_rule_info().action, "Block");
    }

    #[test]
    fn limit_is_an_allow_not_a_block() {
        assert_eq!(rule("limit tcp 22").to_rule_info().action, "Allow");
    }

    #[test]
    fn rule_identity_is_stable_and_family_qualified() {
        let r = rule("allow tcp 5432");
        assert_eq!(
            r.id(),
            "ufw:v4:allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=706f7374677265732066726f6d206c616e"
        );
        let mut v6 = r.clone();
        v6.family = Family::V6;
        assert_ne!(r.id(), v6.id(), "v4 and v6 rules are distinct rules");
    }

    #[test]
    fn display_name_reads_like_ufw_status() {
        assert_eq!(
            display_name(&rule("allow tcp 5432")),
            "ALLOW 5432/tcp from 10.0.0.0/8 — postgres from lan"
        );
        assert_eq!(
            display_name(&rule("allow tcp 8080")),
            "ALLOW 8080/tcp on eth0"
        );
        assert_eq!(display_name(&rule("deny any 23")), "DENY 23");
    }

    #[test]
    fn comments_round_trip_from_hex() {
        assert_eq!(
            decode_hex_comment("706f7374677265732066726f6d206c616e").as_deref(),
            Some("postgres from lan")
        );
        assert_eq!(decode_hex_comment("zz").as_deref(), None);
        assert_eq!(decode_hex_comment("7").as_deref(), None);
    }

    #[test]
    fn a_tuple_without_a_direction_defaults_to_inbound() {
        let text = "### RULES ###\n\
                    ### tuple ### allow tcp 21 0.0.0.0/0 any 0.0.0.0/0\n\
                    -A ufw-user-input -p tcp --dport 21 -j ACCEPT\n\
                    ### END RULES ###\n";
        let p = parse_user_rules(text, Family::V4);
        assert_eq!(p.rules[0].direction, "in");
        assert_eq!(p.rules[0].chain, "ufw-user-input");
    }
}
