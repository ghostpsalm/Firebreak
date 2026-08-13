//! The payload, and the rules about what may be stored.
//!
//! Two jobs, and they are separate on purpose:
//!
//! 1. **Refuse anything that is not the agreed payload.** `deny_unknown_fields`
//!    plus a length cap and a closed vocabulary per field. A collector that
//!    accepts whatever it is sent will eventually store whatever someone
//!    feels like sending it, and it is the operator who then owns that data.
//! 2. **Coarsen what is kept.** The client never sends an address, but the
//!    socket has one, and an IP is personal data. It is truncated to a
//!    network prefix here — before it reaches the database — so the full
//!    address exists only for the life of the request.

use serde::Deserialize;

/// The only payload version this build understands.
pub const SCHEMA: u32 = 1;

/// Cap on any incoming string. Matches the client's own cap, so a
/// well-behaved client never trips it.
const MAX_FIELD: usize = 64;

/// Closed vocabularies. A value outside these is a rejected request, not a
/// stored oddity — this is what keeps the table groupable a year from now.
///
/// **These mirror the client**: `AGES` and `RUNS` are the return values of
/// `age_bucket` and `run_bucket`, and `FEATURES` is the `Feature` enum, all
/// in Firebreak's own `src/telemetry.rs`. Changing a bucket there without
/// changing it here turns every ping from the new build into a 400. Deploy
/// the widened list here *first*, then ship the client.
const OS: [&str; 2] = ["windows", "linux"];
const BACKENDS: [&str; 5] = ["wfp", "ufw", "firewalld", "nftables", "none"];
const AGES: [&str; 6] = ["0", "1-7", "8-30", "31-90", "91-365", "365+"];
const RUNS: [&str; 5] = ["1", "2-5", "6-20", "21-100", "100+"];
const FEATURES: [&str; 8] = [
    "apply",
    "collect",
    "desktop",
    "enable_only",
    "headless",
    "review",
    "support",
    "update",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub schema: u32,
    pub install_id: String,
    pub app_version: String,
    pub os: String,
    pub os_name: String,
    pub os_version: String,
    pub arch: String,
    pub backend: String,
    pub board_vendor: String,
    pub virtual_machine: bool,
    pub age: String,
    pub runs: String,
    pub features: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    Schema(u32),
    Field(&'static str),
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Invalid::Schema(v) => write!(f, "unsupported schema {v}"),
            Invalid::Field(name) => write!(f, "bad field: {name}"),
        }
    }
}

impl Payload {
    /// Check every field. Deliberately exhaustive rather than clever: this
    /// is the whole trust boundary.
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.schema != SCHEMA {
            return Err(Invalid::Schema(self.schema));
        }
        // 128 bits of lowercase hex, exactly as the client mints it
        if self.install_id.len() != 32
            || !self
                .install_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Invalid::Field("install_id"));
        }
        if !OS.contains(&self.os.as_str()) {
            return Err(Invalid::Field("os"));
        }
        if !BACKENDS.contains(&self.backend.as_str()) {
            return Err(Invalid::Field("backend"));
        }
        if !AGES.contains(&self.age.as_str()) {
            return Err(Invalid::Field("age"));
        }
        if !RUNS.contains(&self.runs.as_str()) {
            return Err(Invalid::Field("runs"));
        }
        // Free-ish text, but bounded and printable. os_name and board_vendor
        // come from firmware and /etc/os-release, which are not a promise.
        for (name, value) in [
            ("app_version", &self.app_version),
            ("os_name", &self.os_name),
            ("os_version", &self.os_version),
            ("arch", &self.arch),
            ("board_vendor", &self.board_vendor),
        ] {
            if value.chars().count() > MAX_FIELD || value.chars().any(|c| c.is_control()) {
                return Err(Invalid::Field(name));
            }
        }
        if self.features.len() > FEATURES.len() {
            return Err(Invalid::Field("features"));
        }
        if !self.features.iter().all(|f| FEATURES.contains(&f.as_str())) {
            return Err(Invalid::Field("features"));
        }
        Ok(())
    }

    /// Features as one sorted, de-duplicated, comma-separated cell. Every
    /// value is from [`FEATURES`], so there is nothing here to escape.
    pub fn features_csv(&self) -> String {
        let mut f: Vec<&str> = self.features.iter().map(String::as_str).collect();
        f.sort_unstable();
        f.dedup();
        f.join(",")
    }
}

/// Which address to attribute a request to.
///
/// Caddy *appends* the immediate peer to any `X-Forwarded-For` the client
/// sent, so the header reads `<whatever the client claimed>, <real peer>`.
/// The last entry is therefore the only trustworthy one — taking the first,
/// which is the usual advice for an edge server, would let any client choose
/// what gets recorded about it.
pub fn client_ip(forwarded_for: Option<&str>, peer: std::net::IpAddr) -> std::net::IpAddr {
    forwarded_for
        .and_then(|h| h.rsplit(',').next())
        .map(str::trim)
        .and_then(|s| s.parse().ok())
        .unwrap_or(peer)
}

/// Reduce an address to a network prefix: /24 for IPv4, /48 for IPv6.
///
/// Enough to tell countries and networks apart, not enough to identify a
/// household. The full address is never written anywhere — not to the
/// database, and not to a log.
pub fn truncate(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Payload {
        serde_json::from_str(
            r#"{"schema":1,"install_id":"0123456789abcdef0123456789abcdef",
                "app_version":"0.7.81","os":"linux","os_name":"Fedora Linux",
                "os_version":"44","arch":"x86_64","backend":"firewalld",
                "board_vendor":"ASUSTeK","virtual_machine":false,
                "age":"31-90","runs":"6-20","features":["apply","collect"]}"#,
        )
        .expect("fixture must parse")
    }

    #[test]
    fn a_well_formed_ping_is_accepted() {
        assert_eq!(good().validate(), Ok(()));
    }

    /// The collector must not become a place to put arbitrary data.
    #[test]
    fn unknown_fields_are_refused_outright() {
        let r: Result<Payload, _> = serde_json::from_str(
            r#"{"schema":1,"install_id":"0123456789abcdef0123456789abcdef",
                "app_version":"0.7.81","os":"linux","os_name":"Fedora","os_version":"44",
                "arch":"x86_64","backend":"ufw","board_vendor":"x","virtual_machine":false,
                "age":"0","runs":"1","features":[],"hostname":"secret-box"}"#,
        );
        assert!(
            r.is_err(),
            "an extra field must fail to parse, not be dropped"
        );
    }

    #[test]
    fn a_future_schema_is_refused_rather_than_guessed() {
        let mut p = good();
        p.schema = 2;
        assert_eq!(p.validate(), Err(Invalid::Schema(2)));
    }

    #[test]
    fn install_id_must_be_what_the_client_mints() {
        for bad in [
            "",
            "short",
            "0123456789ABCDEF0123456789ABCDEF",  // uppercase
            "0123456789abcdef0123456789abcdeg",  // non-hex
            "0123456789abcdef0123456789abcdef0", // too long
        ] {
            let mut p = good();
            p.install_id = bad.into();
            assert_eq!(
                p.validate(),
                Err(Invalid::Field("install_id")),
                "should have rejected {bad:?}"
            );
        }
    }

    /// A field name and the way to put something invalid in it.
    type Case = (&'static str, fn(&mut Payload));

    #[test]
    fn vocabularies_are_closed() {
        let cases: [Case; 4] = [
            ("os", |p| p.os = "plan9".into()),
            ("backend", |p| p.backend = "pf".into()),
            ("age", |p| p.age = "3 days".into()),
            ("runs", |p| p.runs = "12".into()),
        ];
        for (field, mutate) in cases {
            let mut p = good();
            mutate(&mut p);
            assert_eq!(p.validate(), Err(Invalid::Field(field)));
        }
    }

    #[test]
    fn features_outside_the_vocabulary_are_refused() {
        let mut p = good();
        p.features = vec!["apply".into(), "exfiltrate".into()];
        assert_eq!(p.validate(), Err(Invalid::Field("features")));
    }

    #[test]
    fn oversize_and_control_characters_are_refused() {
        let mut p = good();
        p.board_vendor = "x".repeat(65);
        assert_eq!(p.validate(), Err(Invalid::Field("board_vendor")));

        let mut p = good();
        p.os_name = "Fedora\nLinux".into();
        assert_eq!(p.validate(), Err(Invalid::Field("os_name")));
    }

    #[test]
    fn features_are_sorted_and_deduplicated() {
        let mut p = good();
        p.features = vec!["review".into(), "apply".into(), "apply".into()];
        assert_eq!(p.features_csv(), "apply,review");
    }

    #[test]
    fn addresses_are_reduced_to_a_prefix() {
        assert_eq!(truncate("203.0.113.47".parse().unwrap()), "203.0.113.0");
        assert_eq!(truncate("8.8.8.8".parse().unwrap()), "8.8.8.0");
        assert_eq!(
            truncate("2001:db8:1234:5678::1".parse().unwrap()),
            "2001:db8:1234::"
        );
    }

    /// A client that sends its own X-Forwarded-For must not be able to
    /// choose what is recorded about it. Caddy appends the real peer, so the
    /// last entry wins.
    #[test]
    fn a_spoofed_forwarded_for_cannot_win() {
        let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            client_ip(Some("9.9.9.9, 203.0.113.47"), peer).to_string(),
            "203.0.113.47"
        );
        // no header at all → the socket's own peer
        assert_eq!(client_ip(None, peer), peer);
        // junk → fall back to the peer rather than storing nonsense
        assert_eq!(client_ip(Some("not-an-ip"), peer), peer);
    }
}
