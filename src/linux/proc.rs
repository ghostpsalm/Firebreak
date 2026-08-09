//! Process attribution from `/proc`.
//!
//! This is where Linux is genuinely worse off than Windows, and it is worth
//! being precise about why. Windows event 5156 carries the rule that matched
//! *and* the application that triggered it in one record. Linux has no such
//! event: the rule side (nftables counters) and the process side (`/proc`,
//! auditd, eBPF) are separate sources with no shared key, and joining them
//! per connection means correlating a 5-tuple across two streams.
//!
//! Firebreak does not attempt that join. It answers the question the rule
//! table actually asks — *which processes are sitting behind the ports this
//! rule opens?* — from the current listener set. That is inference, not
//! per-connection attribution: it names who **could** be reached through a
//! rule, not who was. For deciding whether a rule is over-broad, which is
//! what the tool is for, it is often the more useful answer, and it costs
//! one directory walk.
//!
//! Its limits, stated so nobody reads more into a row than it says:
//!
//!  * A process that was listening yesterday and is not now does not appear.
//!  * Short-lived listeners are missed entirely.
//!  * Outbound connections have no listener, so outbound rules get nothing.
//!  * Resolving another user's process needs root, and without it the answer
//!    silently shrinks rather than failing — see [`super::Report`] and the
//!    root check in `main`.

use std::collections::HashMap;

use crate::listeners::Listener;

/// TCP state 0A = LISTEN, per include/net/tcp_states.h.
const TCP_LISTEN: &str = "0A";

/// One socket as `/proc/net/*` describes it, before we know its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRow {
    pub proto: &'static str,
    pub local_address: String,
    pub local_port: u32,
    pub inode: String,
}

/// Parse one of `/proc/net/{tcp,tcp6,udp,udp6}`.
///
/// `listening_only` keeps TCP sockets in LISTEN. UDP has no listen state, so
/// every bound UDP socket counts — which is correct, since a bound UDP port
/// is reachable.
pub fn parse_net_table(text: &str, proto: &'static str, v6: bool) -> Vec<SocketRow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st tx rx tr tm retrnsmt uid timeout inode
        if f.len() < 10 {
            continue;
        }
        let Some((addr_hex, port_hex)) = f[1].rsplit_once(':') else {
            continue;
        };
        let Ok(local_port) = u32::from_str_radix(port_hex, 16) else {
            continue;
        };
        if proto == "TCP" && f[3] != TCP_LISTEN {
            continue;
        }
        let Some(local_address) = decode_address(addr_hex, v6) else {
            continue;
        };
        out.push(SocketRow {
            proto,
            local_address,
            local_port,
            inode: f[9].to_string(),
        });
    }
    out
}

/// `/proc/net` writes addresses as hex in host byte order per 32-bit word,
/// so 0100007F is 127.0.0.1 rather than 1.0.0.127.
pub fn decode_address(hex: &str, v6: bool) -> Option<String> {
    if v6 {
        if hex.len() != 32 {
            return None;
        }
        let mut groups = Vec::with_capacity(8);
        // four little-endian 32-bit words
        for word in 0..4 {
            let raw = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16).ok()?;
            let be = raw.swap_bytes();
            groups.push((be >> 16) as u16);
            groups.push((be & 0xffff) as u16);
        }
        let addr = std::net::Ipv6Addr::new(
            groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
        );
        Some(addr.to_string())
    } else {
        if hex.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(hex, 16).ok()?;
        let o = raw.to_le_bytes();
        Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
    }
}

/// socket inode -> (pid, process name, executable path), by walking /proc.
fn socket_owners() -> HashMap<String, (u32, String, String)> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            // another user's process without root, or one that just exited
            continue;
        };
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            if let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                out.insert(inode.to_string(), (pid, comm.clone(), exe.clone()));
            }
        }
    }
    out
}

/// Every listening socket on the host, in the shape the shared rule-matching
/// in [`crate::listeners`] already understands.
pub fn enumerate_listeners() -> Vec<Listener> {
    let tables: [(&str, &'static str, bool); 4] = [
        ("/proc/net/tcp", "TCP", false),
        ("/proc/net/tcp6", "TCP", true),
        ("/proc/net/udp", "UDP", false),
        ("/proc/net/udp6", "UDP", true),
    ];
    let owners = socket_owners();
    let mut out = Vec::new();
    for (path, proto, v6) in tables {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for row in parse_net_table(&text, proto, v6) {
            let (pid, name, path) = owners.get(&row.inode).cloned().unwrap_or_default();
            out.push(Listener {
                proto: row.proto.to_string(),
                local_address: row.local_address,
                local_port: row.local_port,
                pid,
                process_name: name,
                process_path: path,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `/proc/net/tcp` from the Fedora 44 host this was written on,
    /// trimmed to a few rows. Row 0 is listening; the third is established
    /// and must not be reported as a listener.
    const REAL_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
        0: 0100007F:4F11 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 52281 2 00000000b1f80692 100 0 0 10 0\n   \
        1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22240 1 00000000a73d3201 100 0 0 10 0\n   \
        2: 0801BD0A:B0F6 9A1714D0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 52879092 1 000000005d28da7a 20 4 30 10 -1\n";

    const REAL_TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
        0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22240 1 00000000a73d3201 100 0 0 10 0\n";

    const REAL_UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n \
        2610: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   193        0 10382 2 00000000b01acf9d 0\n";

    #[test]
    fn addresses_decode_from_host_byte_order() {
        // the classic trap: 0100007F is 127.0.0.1, not 1.0.0.127
        assert_eq!(
            decode_address("0100007F", false).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            decode_address("00000000", false).as_deref(),
            Some("0.0.0.0")
        );
        // 10.189.1.8
        assert_eq!(
            decode_address("0801BD0A", false).as_deref(),
            Some("10.189.1.8")
        );
        assert_eq!(
            decode_address("00000000000000000000000000000000", true).as_deref(),
            Some("::")
        );
    }

    #[test]
    fn malformed_addresses_are_rejected_rather_than_guessed() {
        assert_eq!(decode_address("0100", false), None);
        assert_eq!(decode_address("zzzzzzzz", false), None);
        assert_eq!(decode_address("0100007F", true), None);
    }

    #[test]
    fn only_listening_tcp_sockets_count() {
        let rows = parse_net_table(REAL_TCP, "TCP", false);
        assert_eq!(rows.len(), 2, "the established socket must be excluded");
        assert_eq!(rows[0].local_address, "127.0.0.1");
        assert_eq!(rows[0].local_port, 0x4F11);
        assert_eq!(rows[1].local_port, 22);
        assert_eq!(rows[1].inode, "22240");
    }

    #[test]
    fn every_bound_udp_socket_counts() {
        // UDP has no LISTEN state, and a bound UDP port is reachable, so
        // filtering on state would hide every UDP service on the host.
        let rows = parse_net_table(REAL_UDP, "UDP", false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local_port, 53);
        assert_eq!(rows[0].local_address, "127.0.0.54");
    }

    #[test]
    fn ipv6_rows_parse() {
        let rows = parse_net_table(REAL_TCP6, "TCP", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local_address, "::");
        assert_eq!(rows[0].local_port, 22);
    }

    #[test]
    fn a_truncated_table_yields_nothing_rather_than_panicking() {
        assert!(parse_net_table("header only\n", "TCP", false).is_empty());
        assert!(parse_net_table("h\n 0: junk\n", "TCP", false).is_empty());
        assert!(parse_net_table("", "TCP", false).is_empty());
    }

    #[test]
    fn listeners_bind_to_the_shared_rule_matcher() {
        // The point of returning crate::listeners::Listener: the "which
        // processes are behind this rule's ports" logic is shared with the
        // Windows path rather than reimplemented.
        use crate::model::RuleInfo;
        let ls = vec![Listener {
            proto: "TCP".into(),
            local_address: "0.0.0.0".into(),
            local_port: 8444,
            pid: 42,
            process_name: "clickhouse".into(),
            process_path: "/usr/bin/clickhouse".into(),
        }];
        let rule = RuleInfo {
            name: "firewalld:z/port/1025-65535/tcp".into(),
            display_name: "1025-65535/tcp".into(),
            description: None,
            enabled: "True".into(),
            direction: "Inbound".into(),
            action: "Allow".into(),
            profile: "z".into(),
            group: None,
            program: None,
            protocol: Some("tcp".into()),
            local_port: Some("1025-65535".into()),
            remote_port: None,
            service: None,
            remote_address: None,
        };
        assert_eq!(
            crate::listeners::listeners_for_rule(&rule, &ls),
            vec!["clickhouse:8444"]
        );
    }

    #[test]
    fn reading_the_real_proc_yields_well_formed_listeners() {
        // Smoke test against the live /proc. Deliberately does not require a
        // non-empty result: a minimal container or CI runner may genuinely
        // have nothing bound, and a test that depends on the host's services
        // is flaky rather than strict. The golden fixtures above are what
        // actually pin the parsing.
        for l in enumerate_listeners() {
            assert!(l.local_port > 0, "port 0 is not a real listener");
            assert!(matches!(l.proto.as_str(), "TCP" | "UDP"), "{}", l.proto);
            assert!(!l.local_address.is_empty());
        }
    }
}
