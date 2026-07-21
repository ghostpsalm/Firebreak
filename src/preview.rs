//! `--ui-preview`: launch the UI with the design handoff's fixture data —
//! for reviewing the interface without a Windows box or collected data.
//! Runs unelevated and touches no Windows APIs.

use anyhow::Result;
use chrono::{Duration, Utc};

use crate::listeners::{self, Listener};
use crate::model::{RuleInfo, RuleUsage};
use crate::pipeline::UnmatchedRow;
use crate::{baseline_checks, ui};

fn iso_ago(minutes: i64) -> String {
    (Utc::now() - Duration::minutes(minutes))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[allow(clippy::too_many_arguments)]
fn rule(
    id: &str,
    display: &str,
    enabled: bool,
    dir: &str,
    action: &str,
    profile: &str,
    group: Option<&str>,
    program: Option<&str>,
    proto: Option<&str>,
    lport: Option<&str>,
    service: Option<&str>,
    desc: &str,
) -> RuleInfo {
    RuleInfo {
        name: format!("{{{id}}}"),
        display_name: display.into(),
        description: Some(desc.into()),
        enabled: if enabled { "True" } else { "False" }.into(),
        direction: dir.into(),
        action: action.into(),
        profile: profile.into(),
        group: group.map(Into::into),
        program: program.map(Into::into),
        protocol: proto.map(Into::into),
        local_port: lport.map(Into::into),
        remote_port: None,
        service: service.map(Into::into),
        remote_address: Some("any".into()),
    }
}

fn usage(id: &str, allow: i64, block: i64, last_min_ago: i64, apps: &[(&str, i64)]) -> RuleUsage {
    RuleUsage {
        rule_id: id.into(),
        allow_count: allow,
        block_count: block,
        first_seen: Some(iso_ago(15 * 24 * 60)),
        last_seen: Some(iso_ago(last_min_ago)),
        apps: apps.iter().map(|(p, h)| (p.to_string(), *h)).collect(),
        distinct_peers: 3,
        by_profile: vec![("Domain".into(), allow / 2, block), ("Private".into(), allow - allow / 2, 0)],
    }
}

pub fn run() -> Result<()> {
    // (rule, usage, apps, pending_target) — mirrors the design's `raw` fixture
    let specs: Vec<(RuleInfo, Option<RuleUsage>, Vec<&str>, Option<bool>)> = vec![
        (
            rule("2C5D8F41-9B0A-4E77-A1C3-6F2B90D4E815", "Remote Desktop - User Mode (TCP-In)", true, "Inbound", "Allow", "Domain, Private",
                Some("Remote Desktop"), Some(r"%SystemRoot%\system32\svchost.exe"), Some("TCP"), Some("3389"), Some("TermService"),
                "Inbound rule for the Remote Desktop service to allow RDP traffic."),
            Some(usage("a1", 1204, 0, 4, &[(r"C:\Windows\System32\svchost.exe", 1198), (r"C:\Windows\System32\mstsc.exe", 6)])),
            vec!["Remote Desktop Services"], None,
        ),
        (
            rule("a2", "File and Printer Sharing (SMB-In)", true, "Inbound", "Allow", "Domain, Private, Public",
                Some("File and Printer Sharing"), Some("System"), Some("TCP"), Some("445"), None,
                "Inbound rule for File and Printer Sharing via SMB."),
            Some(usage("a2", 2341, 0, 1, &[("System", 2341)])),
            vec!["System"], None,
        ),
        (
            rule("a3", "mDNS (UDP-In)", true, "Inbound", "Allow", "Any",
                None, Some(r"%SystemRoot%\system32\svchost.exe"), Some("UDP"), Some("5353"), Some("Dnscache"),
                "Inbound rule for mDNS multicast name resolution."),
            Some(usage("a3", 44872, 0, 1, &[(r"C:\Program Files\Google\Chrome\Application\chrome.exe", 40012), (r"%USERPROFILE%\AppData\Roaming\Spotify\Spotify.exe", 4860)])),
            vec!["Google Chrome (Google LLC)", "Spotify (Spotify AB)"], None,
        ),
        (
            rule("a4", "Block QUIC (UDP-Out)", true, "Outbound", "Block", "Domain, Private, Public",
                None, None, Some("UDP"), Some("443"), None,
                "Custom rule blocking outbound QUIC to force the TLS inspection path."),
            Some(usage("a4", 0, 12882, 1, &[(r"C:\Program Files\Google\Chrome\Application\chrome.exe", 9002), (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 3880)])),
            vec!["Google Chrome (Google LLC)", "msedge"], None,
        ),
        (
            rule("a5", "OpenSSH SSH Server (sshd)", true, "Inbound", "Allow", "Domain, Private",
                Some("OpenSSH Server"), Some(r"%SystemRoot%\System32\OpenSSH\sshd.exe"), Some("TCP"), Some("22"), None,
                "Inbound rule for the OpenSSH server (sshd)."),
            Some(usage("a5", 96, 0, 122, &[(r"C:\Windows\System32\OpenSSH\sshd.exe", 96)])),
            vec!["OpenSSH"], None,
        ),
        (
            rule("a6", "AnyDesk (TCP-In)", true, "Inbound", "Allow", "Domain, Private, Public",
                None, Some(r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"), Some("TCP"), None, None,
                "Vendor-created inbound rule for AnyDesk remote access."),
            Some(usage("a6", 8, 0, 8640, &[(r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", 8)])),
            vec!["AnyDesk"], None,
        ),
        (
            rule("a7", "Xbox Game UI (TCP-Out)", true, "Outbound", "Allow", "Any",
                None, Some(r"C:\Program Files\WindowsApps\GamingServices\gamingservices.exe"), Some("TCP"), None, None,
                "Outbound rule for Xbox Game UI services."),
            None, vec![], Some(false), // pending disable
        ),
        (
            rule("a8", "TeamViewer Remote (TCP-In)", true, "Inbound", "Allow", "Domain, Private, Public",
                None, Some(r"C:\Program Files\TeamViewer\TeamViewer.exe"), Some("TCP"), Some("5938"), None,
                "Vendor-created inbound rule for TeamViewer."),
            None, vec![], Some(false), // pending disable
        ),
        (
            rule("a9", "Core Networking - DNS (UDP-Out)", false, "Outbound", "Allow", "Domain, Private, Public",
                Some("Core Networking"), Some(r"%SystemRoot%\system32\svchost.exe"), Some("UDP"), Some("53"), Some("Dnscache"),
                "Outbound rule to allow DNS requests."),
            None, vec![], Some(true), // pending enable
        ),
        (
            rule("a10", "Windows Remote Management (HTTP-In)", true, "Inbound", "Allow", "Domain",
                Some("Windows Remote Management"), Some("System"), Some("TCP"), Some("5985"), None,
                "Inbound rule for Windows Remote Management via WS-Management."),
            None, vec![], None,
        ),
        (
            rule("a11", "Network Discovery (SSDP-In)", true, "Inbound", "Allow", "Private",
                Some("Network Discovery"), Some(r"%SystemRoot%\system32\svchost.exe"), Some("UDP"), Some("1900"), Some("SSDPSRV"),
                "Inbound rule to allow use of SSDP for network discovery."),
            Some(usage("a11", 57, 0, 41, &[(r"C:\Windows\explorer.exe", 57)])),
            vec!["Windows Explorer"], None,
        ),
        (
            rule("a12", "Steam (UDP-In)", false, "Inbound", "Allow", "Private, Public",
                None, Some(r"C:\Program Files (x86)\Steam\steam.exe"), Some("UDP"), Some("27036"), None,
                "Inbound rule created at application install for Steam local transfer."),
            None, vec![], None,
        ),
    ];

    let mock_listeners = vec![
        listener("TCP", "0.0.0.0", 3389, 1104, "svchost", r"C:\Windows\System32\svchost.exe"),
        listener("TCP", "0.0.0.0", 445, 4, "System", ""),
        listener("TCP", "0.0.0.0", 22, 5522, "sshd", r"C:\Windows\System32\OpenSSH\sshd.exe"),
        listener("UDP", "0.0.0.0", 5353, 1220, "svchost", r"C:\Windows\System32\svchost.exe"),
        listener("TCP", "0.0.0.0", 5985, 4, "System", ""),
        listener("UDP", "0.0.0.0", 1900, 1220, "svchost", r"C:\Windows\System32\svchost.exe"),
        listener("TCP", "127.0.0.1", 27060, 8100, "steam", r"C:\Program Files (x86)\Steam\steam.exe"),
    ];

    let rows: Vec<ui::RuleRow> = specs
        .into_iter()
        .map(|(rule, usage, apps, pending)| {
            let flags = baseline_checks::flags_for(&rule);
            let listening = listeners::listeners_for_rule(&rule, &mock_listeners);
            let target_enabled = pending.unwrap_or_else(|| rule.is_enabled());
            let target_profiles = crate::model::ProfileSet::from_rule(&rule);
            // demo reviewed states: one verified, one stale (rule changed
            // since it was checked)
            let reviewed = match rule.display_name.as_str() {
                "OpenSSH SSH Server (sshd)" => ui::ReviewState::Yes("2026-07-12".into()),
                "AnyDesk (TCP-In)" => ui::ReviewState::Stale("2026-06-30".into()),
                _ => ui::ReviewState::No,
            };
            ui::RuleRow {
                rule,
                usage,
                flags,
                seen_apps: apps.into_iter().map(Into::into).collect(),
                listening,
                target_enabled,
                target_profiles,
                reviewed,
            }
        })
        .collect();

    // a ping/nmap session: blocked traffic lands on WFP built-in default
    // block filters, which are not firewall rules
    let unmatched = vec![
        unmatched_row("68231", "Default Inbound Block", 0, 486),
        unmatched_row("67810", "ICMPv6 Echo Request Default Block", 0, 37),
        unmatched_row("67122", "Query User Default (no rule matched)", 0, 61),
    ];

    ui::run_preview(
        rows,
        ui::AuditContext {
            hostname: "DC-EDGE-02".into(),
            auditing_active: true,
            collection_started: Some(iso_ago(15 * 24 * 60)),
            last_ingest: Some(iso_ago(2)),
            events_processed: 1_482_306,
            unmatched_events: 1_204,
            note: String::new(),
        },
        unmatched,
        mock_listeners,
    )
}

fn listener(proto: &str, addr: &str, port: u32, pid: u32, name: &str, path: &str) -> Listener {
    Listener {
        proto: proto.into(),
        local_address: addr.into(),
        local_port: port,
        pid,
        process_name: name.into(),
        process_path: path.into(),
    }
}

fn unmatched_row(fid: &str, name: &str, allow: i64, block: i64) -> UnmatchedRow {
    let boot = iso_ago(15 * 24 * 60);
    UnmatchedRow {
        filter_name: name.into(),
        usage: RuleUsage {
            rule_id: format!("unmatched:{boot}:{fid}"),
            allow_count: allow,
            block_count: block,
            first_seen: Some(iso_ago(300)),
            last_seen: Some(iso_ago(120)),
            apps: vec![("System".into(), block.max(allow))],
            distinct_peers: 12,
            by_profile: Vec::new(),
        },
    }
}
