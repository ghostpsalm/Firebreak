//! `--export-support`: write a single self-contained diagnostic file with
//! everything needed to work out why rule attribution is failing on a real
//! host. It captures the audit state, rule/filter inventories, the live
//! filter→rule map (with the method that matched), a sample of raw 5156/
//! 5157 event XML, and — crucially — a per-event breakdown that tests each
//! attribution path (FilterOrigin vs rule Name/DisplayName; FilterRTID vs
//! the live filter table; providerData tokens vs rule IDs) so the exact
//! break point is visible without guessing.
//!
//! The file contains local network metadata (IPs, process paths, rule
//! names). It's a plain text file the operator can review and redact before
//! sharing.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::filter_map::MappedVia;
use crate::{audit_control, event_query, filter_map, firewall_rules};

pub fn default_path() -> PathBuf {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let dir = std::env::var("USERPROFILE")
        .map(|p| Path::new(&p).join("Desktop"))
        .unwrap_or_else(|_| PathBuf::from("."));
    let base = if dir.exists() {
        dir
    } else {
        PathBuf::from(".")
    };
    base.join(format!("firebreak-support-{stamp}.txt"))
}

macro_rules! section {
    ($out:expr, $title:expr) => {
        let _ = writeln!($out, "\n\n========== {} ==========", $title);
    };
}

pub fn export(out_path: &Path) -> Result<()> {
    let mut o = String::new();
    let _ = writeln!(o, "firebreak support export");
    let _ = writeln!(o, "version {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(o, "generated {}", chrono::Utc::now().to_rfc3339());
    let _ = writeln!(o, "host {}", crate::pipeline::hostname());
    let _ = writeln!(o, "windows: {}", os_version());

    // ---- audit state ----
    section!(o, "AUDIT STATE");
    match audit_control::query_audit_state() {
        Ok(s) => {
            let _ = writeln!(
                o,
                "Filtering Platform Connection: success={} failure={} (fully_enabled={})",
                s.success,
                s.failure,
                s.fully_enabled()
            );
        }
        Err(e) => {
            let _ = writeln!(o, "query failed: {e:#}");
        }
    }
    let _ = writeln!(
        o,
        "subcategory GUID: {}",
        audit_control::FILTERING_PLATFORM_CONNECTION_GUID
    );
    match audit_control::security_log_max_bytes() {
        Ok(b) => {
            let _ = writeln!(
                o,
                "Security log max size: {} bytes ({} MiB)",
                b,
                b / 1024 / 1024
            );
        }
        Err(e) => {
            let _ = writeln!(o, "Security log size query failed: {e:#}");
        }
    }
    // raw auditpol output, for cross-checking the API result
    let _ = writeln!(o, "\n[auditpol /get, verbose]");
    match crate::syspath::command(crate::syspath::system32_tool("auditpol.exe"))
        .args([
            "/get",
            &format!(
                "/subcategory:{}",
                audit_control::FILTERING_PLATFORM_CONNECTION_GUID
            ),
        ])
        .output()
    {
        Ok(out) => {
            let _ = writeln!(o, "{}", String::from_utf8_lossy(&out.stdout).trim());
        }
        Err(e) => {
            let _ = writeln!(o, "auditpol failed: {e}");
        }
    }

    // ---- rules ----
    section!(o, "FIREWALL RULES");
    let rules = match firewall_rules::enumerate_rules() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(o, "enumerate_rules failed: {e:#}");
            Vec::new()
        }
    };
    let _ = writeln!(o, "rule count: {}", rules.len());
    let enabled = rules.iter().filter(|r| r.is_enabled()).count();
    let _ = writeln!(o, "enabled: {enabled}");
    let _ = writeln!(o, "\n[sample rules: Name (InstanceID) | DisplayName]");
    for r in rules.iter().take(12) {
        let _ = writeln!(o, "  {}  |  {}", r.name, r.display_name);
    }

    // ---- filters ----
    section!(o, "WFP FILTERS");
    let filters = match filter_map::enumerate_filters() {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(o, "enumerate_filters failed: {e:#}");
            Vec::new()
        }
    };
    let _ = writeln!(o, "filter count: {}", filters.len());
    let with_pd = filters
        .iter()
        .filter(|f| !f.provider_data_utf16.is_empty())
        .count();
    let _ = writeln!(o, "with non-empty providerData(utf16): {with_pd}");
    // filters whose display name looks like it belongs to a firewall rule
    let rule_display: std::collections::HashSet<&str> =
        rules.iter().map(|r| r.display_name.as_str()).collect();
    let named_like_rule = filters
        .iter()
        .filter(|f| rule_display.contains(f.name.as_str()))
        .count();
    let _ = writeln!(
        o,
        "filters whose name == some rule DisplayName: {named_like_rule}"
    );
    let _ = writeln!(o, "\n[sample filters that carry providerData: filter_id | name | providerData(utf16, trimmed) | providerData(hex, first 64)]");
    let mut shown = 0;
    for f in filters.iter().filter(|f| !f.provider_data_utf16.is_empty()) {
        let _ = writeln!(
            o,
            "  {} | {} | {} | {}",
            f.filter_id,
            f.name,
            truncate(&f.provider_data_utf16, 120),
            f.provider_data_hex.chars().take(64).collect::<String>()
        );
        shown += 1;
        if shown >= 15 {
            break;
        }
    }
    if shown == 0 {
        let _ = writeln!(
            o,
            "  (no filters carry providerData — that itself is diagnostic)"
        );
        let _ = writeln!(o, "\n[sample filters by name instead: filter_id | name]");
        for f in filters.iter().take(15) {
            let _ = writeln!(o, "  {} | {}", f.filter_id, f.name);
        }
    }

    // ---- filter -> rule map ----
    section!(o, "FILTER -> RULE MAP (current live enumeration)");
    let rule_map = filter_map::build_filter_rule_map(&filters, &rules);
    let mut via_pd = 0;
    let mut via_name = 0;
    for (_, via) in rule_map.values() {
        match via {
            MappedVia::ProviderData => via_pd += 1,
            MappedVia::DisplayName => via_name += 1,
        }
    }
    let _ = writeln!(
        o,
        "filters mapped to a rule: {} of {}",
        rule_map.len(),
        filters.len()
    );
    let _ = writeln!(o, "  via providerData token: {via_pd}");
    let _ = writeln!(o, "  via display name:       {via_name}");
    if rule_map.is_empty() {
        let _ = writeln!(
            o,
            ">>> ZERO filters mapped to rules — this is why every event is unattributed."
        );
    }

    // ---- events + per-event attribution test ----
    section!(o, "RECENT 5156/5157 EVENTS — attribution probe");
    let by_name_ci: HashMap<String, &str> = rules
        .iter()
        .map(|r| (r.name.to_lowercase(), r.name.as_str()))
        .collect();
    let by_display_ci: HashMap<String, &str> = rules
        .iter()
        .map(|r| (r.display_name.to_lowercase(), r.name.as_str()))
        .collect();
    let live_filter_ids: std::collections::HashSet<u64> =
        filters.iter().map(|f| f.filter_id).collect();
    let filter_by_id: HashMap<u64, &crate::model::FilterInfo> =
        filters.iter().map(|f| (f.filter_id, f)).collect();

    match event_query::recent_event_xml(25) {
        Ok(xmls) => {
            let _ = writeln!(o, "sampled {} recent events\n", xmls.len());
            for (i, xml) in xmls.iter().enumerate() {
                let ev = match event_query::parse_event_xml(xml) {
                    Some(e) => e,
                    None => continue,
                };
                let _ = writeln!(o, "--- event {i} (EventID {}) ---", ev.event_id);
                let _ = writeln!(o, "  FilterRTID:    {}", ev.filter_rtid);
                let _ = writeln!(o, "  FilterOrigin:  {:?}", ev.filter_origin);
                let _ = writeln!(o, "  Direction:     {}", ev.direction);
                let _ = writeln!(o, "  Application:   {}", ev.application);

                // hypothesis 1: FilterOrigin names a rule?
                if let Some(origin) = &ev.filter_origin {
                    let lo = origin.to_lowercase();
                    let by_name = by_name_ci.get(&lo).copied();
                    let by_disp = by_display_ci.get(&lo).copied();
                    let _ = writeln!(
                        o,
                        "  [H1] FilterOrigin matches rule by Name={:?} by DisplayName={:?}",
                        by_name, by_disp
                    );
                } else {
                    let _ = writeln!(o, "  [H1] no FilterOrigin field present");
                }

                // hypothesis 2: FilterRTID present in the live filter table?
                if live_filter_ids.contains(&ev.filter_rtid) {
                    let f = filter_by_id[&ev.filter_rtid];
                    let mapped = rule_map.get(&ev.filter_rtid);
                    let _ = writeln!(
                        o,
                        "  [H2] RTID found in live filters: name={:?} providerData(utf16)={:?}",
                        f.name,
                        truncate(&f.provider_data_utf16, 100)
                    );
                    let _ = writeln!(
                        o,
                        "       providerData(hex, first 96): {}",
                        f.provider_data_hex.chars().take(96).collect::<String>()
                    );
                    let toks = filter_map::candidate_tokens(&f.provider_data_utf16);
                    let _ = writeln!(
                        o,
                        "       candidate tokens from providerData: {:?}",
                        toks.iter().take(8).collect::<Vec<_>>()
                    );
                    let tok_hit = toks
                        .iter()
                        .any(|tk| by_name_ci.contains_key(&tk.to_lowercase()));
                    let name_hit = by_display_ci.contains_key(&f.name.to_lowercase());
                    let _ = writeln!(o, "       token matches a rule Name: {tok_hit} · filter name matches a rule DisplayName: {name_hit}");
                    let _ = writeln!(
                        o,
                        "       => current map result: {:?}",
                        mapped.map(|(id, via)| (id.as_str(), via.as_str()))
                    );
                } else {
                    let _ = writeln!(o, "  [H2] RTID NOT in live filter table (different boot session, or filter gone)");
                }
                let _ = writeln!(o);
            }
        }
        Err(e) => {
            let _ = writeln!(o, "recent_event_xml failed: {e:#}");
        }
    }

    // ---- raw event XML (2 samples, verbatim) ----
    section!(
        o,
        "RAW EVENT XML (2 verbatim samples — shows exact field names)"
    );
    match event_query::recent_event_xml(2) {
        Ok(xmls) => {
            for (i, xml) in xmls.iter().enumerate() {
                let _ = writeln!(o, "--- raw event {i} ---\n{}\n", xml);
            }
        }
        Err(e) => {
            let _ = writeln!(o, "failed: {e:#}");
        }
    }

    std::fs::write(out_path, o).with_context(|| format!("writing {}", out_path.display()))?;
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn os_version() -> String {
    crate::syspath::command(crate::syspath::system32_tool("cmd.exe"))
        .args(["/c", "ver"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
