//! Enumerate live WFP filters (FwpmFilterEnum0) and map filter run-time IDs
//! back to Windows Firewall rules.
//!
//! For filters created by the Windows Firewall service (MPSSVC), the
//! filter's display name matches the rule's DisplayName, and the
//! providerData blob is expected to carry the rule's identity. Exactly what
//! providerData contains needs verification on a real box (--dump-filters
//! exists for that); matching therefore tries, in order:
//!   1. providerData UTF-16 text containing a rule Name (InstanceID)
//!   2. filter display name == rule DisplayName (ambiguous if duplicated)

use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::model::{FilterInfo, RuleInfo};

#[cfg(windows)]
pub fn enumerate_filters() -> Result<Vec<FilterInfo>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0,
        FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FWPM_FILTER0,
    };

    const RPC_C_AUTHN_WINNT: u32 = 10;

    unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> String {
        if p.is_null() {
            String::new()
        } else {
            p.to_string().unwrap_or_default()
        }
    }

    unsafe {
        let mut engine = HANDLE::default();
        let err = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if err != 0 {
            bail!("FwpmEngineOpen0 failed with error {err} (needs elevation)");
        }

        let result = (|| -> Result<Vec<FilterInfo>> {
            let mut enum_handle = HANDLE::default();
            let err = FwpmFilterCreateEnumHandle0(engine, None, &mut enum_handle);
            if err != 0 {
                bail!("FwpmFilterCreateEnumHandle0 failed with error {err}");
            }

            let mut out = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let err = FwpmFilterEnum0(engine, enum_handle, 512, &mut entries, &mut returned);
                if err != 0 {
                    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
                    bail!("FwpmFilterEnum0 failed with error {err}");
                }
                if returned == 0 {
                    if !entries.is_null() {
                        FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
                    }
                    break;
                }
                for i in 0..returned as usize {
                    let f = &**entries.add(i);
                    // providerData is absent (null/0) on most built-in filters;
                    // from_raw_parts requires non-null even for empty slices
                    let provider_data: &[u8] =
                        if f.providerData.data.is_null() || f.providerData.size == 0 {
                            &[]
                        } else {
                            std::slice::from_raw_parts(
                                f.providerData.data,
                                f.providerData.size as usize,
                            )
                        };
                    let (pd_utf16, pd_hex) = decode_provider_data(provider_data);
                    out.push(FilterInfo {
                        filter_id: f.filterId,
                        name: pwstr_to_string(f.displayData.name),
                        description: pwstr_to_string(f.displayData.description),
                        provider_data_utf16: pd_utf16,
                        provider_data_hex: pd_hex,
                        provider_context_key: format!("{:?}", f.Anonymous.providerContextKey),
                        layer_key: format!("{:?}", f.layerKey),
                    });
                }
                FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            Ok(out)
        })();

        let _ = FwpmEngineClose0(engine);
        result
    }
}

#[cfg(not(windows))]
pub fn enumerate_filters() -> Result<Vec<FilterInfo>> {
    bail!("WFP filter enumeration is only available on Windows")
}

/// Decode a providerData blob as UTF-16LE text (lossy, control chars
/// stripped) plus a hex dump capped for storage.
fn decode_provider_data(data: &[u8]) -> (String, String) {
    let utf16: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text: String = String::from_utf16_lossy(&utf16)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let hex: String = data.iter().take(256).map(|b| format!("{b:02x}")).collect();
    (text, hex)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedVia {
    ProviderData,
    DisplayName,
}

impl MappedVia {
    pub fn as_str(&self) -> &'static str {
        match self {
            MappedVia::ProviderData => "provider_data",
            MappedVia::DisplayName => "display_name",
        }
    }
}

/// Minimum length for a non-braced token to count as a rule-name match:
/// prevents a rule with a short generic Name from matching stray text.
const MIN_TOKEN_LEN: usize = 4;

/// Candidate rule-identity tokens from a providerData text: brace-delimited
/// spans ({GUID}-style InstanceIDs, any length) and maximal runs of
/// identifier-ish characters (CoreNet-DNS-Out-UDP-style IDs, length-gated).
/// Anchored token equality instead of substring `contains` — a rule named
/// "e" must not swallow every filter — and it turns the O(filters × rules)
/// scan into O(filters × tokens) hash lookups.
pub fn candidate_tokens(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    // brace-delimited spans
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        if let Some(close) = rest[open..].find('}') {
            out.push(&rest[open..open + close + 1]);
            rest = &rest[open + close + 1..];
        } else {
            break;
        }
    }
    // identifier runs
    let is_ident = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (is_ident(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_TOKEN_LEN {
                    out.push(&text[s..i]);
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if text.len() - s >= MIN_TOKEN_LEN {
            out.push(&text[s..]);
        }
    }
    out
}

/// Build filter_id -> (rule Name, how it was matched). Rules whose
/// DisplayName is shared by several rules only match via providerData.
pub fn build_filter_rule_map(
    filters: &[FilterInfo],
    rules: &[RuleInfo],
) -> HashMap<u64, (String, MappedVia)> {
    // exact rule Name (InstanceID) lookup for providerData tokens —
    // case-insensitive: GUID hex case differs between WFP blobs and
    // Get-NetFirewallRule output
    let by_name: HashMap<String, &str> = rules
        .iter()
        .map(|r| (r.name.to_lowercase(), r.name.as_str()))
        .collect();
    // display name -> rule name, only when unambiguous (case-insensitive)
    let mut by_display: HashMap<String, Option<&str>> = HashMap::new();
    for r in rules {
        by_display
            .entry(r.display_name.to_lowercase())
            .and_modify(|v| *v = None) // duplicate display name: ambiguous
            .or_insert(Some(r.name.as_str()));
    }

    let mut map = HashMap::new();
    for f in filters {
        // 1. providerData token equal to a rule Name (InstanceID)
        let mut matched: Option<(String, MappedVia)> = None;
        if !f.provider_data_utf16.is_empty() {
            for token in candidate_tokens(&f.provider_data_utf16) {
                if let Some(name) = by_name.get(&token.to_lowercase()) {
                    matched = Some((name.to_string(), MappedVia::ProviderData));
                    break;
                }
            }
        }
        // 2. unambiguous display-name match
        if matched.is_none() && !f.name.is_empty() {
            if let Some(Some(rule_name)) = by_display.get(&f.name.to_lowercase()) {
                matched = Some((rule_name.to_string(), MappedVia::DisplayName));
            }
        }
        if let Some(m) = matched {
            map.insert(f.filter_id, m);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(id: u64, name: &str, provider_data: &str) -> FilterInfo {
        FilterInfo {
            filter_id: id,
            name: name.into(),
            description: String::new(),
            provider_data_utf16: provider_data.into(),
            provider_data_hex: String::new(),
            provider_context_key: String::new(),
            layer_key: String::new(),
        }
    }

    fn rule(name: &str, display: &str) -> RuleInfo {
        RuleInfo {
            name: name.into(),
            display_name: display.into(),
            description: None,
            enabled: "True".into(),
            direction: "Inbound".into(),
            action: "Allow".into(),
            profile: "Any".into(),
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
    fn tokens_extract_braced_guids_and_identifier_runs() {
        let toks = candidate_tokens("v2.31|{a1b2c3d4-0000-1111-2222-333344445555}|CoreNet-DNS-Out");
        assert!(toks.contains(&"{a1b2c3d4-0000-1111-2222-333344445555}"));
        assert!(toks.contains(&"CoreNet-DNS-Out"));
    }

    #[test]
    fn tokens_drop_short_runs() {
        // identifier runs below MIN_TOKEN_LEN must not become candidates
        let toks = candidate_tokens("ab cd efg something-longer");
        assert!(!toks.contains(&"ab"));
        assert!(!toks.contains(&"efg"));
        assert!(toks.contains(&"something-longer"));
    }

    #[test]
    fn provider_data_matches_by_exact_token() {
        let rules = vec![
            rule("CoreNet-DNS-Out", "DNS out"),
            rule("{guid-1}", "Other"),
        ];
        let filters = vec![filter(10, "irrelevant", "x|CoreNet-DNS-Out|y")];
        let map = build_filter_rule_map(&filters, &rules);
        assert_eq!(map[&10].0, "CoreNet-DNS-Out");
        assert_eq!(map[&10].1, MappedVia::ProviderData);
    }

    #[test]
    fn short_rule_name_cannot_swallow_filters() {
        // regression for C-04: a rule named "e" used to substring-match everything
        let rules = vec![rule("e", "Tiny rule")];
        let filters = vec![filter(11, "some filter", "unrelated provider data text")];
        let map = build_filter_rule_map(&filters, &rules);
        assert!(!map.contains_key(&11));
    }

    #[test]
    fn display_name_fallback_only_when_unambiguous() {
        let rules = vec![
            rule("{id-1}", "Shared Name"),
            rule("{id-2}", "Shared Name"),
            rule("{id-3}", "Unique Name"),
        ];
        let filters = vec![filter(20, "Shared Name", ""), filter(21, "Unique Name", "")];
        let map = build_filter_rule_map(&filters, &rules);
        assert!(
            !map.contains_key(&20),
            "ambiguous display name must not match"
        );
        assert_eq!(map[&21].0, "{id-3}");
        assert_eq!(map[&21].1, MappedVia::DisplayName);
    }
}
