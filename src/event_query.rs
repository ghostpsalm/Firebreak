//! Pull 5156/5157 events from the Security channel via the modern EvtQuery
//! API, rendered as XML and parsed with quick-xml.
//!
//! The ingestion cursor is the channel's EventRecordID — monotonic and
//! gapless per channel — not a timestamp. XPath `EventRecordID > N` gives an
//! exact resume point: no `>=` re-read hack, no risk of dropping events that
//! land inside a same-millisecond window, and the cursor is an integer so
//! nothing user-influencable is spliced into the query.

#[cfg(not(windows))]
use anyhow::bail;
use anyhow::Result;

use crate::model::EventRecord;

/// XPath filter for 5156/5157, resuming strictly after `since_record_id`.
pub fn build_query(since_record_id: Option<u64>) -> String {
    match since_record_id {
        Some(id) => format!(
            "*[System[(EventID=5156 or EventID=5157) and EventRecordID > {}]]",
            id
        ),
        None => "*[System[(EventID=5156 or EventID=5157)]]".to_string(),
    }
}

#[cfg(windows)]
mod win {
    use anyhow::{Context, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtQueryChannelPath, EvtQueryForwardDirection,
        EvtQueryReverseDirection, EvtRenderEventXml, EVT_HANDLE,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// RAII wrapper so every open handle is closed on all paths.
    pub struct Handle(pub EVT_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }

    pub fn open_query(channel: &str, xpath: &str, forward: bool) -> Result<Handle> {
        open_query_flagged(channel, xpath, forward, EvtQueryChannelPath.0 as u32)
    }

    /// Open a query against a saved .evtx file rather than a live channel.
    pub fn open_query_file(path: &str, xpath: &str) -> Result<Handle> {
        use windows::Win32::System::EventLog::EvtQueryFilePath;
        open_query_flagged(path, xpath, true, EvtQueryFilePath.0 as u32)
    }

    fn open_query_flagged(source: &str, xpath: &str, forward: bool, source_flag: u32) -> Result<Handle> {
        let source = to_wide(source);
        let query = to_wide(xpath);
        let direction = if forward {
            EvtQueryForwardDirection.0 as u32
        } else {
            EvtQueryReverseDirection.0 as u32
        };
        unsafe {
            let h = EvtQuery(
                None,
                PCWSTR(source.as_ptr()),
                PCWSTR(query.as_ptr()),
                source_flag | direction,
            )
            .context("EvtQuery failed (needs elevation / Event Log Readers, or a readable .evtx)")?;
            Ok(Handle(h))
        }
    }

    /// Fetch the next batch of raw event handles. Ok(0) = end of results.
    pub fn next_batch(result_set: &Handle, handles: &mut [isize]) -> Result<u32> {
        let mut returned: u32 = 0;
        unsafe {
            match EvtNext(result_set.0, handles, 0, 0, &mut returned) {
                Ok(()) => Ok(returned),
                Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => {
                    Ok(0)
                }
                Err(e) => Err(e).context("EvtNext failed"),
            }
        }
    }

    /// Render one event handle to its XML string and close the handle.
    pub fn render_xml(raw: isize, buf: &mut Vec<u16>) -> Option<String> {
        unsafe {
            let h = Handle(EVT_HANDLE(raw));
            let mut used: u32 = 0;
            let mut props: u32 = 0;
            // first call sizes the buffer
            let _ = EvtRender(
                None,
                h.0,
                EvtRenderEventXml.0 as u32,
                0,
                None,
                &mut used,
                &mut props,
            );
            if used == 0 {
                return None;
            }
            buf.resize((used as usize + 1) / 2 + 1, 0);
            let cap_bytes = (buf.len() * 2) as u32;
            EvtRender(
                None,
                h.0,
                EvtRenderEventXml.0 as u32,
                cap_bytes,
                Some(buf.as_mut_ptr() as *mut _),
                &mut used,
                &mut props,
            )
            .ok()?;
            Some(String::from_utf16_lossy(
                &buf[..(used as usize / 2).saturating_sub(1)],
            ))
        }
    }
}

/// Number of matched records the query filter returned but that could not
/// be turned into an `EventRecord` — the XML failed to render, or lacked a
/// field the parser requires. Returned so the caller can surface it: the
/// ingestion checkpoint advances past these records, so a silent skip would
/// exclude them from every count with no coverage-gap signal.
pub type SkippedCount = u64;

#[cfg(windows)]
pub fn query_events(
    since_record_id: Option<u64>,
    on_event: impl FnMut(EventRecord),
) -> Result<SkippedCount> {
    let result_set = win::open_query("Security", &build_query(since_record_id), true)?;
    drain_query(&result_set, on_event)
}

#[cfg(not(windows))]
pub fn query_events(
    _since_record_id: Option<u64>,
    _on_event: impl FnMut(EventRecord),
) -> Result<SkippedCount> {
    bail!("event log query is only available on Windows")
}

/// Read all 5156/5157 events from a saved .evtx file (import path).
#[cfg(windows)]
pub fn query_events_from_file(
    path: &std::path::Path,
    on_event: impl FnMut(EventRecord),
) -> Result<SkippedCount> {
    let xpath = build_query(None);
    let result_set = win::open_query_file(&path.to_string_lossy(), &xpath)?;
    drain_query(&result_set, on_event)
}

#[cfg(not(windows))]
pub fn query_events_from_file(
    _path: &std::path::Path,
    _on_event: impl FnMut(EventRecord),
) -> Result<SkippedCount> {
    bail!("event log query is only available on Windows")
}

/// Pull every matched event from an open result set, delivering the parsed
/// ones to `on_event` and counting the ones that couldn't be parsed.
#[cfg(windows)]
fn drain_query(
    result_set: &win::Handle,
    mut on_event: impl FnMut(EventRecord),
) -> Result<SkippedCount> {
    let mut skipped: SkippedCount = 0;
    let mut render_buf: Vec<u16> = Vec::new();
    loop {
        let mut handles = [0isize; 64];
        let returned = win::next_batch(result_set, &mut handles)?;
        if returned == 0 {
            return Ok(skipped);
        }
        for &raw in handles.iter().take(returned as usize) {
            match win::render_xml(raw, &mut render_buf).as_deref().and_then(parse_event_xml) {
                Some(ev) => on_event(ev),
                // matched the 5156/5157 filter but unparseable — count it so
                // the caller can report it rather than lose it invisibly
                None => skipped += 1,
            }
        }
    }
}

/// Raw rendered XML of the most recent `limit` 5156/5157 events (newest
/// first) — for the --diagnose report, which needs the raw field names and
/// values, not the parsed subset.
#[cfg(windows)]
pub fn recent_event_xml(limit: usize) -> Result<Vec<String>> {
    let result_set = win::open_query("Security", &build_query(None), false)?;
    let mut out = Vec::new();
    let mut buf = Vec::new();
    'outer: loop {
        let mut handles = [0isize; 64];
        let returned = win::next_batch(&result_set, &mut handles)?;
        if returned == 0 {
            break;
        }
        for &raw in handles.iter().take(returned as usize) {
            if let Some(xml) = win::render_xml(raw, &mut buf) {
                out.push(xml);
                if out.len() >= limit {
                    break 'outer;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn recent_event_xml(_limit: usize) -> Result<Vec<String>> {
    bail!("event log query is only available on Windows")
}

/// First event XML matching `xpath`, from either end of the channel.
#[cfg(windows)]
fn first_xml(channel: &str, xpath: &str, forward: bool) -> Result<Option<String>> {
    let result_set = win::open_query(channel, xpath, forward)?;
    let mut handles = [0isize; 1];
    let returned = win::next_batch(&result_set, &mut handles)?;
    if returned == 0 {
        return Ok(None);
    }
    let mut buf = Vec::new();
    Ok(win::render_xml(handles[0], &mut buf))
}


/// Timestamp of the oldest surviving 5156/5157 event (used as the adopted
/// collection start when auditing predates this tool). None if no such
/// events exist.
#[cfg(windows)]
pub fn first_event_time() -> Result<Option<String>> {
    Ok(first_xml("Security", &build_query(None), true)?
        .and_then(|xml| parse_event_xml(&xml))
        .map(|ev| ev.time_created))
}

#[cfg(not(windows))]
pub fn first_event_time() -> Result<Option<String>> {
    bail!("event log query is only available on Windows")
}

/// Record ID of the oldest surviving event of ANY type in the channel —
/// for coverage-gap detection: if this is above our checkpoint, records
/// between were lost to log rollover (or the log was cleared).
#[cfg(windows)]
pub fn oldest_record_id() -> Result<Option<u64>> {
    Ok(first_xml("Security", "*", true)?.and_then(|xml| parse_record_id(&xml)))
}

#[cfg(not(windows))]
pub fn oldest_record_id() -> Result<Option<u64>> {
    bail!("event log query is only available on Windows")
}

/// Record ID of the newest event in the channel — the starting cursor when
/// auditing is first enabled (skip everything that predates enablement).
#[cfg(windows)]
pub fn newest_record_id() -> Result<Option<u64>> {
    Ok(first_xml("Security", "*", false)?.and_then(|xml| parse_record_id(&xml)))
}

#[cfg(not(windows))]
pub fn newest_record_id() -> Result<Option<u64>> {
    bail!("event log query is only available on Windows")
}

/// Direction tokens in 5156/5157 EventData. VERIFY on a real box: expected
/// %%14592 = Inbound, %%14593 = Outbound.
fn decode_direction(raw: &str) -> String {
    match raw {
        "%%14592" => "Inbound".to_string(),
        "%%14593" => "Outbound".to_string(),
        other => other.to_string(),
    }
}

/// Extract just the EventRecordID from any rendered event XML.
pub fn parse_record_id(xml: &str) -> Option<u64> {
    let start = xml.find("<EventRecordID>")? + "<EventRecordID>".len();
    let end = xml[start..].find("</EventRecordID>")? + start;
    xml[start..end].trim().parse().ok()
}

/// Parse one rendered event XML into an EventRecord. Returns None for
/// events that don't carry the fields we need.
pub fn parse_event_xml(xml: &str) -> Option<EventRecord> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut event_id: u32 = 0;
    let mut record_id: u64 = 0;
    let mut time_created = String::new();
    let mut current_data_name: Option<String> = None;
    let mut in_event_id = false;
    let mut in_record_id = false;

    let mut filter_rtid: Option<u64> = None;
    let mut application = String::new();
    let mut direction = String::new();
    let mut filter_origin: Option<String> = None;
    let mut protocol: u32 = 0;
    let mut dest_address = String::new();
    let mut dest_port = String::new();
    let mut source_address = String::new();
    let mut source_port = String::new();
    let mut interface_index: u32 = 0;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match tag {
                    "EventID" => in_event_id = true,
                    "EventRecordID" => in_record_id = true,
                    "TimeCreated" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"SystemTime" {
                                time_created =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Data" => {
                        current_data_name = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                current_data_name =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                let text = t.unescape().unwrap_or_default().to_string();
                if in_event_id {
                    event_id = text.parse().unwrap_or(0);
                } else if in_record_id {
                    record_id = text.parse().unwrap_or(0);
                } else if let Some(name) = &current_data_name {
                    match name.as_str() {
                        "FilterRTID" => filter_rtid = text.parse().ok(),
                        "Application" => application = text,
                        "Direction" => direction = decode_direction(&text),
                        // field name varies across builds; accept both
                        "FilterOrigin" | "RuleName" => {
                            if !text.trim().is_empty() && text != "-" {
                                filter_origin = Some(text);
                            }
                        }
                        "Protocol" => protocol = text.parse().unwrap_or(0),
                        "DestAddress" => dest_address = text,
                        "DestPort" => dest_port = text,
                        "SourceAddress" => source_address = text,
                        "SourcePort" => source_port = text,
                        "InterfaceIndex" => interface_index = text.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match tag {
                    "EventID" => in_event_id = false,
                    "EventRecordID" => in_record_id = false,
                    "Data" => current_data_name = None,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    let filter_rtid = filter_rtid?;
    if event_id != 5156 && event_id != 5157 {
        return None;
    }
    Some(EventRecord {
        event_id,
        record_id,
        time_created,
        filter_rtid,
        application,
        direction,
        filter_origin,
        protocol,
        dest_address,
        dest_port,
        source_address,
        source_port,
        interface_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
<EventID>5156</EventID><Version>1</Version><Level>0</Level><Task>12810</Task><Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-07-15T10:11:12.123456700Z'/>
<EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='88'/>
<Channel>Security</Channel><Computer>HOST</Computer><Security/></System>
<EventData><Data Name='ProcessID'>1234</Data>
<Data Name='Application'>\device\harddiskvolume3\windows\system32\svchost.exe</Data>
<Data Name='Direction'>%%14593</Data>
<Data Name='SourceAddress'>192.168.1.10</Data><Data Name='SourcePort'>53211</Data>
<Data Name='DestAddress'>142.250.66.46</Data><Data Name='DestPort'>443</Data>
<Data Name='Protocol'>6</Data>
<Data Name='FilterRTID'>67321</Data>
<Data Name='LayerName'>%%14611</Data><Data Name='LayerRTID'>48</Data>
<Data Name='RemoteUserID'>S-1-0-0</Data><Data Name='RemoteMachineID'>S-1-0-0</Data></EventData></Event>"#;

    #[test]
    fn parses_5156_fields() {
        let ev = parse_event_xml(SAMPLE).expect("should parse");
        assert_eq!(ev.event_id, 5156);
        assert_eq!(ev.record_id, 12345);
        assert_eq!(ev.filter_rtid, 67321);
        assert_eq!(ev.direction, "Outbound");
        assert_eq!(ev.protocol, 6);
        assert_eq!(ev.dest_port, "443");
        assert!(ev.application.ends_with("svchost.exe"));
        assert!(ev.is_allow());
    }

    #[test]
    fn parses_filter_origin_when_present() {
        // sample has no FilterOrigin field
        assert_eq!(parse_event_xml(SAMPLE).unwrap().filter_origin, None);
        let with_origin = SAMPLE.replace(
            "<Data Name='FilterRTID'>67321</Data>",
            "<Data Name='FilterRTID'>67321</Data><Data Name='FilterOrigin'>{aaaa-bbbb}</Data>",
        );
        assert_eq!(
            parse_event_xml(&with_origin).unwrap().filter_origin.as_deref(),
            Some("{aaaa-bbbb}")
        );
        let dash = SAMPLE.replace(
            "<Data Name='FilterRTID'>67321</Data>",
            "<Data Name='FilterRTID'>67321</Data><Data Name='FilterOrigin'>-</Data>",
        );
        assert_eq!(parse_event_xml(&dash).unwrap().filter_origin, None);
    }

    #[test]
    fn extracts_record_id_from_any_event_xml() {
        assert_eq!(parse_record_id(SAMPLE), Some(12345));
        assert_eq!(parse_record_id("<Event><System></System></Event>"), None);
    }

    #[test]
    fn query_uses_strictly_greater_integer_cursor() {
        assert_eq!(
            build_query(Some(42)),
            "*[System[(EventID=5156 or EventID=5157) and EventRecordID > 42]]"
        );
        assert!(!build_query(None).contains("EventRecordID"));
    }
}
