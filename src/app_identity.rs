//! Turn raw event application paths (\device\harddiskvolumeN\...) into
//! drive-letter paths and friendly product names from PE version info.

use std::collections::HashMap;

/// Map of "\device\harddiskvolume3" (lowercase) -> "C:".
#[cfg(windows)]
pub fn device_path_map() -> HashMap<String, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let mut map = HashMap::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target = [0u16; 512];
        unsafe {
            let len = QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut target));
            if len > 0 {
                // buffer is a MULTI_SZ; first string is the device path
                let first_len = target.iter().position(|&c| c == 0).unwrap_or(0);
                let device = String::from_utf16_lossy(&target[..first_len]);
                map.insert(device.to_lowercase(), drive);
            }
        }
    }
    map
}

#[cfg(not(windows))]
pub fn device_path_map() -> HashMap<String, String> {
    HashMap::new()
}

/// \device\harddiskvolume3\windows\system32\svchost.exe ->
/// C:\windows\system32\svchost.exe. "System" (kernel traffic) and
/// unresolvable device paths pass through unchanged.
pub fn normalize_path(raw: &str, device_map: &HashMap<String, String>) -> String {
    let lower = raw.to_lowercase();
    for (device, drive) in device_map {
        if lower.starts_with(device.as_str()) {
            return format!("{}{}", drive, &raw[device.len()..]);
        }
    }
    raw.to_string()
}

/// Friendly name from PE version info: FileDescription, else ProductName,
/// else the file name itself. Company is returned alongside when present.
#[derive(Debug, Clone, Default)]
pub struct AppIdentity {
    pub friendly_name: String,
    pub company: String,
}

#[cfg(windows)]
pub fn identify(path: &str) -> AppIdentity {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    fn fallback(path: &str) -> AppIdentity {
        AppIdentity {
            friendly_name: path.rsplit(['\\', '/']).next().unwrap_or(path).to_string(),
            company: String::new(),
        }
    }

    unsafe fn query_string(block: &[u8], sub: &str) -> Option<String> {
        let wide: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        if VerQueryValueW(
            block.as_ptr() as *const _,
            PCWSTR(wide.as_ptr()),
            &mut ptr,
            &mut len,
        )
        .as_bool()
            && !ptr.is_null()
            && len > 0
        {
            let slice = std::slice::from_raw_parts(ptr as *const u16, len as usize);
            let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            let s = String::from_utf16_lossy(&slice[..end]);
            if !s.trim().is_empty() {
                return Some(s.trim().to_string());
            }
        }
        None
    }

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None);
        if size == 0 {
            return fallback(path);
        }
        let mut block = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(wide.as_ptr()), 0, size, block.as_mut_ptr() as *mut _)
            .is_err()
        {
            return fallback(path);
        }

        // find the first language/codepage pair in \VarFileInfo\Translation
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        let trans_key: Vec<u16> = "\\VarFileInfo\\Translation"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut lang_cp = String::from("040904B0"); // en-US/unicode default
        if VerQueryValueW(
            block.as_ptr() as *const _,
            PCWSTR(trans_key.as_ptr()),
            &mut ptr,
            &mut len,
        )
        .as_bool()
            && !ptr.is_null()
            && len >= 4
        {
            let pair = std::slice::from_raw_parts(ptr as *const u16, 2);
            lang_cp = format!("{:04X}{:04X}", pair[0], pair[1]);
        }

        let desc = query_string(
            &block,
            &format!("\\StringFileInfo\\{lang_cp}\\FileDescription"),
        );
        let product = query_string(&block, &format!("\\StringFileInfo\\{lang_cp}\\ProductName"));
        let company = query_string(&block, &format!("\\StringFileInfo\\{lang_cp}\\CompanyName"));

        match desc.or(product) {
            Some(name) => AppIdentity {
                friendly_name: name,
                company: company.unwrap_or_default(),
            },
            None => fallback(path),
        }
    }
}

#[cfg(not(windows))]
pub fn identify(path: &str) -> AppIdentity {
    AppIdentity {
        friendly_name: path.rsplit(['\\', '/']).next().unwrap_or(path).to_string(),
        company: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> HashMap<String, String> {
        HashMap::from([(r"\device\harddiskvolume3".to_string(), "C:".to_string())])
    }

    #[test]
    fn normalizes_known_device_prefix() {
        assert_eq!(
            normalize_path(
                r"\device\harddiskvolume3\Windows\System32\svchost.exe",
                &map()
            ),
            r"C:\Windows\System32\svchost.exe"
        );
    }

    #[test]
    fn device_prefix_match_is_case_insensitive() {
        assert_eq!(
            normalize_path(r"\Device\HarddiskVolume3\app.exe", &map()),
            r"C:\app.exe"
        );
    }

    #[test]
    fn unknown_paths_pass_through() {
        assert_eq!(normalize_path("System", &map()), "System");
        assert_eq!(
            normalize_path(r"\device\harddiskvolume9\x.exe", &map()),
            r"\device\harddiskvolume9\x.exe"
        );
    }
}
