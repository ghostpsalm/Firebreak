//! Minimal HTTPS GET over WinHTTP — no subprocess, no TLS crate (Windows
//! provides the TLS stack). Used by the self-update check/download so those
//! paths work under application-control ringfencing.

#[cfg(windows)]
use anyhow::{anyhow, bail, Result};

/// HTTPS GET. Follows redirects (WinHTTP default for https→https, which is
/// what GitHub's releases/latest/download uses). `extra_headers` are CRLF-
/// separated (no trailing CRLF), e.g. "Accept: application/vnd.github+json".
#[cfg(windows)]
pub fn get(url: &str, extra_headers: &str) -> Result<Vec<u8>> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
    };

    let (host, path) = split_url(url)?;

    // RAII guard so every HINTERNET closes on any early return
    struct H(*mut core::ffi::c_void);
    impl Drop for H {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = WinHttpCloseHandle(self.0);
                }
            }
        }
    }

    unsafe {
        let session = WinHttpOpen(
            &HSTRING::from("firebreak"),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() {
            bail!("WinHttpOpen failed: {}", windows::core::Error::from_win32());
        }
        let _session = H(session);

        let connect = WinHttpConnect(session, &HSTRING::from(host.as_str()), 443, 0);
        if connect.is_null() {
            bail!(
                "WinHttpConnect failed: {}",
                windows::core::Error::from_win32()
            );
        }
        let _connect = H(connect);

        let request = WinHttpOpenRequest(
            connect,
            &HSTRING::from("GET"),
            &HSTRING::from(path.as_str()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null_mut(),
            WINHTTP_FLAG_SECURE,
        );
        if request.is_null() {
            bail!(
                "WinHttpOpenRequest failed: {}",
                windows::core::Error::from_win32()
            );
        }
        let _request = H(request);

        let headers: Vec<u16> = extra_headers.encode_utf16().collect();
        let headers_opt: Option<&[u16]> = if headers.is_empty() {
            None
        } else {
            Some(&headers)
        };
        WinHttpSendRequest(request, headers_opt, None, 0, 0, 0).map_err(|_| {
            anyhow!(
                "WinHttpSendRequest failed: {}",
                windows::core::Error::from_win32()
            )
        })?;

        WinHttpReceiveResponse(request, std::ptr::null_mut()).map_err(|_| {
            anyhow!(
                "WinHttpReceiveResponse failed: {}",
                windows::core::Error::from_win32()
            )
        })?;

        let mut body = Vec::new();
        loop {
            let mut avail = 0u32;
            WinHttpQueryDataAvailable(request, &mut avail).map_err(|_| {
                anyhow!(
                    "WinHttpQueryDataAvailable failed: {}",
                    windows::core::Error::from_win32()
                )
            })?;
            if avail == 0 {
                break;
            }
            let mut chunk = vec![0u8; avail as usize];
            let mut read = 0u32;
            WinHttpReadData(request, chunk.as_mut_ptr() as *mut _, avail, &mut read).map_err(
                |_| {
                    anyhow!(
                        "WinHttpReadData failed: {}",
                        windows::core::Error::from_win32()
                    )
                },
            )?;
            chunk.truncate(read as usize);
            body.extend_from_slice(&chunk);
            if read == 0 {
                break;
            }
        }
        Ok(body)
    }
}

/// "https://host/a/b?c" → ("host", "/a/b?c"). Https only.
#[cfg(windows)]
fn split_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https URLs are supported: {url}"))?;
    match rest.split_once('/') {
        Some((host, path)) => Ok((host.to_string(), format!("/{path}"))),
        None => Ok((rest.to_string(), "/".to_string())),
    }
}
