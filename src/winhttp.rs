//! Minimal HTTPS over WinHTTP — no subprocess, no TLS crate (Windows
//! provides the TLS stack). Used by the self-update check/download and by
//! the usage ping, so those paths work under application-control
//! ringfencing.

#[cfg(windows)]
use anyhow::{anyhow, bail, Result};

/// Timeouts for a download: generous, because a release asset over a slow
/// link is a legitimate several-minute transfer.
#[cfg(windows)]
pub const DOWNLOAD_TIMEOUTS: Timeouts = Timeouts {
    resolve_ms: 10_000,
    connect_ms: 20_000,
    send_ms: 30_000,
    receive_ms: 60_000,
};

/// Timeouts for the usage ping. Short on purpose: the ping is best-effort
/// and must never be the reason a run takes longer to finish.
#[cfg(windows)]
pub const PING_TIMEOUTS: Timeouts = Timeouts {
    resolve_ms: 3_000,
    connect_ms: 4_000,
    send_ms: 4_000,
    receive_ms: 4_000,
};

#[cfg(windows)]
#[derive(Clone, Copy)]
pub struct Timeouts {
    pub resolve_ms: u32,
    pub connect_ms: u32,
    pub send_ms: u32,
    pub receive_ms: u32,
}

/// HTTPS GET. Follows redirects (WinHTTP default for https→https, which is
/// what GitHub's releases/latest/download uses). `extra_headers` are CRLF-
/// separated (no trailing CRLF), e.g. "Accept: application/vnd.github+json".
#[cfg(windows)]
pub fn get(url: &str, extra_headers: &str) -> Result<Vec<u8>> {
    get_with_progress(url, extra_headers, &|_, _| {})
}

/// As [`get`], calling `progress(received, total)` after each chunk. `total`
/// is the `Content-Length` header when the server sends one — absent on a
/// chunked response, where the caller shows bytes rather than a percentage.
#[cfg(windows)]
pub fn get_with_progress(
    url: &str,
    extra_headers: &str,
    progress: &dyn Fn(u64, Option<u64>),
) -> Result<Vec<u8>> {
    let (status, body) = send(
        Request {
            method: "GET",
            url,
            headers: extra_headers,
            body: None,
            timeouts: DOWNLOAD_TIMEOUTS,
        },
        progress,
    )?;
    check_status(status)?;
    Ok(body)
}

/// HTTPS POST of a JSON body. Returns the response status so a caller can
/// tell "the server said no" from "the network is down"; the body is
/// discarded, since nothing that posts here reads a reply.
#[cfg(windows)]
pub fn post_json(url: &str, body: &[u8]) -> Result<u32> {
    let (status, _) = send(
        Request {
            method: "POST",
            url,
            headers: "Content-Type: application/json",
            body: Some(body),
            timeouts: PING_TIMEOUTS,
        },
        &|_, _| {},
    )?;
    Ok(status)
}

#[cfg(windows)]
struct Request<'a> {
    method: &'a str,
    url: &'a str,
    /// CRLF-separated, no trailing CRLF. Empty for none.
    headers: &'a str,
    body: Option<&'a [u8]>,
    timeouts: Timeouts,
}

/// The one place that talks to WinHTTP. GET and POST differ only in the verb,
/// the optional body and the timeouts, so they share this rather than keeping
/// two copies of the handle lifecycle in a path that runs elevated.
#[cfg(windows)]
fn send(req: Request, progress: &dyn Fn(u64, Option<u64>)) -> Result<(u32, Vec<u8>)> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
        WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
    };

    let (host, path) = split_url(req.url)?;

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

        // Best effort: a host that refuses to set timeouts still works, it
        // just falls back to WinHTTP's much longer defaults.
        let _ = WinHttpSetTimeouts(
            session,
            req.timeouts.resolve_ms as i32,
            req.timeouts.connect_ms as i32,
            req.timeouts.send_ms as i32,
            req.timeouts.receive_ms as i32,
        );

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
            &HSTRING::from(req.method),
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

        let headers: Vec<u16> = req.headers.encode_utf16().collect();
        let headers_opt: Option<&[u16]> = if headers.is_empty() {
            None
        } else {
            Some(&headers)
        };
        let (optional, len) = match req.body {
            Some(b) if !b.is_empty() => (Some(b.as_ptr() as *const core::ffi::c_void), b.len()),
            _ => (None, 0),
        };
        WinHttpSendRequest(request, headers_opt, optional, len as u32, len as u32, 0).map_err(
            |_| {
                anyhow!(
                    "WinHttpSendRequest failed: {}",
                    windows::core::Error::from_win32()
                )
            },
        )?;

        WinHttpReceiveResponse(request, std::ptr::null_mut()).map_err(|_| {
            anyhow!(
                "WinHttpReceiveResponse failed: {}",
                windows::core::Error::from_win32()
            )
        })?;

        let status = status_code(request);
        let total = content_length(request);
        progress(0, total);

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
            progress(body.len() as u64, total);
            if read == 0 {
                break;
            }
        }
        Ok((status, body))
    }
}

/// Turn an HTTP error status into an error. Without this a 404 reaches the
/// caller as an unexplained JSON parse failure.
#[cfg(windows)]
fn check_status(status: u32) -> Result<()> {
    // 0 means the status could not be read; the body is the better signal
    // then, so don't manufacture a failure from a missing header.
    if status >= 400 {
        bail!("server returned HTTP {status}");
    }
    Ok(())
}

/// The response's status line code, or 0 if it could not be read.
#[cfg(windows)]
unsafe fn status_code(request: *mut core::ffi::c_void) -> u32 {
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinHttp::{
        WinHttpQueryHeaders, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    };

    let mut code: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as u32;
    match WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        PCWSTR::null(),
        Some(&mut code as *mut u32 as *mut _),
        &mut len,
        std::ptr::null_mut(),
    ) {
        Ok(()) => code,
        Err(_) => 0,
    }
}

/// The response's `Content-Length`, if it declared one. Best effort: a
/// missing or unparseable header costs the progress bar its end, nothing
/// more, so every failure path here returns `None` rather than erroring.
#[cfg(windows)]
unsafe fn content_length(request: *mut core::ffi::c_void) -> Option<u64> {
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinHttp::{WinHttpQueryHeaders, WINHTTP_QUERY_CONTENT_LENGTH};

    let mut buf = [0u16; 32];
    let mut len = (buf.len() * 2) as u32;
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_CONTENT_LENGTH,
        PCWSTR::null(),
        Some(buf.as_mut_ptr() as *mut _),
        &mut len,
        std::ptr::null_mut(),
    )
    .ok()?;
    let chars = (len as usize / 2).min(buf.len());
    String::from_utf16_lossy(&buf[..chars]).trim().parse().ok()
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
