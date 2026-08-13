//! Just enough HTTP/1.1 to be the thing behind Caddy.
//!
//! This is not a general web server and must not grow into one. It speaks to
//! one client — the reverse proxy on localhost — and its job is to refuse
//! anything surprising early and cheaply. Every limit below is a refusal
//! rather than an allocation.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;

/// Largest request line + headers we will read before giving up. A proxied
/// ping's headers are a few hundred bytes.
const MAX_HEAD: usize = 8 * 1024;

/// Largest body we will read. The payload is ~300 bytes; this is generous by
/// an order of magnitude and still bounded.
pub const MAX_BODY: usize = 8 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    /// Value of `X-Forwarded-For`, verbatim, if the proxy set one.
    pub forwarded_for: Option<String>,
}

#[derive(Debug)]
pub enum ReadError {
    /// Connection closed, timed out, or otherwise unusable.
    Io,
    /// Well-formed enough to answer, but we refuse it.
    TooLarge,
    Malformed,
}

/// Read one request. Returns `Err` rather than panicking on anything odd —
/// this is the internet-facing edge, even with a proxy in front.
///
/// Takes a `BufRead` rather than the socket so the limits below can actually
/// be tested against a hostile stream instead of asserted in a comment.
pub fn read_request(reader: &mut impl BufRead) -> Result<Request, ReadError> {
    let mut head = String::new();
    // The budget is applied *through* the reader, not checked after the
    // fact. `read_line` alone grows its String until it finds a newline, so
    // a client that sends megabytes without one would be answered with an
    // allocation rather than a refusal.
    let mut budget = MAX_HEAD;
    loop {
        let mut line = String::new();
        let n = reader
            .by_ref()
            .take(budget as u64)
            .read_line(&mut line)
            .map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Err(ReadError::Io);
        }
        budget -= n;
        head.push_str(&line);
        if line == "\r\n" || line == "\n" {
            break;
        }
        if budget == 0 {
            return Err(ReadError::TooLarge);
        }
    }

    let mut lines = head.lines();
    let request_line = lines.next().ok_or(ReadError::Malformed)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ReadError::Malformed)?.to_string();
    let path = parts.next().ok_or(ReadError::Malformed)?.to_string();

    let mut content_length = 0usize;
    let mut forwarded_for = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = value.parse().map_err(|_| ReadError::Malformed)?;
                if content_length > MAX_BODY {
                    return Err(ReadError::TooLarge);
                }
            }
            "x-forwarded-for" => forwarded_for = Some(value.to_string()),
            _ => {}
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|_| ReadError::Io)?;
    }

    Ok(Request {
        method,
        // strip any query string; nothing here takes parameters
        path: path.split('?').next().unwrap_or("/").to_string(),
        body,
        forwarded_for,
    })
}

/// Write a response and close. Bodies are short fixed strings — nothing a
/// caller sent is ever echoed back, so there is nothing here to inject into.
pub fn respond(mut stream: &TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Result<Request, ReadError> {
        read_request(&mut std::io::BufReader::new(raw))
    }

    #[test]
    fn a_proxied_ping_parses() {
        let r = parse(
            b"POST /v1/ping HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9, 203.0.113.4\r\n\
              Content-Length: 2\r\n\r\n{}",
        )
        .expect("should parse");
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/v1/ping");
        assert_eq!(r.body, b"{}");
        assert_eq!(r.forwarded_for.as_deref(), Some("9.9.9.9, 203.0.113.4"));
    }

    /// The bug this test exists for: `read_line` grows until it finds a
    /// newline, so a client that never sends one used to be answered with
    /// an allocation the size of whatever it felt like sending.
    #[test]
    fn a_header_line_with_no_newline_is_refused_not_buffered() {
        let mut raw = b"POST /v1/ping HTTP/1.1\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'A', MAX_BODY * 8));
        assert!(matches!(parse(&raw), Err(ReadError::TooLarge)));
    }

    #[test]
    fn too_many_headers_are_refused() {
        let mut raw = b"POST /v1/ping HTTP/1.1\r\n".to_vec();
        for i in 0..2000 {
            raw.extend(format!("X-Pad-{i}: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n").bytes());
        }
        raw.extend(b"\r\n");
        assert!(matches!(parse(&raw), Err(ReadError::TooLarge)));
    }

    #[test]
    fn an_oversize_body_is_refused_before_it_is_read() {
        let raw = format!(
            "POST /v1/ping HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(matches!(parse(raw.as_bytes()), Err(ReadError::TooLarge)));
    }

    #[test]
    fn a_negative_or_junk_content_length_is_malformed() {
        for cl in ["-1", "abc", "99999999999999999999"] {
            let raw = format!("POST /v1/ping HTTP/1.1\r\nContent-Length: {cl}\r\n\r\n");
            assert!(
                matches!(parse(raw.as_bytes()), Err(ReadError::Malformed)),
                "should have rejected Content-Length: {cl}"
            );
        }
    }

    /// A body shorter than the declared length must not yield a request with
    /// a half-filled buffer that then parses as something.
    #[test]
    fn a_truncated_body_is_an_error() {
        let raw = b"POST /v1/ping HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        assert!(matches!(parse(raw), Err(ReadError::Io)));
    }

    #[test]
    fn a_query_string_does_not_change_the_route() {
        let r = parse(b"GET /healthz?x=../../etc/passwd HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.path, "/healthz");
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let r = parse(
            b"POST /v1/ping HTTP/1.1\r\nCONTENT-LENGTH: 2\r\nx-forwarded-for: 1.2.3.4\r\n\r\nhi",
        )
        .unwrap();
        assert_eq!(r.body, b"hi");
        assert_eq!(r.forwarded_for.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn an_empty_stream_is_not_a_request() {
        assert!(matches!(parse(b""), Err(ReadError::Io)));
    }
}
