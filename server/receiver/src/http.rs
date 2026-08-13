//! Just enough HTTP/1.1 to be the thing behind Caddy.
//!
//! This is not a general web server and must not grow into one. It speaks to
//! one client — the reverse proxy on localhost — and its job is to refuse
//! anything surprising early and cheaply. Every limit below is a refusal
//! rather than an allocation.

use std::io::{BufRead, BufReader, Read, Write};
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
pub fn read_request(stream: &TcpStream) -> Result<Request, ReadError> {
    let mut reader = BufReader::new(stream);

    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Err(ReadError::Io);
        }
        head.push_str(&line);
        if head.len() > MAX_HEAD {
            return Err(ReadError::TooLarge);
        }
        if line == "\r\n" || line == "\n" {
            break;
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
