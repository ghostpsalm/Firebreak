//! Firebreak's telemetry collector.
//!
//! Sits on localhost behind Caddy, which terminates TLS and hands over the
//! peer address. Accepts exactly one thing — `POST /v1/ping` carrying the
//! payload `firebreak`'s `src/telemetry.rs` builds — validates it hard,
//! coarsens the address, and writes a row.
//!
//! Operational shape, all deliberate:
//!
//! * **Binds to loopback by default.** The only thing that should be able to
//!   reach it is the proxy on the same host.
//! * **Bounded everywhere.** Connection count, header size, body size,
//!   socket timeouts and a per-network request rate all have ceilings, so a
//!   bad day costs a refusal rather than the box.
//! * **Logs prefixes, never addresses.** Truncation happens before anything
//!   is written down, including to the journal — otherwise the retention
//!   policy on the database would be undone by the log next to it.

mod db;
mod http;
mod ping;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Simultaneous connections. Past this, new ones are refused immediately
/// rather than queued into memory.
const MAX_CONNECTIONS: usize = 64;

/// How long a single client may take over its request.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let bind: String = env_or("FB_BIND", "127.0.0.1:8787".to_string());
    let db_path: String = env_or(
        "FB_DB",
        "/var/lib/firebreak-receiver/telemetry.db".to_string(),
    );
    let retention_days: u32 = env_or("FB_RETENTION_DAYS", 400);
    let rate_per_hour: u32 = env_or("FB_RATE_PER_HOUR", 240);

    let db = match db::Db::open(&db_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("fatal: cannot open {db_path}: {e}");
            std::process::exit(1);
        }
    };
    match db.prune(retention_days) {
        Ok(n) if n > 0 => println!("startup: pruned {n} rows past {retention_days} days"),
        Ok(_) => {}
        Err(e) => eprintln!("warning: retention sweep failed: {e}"),
    }

    // Retention is a promise, so it runs on a timer rather than only at
    // startup — a process that stays up for a year would otherwise never
    // enforce it again.
    {
        let db = Arc::clone(&db);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(24 * 60 * 60));
            match db.prune(retention_days) {
                Ok(n) if n > 0 => println!("retention: pruned {n} rows"),
                Ok(_) => {}
                Err(e) => eprintln!("warning: retention sweep failed: {e}"),
            }
        });
    }

    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fatal: cannot bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    println!("firebreak-receiver listening on {bind}, db {db_path}, retention {retention_days}d");

    let limiter = Arc::new(Mutex::new(RateLimiter::new(rate_per_hour)));
    let live = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        if live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            http::respond(&stream, 503, "busy\n");
            continue;
        }
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

        let db = Arc::clone(&db);
        let limiter = Arc::clone(&limiter);
        let live = Arc::clone(&live);
        live.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            handle(&stream, &db, &limiter);
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn handle(stream: &TcpStream, db: &db::Db, limiter: &Mutex<RateLimiter>) {
    let mut reader = std::io::BufReader::new(stream);
    let req = match http::read_request(&mut reader) {
        Ok(r) => r,
        Err(http::ReadError::TooLarge) => return http::respond(stream, 413, "too large\n"),
        Err(http::ReadError::Malformed) => return http::respond(stream, 400, "malformed\n"),
        Err(http::ReadError::Io) => return,
    };

    // Cheap liveness for the proxy and for monitoring. Says nothing about
    // the data.
    if req.path == "/healthz" {
        return http::respond(stream, 200, "ok\n");
    }
    if req.path != "/v1/ping" {
        return http::respond(stream, 404, "not found\n");
    }
    if req.method != "POST" {
        return http::respond(stream, 405, "post only\n");
    }

    let peer = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let ip = ping::client_ip(req.forwarded_for.as_deref(), peer);
    // From here on only the prefix exists. Nothing below may see `ip`.
    let prefix = ping::truncate(ip);

    if !limiter.lock().expect("limiter mutex").allow(&prefix) {
        return http::respond(stream, 429, "slow down\n");
    }

    let payload: ping::Payload = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(e) => {
            println!("reject {prefix}: unparseable ({e})");
            return http::respond(stream, 400, "bad json\n");
        }
    };
    if let Err(e) = payload.validate() {
        println!("reject {prefix}: {e}");
        return http::respond(stream, 400, "bad payload\n");
    }

    match db.record(&payload, &prefix) {
        Ok(db::Recorded::Inserted) => {
            println!(
                "ping {prefix} {} {} {} {}",
                payload.os, payload.os_version, payload.backend, payload.app_version
            );
            http::respond(stream, 204, "");
        }
        Ok(db::Recorded::Duplicate) => {
            // Not an error: a machine rebooted twice in a day, or a clock
            // moved. The row is refreshed and the count stays honest.
            http::respond(stream, 204, "");
        }
        Err(e) => {
            eprintln!("error: storing ping from {prefix}: {e}");
            http::respond(stream, 503, "try later\n");
        }
    }
}

/// Fixed-window request cap per network prefix.
///
/// Per prefix rather than per install ID: an ID is chosen by the client, so
/// limiting on it would let anyone mint a fresh one and start again. The
/// window is generous because a single /24 can legitimately hold a lot of
/// machines that all boot at nine in the morning.
struct RateLimiter {
    per_hour: u32,
    window: Instant,
    counts: std::collections::HashMap<String, u32>,
}

impl RateLimiter {
    fn new(per_hour: u32) -> Self {
        RateLimiter {
            per_hour,
            window: Instant::now(),
            counts: std::collections::HashMap::new(),
        }
    }

    fn allow(&mut self, prefix: &str) -> bool {
        // Clearing the whole map each hour is also what keeps it from
        // growing without bound — there is no per-entry expiry to get wrong.
        if self.window.elapsed() >= Duration::from_secs(3600) {
            self.counts.clear();
            self.window = Instant::now();
        }
        let n = self.counts.entry(prefix.to_string()).or_insert(0);
        if *n >= self.per_hour {
            return false;
        }
        *n += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limiter_refuses_past_its_ceiling() {
        let mut r = RateLimiter::new(3);
        assert!(r.allow("203.0.113.0"));
        assert!(r.allow("203.0.113.0"));
        assert!(r.allow("203.0.113.0"));
        assert!(!r.allow("203.0.113.0"), "fourth in the window is refused");
        // a different network is unaffected by its neighbour
        assert!(r.allow("198.51.100.0"));
    }

    #[test]
    fn the_window_resets() {
        let mut r = RateLimiter::new(1);
        assert!(r.allow("203.0.113.0"));
        assert!(!r.allow("203.0.113.0"));
        r.window = Instant::now() - Duration::from_secs(3601);
        assert!(r.allow("203.0.113.0"), "a new window starts clean");
        assert!(r.counts.len() == 1, "the old window's entries are dropped");
    }
}
