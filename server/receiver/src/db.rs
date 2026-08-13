//! The store: one row per install per day.
//!
//! SQLite because the whole point of the exercise is a box you do not have
//! to operate. A ping is a few hundred bytes once a day per install; at ten
//! thousand installs that is under a megabyte a week, and the file can be
//! copied off with `scp` and queried on a laptop.

use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::ping::Payload;

pub struct Db {
    conn: Mutex<Connection>,
}

/// What happened to a ping — worth distinguishing in the logs, because a
/// sudden run of `Duplicate` means a client is ignoring its own daily
/// interval and is a bug worth chasing.
#[derive(Debug, PartialEq, Eq)]
pub enum Recorded {
    Inserted,
    /// Same install, same day: the row was refreshed rather than added.
    Duplicate,
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS ping (
                id              INTEGER PRIMARY KEY,
                received_at     TEXT    NOT NULL,
                day             TEXT    NOT NULL,
                install_id      TEXT    NOT NULL,
                app_version     TEXT    NOT NULL,
                os              TEXT    NOT NULL,
                os_name         TEXT    NOT NULL,
                os_version      TEXT    NOT NULL,
                arch            TEXT    NOT NULL,
                backend         TEXT    NOT NULL,
                board_vendor    TEXT    NOT NULL,
                virtual_machine INTEGER NOT NULL,
                age             TEXT    NOT NULL,
                runs            TEXT    NOT NULL,
                features        TEXT    NOT NULL,
                -- a /24 or /48 network, never a full address
                ip_prefix       TEXT    NOT NULL
            );

            -- One row per install per day, enforced here rather than trusted
            -- to the client: a client that ignores its own 24h interval, or
            -- replays someone else's payload, cannot inflate the numbers.
            CREATE UNIQUE INDEX IF NOT EXISTS ping_daily
                ON ping(install_id, day);
            CREATE INDEX IF NOT EXISTS ping_by_day ON ping(day);
            "#,
        )?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// Store a validated ping. The clock is SQLite's, so the service needs
    /// no time crate and the stamp is the server's rather than a claim made
    /// by the client.
    pub fn record(&self, p: &Payload, ip_prefix: &str) -> rusqlite::Result<Recorded> {
        let conn = self.conn.lock().expect("db mutex");
        // Asked before the upsert, under the same lock, because afterwards
        // an insert and an update are indistinguishable by row count.
        let already: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ping WHERE install_id = ?1 AND day = date('now')",
            params![p.install_id],
            |r| r.get(0),
        )?;
        conn.execute(
            r#"
            INSERT INTO ping (
                received_at, day, install_id, app_version, os, os_name, os_version,
                arch, backend, board_vendor, virtual_machine, age, runs, features, ip_prefix
            ) VALUES (
                strftime('%Y-%m-%dT%H:%M:%SZ','now'), date('now'),
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
            )
            ON CONFLICT(install_id, day) DO UPDATE SET
                received_at = excluded.received_at,
                app_version = excluded.app_version,
                os_name     = excluded.os_name,
                os_version  = excluded.os_version,
                backend     = excluded.backend,
                age         = excluded.age,
                runs        = excluded.runs,
                features    = excluded.features
            "#,
            params![
                p.install_id,
                p.app_version,
                p.os,
                p.os_name,
                p.os_version,
                p.arch,
                p.backend,
                p.board_vendor,
                p.virtual_machine as i32,
                p.age,
                p.runs,
                p.features_csv(),
                ip_prefix,
            ],
        )?;
        Ok(if already == 0 {
            Recorded::Inserted
        } else {
            Recorded::Duplicate
        })
    }

    /// Drop rows past the retention window.
    ///
    /// A network prefix is still arguably personal data, so "keep it
    /// forever" is a decision that has to be made deliberately rather than
    /// by omission. Called at startup and once a day.
    pub fn prune(&self, days: u32) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().expect("db mutex");
        conn.execute(
            "DELETE FROM ping WHERE day < date('now', ?1)",
            params![format!("-{days} days")],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(id: &str) -> Payload {
        serde_json::from_str(&format!(
            r#"{{"schema":1,"install_id":"{id}","app_version":"0.7.81","os":"linux",
                 "os_name":"Fedora Linux","os_version":"44","arch":"x86_64",
                 "backend":"ufw","board_vendor":"ASUSTeK","virtual_machine":false,
                 "age":"0","runs":"1","features":["apply"]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_ping_round_trips() {
        let db = Db::open(":memory:").unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            db.record(&payload(id), "203.0.113.0").unwrap(),
            Recorded::Inserted
        );
        let conn = db.conn.lock().unwrap();
        let (stored_id, prefix, features): (String, String, String) = conn
            .query_row(
                "SELECT install_id, ip_prefix, features FROM ping",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored_id, id);
        assert_eq!(prefix, "203.0.113.0");
        assert_eq!(features, "apply");
    }

    /// The daily uniqueness is the server's rule, not the client's promise.
    #[test]
    fn a_second_ping_the_same_day_does_not_add_a_row() {
        let db = Db::open(":memory:").unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        db.record(&payload(id), "203.0.113.0").unwrap();
        db.record(&payload(id), "203.0.113.0").unwrap();
        db.record(&payload(id), "198.51.100.0").unwrap();
        let n: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ping", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "one install, one day, one row");
    }

    #[test]
    fn separate_installs_each_get_a_row() {
        let db = Db::open(":memory:").unwrap();
        db.record(&payload("0123456789abcdef0123456789abcdef"), "203.0.113.0")
            .unwrap();
        db.record(&payload("fedcba9876543210fedcba9876543210"), "203.0.113.0")
            .unwrap();
        let n: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ping", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn retention_drops_old_rows_and_keeps_current_ones() {
        let db = Db::open(":memory:").unwrap();
        db.record(&payload("0123456789abcdef0123456789abcdef"), "203.0.113.0")
            .unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO ping (received_at, day, install_id, app_version, os, os_name,
                    os_version, arch, backend, board_vendor, virtual_machine, age, runs,
                    features, ip_prefix)
                 VALUES ('old', date('now','-500 days'), 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    '0.1.0','linux','x','1','x86_64','ufw','x',0,'0','1','','203.0.113.0')",
                [],
            )
            .unwrap();
        assert_eq!(db.prune(400).unwrap(), 1, "the 500-day-old row goes");
        let n: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ping", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "today's row stays");
    }
}
