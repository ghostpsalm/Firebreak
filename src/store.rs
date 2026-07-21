use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

use crate::model::{EventRecord, RuleInfo, RuleUsage};

pub struct Store {
    conn: Connection,
}

/// Bump when the attribution model changes so existing DBs auto-reset on
/// next open. v3 = scope attribution with unconstrained-rule exclusion and
/// per-profile counts. v4 = disabled rules excluded from attribution (#1).
const MODEL_VERSION: &str = "4";

/// Default DB location: %ProgramData%\firebreak\firebreak.db (survives per-user
/// profile churn; tool runs elevated anyway).
pub fn default_db_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("firebreak").join("firebreak.db")
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            crate::secure_dir::ensure_secured_dir(dir)
                .with_context(|| format!("securing {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening db {}", path.display()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- rolled-up usage per rule; rule_id is the firewall rule Name
            -- (InstanceID), a 'disp:<name>|<dir>' group key, or a
            -- 'default:<FilterOrigin>' system-filter bucket
            CREATE TABLE IF NOT EXISTS rule_usage (
                rule_id     TEXT PRIMARY KEY,
                allow_count INTEGER NOT NULL DEFAULT 0,
                block_count INTEGER NOT NULL DEFAULT 0,
                first_seen  TEXT,
                last_seen   TEXT
            );

            CREATE TABLE IF NOT EXISTS rule_apps (
                rule_id   TEXT NOT NULL,
                app_path  TEXT NOT NULL,
                hits      INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                PRIMARY KEY (rule_id, app_path)
            );

            -- distinct remote peers per rule (source addr for inbound,
            -- destination for outbound) — powers "N distinct source IPs"
            CREATE TABLE IF NOT EXISTS rule_peers (
                rule_id TEXT NOT NULL,
                peer    TEXT NOT NULL,
                PRIMARY KEY (rule_id, peer)
            );

            -- per-profile allow/block split (Domain/Private/Public/Unknown)
            CREATE TABLE IF NOT EXISTS rule_profile_usage (
                rule_id     TEXT NOT NULL,
                profile     TEXT NOT NULL,
                allow_count INTEGER NOT NULL DEFAULT 0,
                block_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (rule_id, profile)
            );

            -- WFP filter-id -> rule mapping, persisted per run and keyed by
            -- boot session (boot start time, ISO). Filter run-time IDs are
            -- only meaningful within one boot: the same numeric ID can name
            -- a different filter after a reboot, so a mapping must never be
            -- applied to events from another session.
            CREATE TABLE IF NOT EXISTS filter_map (
                filter_id    INTEGER NOT NULL,
                boot_session TEXT NOT NULL,
                rule_id      TEXT,
                filter_name  TEXT,
                mapped_via   TEXT,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (filter_id, boot_session)
            );

            -- snapshot of the enabled rule set at audit-enable time and on
            -- each run, so "rule existed but never appeared" is answerable
            CREATE TABLE IF NOT EXISTS rule_snapshot (
                snapshot_at  TEXT NOT NULL,
                rule_json    TEXT NOT NULL
            );

            -- user attestation: this rule (at this definition fingerprint)
            -- has been verified. A user artifact, not derived data — it
            -- survives ingestion resets and model-version wipes.
            CREATE TABLE IF NOT EXISTS reviewed_rules (
                rule_id     TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                reviewed_at TEXT NOT NULL
            );
            "#,
        )?;
        let store = Store { conn };
        // Self-healing: when the attribution model changes, aggregated usage
        // from the old model is meaningless and the checkpoint has advanced
        // past the events. Auto-wipe usage + checkpoint so the next run
        // re-ingests the whole log under the new model — no manual DB delete.
        let current = store.get_meta("model_version")?;
        if current.as_deref() != Some(MODEL_VERSION) {
            store.reset_ingestion()?;
            store.set_meta("model_version", MODEL_VERSION)?;
        }
        Ok(store)
    }

    /// Clear all aggregated usage and the ingestion checkpoint so the next
    /// analyze() re-reads the entire Security log. Keeps audit-enable state
    /// (prior_audit_*, collection_started) and rule snapshots.
    pub fn reset_ingestion(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM rule_usage;
             DELETE FROM rule_apps;
             DELETE FROM rule_peers;
             DELETE FROM rule_profile_usage;
             DELETE FROM meta WHERE key = 'checkpoint_record_id';
             DELETE FROM meta WHERE key LIKE 'bucketlabel:%';",
        )?;
        Ok(())
    }

    // ---- transactions ----
    // Ingestion runs as one transaction: aggregation and the checkpoint
    // advance commit together, so a crash mid-ingest rolls back cleanly and
    // a rerun cannot double-count. Also ~10^4x fewer WAL commits than
    // per-event autocommit.

    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub fn rollback(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    // ---- meta / checkpoint ----

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )?;
        stmt.execute(params![key, value])?;
        Ok(())
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached("DELETE FROM meta WHERE key = ?1")?;
        stmt.execute(params![key])?;
        Ok(())
    }

    // ---- reviewed marks ----

    /// Mark a rule as reviewed at its current definition fingerprint.
    pub fn set_reviewed(&self, rule_id: &str, fingerprint: &str, reviewed_at: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO reviewed_rules (rule_id, fingerprint, reviewed_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(rule_id) DO UPDATE SET fingerprint = excluded.fingerprint,
                                                reviewed_at = excluded.reviewed_at",
        )?;
        stmt.execute(params![rule_id, fingerprint, reviewed_at])?;
        Ok(())
    }

    pub fn clear_reviewed(&self, rule_id: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached("DELETE FROM reviewed_rules WHERE rule_id = ?1")?;
        stmt.execute(params![rule_id])?;
        Ok(())
    }

    /// rule_id -> (fingerprint, reviewed_at)
    pub fn load_reviewed(&self) -> Result<std::collections::HashMap<String, (String, String)>> {
        let mut stmt = self.conn.prepare("SELECT rule_id, fingerprint, reviewed_at FROM reviewed_rules")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, r.get::<_, String>(2)?))))?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// Last-processed EventRecordID (Security channel). The next ingest
    /// resumes strictly after this record.
    pub fn checkpoint_record_id(&self) -> Result<Option<u64>> {
        Ok(self
            .get_meta("checkpoint_record_id")?
            .and_then(|v| v.parse().ok()))
    }

    pub fn set_checkpoint_record_id(&self, id: u64) -> Result<()> {
        self.set_meta("checkpoint_record_id", &id.to_string())
    }

    // ---- ingestion ----

    /// Record one event against a resolved rule id (or default bucket).
    /// `profile` is the network profile the connection used. Hot path —
    /// statements are cached, and the caller wraps the whole ingestion in
    /// one transaction via begin()/commit().
    pub fn record_event(
        &self,
        rule_id: &str,
        ev: &EventRecord,
        app_normalized: &str,
        profile: &str,
    ) -> Result<()> {
        let (allow, block) = if ev.is_allow() { (1, 0) } else { (0, 1) };
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO rule_usage (rule_id, allow_count, block_count, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(rule_id) DO UPDATE SET
                allow_count = allow_count + ?2,
                block_count = block_count + ?3,
                first_seen  = MIN(first_seen, ?4),
                last_seen   = MAX(last_seen, ?4)",
        )?;
        stmt.execute(params![rule_id, allow, block, ev.time_created])?;
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO rule_profile_usage (rule_id, profile, allow_count, block_count)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(rule_id, profile) DO UPDATE SET
                allow_count = allow_count + ?3,
                block_count = block_count + ?4",
        )?;
        stmt.execute(params![rule_id, profile, allow, block])?;
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO rule_apps (rule_id, app_path, hits, last_seen)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(rule_id, app_path) DO UPDATE SET
                hits = hits + 1,
                last_seen = MAX(last_seen, ?3)",
        )?;
        stmt.execute(params![rule_id, app_normalized, ev.time_created])?;
        let peer = if ev.direction.eq_ignore_ascii_case("inbound") {
            ev.source_address.as_str()
        } else {
            ev.dest_address.as_str()
        };
        if !peer.is_empty() && peer != "-" {
            let mut stmt = self.conn.prepare_cached(
                "INSERT OR IGNORE INTO rule_peers (rule_id, peer) VALUES (?1, ?2)",
            )?;
            stmt.execute(params![rule_id, peer])?;
        }
        Ok(())
    }

    /// Keeps only the first snapshot (the rule set as it stood when
    /// collection started) and the latest — enough to answer "what changed
    /// since the audit began" without growing the DB on every run.
    pub fn snapshot_rules(&self, rules: &[RuleInfo], now_iso: &str) -> Result<()> {
        let json = serde_json::to_string(rules)?;
        self.conn.execute(
            "INSERT INTO rule_snapshot (snapshot_at, rule_json) VALUES (?1, ?2)",
            params![now_iso, json],
        )?;
        self.conn.execute(
            "DELETE FROM rule_snapshot WHERE snapshot_at NOT IN (
                (SELECT MIN(snapshot_at) FROM rule_snapshot),
                (SELECT MAX(snapshot_at) FROM rule_snapshot)
            )",
            [],
        )?;
        Ok(())
    }

    // ---- reporting ----

    /// All usage in two whole-table queries (instead of two per rule).
    /// Apps are ordered by hits within each rule.
    pub fn all_usage(&self) -> Result<std::collections::HashMap<String, RuleUsage>> {
        let mut map: std::collections::HashMap<String, RuleUsage> =
            std::collections::HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, allow_count, block_count, first_seen, last_seen FROM rule_usage",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RuleUsage {
                rule_id: row.get(0)?,
                allow_count: row.get(1)?,
                block_count: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                apps: Vec::new(),
                distinct_peers: 0,
                by_profile: Vec::new(),
            })
        })?;
        for u in rows {
            let u = u?;
            map.insert(u.rule_id.clone(), u);
        }
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, profile, allow_count, block_count FROM rule_profile_usage
             ORDER BY rule_id, profile",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for r in rows {
            let (rule_id, profile, allow, block) = r?;
            if let Some(u) = map.get_mut(&rule_id) {
                u.by_profile.push((profile, allow, block));
            }
        }
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, app_path, hits FROM rule_apps ORDER BY rule_id, hits DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for r in rows {
            let (rule_id, app, hits) = r?;
            if let Some(u) = map.get_mut(&rule_id) {
                u.apps.push((app, hits));
            }
        }
        let mut stmt = self
            .conn
            .prepare("SELECT rule_id, COUNT(*) FROM rule_peers GROUP BY rule_id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (rule_id, n) = r?;
            if let Some(u) = map.get_mut(&rule_id) {
                u.distinct_peers = n;
            }
        }
        Ok(map)
    }

    #[allow(dead_code)]
    pub fn usage_for(&self, rule_id: &str) -> Result<Option<RuleUsage>> {
        let mut stmt = self.conn.prepare(
            "SELECT allow_count, block_count, first_seen, last_seen
             FROM rule_usage WHERE rule_id = ?1",
        )?;
        let mut rows = stmt.query(params![rule_id])?;
        let mut usage = match rows.next()? {
            Some(row) => RuleUsage {
                rule_id: rule_id.to_string(),
                allow_count: row.get(0)?,
                block_count: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
                apps: Vec::new(),
                distinct_peers: 0,
                by_profile: Vec::new(),
            },
            None => return Ok(None),
        };
        let mut stmt = self.conn.prepare(
            "SELECT app_path, hits FROM rule_apps WHERE rule_id = ?1 ORDER BY hits DESC",
        )?;
        let rows = stmt.query_map(params![rule_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for r in rows {
            usage.apps.push(r?);
        }
        Ok(Some(usage))
    }

    /// All usage rows whose rule_id starts with 'default:' — events decided
    /// by a default/system WFP filter rather than a firewall rule, keyed by
    /// FilterOrigin. Most hits first.
    pub fn unmatched_usage(&self) -> Result<Vec<RuleUsage>> {
        let mut out: Vec<RuleUsage> = self
            .all_usage()?
            .into_values()
            .filter(|u| u.rule_id.starts_with("default:"))
            .collect();
        out.sort_by_key(|u| -(u.allow_count + u.block_count));
        Ok(out)
    }

    pub fn set_bucket_label(&self, bucket_id: &str, label: &str) -> Result<()> {
        self.set_meta(&format!("bucketlabel:{bucket_id}"), label)
    }

    pub fn bucket_labels(&self) -> Result<std::collections::HashMap<String, String>> {
        let mut map = std::collections::HashMap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM meta WHERE key LIKE 'bucketlabel:%'")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for r in rows {
            let (k, v) = r?;
            if let Some(id) = k.strip_prefix("bucketlabel:") {
                map.insert(id.to_string(), v);
            }
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempStore {
        store: Store,
        dir: PathBuf,
    }

    impl TempStore {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "firebreak-test-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Store::open(&dir.join("t.db")).expect("open store");
            TempStore { store, dir }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn ev(record_id: u64, event_id: u32, time: &str, rtid: u64) -> EventRecord {
        EventRecord {
            event_id,
            record_id,
            time_created: time.into(),
            filter_rtid: rtid,
            application: r"\device\hd1\a.exe".into(),
            direction: "Outbound".into(),
            filter_origin: None,
            protocol: 6,
            dest_address: "1.2.3.4".into(),
            dest_port: "443".into(),
            source_address: "10.0.0.1".into(),
            source_port: "50000".into(),
            interface_index: 0,
        }
    }

    #[test]
    fn events_aggregate_counts_apps_and_seen_range() {
        let t = TempStore::new("agg");
        t.store
            .record_event("r1", &ev(1, 5156, "2026-07-02T00:00:00.000Z", 7), r"C:\a.exe", "Public")
            .unwrap();
        t.store
            .record_event("r1", &ev(2, 5157, "2026-07-03T00:00:00.000Z", 7), r"C:\b.exe", "Public")
            .unwrap();
        t.store
            .record_event("r1", &ev(3, 5156, "2026-07-01T00:00:00.000Z", 7), r"C:\a.exe", "Public")
            .unwrap();
        let u = t.store.all_usage().unwrap().remove("r1").expect("usage");
        assert_eq!(u.allow_count, 2);
        assert_eq!(u.block_count, 1);
        assert_eq!(u.first_seen.as_deref(), Some("2026-07-01T00:00:00.000Z"));
        assert_eq!(u.last_seen.as_deref(), Some("2026-07-03T00:00:00.000Z"));
        assert_eq!(u.apps[0], (r"C:\a.exe".to_string(), 2)); // most hits first
    }

    #[test]
    fn checkpoint_round_trips() {
        let t = TempStore::new("cp");
        assert_eq!(t.store.checkpoint_record_id().unwrap(), None);
        t.store.set_checkpoint_record_id(42).unwrap();
        assert_eq!(t.store.checkpoint_record_id().unwrap(), Some(42));
    }

    #[test]
    fn bucket_labels_round_trip() {
        let t = TempStore::new("buckets");
        t.store.set_bucket_label("default:Unknown", "Unknown").unwrap();
        let m = t.store.bucket_labels().unwrap();
        assert_eq!(m.get("default:Unknown").map(String::as_str), Some("Unknown"));
    }

    #[test]
    fn snapshots_keep_only_first_and_latest() {
        let t = TempStore::new("snap");
        t.store.snapshot_rules(&[], "2026-07-01T00:00:00Z").unwrap();
        t.store.snapshot_rules(&[], "2026-07-02T00:00:00Z").unwrap();
        t.store.snapshot_rules(&[], "2026-07-03T00:00:00Z").unwrap();
        let count: i64 = t
            .store
            .conn
            .query_row("SELECT COUNT(*) FROM rule_snapshot", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let times: Vec<String> = {
            let mut stmt = t
                .store
                .conn
                .prepare("SELECT snapshot_at FROM rule_snapshot ORDER BY snapshot_at")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        assert_eq!(times, vec!["2026-07-01T00:00:00Z", "2026-07-03T00:00:00Z"]);
    }

    #[test]
    fn unmatched_usage_filters_and_sorts() {
        let t = TempStore::new("unmatched");
        t.store
            .record_event("default:Unknown", &ev(1, 5156, "2026-07-01T00:00:00Z", 5), "a", "Public")
            .unwrap();
        for i in 0..3 {
            t.store
                .record_event(
                    "default:Stealth",
                    &ev(2 + i, 5157, "2026-07-01T00:00:00Z", 6),
                    "b",
                    "Public",
                )
                .unwrap();
        }
        t.store
            .record_event("real-rule", &ev(9, 5156, "2026-07-01T00:00:00Z", 7), "c", "Public")
            .unwrap();
        let unmatched = t.store.unmatched_usage().unwrap();
        assert_eq!(unmatched.len(), 2);
        assert_eq!(unmatched[0].rule_id, "default:Stealth");
    }
}
