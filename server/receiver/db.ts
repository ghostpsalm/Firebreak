/**
 * The store: one row per install per day.
 *
 * SQLite because the whole point of the exercise is a box you do not have to
 * operate. A ping is a few hundred bytes once a day per install; at ten
 * thousand installs that is under a megabyte a week, and the file can be
 * copied off with `scp` and queried on a laptop.
 *
 * `node:sqlite` is built into Deno, so this needs no FFI permission and no
 * third-party module — the process runs with nothing but scoped read/write
 * on the database directory and a single listening port.
 */

import { DatabaseSync } from "node:sqlite";

import { featuresCsv, type Payload } from "./ping.ts";

/**
 * What happened to a ping — worth distinguishing in the logs, because a
 * sudden run of "duplicate" means a client is ignoring its own daily
 * interval and is a bug worth chasing.
 */
export type Recorded = "inserted" | "duplicate";

export class Db {
  #db: DatabaseSync;

  constructor(path: string) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
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

      -- One row per install per day, enforced here rather than trusted to
      -- the client: a client that ignores its own 24h interval, or replays
      -- someone else's payload, cannot inflate the numbers.
      CREATE UNIQUE INDEX IF NOT EXISTS ping_daily ON ping(install_id, day);
      CREATE INDEX IF NOT EXISTS ping_by_day ON ping(day);
    `);
  }

  /**
   * Store a validated ping. The clock is SQLite's, so the stamp is the
   * server's rather than a claim made by the client.
   */
  record(p: Payload, ipPrefix: string): Recorded {
    // Asked before the upsert, because afterwards an insert and an update
    // are indistinguishable.
    const existing = this.#db
      .prepare(
        "SELECT COUNT(*) AS n FROM ping WHERE install_id = ? AND day = date('now')",
      )
      .get(p.install_id) as { n: number };

    this.#db
      .prepare(`
        INSERT INTO ping (
            received_at, day, install_id, app_version, os, os_name, os_version,
            arch, backend, board_vendor, virtual_machine, age, runs, features, ip_prefix
        ) VALUES (
            strftime('%Y-%m-%dT%H:%M:%SZ','now'), date('now'),
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
      `)
      .run(
        p.install_id,
        p.app_version,
        p.os,
        p.os_name,
        p.os_version,
        p.arch,
        p.backend,
        p.board_vendor,
        p.virtual_machine ? 1 : 0,
        p.age,
        p.runs,
        featuresCsv(p),
        ipPrefix,
      );

    return existing.n === 0 ? "inserted" : "duplicate";
  }

  /**
   * Drop rows past the retention window.
   *
   * A network prefix is still arguably personal data, so "keep it forever"
   * is a decision that has to be made deliberately rather than by omission.
   * Called at startup and once a day.
   */
  prune(days: number): number {
    const r = this.#db
      .prepare("DELETE FROM ping WHERE day < date('now', ?)")
      .run(`-${days} days`);
    return Number(r.changes);
  }

  /** Test and diagnostic access. Not used by the request path. */
  query(sql: string): unknown[] {
    return this.#db.prepare(sql).all();
  }

  close() {
    this.#db.close();
  }
}
