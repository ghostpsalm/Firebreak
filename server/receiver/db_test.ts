import { assertEquals } from "jsr:@std/assert@1";

import { Db } from "./db.ts";
import { type Payload, validate } from "./ping.ts";

function payload(installId: string): Payload {
  const r = validate({
    schema: 1,
    install_id: installId,
    app_version: "0.7.81",
    os: "linux",
    os_name: "Fedora Linux",
    os_version: "44",
    arch: "x86_64",
    backend: "ufw",
    board_vendor: "ASUSTeK",
    virtual_machine: false,
    age: "0",
    runs: "1",
    features: ["apply"],
  });
  if (!r.ok) throw new Error(`fixture must validate: ${r.reason}`);
  return r.payload;
}

const A = "0123456789abcdef0123456789abcdef";
const B = "fedcba9876543210fedcba9876543210";

function withDb(fn: (db: Db) => void) {
  const db = new Db(":memory:");
  try {
    fn(db);
  } finally {
    db.close();
  }
}

Deno.test("a ping round trips", () => {
  withDb((db) => {
    assertEquals(db.record(payload(A), "203.0.113.0"), "inserted");
    const rows = db.query(
      "SELECT install_id, ip_prefix, features FROM ping",
    ) as Record<string, unknown>[];
    assertEquals(rows.length, 1);
    assertEquals(rows[0].install_id, A);
    assertEquals(rows[0].ip_prefix, "203.0.113.0");
    assertEquals(rows[0].features, "apply");
  });
});

Deno.test("the daily rule is the server's, not the client's promise", () => {
  withDb((db) => {
    assertEquals(db.record(payload(A), "203.0.113.0"), "inserted");
    assertEquals(db.record(payload(A), "203.0.113.0"), "duplicate");
    // a different apparent network cannot buy another row either
    assertEquals(db.record(payload(A), "198.51.100.0"), "duplicate");
    const n = db.query("SELECT COUNT(*) AS n FROM ping") as { n: number }[];
    assertEquals(n[0].n, 1, "one install, one day, one row");
  });
});

Deno.test("separate installs each get a row", () => {
  withDb((db) => {
    db.record(payload(A), "203.0.113.0");
    db.record(payload(B), "203.0.113.0");
    const n = db.query("SELECT COUNT(*) AS n FROM ping") as { n: number }[];
    assertEquals(n[0].n, 2);
  });
});

Deno.test("a repeat ping refreshes the row rather than adding one", () => {
  withDb((db) => {
    db.record(payload(A), "203.0.113.0");
    const later = { ...payload(A), app_version: "0.8.0", runs: "6-20" };
    db.record(later, "203.0.113.0");
    const rows = db.query(
      "SELECT app_version, runs FROM ping",
    ) as Record<string, unknown>[];
    assertEquals(rows.length, 1);
    assertEquals(rows[0].app_version, "0.8.0");
    assertEquals(rows[0].runs, "6-20");
  });
});

Deno.test("retention drops old rows and keeps current ones", () => {
  withDb((db) => {
    db.record(payload(A), "203.0.113.0");
    db.query(`
      INSERT INTO ping (received_at, day, install_id, app_version, os, os_name,
          os_version, arch, backend, board_vendor, virtual_machine, age, runs,
          features, ip_prefix)
      VALUES ('old', date('now','-500 days'), 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          '0.1.0','linux','x','1','x86_64','ufw','x',0,'0','1','','203.0.113.0')
      RETURNING id
    `);
    assertEquals(db.prune(400), 1, "the 500-day-old row goes");
    const n = db.query("SELECT COUNT(*) AS n FROM ping") as { n: number }[];
    assertEquals(n[0].n, 1, "today's row stays");
  });
});
