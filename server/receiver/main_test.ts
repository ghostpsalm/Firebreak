import { assertEquals } from "jsr:@std/assert@1";

import { Db } from "./db.ts";
import { handler, RateLimiter, readCapped } from "./main.ts";

const GOOD = {
  schema: 1,
  install_id: "0123456789abcdef0123456789abcdef",
  app_version: "0.7.81",
  os: "linux",
  os_name: "Fedora Linux",
  os_version: "44",
  arch: "x86_64",
  backend: "firewalld",
  board_vendor: "ASUSTeK",
  virtual_machine: false,
  age: "31-90",
  runs: "6-20",
  features: ["apply", "collect"],
};

/** A collector wired to an in-memory database, as the listener would build it. */
function collector(perHour = 240) {
  const db = new Db(":memory:");
  const serve = handler(db, new RateLimiter(perHour));
  return {
    db,
    post: (body: string, headers: Record<string, string> = {}) =>
      serve(
        new Request("http://x/v1/ping", { method: "POST", body, headers }),
        "127.0.0.1",
      ),
    get: (path: string) => serve(new Request(`http://x${path}`), "127.0.0.1"),
    rows: () =>
      db.query("SELECT install_id, ip_prefix FROM ping") as Record<
        string,
        unknown
      >[],
    close: () => db.close(),
  };
}

Deno.test("healthz answers without touching the data", async () => {
  const c = collector();
  assertEquals((await c.get("/healthz")).status, 200);
  c.close();
});

Deno.test("only the one route and the one method exist", async () => {
  const c = collector();
  assertEquals((await c.get("/admin")).status, 404);
  assertEquals((await c.get("/")).status, 404);
  assertEquals((await c.get("/v1/ping")).status, 405);
  c.close();
});

Deno.test("a good ping is stored", async () => {
  const c = collector();
  assertEquals((await c.post(JSON.stringify(GOOD))).status, 204);
  assertEquals(c.rows().length, 1);
  c.close();
});

Deno.test("the stored network comes from the proxy, not the client", async () => {
  const c = collector();
  await c.post(JSON.stringify(GOOD), {
    "x-forwarded-for": "9.9.9.9, 203.0.113.47",
  });
  assertEquals(c.rows()[0].ip_prefix, "203.0.113.0");
  c.close();
});

Deno.test("junk and extra fields are refused, and nothing is stored", async () => {
  const c = collector();
  assertEquals((await c.post("not json at all")).status, 400);
  assertEquals(
    (await c.post(JSON.stringify({ ...GOOD, hostname: "secret" }))).status,
    400,
  );
  assertEquals(
    (await c.post(JSON.stringify({ ...GOOD, backend: "pf" }))).status,
    400,
  );
  assertEquals(c.rows().length, 0);
  c.close();
});

Deno.test("an oversize body is refused", async () => {
  const c = collector();
  const huge = JSON.stringify({ ...GOOD, os_name: "x".repeat(20_000) });
  assertEquals((await c.post(huge)).status, 413);
  c.close();
});

Deno.test("a lying Content-Length does not get past the cap", async () => {
  // The stream is capped as well as the header, because a header is a claim.
  const body = "x".repeat(20_000);
  const req = new Request("http://x/v1/ping", { method: "POST", body });
  assertEquals(await readCapped(req, 8 * 1024), null);
});

Deno.test("the rate limiter refuses past its ceiling", async () => {
  const c = collector(2);
  assertEquals((await c.post(JSON.stringify(GOOD))).status, 204);
  assertEquals((await c.post(JSON.stringify(GOOD))).status, 204);
  assertEquals((await c.post(JSON.stringify(GOOD))).status, 429);
  c.close();
});

Deno.test("the rate window resets and does not grow without bound", () => {
  const r = new RateLimiter(1, 0);
  assertEquals(r.allow("203.0.113.0", 0), true);
  assertEquals(r.allow("203.0.113.0", 0), false);
  // an hour later the window is a fresh one
  assertEquals(r.allow("203.0.113.0", 3_600_001), true);
});
