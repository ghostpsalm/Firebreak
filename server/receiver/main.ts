/**
 * Firebreak's telemetry collector.
 *
 * Sits on localhost behind nginx, which terminates TLS and hands over the
 * peer address. Accepts exactly one thing — `POST /v1/ping` carrying the
 * payload Firebreak's `src/telemetry.rs` builds — validates it hard,
 * coarsens the address, and writes a row.
 *
 * Operational shape, all deliberate:
 *
 * - **Binds loopback by default.** The only thing that should reach it is
 *   the proxy on the same host.
 * - **The process is confined by Deno itself**, not only by systemd. It runs
 *   with `--allow-net` scoped to its own listening address, read/write
 *   scoped to the database directory, and nothing else — no subprocess, no
 *   FFI, no wider filesystem. That permission set is the security boundary
 *   worth reading before anything below.
 * - **Bounded everywhere.** Body size, request rate per network and the
 *   listener's own concurrency all have ceilings, so a bad day costs a
 *   refusal rather than the box.
 * - **Logs prefixes, never addresses.** Truncation happens before anything
 *   is written down, including to the journal — otherwise the retention
 *   policy on the database would be undone by the log next to it.
 */

import { Db } from "./db.ts";
import { clientIp, truncate, validate } from "./ping.ts";

/** Largest body we will read. The payload is ~300 bytes; this is generous
 * by an order of magnitude and still bounded. */
const MAX_BODY = 8 * 1024;

function env(key: string, fallback: string): string {
  return Deno.env.get(key) ?? fallback;
}

function envNum(key: string, fallback: number): number {
  const v = Number(Deno.env.get(key));
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

/**
 * Fixed-window request cap per network prefix.
 *
 * Per prefix rather than per install ID: an ID is chosen by the client, so
 * limiting on it would let anyone mint a fresh one and start again. The
 * window is generous because a single /24 can legitimately hold a lot of
 * machines that all boot at nine in the morning.
 */
export class RateLimiter {
  #perHour: number;
  #windowStart: number;
  #counts = new Map<string, number>();

  constructor(perHour: number, now = Date.now()) {
    this.#perHour = perHour;
    this.#windowStart = now;
  }

  allow(prefix: string, now = Date.now()): boolean {
    // Clearing the whole map each hour is also what keeps it from growing
    // without bound — there is no per-entry expiry to get wrong.
    if (now - this.#windowStart >= 3_600_000) {
      this.#counts.clear();
      this.#windowStart = now;
    }
    const n = this.#counts.get(prefix) ?? 0;
    if (n >= this.#perHour) return false;
    this.#counts.set(prefix, n + 1);
    return true;
  }
}

/**
 * Read a request body, refusing anything over `max`.
 *
 * The declared Content-Length is checked first, but the stream is capped as
 * well: a header is a claim, and a chunked request has no length to claim.
 * Returns null when the body is too large.
 */
export async function readCapped(
  req: Request,
  max: number,
): Promise<Uint8Array | null> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared) || Number(declared) > max) return null;
  }
  if (!req.body) return new Uint8Array();

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

const text = (status: number, body: string) =>
  new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });

export function handler(db: Db, limiter: RateLimiter) {
  return async (req: Request, peer: string): Promise<Response> => {
    const path = new URL(req.url).pathname;

    // Cheap liveness for the proxy and for monitoring. Says nothing about
    // the data.
    if (path === "/healthz") return text(200, "ok\n");
    if (path !== "/v1/ping") return text(404, "not found\n");
    if (req.method !== "POST") return text(405, "post only\n");

    const ip = clientIp(req.headers.get("x-forwarded-for"), peer);
    // From here on only the prefix exists. Nothing below may see `ip`.
    const prefix = truncate(ip);

    if (!limiter.allow(prefix)) return text(429, "slow down\n");

    const body = await readCapped(req, MAX_BODY);
    if (body === null) return text(413, "too large\n");

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(body));
    } catch {
      console.log(`reject ${prefix}: unparseable`);
      return text(400, "bad json\n");
    }

    const result = validate(parsed);
    if (!result.ok) {
      console.log(`reject ${prefix}: ${result.reason}`);
      return text(400, "bad payload\n");
    }
    const p = result.payload;

    try {
      const outcome = db.record(p, prefix);
      if (outcome === "inserted") {
        console.log(
          `ping ${prefix} ${p.os} ${p.os_version} ${p.backend} ${p.app_version}`,
        );
      }
      // A duplicate is not an error: a machine rebooted twice in a day, or a
      // clock moved. The row is refreshed and the count stays honest.
      return new Response(null, { status: 204 });
    } catch (e) {
      console.error(`error: storing ping from ${prefix}: ${e}`);
      return text(503, "try later\n");
    }
  };
}

if (import.meta.main) {
  const host = env("FB_HOST", "127.0.0.1");
  const port = envNum("FB_PORT", 8787);
  const dbPath = env("FB_DB", "/var/lib/firebreak-receiver/telemetry.db");
  const retentionDays = envNum("FB_RETENTION_DAYS", 400);
  const ratePerHour = envNum("FB_RATE_PER_HOUR", 240);

  let db: Db;
  try {
    db = new Db(dbPath);
  } catch (e) {
    console.error(`fatal: cannot open ${dbPath}: ${e}`);
    Deno.exit(1);
  }

  const sweep = () => {
    try {
      const n = db.prune(retentionDays);
      if (n > 0) console.log(`retention: pruned ${n} rows`);
    } catch (e) {
      console.error(`warning: retention sweep failed: ${e}`);
    }
  };
  sweep();
  // Retention is a promise, so it runs on a timer rather than only at
  // startup — a process that stays up for a year would otherwise never
  // enforce it again.
  setInterval(sweep, 24 * 60 * 60 * 1000);

  const serve = handler(db, new RateLimiter(ratePerHour));

  const server = Deno.serve({
    hostname: host,
    port,
    onListen: () =>
      console.log(
        `firebreak-receiver listening on ${host}:${port}, db ${dbPath}, ` +
          `retention ${retentionDays}d (deno ${Deno.version.deno})`,
      ),
    // Without this an unexpected throw becomes a bare 500 with nothing
    // written down — the failure mode that is hardest to diagnose later,
    // because the only evidence is a client reporting an error you cannot
    // see. No request content is logged, only where it broke.
    onError: (e) => {
      console.error(
        `error: unhandled request failure: ${
          e instanceof Error ? e.stack ?? e.message : e
        }`,
      );
      return text(500, "error\n");
    },
  }, (req, info) => serve(req, info.remoteAddr.hostname));

  // systemd sends SIGTERM on stop and restart; close the database rather
  // than leaving a WAL to be recovered on next boot.
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    Deno.addSignalListener(sig, async () => {
      await server.shutdown();
      db.close();
      Deno.exit(0);
    });
  }
}
