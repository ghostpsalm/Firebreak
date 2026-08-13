/**
 * The payload, and the rules about what may be stored.
 *
 * Two jobs, kept separate on purpose:
 *
 * 1. **Refuse anything that is not the agreed payload.** An exact key set,
 *    a length cap and a closed vocabulary per field. A collector that
 *    accepts whatever it is sent will eventually store whatever someone
 *    feels like sending it, and it is the operator who then owns that data.
 * 2. **Coarsen what is kept.** The client never sends an address, but the
 *    socket has one, and an IP is personal data. It is truncated here —
 *    before it reaches the database — so the full address exists only for
 *    the life of the request.
 *
 * TypeScript types vanish at runtime, so nothing below is inferred from a
 * type: every field is checked against a value that exists at runtime.
 */

/** The only payload version this build understands. */
export const SCHEMA = 1;

/** Cap on any incoming string. Matches the client's own cap, so a
 * well-behaved client never trips it. */
const MAX_FIELD = 64;

/**
 * Closed vocabularies. A value outside these is a rejected request, not a
 * stored oddity — this is what keeps the table groupable a year from now.
 *
 * **These mirror the client**: `AGES` and `RUNS` are the return values of
 * `age_bucket` and `run_bucket`, and `FEATURES` is the `Feature` enum, all
 * in Firebreak's own `src/telemetry.rs`. Changing a bucket there without
 * changing it here turns every ping from the new build into a 400. Deploy
 * the widened list here *first*, then ship the client.
 */
const OS = ["windows", "linux"];
const BACKENDS = ["wfp", "ufw", "firewalld", "nftables", "none"];
const AGES = ["0", "1-7", "8-30", "31-90", "91-365", "365+"];
const RUNS = ["1", "2-5", "6-20", "21-100", "100+"];
const FEATURES = [
  "apply",
  "collect",
  "desktop",
  "enable_only",
  "headless",
  "review",
  "support",
  "update",
];

/** Exactly the keys a payload may have — no more, no fewer. */
const STRING_FIELDS = [
  "install_id",
  "app_version",
  "os",
  "os_name",
  "os_version",
  "arch",
  "backend",
  "board_vendor",
  "age",
  "runs",
] as const;

const ALL_KEYS = [
  "schema",
  ...STRING_FIELDS,
  "virtual_machine",
  "features",
].sort();

export type Payload = {
  schema: number;
  install_id: string;
  app_version: string;
  os: string;
  os_name: string;
  os_version: string;
  arch: string;
  backend: string;
  board_vendor: string;
  virtual_machine: boolean;
  age: string;
  runs: string;
  features: string[];
};

export type Validated =
  | { ok: true; payload: Payload }
  | { ok: false; reason: string };

/**
 * Check every field. Deliberately exhaustive rather than clever: this is
 * the whole trust boundary.
 */
export function validate(value: unknown): Validated {
  const bad = (reason: string): Validated => ({ ok: false, reason });

  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return bad("not an object");
  }
  const o = value as Record<string, unknown>;

  // The equivalent of serde's deny_unknown_fields: an extra key is a
  // rejection, not something quietly dropped. The collector must not become
  // a place to put arbitrary data.
  const keys = Object.keys(o).sort();
  if (keys.length !== ALL_KEYS.length || keys.some((k, i) => k !== ALL_KEYS[i])) {
    return bad(`unexpected key set: ${keys.join(",")}`);
  }

  if (o.schema !== SCHEMA) return bad(`unsupported schema ${o.schema}`);

  for (const f of STRING_FIELDS) {
    if (typeof o[f] !== "string") return bad(`bad field: ${f}`);
  }
  if (typeof o.virtual_machine !== "boolean") {
    return bad("bad field: virtual_machine");
  }

  // 128 bits of lowercase hex, exactly as the client mints it
  if (!/^[0-9a-f]{32}$/.test(o.install_id as string)) {
    return bad("bad field: install_id");
  }

  const vocab: [string, string[]][] = [
    ["os", OS],
    ["backend", BACKENDS],
    ["age", AGES],
    ["runs", RUNS],
  ];
  for (const [field, allowed] of vocab) {
    if (!allowed.includes(o[field] as string)) return bad(`bad field: ${field}`);
  }

  // Free-ish text, but bounded and printable. os_name and board_vendor come
  // from firmware and /etc/os-release, which are not a promise.
  for (const f of ["app_version", "os_name", "os_version", "arch", "board_vendor"]) {
    const v = o[f] as string;
    const chars = [...v];
    // Explicit code points rather than a control-character regex: the escape
    // is easy to get subtly wrong, and this is the check that stops a
    // firmware string putting a newline into someone's database.
    const control = chars.some((ch) => {
      const c = ch.codePointAt(0)!;
      return c < 0x20 || c === 0x7f;
    });
    if (chars.length > MAX_FIELD || control) return bad(`bad field: ${f}`);
  }

  if (!Array.isArray(o.features)) return bad("bad field: features");
  if (o.features.length > FEATURES.length) return bad("bad field: features");
  if (!o.features.every((f) => typeof f === "string" && FEATURES.includes(f))) {
    return bad("bad field: features");
  }

  return { ok: true, payload: o as unknown as Payload };
}

/**
 * Features as one sorted, de-duplicated, comma-separated cell. Every value
 * is from FEATURES, so there is nothing here to escape.
 */
export function featuresCsv(p: Payload): string {
  return [...new Set(p.features)].sort().join(",");
}

/**
 * Which address to attribute a request to.
 *
 * Both nginx (`$proxy_add_x_forwarded_for`) and Caddy *append* the immediate
 * peer to any `X-Forwarded-For` the client sent, so the header reads
 * `<whatever the client claimed>, <real peer>`. The last entry is therefore
 * the only trustworthy one — taking the first, which is the usual advice for
 * an edge server, would let any client choose what gets recorded about it.
 */
export function clientIp(forwardedFor: string | null, peer: string): string {
  if (forwardedFor) {
    const last = forwardedFor.split(",").pop()?.trim();
    if (last && isAddress(last)) return last;
  }
  return peer;
}

/**
 * Is this something we are willing to treat as an address at all?
 *
 * Bounded and character-restricted rather than fully parsed: whatever passes
 * here gets truncated and stored, so "looks vaguely like an address" is not
 * good enough — a header is attacker-controlled input.
 */
function isAddress(s: string): boolean {
  if (s.length > 45) return false; // longest possible IPv6 text form
  return s.includes(":") ? /^[0-9a-fA-F:.]+$/.test(s) : isIpv4(s);
}

function isIpv4(s: string): boolean {
  const parts = s.split(".");
  return parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/**
 * Reduce an address to a network prefix: /24 for IPv4, /48 for IPv6.
 *
 * Enough to tell countries and networks apart, not enough to identify a
 * household. The full address is never written anywhere — not to the
 * database, and not to a log.
 */
export function truncate(ip: string): string {
  if (isIpv4(ip)) {
    const o = ip.split(".");
    return `${o[0]}.${o[1]}.${o[2]}.0`;
  }
  // IPv6: keep the first three groups (48 bits). Expanding "::" properly is
  // not needed — everything after the third group is dropped either way.
  const head = ip.split("%")[0].split(":");
  const kept = head.slice(0, 3).map((g) => g === "" ? "0" : g);
  while (kept.length < 3) kept.push("0");
  return `${kept.join(":")}::`;
}
