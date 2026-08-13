import { assert, assertEquals } from "jsr:@std/assert@1";

import { clientIp, featuresCsv, truncate, validate } from "./ping.ts";

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

const good = () => structuredClone(GOOD);

/** The reason a rejection gives, or null if it was accepted. */
function reject(p: unknown): string | null {
  const r = validate(p);
  return r.ok ? null : r.reason;
}

Deno.test("a well-formed ping is accepted", () => {
  assertEquals(reject(good()), null);
});

Deno.test("unknown fields are refused outright", () => {
  const p = { ...good(), hostname: "secret-box" };
  assert(reject(p)?.includes("unexpected key set"));
});

Deno.test("a missing field is refused, not defaulted", () => {
  const p = good() as Record<string, unknown>;
  delete p.board_vendor;
  assert(reject(p)?.includes("unexpected key set"));
});

Deno.test("a future schema is refused rather than guessed", () => {
  assertEquals(reject({ ...good(), schema: 2 }), "unsupported schema 2");
});

Deno.test("install_id must be what the client mints", () => {
  for (
    const bad of [
      "",
      "short",
      "0123456789ABCDEF0123456789ABCDEF", // uppercase
      "0123456789abcdef0123456789abcdeg", // non-hex
      "0123456789abcdef0123456789abcdef0", // too long
    ]
  ) {
    assertEquals(
      reject({ ...good(), install_id: bad }),
      "bad field: install_id",
      `should have rejected ${JSON.stringify(bad)}`,
    );
  }
});

Deno.test("vocabularies are closed", () => {
  const cases: [string, string][] = [
    ["os", "plan9"],
    ["backend", "pf"],
    ["age", "3 days"],
    ["runs", "12"],
  ];
  for (const [field, value] of cases) {
    assertEquals(reject({ ...good(), [field]: value }), `bad field: ${field}`);
  }
});

Deno.test("features outside the vocabulary are refused", () => {
  const p = { ...good(), features: ["apply", "exfiltrate"] };
  assertEquals(reject(p), "bad field: features");
});

Deno.test("oversize and control characters are refused", () => {
  assertEquals(
    reject({ ...good(), board_vendor: "x".repeat(65) }),
    "bad field: board_vendor",
  );
  // Written as escapes on purpose: a literal control byte in a source file
  // is invisible in review and turns the file binary to grep.
  assertEquals(
    reject({ ...good(), os_name: "Fedora\u000aLinux" }),
    "bad field: os_name",
  );
  assertEquals(
    reject({ ...good(), os_name: "Fedora\u0000Linux" }),
    "bad field: os_name",
  );
  assertEquals(
    reject({ ...good(), board_vendor: "ASUSTeK\u007f" }),
    "bad field: board_vendor",
  );
  // a plain space is not a control character and must still be allowed
  assertEquals(reject({ ...good(), os_name: "Fedora Linux 44" }), null);
});

Deno.test("wrong types are refused rather than coerced", () => {
  assertEquals(
    reject({ ...good(), virtual_machine: "false" }),
    "bad field: virtual_machine",
  );
  assertEquals(reject({ ...good(), os_version: 44 }), "bad field: os_version");
  assertEquals(reject({ ...good(), features: "apply" }), "bad field: features");
  assert(reject("a string") !== null);
  assert(reject(null) !== null);
  assert(reject([1, 2, 3]) !== null);
});

Deno.test("features are sorted and deduplicated", () => {
  const r = validate({ ...good(), features: ["review", "apply", "apply"] });
  assert(r.ok);
  assertEquals(featuresCsv(r.payload), "apply,review");
});

Deno.test("addresses are reduced to a prefix", () => {
  assertEquals(truncate("203.0.113.47"), "203.0.113.0");
  assertEquals(truncate("8.8.8.8"), "8.8.8.0");
  assertEquals(truncate("2001:db8:1234:5678::1"), "2001:db8:1234::");
});

Deno.test("a spoofed X-Forwarded-For cannot win", () => {
  // nginx and Caddy both append the real peer, so the last entry is the
  // only trustworthy one.
  assertEquals(clientIp("9.9.9.9, 203.0.113.47", "127.0.0.1"), "203.0.113.47");
  assertEquals(clientIp(null, "127.0.0.1"), "127.0.0.1");
  assertEquals(clientIp("not-an-ip", "127.0.0.1"), "127.0.0.1");
  // junk that merely looks address-ish must not be stored
  assertEquals(clientIp("9.9.9.999", "127.0.0.1"), "127.0.0.1");
  assertEquals(clientIp("x".repeat(200), "127.0.0.1"), "127.0.0.1");
});
