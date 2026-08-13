# Firebreak

On-demand firewall rule-usage auditor for Windows and Linux: finds unused
and over-broad rules. No service, no driver — it runs, reports, and exits.

- **Windows** correlates WFP audit events (Security log 5156/5157) with the
  live WFP filter table and `Get-NetFirewallRule`. Native Rust GUI
  (`eframe`/`egui`).
- **Linux** reads per-rule packet counters instead, because there is no
  Linux event carrying rule identity and process identity together. See
  `docs/spike-linux-port.md` for the full evidence survey behind that call.

See `docs/ARCHITECTURE.md` for the Windows design rationale (why the
Security log, not `pfirewall.log` or a packet-capture driver) and
`docs/internals.md` for the ingest pipeline.

## Stack

- Rust, edition 2021, GUI via `eframe`/`egui` 0.29.
- **Two real targets.** The Windows evidence layer (WFP, Security Event Log,
  audit policy, PowerShell rule enumeration) is `#[cfg(windows)]`; the Linux
  one lives under `src/linux/` and is `#[cfg(target_os = "linux")]`. Logic
  that is portable but only *called* from one platform is
  `#[cfg(any(windows, test))]` so it stays unit-tested from either host.
- Cross-compiled from Linux to `x86_64-pc-windows-gnu` (needs
  `mingw-w64` + `rustup target add x86_64-pc-windows-gnu`); native build on
  Windows works too.
- `rusqlite` (bundled) for the local store —
  `%ProgramData%\firebreak\firebreak.db` or `/var/lib/firebreak/firebreak.db`,
  both created private and refused if another principal owns them
  (`src/secure_dir.rs`).
- `minisign-verify` for self-update signature checking (fails closed —
  see `signing/README.md` and `src/update.rs`).

## Linux backends (`src/linux/`)

| backend | rule identity | evidence | instrument? |
|---|---|---|---|
| ufw | `### tuple ###` in `user.rules` | iptables counters, always on | no |
| firewalld | zone + service/port | Firebreak's own shadow nft table | **yes** |
| nftables | family/table/chain + expression digest | the rule's *own* counter | partly |

Detection order is ufw → firewalld → raw nftables, and the order matters:
the first two *are* nftables underneath, so checking raw nftables first
would audit their generated rules instead of the vocabulary the user wrote.

Four things to know before touching them:

- **A kernel counter is a gauge, not an event stream.** It resets on reboot,
  reload and `iptables -Z`. `linux/counters.rs` banks the old lifetime
  instead of re-adding raw readings. Never add a raw counter to a total.
- **firewalld's nft table is `flags owner`** — the kernel refuses to let any
  process add a counter to it, sudo included. Hence the shadow table, at
  input priority 300 so a hit means "firewalld allowed this".
- **Unmeasurable is not unused.** Rich rules, ipsets, protocol-only entries,
  unparseable tuples and counter-less nft rules are reported in their own
  section. Folding them into the zero-hit list would invite deleting a
  load-bearing rule.
- **"Disable" does not mean the same thing on every backend.** Windows sets
  a flag the rule survives; firewalld removes a service/port from a zone and
  can add it back; **ufw and nftables have no off switch at all, so disabling
  deletes the rule.** `linux::apply::Reversibility` carries that to the
  confirm dialog — a dialog saying "disable" over a deletion is how someone
  loses a rule they meant to keep. Apply always writes a full config backup
  first and re-reads afterwards to confirm the rule actually went.
- **Raw nftables is the only backend that edits the user's rules** for
  *collection*. Adding a
  counter takes the kernel's own JSON expression and inserts
  `{"counter": null}` before the verdict — never re-derived from text — after
  a full ruleset backup, and every touched rule is re-read and verified to be
  its original self plus exactly one counter, or the whole thing is rolled
  back. Keep all three of those. Identity is an expression digest, not the
  handle, which is renumbered on every reload.

Rule scope is a backend-supplied vocabulary (`model::ScopeVocabulary`), not
Windows' Domain/Private/Public: firewalld zones are arbitrary and ufw has no
scopes at all.

## Gate

`./scripts/gate.sh` — fmt, clippy, test. Must be green before every commit.

**On a Linux host it lints both targets**: `x86_64-pc-windows-gnu` (the
Windows code, only checkable by cross-compiling) and native (the Linux
backends). The native lint used to be skipped because Windows-only code
compiled on Linux read as dead; that is now stated as `#[cfg(windows)]`
rather than suppressed, so the native lint is signal — and it is the only
thing that lints `src/linux/` at all. Don't drop it.

CI (`.github/workflows/ci.yml`) runs the same gate on push/PR to `main`,
installing `mingw-w64` first.

## The default-inbound row

Every rule is an *exception*; the verdict in the gaps between them is what
decides whether a listening socket with no rule is exposed. `default_policy`
reads it per platform — firewalld's `filter_INPUT` tail, ufw's
`DEFAULT_INPUT_POLICY`, an nftables base-chain policy, or Windows'
per-profile `DefaultInboundAction` — and it appears in three places: the
evidence header, the socket list (replacing a bare `—`), and a synthetic row
in the rule table.

- **Never assumed, per host.** Raw nftables is commonly `policy accept`, and
  a Windows profile with the firewall switched off is open whatever its
  configured action says. Unreadable is reported as unknown, never as a deny
  — claiming a deny that is not there tells someone an exposed port is shut.
- **The synthetic row is not a rule**, and `RuleSource::DefaultPolicy` is
  what enforces that: no checkbox, no review circle, no scope chips, and
  excluded from plans, quick actions, the zero-hit list, the CSV export and
  the rule count. `hits_known` is false — counters sit *after* the firewall's
  verdict, so refused traffic is counted nowhere, and zero would read as
  "measured, never matched".
- **Windows keeps one per profile and they need not agree**, so it emits one
  row per distinct verdict rather than averaging them into a single claim.

## Auto-refresh (Linux)

The open window re-reads counters every 5s. A *full* pass costs seconds —
one `firewall-cmd` per zone and per service at ~240ms each — while the
counter read is ~7ms, so the tick re-reads counters against the vocabulary
cached by the last full pass (`firewalld::cached_zones`, `linux::recount`).
Full passes happen on open, on Refresh now, and after an apply. The tick
stands down whenever a change is staged, the drawer or a menu is open, or an
apply is in flight: `absorb` replaces every row and clears the selection, so
refreshing then would discard the user's work. Windows has no auto-refresh —
a refresh there re-ingests the Security log.

## Portable audit bundles

Two bundle formats, because the two platforms have different evidence to
hand over. Windows ships a **Security log** (`collect.rs`) for the reviewing
machine to replay. Linux ships **totals** (`review.rs`) — a kernel counter is
a gauge, so there is no event stream to give, only what has been banked.

`firebreak --collect [path]` writes one; `firebreak --review <path>` opens it
on either platform (`--no-ui` prints it instead, for a headless host). The
reader needs no privileges and never touches the local firewall.

- **Review mode is read-only, and not merely as a courtesy.** A bundle's rule
  names belong to the machine it came from; Windows names are InstanceIDs, so
  applying them here could edit a *local* rule that happens to share a name.
  `App::read_only` blocks apply, enable, stop and reviewed marks, and a band
  names the source host so a review window is never mistaken for a live one.
- **The bundle carries its own `ScopeVocabulary`**, and review mode *adopts*
  it (`model::adopt_vocabulary`) rather than `set_vocabulary`'s first-call-
  wins, which exists to stop a backend redefining scopes mid-run. Rendering
  another host's zones against this host's list is the one case where
  replacing is correct.
- **Unknown must survive the trip.** A rule the collecting host could not
  measure travels as `hits: None`, not `0` — zero is the list a reviewer works
  through deleting things from.

## Telemetry (`src/telemetry.rs`, `server/`)

An opt-in daily usage ping, and the collector that receives it. `TELEMETRY.md`
is the public statement of what is sent; keep it in step with `Payload`, and
with the consent dialog, which lists the same fields in prose.

The tool runs as admin/root over someone's firewall, so the bar is *auditable*
rather than merely disclosed. Five properties carry that, and none of them is
decoration:

- **`ENDPOINT` empty means the whole feature is off** — no prompt, no stored
  state, no request. It is empty in the repo, so a source build cannot report.
  Same fail-closed shape as `TRUSTED_PUBLIC_KEY`. `consent()` returns
  `Unasked` when unconfigured, which is what enforces it.
- **`--telemetry preview` prints the real payload**, from the same `build()`
  the sender uses. A preview that merely describes the payload is worth
  nothing; don't let the two paths diverge.
- **The payload is a closed set of low-cardinality facts**, every one assembled
  here from an enumerated source. `Feature` is an enum precisely so there is
  no way to record an arbitrary string. `payload_shape_is_pinned` fails if a
  field appears or vanishes — that failure is a prompt to update the docs and
  the dialog, not to update the assertion.
- **Ages and run counts are buckets, not numbers.** The install ID rotates
  every 90 days; an exact age would let a new ID be stitched onto the old one
  and defeat the rotation. Never "improve" these into integers.
- **Denying erases the identity.** `set_consent(Denied)` deletes the install
  ID, enrolment date and run count — a "no" must leave nothing behind that a
  later bug could send.

Be accurate about the IP. The payload carries no address, but the collector
sees one like any web server. Saying "we never send your IP" and stopping
there is the exact dishonesty this feature is built to avoid, so the dialog,
the `--help` text, `README.md` and `TELEMETRY.md` all state the truncation
(`/24`, `/48`) instead. nginx's access log is off for the same reason: a log
beside the database must not hold what the database is careful not to.

On the server side (`server/receiver`, `server/terraform`): unknown JSON
fields are rejected outright rather than dropped, every field is checked
against a closed vocabulary or a length cap, the one-row-per-install-per-day
rule is a unique index rather than a trust in the client, and
`X-Forwarded-For` is read from the **end** — nginx's
`$proxy_add_x_forwarded_for` appends the real peer, so
taking the first entry would let a client choose what is recorded about it.

**Deployment is automated but narrow.** A push to `main` that passes the gate
deploys the collector (`.github/workflows/ci.yml`, `deploy` job). The key CI
holds is installed with `command="…/firebreak-deploy",restrict`, so it can
redeploy the collector and nothing else — a stolen secret is not a shell on
the box. The script extracts only three named members from the archive,
typechecks before installing, skips the restart when the code is unchanged,
and rolls back if the health check fails. Keep all four. **Infrastructure is
deliberately not applied from CI** — that needs create/destroy credentials
and remote state, and stays a decision made at a keyboard.

The receiver is a **Deno/TypeScript** service, not Rust: there is no build
step, so deploying it is a file copy and a restart, and the runtime enforces
its own sandbox (`--no-remote`, `--allow-net` scoped to one port,
`--allow-read`/`--allow-write` scoped to one directory) rather than relying on
systemd alone. Its tests are `*_test.ts` beside each module — the Deno idiom,
and the one place this repo's inline-tests convention does not apply.
**`./scripts/gate.sh` covers it too**, skipping with a loud warning when Deno
is absent so a Windows contributor is not blocked; CI installs Deno so the
checks are never silently skipped there.

## Installing

`install/` holds the two one-line installers (`install.sh` for Linux,
`install.ps1` for Windows) and the winget manifests. Both scripts verify the
release signature against the same key the binary pins, abort on a mismatch,
and — when no verifier is present — continue but say so and print the
SHA-256 rather than implying a check that did not happen.

Neither script is a packaging afterthought: they exist because Firebreak
needs privilege, so "download and double-click" cannot work. Linux gets a
desktop entry (`--install-desktop`, elevating through pkexec at launch);
Windows gets a Start Menu shortcut whose target carries the
`requireAdministrator` manifest. The winget manifests are **not** submitted
by any script — publishing there is a PR against `microsoft/winget-pkgs` and
an owner's decision; run `install/winget/refresh.sh` first so the hash
matches the published asset.

## Dialogs

About and Updates are the same 360px modal in two states — one `scrim` +
`dialog_window` + `indented` helper set in `ui/paint.rs`, so they cannot
drift apart. Updates is its own window rather than a strip inside About
because an update is a task with a course to run (check → download → verify
→ install → restart) and each state has something to say; About only says
what the build is, and links across.

The progress bar is drawn only when the transfer's size is actually known —
`Content-Length` on Windows, a HEAD probe on Linux. Unknown size gets a
sweeping indeterminate block, never a filled bar, because a bar that reads
"done" while bytes are still arriving is worse than no bar.

## Conventions

- **Commits**: short imperative summary line, no period, occasionally with
  an issue number in parens — `Fix X (#3)`, `Add Y; bump to 0.5.9`. A
  version bump commit stands alone (`Bump version to 0.7.0`) — it is a
  release decision, never bundled into a feature commit. Multi-step work
  is numbered inline, e.g. `#7 de-PowerShell (1/n): ...` / `(2/n): ...`.
  No AI attribution trailers.
- **Tests are inline**, `#[cfg(test)] mod tests` at the bottom of the file
  they cover, not a separate `tests/` tree.
- **Dead code is deleted, not `#[allow]`ed** — with two known, deliberate
  exceptions right now: `Sort::Enabled` (`src/ui.rs`) has full comparator
  logic but no table header wires it up yet, and
  `ChangeKind::Profiles::was_enabled` (`src/ui.rs`) is captured for a
  revert-to-prior-scope path that doesn't exist yet. Both are marked
  `#[allow(dead_code)]` with a comment rather than removed — worth a
  follow-up issue if you're looking for one.
- **Release builds are speed-tuned**, not size-tuned (`Cargo.toml`
  `[profile.release]`: fat LTO, one codegen unit, `panic = "abort"`) — the
  Security-log XML parsing and SQLite ingest hot paths and UI frame times
  matter more than a few extra MB on disk.

## Risk profile

- **Requires admin (`requireAdministrator` manifest) by design**, not
  oversight — `docs/least-privilege.md` is the standing survey of why:
  every read in the evidence loop (Security log, audit policy, WFP filter
  enum, the ACL-protected local DB) is admin-bound. Don't "fix" this
  without reading that doc first; it's a considered verdict, not drift.
  Linux needs root for the same reason: ufw's rule files, the iptables
  counters and `/proc/<pid>/exe` for other users' processes. Without it
  process attribution *silently shrinks* rather than failing, which is why
  the Linux path refuses to run unprivileged instead of degrading.
- **On firewalld, collecting means writing to the kernel firewall.** The
  Windows side never does this — it only reads. The shadow table is
  therefore opt-in (`--enable-only`) and removable (`--restore-audit`), a
  plain run never installs it, and the table carries no verdicts so it
  cannot change any packet's fate. Keep all four of those properties.
- **Self-update is a supply-chain surface**: the in-app updater downloads
  a release asset and its `.minisig` signature, verifying against a pinned
  public key (`TRUSTED_PUBLIC_KEY` in `src/update.rs`) before installing.
  This must fail closed — never loosen it to make an update path work.
  The private signing key lives only in `signing/` (git-ignored); see
  `signing/README.md` before touching anything release-signing-related.
- **No retroactive data**: the tool's entire value proposition depends on
  audit events that only start accruing once "Filtering Platform
  Connection" auditing is enabled. Code that touches collection timing,
  the checkpoint (`store.rs`), or ingest idempotency is higher-consequence
  than it looks — a bug there can silently under- or double-count real
  security evidence, not just misrender a UI.
- License is proprietary (`LICENSE`) — this is closed-source, not an
  open-source project structured like one.
