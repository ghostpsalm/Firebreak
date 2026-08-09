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

Three things to know before touching them:

- **A kernel counter is a gauge, not an event stream.** It resets on reboot,
  reload and `iptables -Z`. `linux/counters.rs` banks the old lifetime
  instead of re-adding raw readings. Never add a raw counter to a total.
- **firewalld's nft table is `flags owner`** — the kernel refuses to let any
  process add a counter to it, sudo included. Hence the shadow table, at
  input priority 300 so a hit means "firewalld allowed this".
- **Unmeasurable is not unused.** Rich rules, ipsets, protocol-only entries
  and unparseable tuples are reported in their own section. Folding them
  into the zero-hit list would invite deleting a load-bearing rule.

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
