# Firebreak

On-demand Windows Firewall rule-usage auditor: correlates WFP audit events
(Security log 5156/5157) with the live WFP filter table and
`Get-NetFirewallRule` to find unused and over-broad rules. No service, no
driver — a native Rust GUI (`eframe`/`egui`) that runs, reports, and exits.
See `docs/ARCHITECTURE.md` for the design rationale (why the Security log,
not `pfirewall.log` or a packet-capture driver) and `docs/internals.md` for
the ingest pipeline.

## Stack

- Rust, edition 2021, GUI via `eframe`/`egui` 0.29.
- **Windows-only in practice.** Almost every real code path is
  `#[cfg(windows)]` — WFP, the Security Event Log, audit policy, elevation.
  The non-Windows fallback paths exist only so the pure logic (parsing,
  scoping, aggregation) can be unit-tested from Linux.
- Cross-compiled from Linux to `x86_64-pc-windows-gnu` (needs
  `mingw-w64` + `rustup target add x86_64-pc-windows-gnu`); native build on
  Windows works too. `cargo test` runs cross-platform — the tests exercise
  the `#[cfg(not(windows))]`-safe logic, not the WinAPI calls themselves.
- `rusqlite` (bundled) for the local `%ProgramData%\firebreak\firebreak.db`.
- `minisign-verify` for self-update signature checking (fails closed —
  see `signing/README.md` and `src/update.rs`).

## Gate

`./scripts/gate.sh` — fmt, clippy, test. Must be green before every commit.

**Clippy lints the `x86_64-pc-windows-gnu` target, not native Linux.**
Because of the `#[cfg(windows)]` gating above, linting the native target
reports huge swaths of real, used code as dead — it's noise, not signal.
The gate detects the host and lints natively only when actually run on
Windows.

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
