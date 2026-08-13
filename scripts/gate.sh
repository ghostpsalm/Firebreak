#!/usr/bin/env bash
# The pre-commit quality bar for Firebreak. Must be green before any commit.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== cargo fmt --check =="
cargo fmt --check

echo "== cargo clippy =="
if [[ "${OS:-}" == "Windows_NT" ]]; then
    cargo clippy --all-targets -- -D warnings
else
    # Two real deployment targets, so lint both. The Windows target is the one
    # the bulk of the code is written for and can only be checked by
    # cross-compiling (needs the x86_64-pc-windows-gnu rustup target and a
    # mingw-w64 gcc); the native target is the Linux build and its backends.
    #
    # Native linting used to be skipped because Windows-only code compiled on
    # Linux read as dead. That is now expressed as #[cfg(windows)] instead, so
    # the native lint is signal again — and it is the ONLY thing that lints the
    # Linux backends at all. Do not drop it.
    echo "-- windows target --"
    cargo clippy --target x86_64-pc-windows-gnu -- -D warnings
    echo "-- native (linux) target --"
    cargo clippy --all-targets -- -D warnings
fi

echo "== cargo test =="
cargo test

# The collector is a separate Deno service under server/, so none of the
# above touches it. It parses input from the internet — the last thing it
# should be is the unlinted corner of the repo.
#
# Skipped with a warning rather than failing when Deno is absent: a Windows
# contributor building the client should not be blocked by the collector's
# toolchain. CI has Deno, so the checks are never quietly skipped there.
echo "== receiver (server/receiver) =="
if command -v deno >/dev/null 2>&1; then
    (
        cd server/receiver
        deno fmt --check
        deno lint
        deno check main.ts
        deno test --allow-read --allow-write --allow-env
    )
else
    echo "!! deno not installed — collector NOT checked (see server/README.md)"
fi

echo "== gate passed =="
