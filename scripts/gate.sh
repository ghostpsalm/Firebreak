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

# The collector is its own crate under server/, so none of the above touches
# it. It is a service that parses input from the internet — the last thing it
# should be is the unlinted corner of the repo.
echo "== receiver (server/receiver) =="
(
    cd server/receiver
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
)

echo "== gate passed =="
