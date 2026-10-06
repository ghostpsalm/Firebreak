#!/usr/bin/env bash
# The pre-commit quality bar for Firebreak. Must be green before any commit.
set -euo pipefail
cd "$(dirname "$0")/.."

# Prerequisites, checked up front and all at once: a tool the gate needs and
# cannot find is a red gate, never a skip. A gate that exits 0 after printing
# "NOT checked" is a false green on every machine the tool is missing from —
# CI that lost its setup step, a fresh checkout, four recorded Factory runs
# (#23). Reported before any leg runs so the answer arrives in a second
# rather than after several minutes of clippy, and with no opt-out: an escape
# hatch is the same defect under a nicer name.
echo "== prerequisites =="
missing=()
if command -v cargo >/dev/null 2>&1; then
    cargo fmt --version >/dev/null 2>&1 || missing+=("rustfmt (rustup component add rustfmt)")
    cargo clippy --version >/dev/null 2>&1 || missing+=("clippy (rustup component add clippy)")
    # The Windows clippy leg below cross-compiles: it needs the target's std
    # (looked up in the sysroot, so this holds without rustup too) and a
    # mingw-w64 gcc, which bundled SQLite's C build calls even for a check.
    if [[ "${OS:-}" != "Windows_NT" ]]; then
        [[ -d "$(rustc --print sysroot)/lib/rustlib/x86_64-pc-windows-gnu" ]] ||
            missing+=("the x86_64-pc-windows-gnu target (rustup target add x86_64-pc-windows-gnu)")
        command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 ||
            missing+=("x86_64-w64-mingw32-gcc (mingw-w64)")
    fi
else
    missing+=("cargo (Rust toolchain — https://rustup.rs)")
fi
command -v deno >/dev/null 2>&1 || missing+=("deno (the collector under server/ — see server/README.md)")
if (( ${#missing[@]} )); then
    echo "!! the gate cannot run — missing:" >&2
    printf '!!   - %s\n' "${missing[@]}" >&2
    exit 1
fi

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
    # --all-targets on both legs, so test code is linted too. The Windows leg
    # went without it for a while, which meant Windows-only tests were never
    # linted and nobody could see they were missing (#20).
    echo "-- windows target --"
    cargo clippy --all-targets --target x86_64-pc-windows-gnu -- -D warnings
    echo "-- native (linux) target --"
    cargo clippy --all-targets -- -D warnings
fi

echo "== cargo test =="
cargo test

# The collector is a separate Deno service under server/, so none of the
# above touches it. It parses input from the internet — the last thing it
# should be is the unlinted corner of the repo.
#
# Unconditional: deno is a prerequisite above, so there is no second code
# path here that could skip the one component nothing else checks.
echo "== receiver (server/receiver) =="
(
    cd server/receiver
    deno fmt --check
    deno lint
    deno check main.ts
    deno test --allow-read --allow-write --allow-env
)

echo "== gate passed =="
