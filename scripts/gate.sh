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
    # Firebreak is a Windows-only app (heavy #[cfg(windows)] use). Linting the
    # native Linux target flags huge swaths of real code as dead, since none
    # of it is reachable outside a Windows build. Lint the actual deployment
    # target instead — requires the x86_64-pc-windows-gnu rustup target and
    # a mingw-w64 gcc (`rustup target add x86_64-pc-windows-gnu`).
    cargo clippy --target x86_64-pc-windows-gnu -- -D warnings
fi

echo "== cargo test =="
cargo test

echo "== gate passed =="
