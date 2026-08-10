#!/bin/sh
# Firebreak installer for Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/ghostpsalm/Firebreak/main/install/install.sh | sudo sh
#
# Installs the latest released binary to /usr/local/bin/firebreak and adds a
# desktop entry, so Firebreak appears in the application menu and asks for
# authorisation when launched.
#
# What it will not do: install something it could not check. If minisign or
# rsign is present the release signature is verified against the key pinned
# below and a mismatch aborts. If neither is present the install continues —
# refusing would only push people to `curl | sh` something worse — but it
# says so plainly and prints the SHA-256 to compare against the release page.
#
# Options:
#   --prefix DIR   install directory (default /usr/local/bin)
#   --no-desktop   skip the application-menu entry
#   --uninstall    remove the binary, the entry and the launcher

set -eu

REPO="ghostpsalm/Firebreak"
ASSET="firebreak-linux-x86_64"
# The public key release assets are signed with — the same one pinned in the
# binary as TRUSTED_PUBLIC_KEY. A signature that does not verify against this
# is not a Firebreak release, whatever it claims.
PUBKEY="RWQqalkBegJ2f0SS5E5JvOJX6WnuZfhaCKYiSdOrmugiiZoufxFMTplC"

PREFIX="/usr/local/bin"
DESKTOP=1
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --no-desktop) DESKTOP=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root — it installs to $PREFIX and needs root anyway to audit the firewall.
Try:  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install/install.sh | sudo sh"

TARGET="$PREFIX/firebreak"

if [ "$UNINSTALL" = 1 ]; then
    [ -x "$TARGET" ] && "$TARGET" --uninstall-desktop 2>/dev/null || true
    rm -f "$TARGET"
    say "Removed $TARGET and its desktop entry. The database at /var/lib/firebreak was left alone."
    exit 0
fi

case "$(uname -m)" in
    x86_64|amd64) ;;
    *) die "no release build for $(uname -m) — Firebreak publishes x86_64 only. Build from source instead." ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

BASE="https://github.com/$REPO/releases/latest/download"
say "Downloading the latest Firebreak…"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$TMP/$ASSET" "$BASE/$ASSET" \
    || die "could not download $BASE/$ASSET"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$TMP/$ASSET.minisig" "$BASE/$ASSET.minisig" \
    || say "note: no signature published alongside this release"

# Verify with whichever verifier is on the box. Both take the same arguments.
VERIFIER=""
for v in minisign rsign; do
    if command -v "$v" >/dev/null 2>&1; then VERIFIER="$v"; break; fi
done

if [ -n "$VERIFIER" ] && [ -f "$TMP/$ASSET.minisig" ]; then
    say "Verifying the signature with $VERIFIER…"
    printf 'untrusted comment: firebreak\n%s\n' "$PUBKEY" > "$TMP/firebreak.pub"
    "$VERIFIER" verify -p "$TMP/firebreak.pub" -x "$TMP/$ASSET.minisig" -m "$TMP/$ASSET" >/dev/null 2>&1 \
        || "$VERIFIER" verify -p "$TMP/firebreak.pub" -x "$TMP/$ASSET.minisig" "$TMP/$ASSET" >/dev/null 2>&1 \
        || die "the download did NOT verify against Firebreak's signing key — refusing to install it.
This is what that check is for: do not run the downloaded file."
    say "Signature verified."
else
    say ""
    say "NOT VERIFIED: neither minisign nor rsign is installed, so the release"
    say "signature was not checked. The download came over HTTPS from GitHub."
    if command -v sha256sum >/dev/null 2>&1; then
        say "SHA-256 of what was downloaded — compare it against the release page:"
        sha256sum "$TMP/$ASSET" | awk '{print "  " $1}'
    fi
    say "To check properly: install minisign and re-run this script."
    say ""
fi

install -d "$PREFIX"
install -m 0755 "$TMP/$ASSET" "$TARGET"
say "Installed $TARGET"

if [ "$DESKTOP" = 1 ]; then
    "$TARGET" --install-desktop || say "note: the desktop entry could not be installed; the binary is still usable from a terminal"
fi

say ""
say "Firebreak is installed. It needs root — that is why the menu entry asks"
say "for authorisation. From a terminal:  sudo firebreak"
