#!/usr/bin/env bash
# Rewrite the winget manifests for a release: version, date, and the real
# SHA-256 of the .exe that was published. winget rejects a manifest whose
# hash does not match the asset, so this is not optional bookkeeping.
#
#   ./install/winget/refresh.sh path/to/firebreak.exe 0.7.79
set -euo pipefail
exe="${1:?usage: refresh.sh <firebreak.exe> <version>}"
version="${2:?usage: refresh.sh <firebreak.exe> <version>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sha="$(sha256sum "$exe" | cut -d' ' -f1 | tr 'a-f' 'A-F')"

for f in "$here"/ghostpsalm.Firebreak*.yaml; do
    sed -i -E "s/^PackageVersion: .*/PackageVersion: $version/" "$f"
    sed -i -E "s|releases/download/v[^/]+/|releases/download/v$version/|" "$f"
    sed -i -E "s/^  InstallerSha256: .*/  InstallerSha256: $sha/" "$f"
    sed -i -E "s/^ReleaseDate: .*/ReleaseDate: $(date -u +%Y-%m-%d)/" "$f"
done
echo "winget manifests updated to $version (sha256 $sha)"
echo "Submit by opening a PR against microsoft/winget-pkgs:"
echo "  manifests/g/ghostpsalm/Firebreak/$version/"
