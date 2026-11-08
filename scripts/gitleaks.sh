#!/usr/bin/env bash
# Secret scan for this repository (NFR-01, live check 7) with a pinned, checksum-verified gitleaks.
#
#   scripts/gitleaks.sh              scan the whole git history (what the jury runs)
#   scripts/gitleaks.sh --no-git     scan the files as they are now, committed or not
#   scripts/gitleaks.sh <args>       any other gitleaks arguments, e.g. "version"
#
# Uses gitleaks from PATH if it is the pinned version, otherwise downloads the official release once
# into .tools/ (ignored by git) and checks its SHA-256 before running it. Exit code 1 = leaks found.
# Known false positives are listed, with a reason, in .gitleaksignore.
set -euo pipefail
cd "$(dirname "$0")/.."

version=8.30.1
case "$(uname -sm)" in
    "Linux x86_64")  platform=linux_x64;   sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    "Linux aarch64") platform=linux_arm64; sha=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    "Darwin arm64")  platform=darwin_arm64; sha=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
    "Darwin x86_64") platform=darwin_x64;  sha=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
    *) echo "No pinned gitleaks build for $(uname -sm)." >&2; exit 2 ;;
esac

find_gitleaks() {
    local candidate
    for candidate in "$(command -v gitleaks 2>/dev/null || true)" ".tools/gitleaks-$version/gitleaks"; do
        [[ -n $candidate && -x $candidate ]] || continue
        [[ $("$candidate" version 2>/dev/null) == *"$version"* ]] && { echo "$candidate"; return; }
    done
}

bin=$(find_gitleaks)
if [[ -z $bin ]]; then
    archive="gitleaks_${version}_${platform}.tar.gz"
    dir=".tools/gitleaks-$version"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "Downloading gitleaks $version ($platform)" >&2
    curl --fail --location --retry 3 -sS -o "$tmp/$archive" \
        "https://github.com/gitleaks/gitleaks/releases/download/v$version/$archive" ||
        { echo "Download failed. Connect to the internet once, or install gitleaks $version yourself." >&2; exit 2; }
    if command -v sha256sum >/dev/null; then
        actual=$(sha256sum "$tmp/$archive")
    else
        actual=$(shasum -a 256 "$tmp/$archive")
    fi
    [[ ${actual%% *} == "$sha" ]] || { echo "gitleaks download has the wrong SHA-256; not running it." >&2; exit 2; }
    tar -xzf "$tmp/$archive" -C "$tmp" gitleaks
    mkdir -p "$dir"
    mv "$tmp/gitleaks" "$dir/gitleaks"
    chmod 0755 "$dir/gitleaks"
    bin="$dir/gitleaks"
fi

if (($# == 0)); then
    set -- detect --source . --no-banner --redact
elif [[ $1 == --* ]]; then
    set -- detect --source . --no-banner --redact "$@"
fi
exec "$bin" "$@"
