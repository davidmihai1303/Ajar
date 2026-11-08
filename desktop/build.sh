#!/usr/bin/env bash
# Build the Ajar desktop app for Ubuntu (AppImage + .deb, x86-64 and ARM64) inside a Linux
# container, then copy the four files to release/downloads/, where the running Ajar app offers
# them for download (docker-compose mounts that folder read-only).
#
#   desktop/build.sh            # needs Docker; works on Linux and macOS
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
out="$root/release/downloads"

docker run --rm \
  -v "$here":/desktop \
  -w /desktop \
  -e USE_SYSTEM_FPM=true \
  -e ELECTRON_CACHE=/desktop/.cache/electron \
  -e ELECTRON_BUILDER_CACHE=/desktop/.cache/electron-builder \
  node:22-bookworm \
  bash -euo pipefail -c '
    apt-get update -qq && apt-get install -y -qq ruby ruby-dev build-essential >/dev/null
    gem install --no-document fpm -v 1.15.1 >/dev/null
    npm ci --no-audit --no-fund --ignore-scripts
    rm -rf dist
    npx electron-builder --linux AppImage deb --x64 --arm64 --publish never
    chown -R '"$(id -u):$(id -g)"' dist .cache node_modules
  '

mkdir -p "$out"
rm -f "$out"/Ajar-*
cp "$here"/dist/Ajar-*.AppImage "$here"/dist/Ajar-*.deb "$out"/
ls -la "$out"
