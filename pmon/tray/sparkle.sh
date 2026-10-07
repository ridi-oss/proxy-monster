#!/usr/bin/env bash
# Unpacks the pinned Sparkle release into a directory (framework and bin/sign_update), from a checksummed
# download cache. Sourced by build-app.sh; run directly by the release workflow to sign the appcast.
#
#   sparkle.sh <dir>
set -euo pipefail

SPARKLE_VERSION=2.10.0
SPARKLE_SHA256=c2bf58aa8387266ac179357b1415d6f2635f044da8be41042af32425dae6da0c

fetch_sparkle() {
    local cache="${XDG_CACHE_HOME:-$HOME/Library/Caches}/proxy-monster"
    local tarball="$cache/Sparkle-$SPARKLE_VERSION.tar.xz"
    if [ ! -f "$tarball" ]; then
        mkdir -p "$cache"
        curl -fsSL -o "$tarball.part" \
            "https://github.com/sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION/Sparkle-$SPARKLE_VERSION.tar.xz"
        mv "$tarball.part" "$tarball"
    fi
    echo "$SPARKLE_SHA256  $tarball" | shasum -a 256 -c - >/dev/null
    mkdir -p "$1"
    tar -xJf "$tarball" -C "$1"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    fetch_sparkle "$1"
fi
