#!/usr/bin/env bash
# Write <dir>/checksums.txt for a release: the release's current lines for other files, plus fresh hashes of
# <dir>/<prefix>*. Each release job owns the lines for its own prefix, so a re-run of either replaces only
# its own rows.
#
#   release-checksums.sh <tag> <prefix> <dir>
set -euo pipefail

TAG="$1" PREFIX="$2" DIR="$3"
: >"$DIR/checksums.other"
if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' | grep -qx checksums.txt; then
    gh release download "$TAG" --repo "$GITHUB_REPOSITORY" -p checksums.txt -O - |
        awk -v p="$PREFIX" 'index($2, p) != 1' >"$DIR/checksums.other"
fi
(cd "$DIR" && shasum -a 256 "$PREFIX"* | cat checksums.other - | sort -k2 >checksums.txt && rm checksums.other)
cat "$DIR/checksums.txt"
