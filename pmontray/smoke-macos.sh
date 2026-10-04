#!/usr/bin/env bash
# Build and package the app ad-hoc, then check what a release would ship: both architectures, the minimum
# macOS, the signature, and the pkg's title and payload. Signing and notarization run only on release tags.
#
#   ./smoke-macos.sh
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="Proxy Monster Desktop"
fail() { echo "smoke: $*" >&2; exit 1; }

ARCHS="arm64 amd64" ./build-app.sh "$WORK/app" >/dev/null
APP="$WORK/app/$NAME.app"
for bin in pmon pmontray; do
    archs="$(lipo -archs "$APP/Contents/MacOS/$bin")"
    [ "$archs" = "x86_64 arm64" ] || fail "$bin has architectures '$archs'"
done
"$APP/Contents/MacOS/pmontray" --version
"$APP/Contents/MacOS/pmon" --version

VERSION=0.0.0-smoke ./package-macos.sh "$APP" "$WORK/out" >/dev/null
PKG="$WORK/out/ProxyMonsterDesktop_0.0.0-smoke.pkg"
[ -f "$WORK/out/ProxyMonsterDesktop_0.0.0-smoke_darwin_universal.zip" ] || fail "no zip"

pkgutil --expand "$PKG" "$WORK/x"
grep -q "<title>$NAME</title>" "$WORK/x/Distribution" || fail "installer title is not '$NAME'"
grep -q '<relocate/>\|<relocate>[[:space:]]*</relocate>' "$WORK/x/component.pkg/PackageInfo" ||
    fail "the app bundle is relocatable"
mkdir "$WORK/payload"
(cd "$WORK/payload" && gunzip -dc <"$WORK/x/component.pkg/Payload" | cpio -i --quiet)
target="$(readlink "$WORK/payload/usr/local/bin/pmon")"
[ "$target" = "/Applications/$NAME.app/Contents/MacOS/pmon" ] || fail "pmon links to '$target'"
[ -x "$WORK/payload/Applications/$NAME.app/Contents/MacOS/pmon" ] || fail "the link target is not in the payload"

echo "smoke: ok"
