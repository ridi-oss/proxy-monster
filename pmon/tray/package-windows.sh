#!/usr/bin/env bash
# Build Proxy Monster Desktop for Windows and package it as a per-user MSI, on macOS or Linux.
#
#   ./package-windows.sh <amd64|arm64> <out-dir>   -> <out-dir>/bin-<arch>/ and ProxyMonsterDesktop_<version>_windows_<arch>.msi
#
# Environment:
#   VERSION             version in the binaries and the MSI (required, x.y.z)
#   BIN                 package the pmontray.exe and pmon.exe in this directory instead of building them, which is
#                       how sign-windows.sh packages signed binaries
#   NO_MSI              set, stop after the binaries
#   FEED_URL            WinSparkle appcast URL; unset, the app has no updater
#   SPARKLE_PUBLIC_KEY  the EdDSA public key updates are signed with; required with FEED_URL
#
# Needs Go (unless BIN) and msitools' wixl 0.106 or later (brew install msitools); older ones crash on <Environment>. wixl has no ARM64 target, so
# the ARM64 MSI is an x64 package holding ARM64 binaries: a per-user install under %LOCALAPPDATA% that writes
# only HKCU does not depend on the package's platform.
set -euo pipefail

cd "$(dirname "$0")"
ARCH="$1"
OUT="$2"
: "${VERSION:?VERSION is required}"
[[ "$ARCH" == amd64 || "$ARCH" == arm64 ]] || { echo "error: arch is amd64 or arm64, not $ARCH" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: VERSION is x.y.z, not $VERSION" >&2; exit 1; }
if [ -n "${FEED_URL:-}" ]; then
    : "${SPARKLE_PUBLIC_KEY:?FEED_URL needs SPARKLE_PUBLIC_KEY}"
fi
WINSPARKLE_VERSION=0.9.4
WINSPARKLE_SHA256=6037df37fc263bd1650a1c4949681a9d40ffe991d01f35892a406cb5d103c976

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
if [ -z "${BIN:-}" ]; then
    BIN="$OUT/bin-$ARCH"
    mkdir -p "$BIN"
    target=(env GOOS=windows GOARCH="$ARCH" CGO_ENABLED=0 GOWORK=off)
    (cd .. && "${target[@]}" go build -trimpath -ldflags '-s -w' -o "$BIN/pmon.exe" .)
    # The app icon (Explorer, taskbar, the Settings window) and version, as Windows resources go build links in.
    GOWORK=off go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch "$ARCH" \
        --product-version "$VERSION.0" --file-version "$VERSION.0"
    trap 'rm -f rsrc_windows_*.syso' EXIT
    # windowsgui: no console window behind a notification-area app.
    "${target[@]}" go build -trimpath -o "$BIN/pmontray.exe" \
        -ldflags "-s -w -H=windowsgui -X main.version=$VERSION -X main.feedURL=${FEED_URL:-} -X main.sparklePublicKey=${SPARKLE_PUBLIC_KEY:-}" .
fi
BIN="$(cd "$BIN" && pwd)"

zip="$OUT/WinSparkle-$WINSPARKLE_VERSION.zip"
[ -f "$zip" ] || curl -fsSL -o "$zip" "https://github.com/vslavik/winsparkle/releases/download/v$WINSPARKLE_VERSION/WinSparkle-$WINSPARKLE_VERSION.zip"
if [ "$(shasum -a 256 "$zip" | cut -d' ' -f1)" != "$WINSPARKLE_SHA256" ]; then
    echo "error: $zip does not match its pinned checksum" >&2
    exit 1
fi
dll="WinSparkle-$WINSPARKLE_VERSION/$([ "$ARCH" = amd64 ] && echo x64 || echo ARM64)/Release/WinSparkle.dll"
unzip -o -j -q "$zip" "$dll" -d "$BIN"

for f in pmontray.exe pmon.exe WinSparkle.dll; do
    [ -f "$BIN/$f" ] || { echo "error: $BIN has no $f" >&2; exit 1; }
done
[ -z "${NO_MSI:-}" ] || exit 0
msi="$OUT/ProxyMonsterDesktop_${VERSION}_windows_$ARCH.msi"
rm -f "$msi"
(cd windows && wixl -a x64 -D "Version=$VERSION" -D "Arch=$ARCH" -D "Bin=$BIN" -o "$msi" ProxyMonsterDesktop.wxs)
# wixl reports some errors and still exits 0.
[ -s "$msi" ] || { echo "error: wixl wrote no $msi" >&2; exit 1; }
echo "built $msi"
