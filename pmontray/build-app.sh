#!/usr/bin/env bash
# Build pmontray as the macOS app "Proxy Monster Desktop", with pmon bundled inside it.
#
# A bundle is required, not cosmetic: LSUIElement (no Dock icon, no menu bar of its own) is an Info.plist
# property, and the bundle identity is what macOS attaches the Login Item and notification permission to.
#
#   ./build-app.sh                 -> "./dist/Proxy Monster Desktop.app" (host arch, ad-hoc signed)
#   ./build-app.sh /Applications   -> installs there
#
# Environment:
#   VERSION         bundle version (default: git describe)
#   ARCHS           Go architectures to build; more than one makes a universal binary (default: host arch)
#   SIGN_IDENTITY   codesign identity (default "-", ad-hoc). A real identity also turns on the hardened runtime
#                   and a secure timestamp, which notarization requires.
#   SIGN_KEYCHAIN   keychain holding SIGN_IDENTITY (default: the search list)
set -euo pipefail

cd "$(dirname "$0")"
DEST="${1:-./dist}"
mkdir -p "$DEST"
# Absolute, because the builds below run in subshells with a different working directory.
DEST="$(cd "$DEST" && pwd)"
APP="$DEST/Proxy Monster Desktop.app"
VERSION="${VERSION:-$(git -C .. describe --tags --always --dirty 2>/dev/null || echo dev)}"
ARCHS="${ARCHS:-$(go env GOARCH)}"
# cgo's clang otherwise targets the build host's macOS. Passed as CGO flags: Go's build cache ignores
# MACOSX_DEPLOYMENT_TARGET, so a cached object would keep the host's target.
MIN_MACOS=12.0
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# GOWORK=off: each module resolves its own go.mod, the same as the release build of pmon. Bundling pmon
# INSIDE the app keeps the daemon the tray spawns from skewing against the tray.
pmon_slices=() tray_slices=()
for arch in $ARCHS; do
    echo "building pmon and pmontray for ${arch}…"
    (cd ../pmon && GOWORK=off CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w" -o "$WORK/pmon-$arch" .)
    # The systray is cgo; clang targets the slice's arch, so one host builds every slice.
    clang_arch="$arch"
    [ "$arch" = amd64 ] && clang_arch=x86_64
    GOWORK=off CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" CC="clang -arch $clang_arch" \
        CGO_CFLAGS="-O2 -g -mmacosx-version-min=$MIN_MACOS" CGO_LDFLAGS="-mmacosx-version-min=$MIN_MACOS" \
        go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$WORK/pmontray-$arch" .
    pmon_slices+=("$WORK/pmon-$arch")
    tray_slices+=("$WORK/pmontray-$arch")
done
lipo -create -output "$APP/Contents/MacOS/pmon" "${pmon_slices[@]}"
lipo -create -output "$APP/Contents/MacOS/pmontray" "${tray_slices[@]}"
for bin in pmon pmontray; do
    minos="$(otool -arch all -l "$APP/Contents/MacOS/$bin" | awk '/minos/ {print $2}' | sort -u)"
    if [ "$minos" != "$MIN_MACOS" ]; then
        echo "error: $bin targets macOS $minos, not $MIN_MACOS" >&2
        exit 1
    fi
done

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Proxy Monster Desktop</string>
    <key>CFBundleDisplayName</key>
    <string>Proxy Monster Desktop</string>
    <key>CFBundleIdentifier</key>
    <string>com.ridi.oss.proxymonster.pmontray</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleExecutable</key>
    <string>pmontray</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <!-- Menu-bar-only: no Dock icon, no app menu bar. -->
    <key>LSUIElement</key>
    <true/>
    <!-- The oldest macOS the Go toolchain targets. -->
    <key>LSMinimumSystemVersion</key>
    <string>$MIN_MACOS</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# Finder/Login-Items icon. CFBundleIconFile names "icon", so macOS looks for Resources/icon.icns; without it the
# bundle shows a generic icon in Login Items. The menu-bar icon is separate (embedded in the binary).
cp icon.png "$APP/Contents/Resources/icon.png"
if command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then
    ICONSET="$WORK/icon.iconset"
    mkdir -p "$ICONSET"
    for size in 16 32 128 256 512; do
        sips -z $size $size icon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null 2>&1 || true
        sips -z $((size*2)) $((size*2)) icon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null 2>&1 || true
    done
    iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/icon.icns" 2>/dev/null || \
        echo "note: icns generation failed; the bundle will show a generic Finder icon"
fi

# Inside-out: the nested pmon first, then the bundle (which signs the main executable). Not --deep, which
# applies one identifier and one set of options to every nested binary.
sign_flags=(--force --sign "$SIGN_IDENTITY")
if [ "$SIGN_IDENTITY" != "-" ]; then
    sign_flags+=(--options runtime --timestamp)
fi
if [ -n "${SIGN_KEYCHAIN:-}" ]; then
    sign_flags+=(--keychain "$SIGN_KEYCHAIN")
fi
codesign "${sign_flags[@]}" --identifier com.ridi.oss.proxymonster.pmon "$APP/Contents/MacOS/pmon"
codesign "${sign_flags[@]}" "$APP"
codesign --verify --strict --deep "$APP"

echo "built $APP ($VERSION, $(lipo -archs "$APP/Contents/MacOS/pmontray"))"
echo
echo "run it:            open \"$APP\""
echo "start at login:    System Settings > General > Login Items > add $APP"
echo "bundled CLI:       $APP/Contents/MacOS/pmon"
