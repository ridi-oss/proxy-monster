#!/usr/bin/env bash
# Package the app build-app.sh built for distribution: a .zip of the app (for the Homebrew cask) and a .pkg
# that installs it into /Applications with `pmon` linked onto PATH.
#
#   ./package-macos.sh "<path/to/Proxy Monster Desktop.app>" <out-dir>
#
# Environment:
#   VERSION              version in the artifact names and the pkg receipt (required)
#   INSTALLER_IDENTITY   productsign identity ("Developer ID Installer: …"); unset leaves the pkg unsigned
#   SIGN_KEYCHAIN        keychain holding INSTALLER_IDENTITY
#   NOTARY_KEY_PATH, NOTARY_KEY_ID, NOTARY_ISSUER_ID
#                        App Store Connect API key; when set, both artifacts are notarized and stapled
set -euo pipefail

NAME="$(basename "$1")"
APP="$(cd "$(dirname "$1")" && pwd)/$NAME"
OUT="$2"
: "${VERSION:?VERSION is required}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ZIP="$OUT/ProxyMonsterDesktop_${VERSION}_darwin_universal.zip"
PKG="$OUT/ProxyMonsterDesktop_${VERSION}.pkg"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

notarize() {
    local result id status
    result="$(xcrun notarytool submit "$1" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" \
        --issuer "$NOTARY_ISSUER_ID" --wait --output-format json)"
    id="$(plutil -extract id raw - <<<"$result")"
    status="$(plutil -extract status raw - <<<"$result")"
    echo "notarization of $(basename "$1"): $status ($id)"
    if [ "$status" != Accepted ]; then
        xcrun notarytool log "$id" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID"
        return 1
    fi
}

# The zip: notarize it, staple the ticket into the app itself, then re-zip so the download carries the ticket
# and passes Gatekeeper offline. A zip cannot hold a ticket of its own.
ditto -c -k --keepParent "$APP" "$ZIP"
if [ -n "${NOTARY_KEY_PATH:-}" ]; then
    notarize "$ZIP"
    xcrun stapler staple "$APP"
    rm "$ZIP"
    ditto -c -k --keepParent "$APP" "$ZIP"
fi

# The pkg payload is laid out from /. The pmon link is part of the payload rather than a postinstall step,
# so the receipt records it and an uninstall can find it.
ROOT="$WORK/root"
mkdir -p "$ROOT/Applications" "$ROOT/usr/local/bin"
ditto "$APP" "$ROOT/Applications/$NAME"
ln -s "/Applications/$NAME/Contents/MacOS/pmon" "$ROOT/usr/local/bin/pmon"

# Not relocatable: otherwise Installer "upgrades" a copy of the app it finds anywhere else on disk (a dev build
# in ~/Downloads, say) instead of writing /Applications, and the pmon link then points at nothing.
pkgbuild --analyze --root "$ROOT" "$WORK/components.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$WORK/components.plist"
pkgbuild --root "$ROOT" --component-plist "$WORK/components.plist" --install-location / \
    --identifier com.ridi.oss.proxymonster.pmontray --version "$VERSION" "$WORK/component.pkg"

# The product archive wraps the component so the Installer window carries the app's name as its title.
cat >"$WORK/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>${NAME%.app}</title>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <domains enable_localSystem="true"/>
    <choices-outline><line choice="default"/></choices-outline>
    <choice id="default" title="${NAME%.app}"><pkg-ref id="com.ridi.oss.proxymonster.pmontray"/></choice>
    <pkg-ref id="com.ridi.oss.proxymonster.pmontray" version="$VERSION">component.pkg</pkg-ref>
</installer-gui-script>
XML
productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" "$WORK/product.pkg"

if [ -n "${INSTALLER_IDENTITY:-}" ]; then
    sign_flags=(--sign "$INSTALLER_IDENTITY" --timestamp)
    [ -n "${SIGN_KEYCHAIN:-}" ] && sign_flags+=(--keychain "$SIGN_KEYCHAIN")
    productsign "${sign_flags[@]}" "$WORK/product.pkg" "$PKG"
    pkgutil --check-signature "$PKG"
else
    mv "$WORK/product.pkg" "$PKG"
fi
if [ -n "${NOTARY_KEY_PATH:-}" ]; then
    notarize "$PKG"
    xcrun stapler staple "$PKG"
fi

echo "packaged:"
ls -l "$ZIP" "$PKG"
