#!/usr/bin/env bash
# Create a throwaway keychain holding the Developer ID identities, for a release build to sign with.
#
#   ./signing-keychain.sh <keychain-path>     # then: security delete-keychain <keychain-path>
#
# Environment: MACOS_APP_P12, MACOS_INSTALLER_P12 (base64 .p12) and MACOS_APP_P12_PASSWORD,
# MACOS_INSTALLER_P12_PASSWORD.
set -euo pipefail

KC="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PW="$(uuidgen)"

security create-keychain -p "$PW" "$KC"
security set-keychain-settings -lut 3600 "$KC"
security unlock-keychain -p "$PW" "$KC"

base64 -d <<<"$MACOS_APP_P12" >"$WORK/app.p12"
base64 -d <<<"$MACOS_INSTALLER_P12" >"$WORK/installer.p12"
security import "$WORK/app.p12" -k "$KC" -P "$MACOS_APP_P12_PASSWORD" -T /usr/bin/codesign
security import "$WORK/installer.p12" -k "$KC" -P "$MACOS_INSTALLER_P12_PASSWORD" -T /usr/bin/productsign
# The .p12 holds only the leaf; codesign needs the intermediate to build the chain, and a bare CLT install
# does not ship it.
curl -fsSL https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$WORK/g2.cer"
echo "f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a  $WORK/g2.cer" | shasum -a 256 -c -
security import "$WORK/g2.cer" -k "$KC"
# Lets codesign/productsign use the keys without a UI prompt.
security set-key-partition-list -S apple-tool:,apple: -s -k "$PW" "$KC" >/dev/null

# On the search list, so codesign and productsign resolve the identity by name.
security list-keychains -d user -s "$KC" $(security list-keychains -d user | tr -d '"')
security find-identity -v "$KC"
