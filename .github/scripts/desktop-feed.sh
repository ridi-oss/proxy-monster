#!/usr/bin/env bash
# Point Proxy Monster Desktop's update feed at a release: sign its zip for Sparkle and replace
# appcast-macos.xml and ProxyMonsterDesktop.pkg on the rolling desktop-feed release. The pkg is there so the
# console can link one download that is always current. A re-run for an older tag leaves a newer feed alone.
#
#   SPARKLE_ED_KEY=… desktop-feed.sh <tag> <dir>
set -euo pipefail

TAG="$1" DIR="$2"
VERSION="${TAG#pmon-v}"
FEED=desktop-feed
REPO="$GITHUB_REPOSITORY"
ZIP="ProxyMonsterDesktop_${VERSION}_darwin_universal.zip"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if ! gh release view "$FEED" --repo "$REPO" >/dev/null 2>&1; then
    gh release create "$FEED" --repo "$REPO" --target main --prerelease --latest=false \
        --title "Proxy Monster Desktop update feed" \
        --notes "Rolling release: the appcast Proxy Monster Desktop checks for updates, and the current installer. Versioned downloads are on the pmon-v* releases."
fi

if gh release view "$FEED" --repo "$REPO" --json assets --jq '.assets[].name' | grep -qx appcast-macos.xml; then
    gh release download "$FEED" --repo "$REPO" -p appcast-macos.xml -O "$WORK/current.xml"
    current="$(sed -n 's:.*<sparkle\:version>\(.*\)</sparkle\:version>.*:\1:p' "$WORK/current.xml" | head -1)"
    if [ -n "$current" ] && [ "$(printf '%s\n%s\n' "$current" "$VERSION" | sort -V | tail -1)" != "$VERSION" ]; then
        echo "the feed already has $current, newer than $VERSION; leaving it"
        exit 0
    fi
fi

"$(dirname "$0")/../../pmon/tray/sparkle.sh" "$WORK/sparkle"
signature="$(printf '%s' "$SPARKLE_ED_KEY" | "$WORK/sparkle/bin/sign_update" --ed-key-file - "$DIR/$ZIP")"
# The app accepts only signatures from the key it was built with; check against that, not the secret.
sed -E 's/.*edSignature="([^"]*)".*/\1/' <<<"$signature" | base64 -d >"$WORK/zip.sig"
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; base64 -d <"$(dirname "$0")/../../pmon/tray/sparkle-public-key"; } \
    >"$WORK/public.der"
# LibreSSL, macOS's own openssl, cannot verify Ed25519.
openssl="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"
[ -x "$openssl" ] || openssl=openssl
"$openssl" pkeyutl -verify -pubin -inkey "$WORK/public.der" -keyform DER -rawin -in "$DIR/$ZIP" -sigfile "$WORK/zip.sig" >/dev/null || {
    echo "the signing key does not match pmon/tray/sparkle-public-key" >&2
    exit 1
}

cat >"$WORK/appcast-macos.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Proxy Monster Desktop</title>
    <item>
      <title>$VERSION</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <link>https://github.com/$REPO/releases/tag/$TAG</link>
      <sparkle:version>$VERSION</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>
      <enclosure url="https://github.com/$REPO/releases/download/$TAG/$ZIP" $signature type="application/octet-stream"/>
    </item>
  </channel>
</rss>
XML
xmllint --noout "$WORK/appcast-macos.xml"
cp "$DIR/ProxyMonsterDesktop_${VERSION}.pkg" "$WORK/ProxyMonsterDesktop.pkg"
gh release upload "$FEED" "$WORK/appcast-macos.xml" "$WORK/ProxyMonsterDesktop.pkg" --repo "$REPO" --clobber
echo "feed now offers $VERSION"
