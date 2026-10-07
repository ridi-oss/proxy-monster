#!/usr/bin/env bash
# Sign a Proxy Monster Desktop release for Windows with the code-signing token, then attach the signed MSIs.
#
#   ./sign-windows.sh pmon-v0.1.9
#
# Run on the macOS or Linux machine the USB token is plugged into, from a checkout of this repository at the tag;
# it asks for the token PIN once. It downloads the release's unsigned binaries, checks they were built by this
# repository's release workflow (GitHub artifact attestation), signs pmontray.exe and pmon.exe, packages them
# into MSIs (package-windows.sh), signs the MSIs, and uploads them with zips of the signed files. Then publish
# the update feed:
#   gh workflow run desktop-feed-windows.yml --ref pmon-v0.1.9
#
# Environment:
#   PKCS11_MODULE   the token's PKCS#11 library (default: SafeNet Authentication Client's)
#   PKCS11_CERT     PKCS#11 URI of the signing certificate (default: the token's only one)
#   PKCS11_KEY      PKCS#11 URI of its private key (default: the token's only one)
#   CHAIN           PEM file of the intermediate certificates to embed
#   CA_FILE         PEM roots to verify the signatures against (default: the system bundle, which may lack the
#                   code-signing root)
#   TIMESTAMP_URL   RFC 3161 timestamp server (default: DigiCert's)
#   REPO            default ridi-oss/proxy-monster
#
# Needs osslsigncode, OpenSSL's PKCS#11 provider (brew install osslsigncode libp11 msitools), and gh, logged in.
set -euo pipefail

cd "$(dirname "$0")"
TAG="$1"
REPO="${REPO:-ridi-oss/proxy-monster}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/local/lib/libeToken.dylib}"
PKCS11_CERT="${PKCS11_CERT:-pkcs11:type=cert}"
PKCS11_KEY="${PKCS11_KEY:-pkcs11:type=private}"
TIMESTAMP_URL="${TIMESTAMP_URL:-http://timestamp.digicert.com}"
[[ "$TAG" =~ ^pmon-v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: $TAG is not a pmon release tag (pmon-v<major>.<minor>.<patch>)" >&2; exit 1; }
VERSION="${TAG#pmon-v}"
# The MSI is authored from this checkout, so it must be the tag, unmodified.
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || { echo "error: check out $TAG first (git checkout $TAG)" >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=all -- .)" ] || { echo "error: the checkout has local changes" >&2; exit 1; }
COMMIT="$(git rev-parse HEAD)"
# Homebrew's libp11 installs the provider outside OpenSSL's own module folder.
if [ -z "${OPENSSL_MODULES:-}" ] && command -v brew >/dev/null && [ -d "$(brew --prefix)/lib/ossl-modules" ]; then
    OPENSSL_MODULES="$(brew --prefix)/lib/ossl-modules"
    export OPENSSL_MODULES
fi
THUMBPRINT="$(tr -d '[:space:]' < windows/signing-cert-sha1)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; unset PIN' EXIT

{ set +x; } 2>/dev/null
read -rsp "Token PIN: " PIN; echo

sign() {
    local f="$1"
    printf '%s' "$PIN" | osslsigncode sign -pkcs11module "$PKCS11_MODULE" -pkcs11cert "$PKCS11_CERT" -key "$PKCS11_KEY" \
        -readpass - ${CHAIN:+-ac "$CHAIN"} -h sha256 -n "Proxy Monster Desktop" -ts "$TIMESTAMP_URL" \
        -in "$f" -out "$f.signed" >/dev/null
    mv "$f.signed" "$f"
    check "$f"
}

# check requires a signature that verifies, chain and timestamp included, by the certificate in
# windows/signing-cert-sha1.
check() {
    local f="$1" out signer
    out="$(osslsigncode verify ${CA_FILE:+-CAfile "$CA_FILE"} -in "$f" 2>&1)" && [ "$(tail -n1 <<<"$out")" = Succeeded ] ||
        { echo "error: $f does not verify:" >&2; grep -E 'Error|failed|Failed' <<<"$out" >&2; exit 1; }
    signer="$(awk '/Signer #0:/{s=1} s && /Serial :/{print $NF; exit}' <<<"$out")"
    osslsigncode extract-signature -pem -in "$f" -out "$WORK/sig.pem" >/dev/null
    openssl pkcs7 -in "$WORK/sig.pem" -print_certs -out "$WORK/certs.pem"
    grep -qix "$THUMBPRINT $signer" <<<"$(split_certs "$WORK/certs.pem")" || { echo "error: $f is not signed by the certificate in signing-cert-sha1" >&2; exit 1; }
    rm -f "$WORK/sig.pem" "$WORK/certs.pem"
}

# split_certs prints the SHA-1 thumbprint and serial of each certificate in a PEM file.
split_certs() {
    awk -v dir="$WORK" '/BEGIN CERTIFICATE/{n++} n{print > (dir "/cert" n ".pem")}' "$1"
    for c in "$WORK"/cert*.pem; do
        echo "$(openssl x509 -in "$c" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :) $(openssl x509 -in "$c" -noout -serial | cut -d= -f2)"
        rm -f "$c"
    done
}

for arch in amd64 arm64; do
    zip="ProxyMonsterDesktop_${VERSION}_windows_${arch}_unsigned.zip"
    gh release download "$TAG" --repo "$REPO" --pattern "$zip" --dir "$WORK"
    gh attestation verify "$WORK/$zip" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/pmon-release-binaries.yml" \
        --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" >/dev/null
    bin="$WORK/$arch"
    unzip -q "$WORK/$zip" -d "$bin"
    sign "$bin/pmontray.exe"
    sign "$bin/pmon.exe"
    BIN="$bin" VERSION="$VERSION" ./package-windows.sh "$arch" "$WORK/out"
    sign "$WORK/out/ProxyMonsterDesktop_${VERSION}_windows_$arch.msi"
    # The same signed files, to run from any folder without installing.
    zip -q -j "$WORK/out/ProxyMonsterDesktop_${VERSION}_windows_$arch.zip" "$bin/pmontray.exe" "$bin/pmon.exe" "$bin/WinSparkle.dll"
done
unset PIN

gh release upload "$TAG" "$WORK"/out/ProxyMonsterDesktop_*_windows_*.{msi,zip} --repo "$REPO" --clobber
echo "uploaded. Next: gh workflow run desktop-feed-windows.yml --repo $REPO --ref $TAG"
