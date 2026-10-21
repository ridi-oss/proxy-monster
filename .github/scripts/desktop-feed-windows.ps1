# Sign a release's Windows MSIs for WinSparkle and replace appcast-windows.xml on the rolling desktop-feed
# release, with the x64 installer under a fixed name for a download link that is always current. Refuses an MSI
# not signed by the certificate in pmon/tray/windows/signing-cert-sha1, and leaves a newer feed alone.
param([Parameter(Mandatory)] [string] $Tag)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$version = $Tag -replace '^pmon-v', ''
$repo = $env:GITHUB_REPOSITORY
$work = Join-Path $env:RUNNER_TEMP 'feed'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$assets = gh release view desktop-feed --repo $repo --json assets --jq '.assets[].name'
if ($LASTEXITCODE) { throw 'no desktop-feed release; the macOS release job creates it' }
if ($assets -contains 'appcast-windows.xml') {
    gh release download desktop-feed --repo $repo -p appcast-windows.xml -O (Join-Path $work 'current.xml')
    if ($LASTEXITCODE) { throw 'could not read the current Windows feed' }
    $ns = @{ sparkle = 'http://www.andymatuschak.org/xml-namespaces/sparkle' }
    $current = Select-Xml -Path (Join-Path $work 'current.xml') -XPath '//sparkle:version' -Namespace $ns |
        Select-Object -First 1 | ForEach-Object { $_.Node.InnerText }
    if ($current -and ([version]$current -gt [version]$version)) {
        Write-Host "the feed already has $current, newer than $version; leaving it"
        exit 0
    }
}

$thumbprint = (Get-Content pmon/tray/windows/signing-cert-sha1 -Raw).Trim()
$openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
$pubDer = Join-Path $work 'public.der'
[IO.File]::WriteAllBytes($pubDer, [byte[]](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) +
    [Convert]::FromBase64String((Get-Content pmon/tray/sparkle-public-key -Raw).Trim()))

$der = Join-Path $work 'key.der'
$items = ''
try {
    # Sparkle's EdDSA signature is a plain Ed25519 signature of the file, keyed by the 32-byte seed in the secret.
    $prefix = [byte[]](0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20)
    [IO.File]::WriteAllBytes($der, $prefix + [Convert]::FromBase64String($env:SPARKLE_ED_KEY))
    foreach ($arch in @{ amd64 = 'windows-x64'; arm64 = 'windows-arm64' }.GetEnumerator()) {
        $name = "ProxyMonsterDesktop_${version}_windows_$($arch.Key).msi"
        gh release download $Tag --repo $repo -p $name --dir $work --clobber
        if ($LASTEXITCODE) { throw "no $name on $Tag; run sign-windows.sh first" }
        $msi = Join-Path $work $name
        $auth = Get-AuthenticodeSignature $msi
        if ($auth.Status -ne 'Valid') { throw "$name is not validly signed ($($auth.Status))" }
        if ($auth.SignerCertificate.Thumbprint -ne $thumbprint) {
            throw "$name is signed by $($auth.SignerCertificate.Subject), not the certificate in signing-cert-sha1"
        }
        $sig = Join-Path $work "$name.sig"
        & $openssl pkeyutl -sign -inkey $der -keyform DER -rawin -in $msi -out $sig
        if ($LASTEXITCODE) { throw "could not sign $name" }
        # The app accepts only signatures from the key it was built with.
        & $openssl pkeyutl -verify -pubin -inkey $pubDer -keyform DER -rawin -in $msi -sigfile $sig | Out-Null
        if ($LASTEXITCODE) { throw 'the signing key does not match pmon/tray/sparkle-public-key' }
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sig))
        $length = (Get-Item $msi).Length
        $items += @"
    <item>
      <title>$version</title>
      <link>https://github.com/$repo/releases/tag/$Tag</link>
      <sparkle:version>$version</sparkle:version>
      <enclosure url="https://github.com/$repo/releases/download/$Tag/$name" sparkle:os="$($arch.Value)" sparkle:edSignature="$b64" length="$length" type="application/octet-stream" sparkle:installerArguments="/passive /norestart LAUNCHAPP=1"/>
    </item>

"@
    }
} finally {
    Remove-Item -Force $der -ErrorAction SilentlyContinue
}

$appcast = Join-Path $work 'appcast-windows.xml'
@"
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Proxy Monster Desktop</title>
$items  </channel>
</rss>
"@ | Set-Content -Encoding utf8NoBOM $appcast
[xml](Get-Content $appcast) | Out-Null
$stable = Join-Path $work 'ProxyMonsterDesktop-x64.msi'
Copy-Item (Join-Path $work "ProxyMonsterDesktop_${version}_windows_amd64.msi") $stable
gh release upload desktop-feed $appcast $stable --repo $repo --clobber
if ($LASTEXITCODE) { throw 'upload failed' }
Write-Host "Windows feed now offers $version"
