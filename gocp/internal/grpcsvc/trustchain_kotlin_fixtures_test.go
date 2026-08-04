package grpcsvc

import (
	"strings"
	"testing"
)

// The two TrustChainInspectionTest.kt cases the minted-certificate suite in trustchain_test.go does
// not reach, ported against THE KOTLIN'S OWN PEM FIXTURES — the identical bytes, copied out of
// TrustChainInspectionTest.kt's companion object. Same input, same asserted outcome, so the two
// languages are compared on the same evidence rather than on two independently minted fixtures.
//
// Why the fixtures rather than mint(): both cases turn on a property mint() does not express by
// accident.
//
//   - `a smuggled trust anchor is reported` has TWO forms in the Kotlin. The existing
//     TestInspectTrustChainRejectsASmuggledAnchor covers only the shorter one AND mints its stranger as
//     a REAL CA, so it lands on rule 4c (signature). The Kotlin's SELF_SIGNED stranger is CA:FALSE
//     (verified: `openssl x509 -text` reports "X509v3 Basic Constraints: critical CA:FALSE"), so the
//     Kotlin's own two forms land on rule 4a, and the THREE-certificate form — a chain that otherwise
//     verifies with an extra anchor appended — was untested in Go entirely.
//   - `a certificate that only CLAIMS to be its own issuer is reported` needs a certificate whose
//     Issuer NAME equals its Subject while its SIGNATURE is another key's. mint() cannot produce that:
//     x509.CreateCertificate copies the issuer name from whichever parent actually signs.
//
// Neither certificate's expiry is load-bearing — InspectTrustChain never looks at NotBefore/NotAfter
// (trustchain.go has no validity check at all), so these fixtures do not become a time bomb in 2027.

const (
	ktCA_LEAF = `-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUCMlJHsWQYF9aDuby/9E5L6bOjrUwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMB4XDTI2MDcyNzA5MDUwOFoX
DTI3MDcyNzA5MDUwOFowHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc265GclVN6fROXzi+yxYz
PyWp/0DuoV6VZBIxjoPAYZE5iMpLqz4COlr/y+0sRZ8fy3/3v3VF+AkR+Nreeznd
WNNBdnDkYg48vgy6Og4V7riU2uFL6SEGqCsM3Thcj3TffNmfRd2+OebD8CMg91Hs
Hn6ddmCVT0yUrJstLasuS4yNd0JVrX8FrxxaljQjlVX7H+kSLVn+x/qLLga1wWRd
wEHd7LObrk06WvPsMP+qbyQTA9CP7GJtbv7vEloECE3sS2l3QjWUQGp4YFrnMWl5
wdZSuThXz9sub/y0c51vLvzDJVVbNYdshMBrpZWbp6cALVS+qzCt35drj6WOnkUt
AgMBAAGjcTBvMAwGA1UdEwEB/wQCMAAwHwYDVR0RBBgwFoIUcG0tcHJveHkuZXhh
bXBsZS5jb20wHQYDVR0OBBYEFBj09SNWr+0aRPR3d2yu+D71Ne9QMB8GA1UdIwQY
MBaAFPLbxOH+O1GK8v0GeivzFC4vXMp+MA0GCSqGSIb3DQEBCwUAA4IBAQBVsgMq
MBK2K1hwcDWlMDxRAnXjxlBlTFOAYUqHPj3Ldxqwma753kPcXaikfS4NJ9+ykHkh
0tr+UhYe7GzW28pEz2qzkh1uBqYi2gQHgFMyIkjCECFSE8YVFXaVWFdVI9NEeRdp
KzWxd4PrudQ1Rz9AN2OTD1O/HXlvZ5McWltira59nLZKmKt27Z10qq3vBrjHapoX
0m9jVxpnAquar42WJTlKcs7xp8Z6uKVqCURu4csrWDalAWprdHHKaxLazVjh1L2w
qAv8gJuOTmYouD/hcFK0SCNtT3Rq4f9HFQlo7mYjXs02LK/IIYTxUwmJzW2W06vF
TBtfh2tHAcUTxjLG
-----END CERTIFICATE-----
`

	ktISSUING_CA = `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUUgWMsQi5dszsgUyVMRAvICNT6jswDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMB4XDTI2MDcyNzA5MDUwN1oX
DTI3MDcyNzA5MDUwN1owGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjpMm4TxsR6lr96BsZZNXg4FS5u6n
/4B4EsOVSr0HzN0w8+HVNKtFDn1OozhXsYgZhrR2xTbpETx/+W/D8MUeYw8mW9N4
P68hj7ueSs6R1PGwVBqm0/O2C4cDiKtBTNMwdYjlBejVlQ7mS2PhuzDEQCmi8S3B
77poEOjBo2s/BlID14MqTrqs9/6xs1akR5duC0ZUywxhUGsWDIsRhQ1wKtny+s/2
1IWi7vP3XuXjcHS7mitYzfq5OsqgUeiZrN2AtBxj3+u2ym4BFXx+tFFJtbV+G/dS
YGOI3mCC1JPm5Qc3COIeNCdLzd3H794R8d1FquY4ChV0p3daDLHOJXtS5wIDAQAB
o1MwUTAdBgNVHQ4EFgQU8tvE4f47UYry/QZ6K/MULi9cyn4wHwYDVR0jBBgwFoAU
8tvE4f47UYry/QZ6K/MULi9cyn4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAcRIDy5Pf2lUTQy7xNg07vBFXhbON2uquwDGqQzGZvEr+luZ31isc
B+HTqwDNTBgQ4pZWwJLY3VjiKPJ1JOJir0IUdgHnJoVbqfwchM6hW1iGx+yOwUs2
HHpK4dAKd9nOY4gsJmie8Y9wMCvGW3/SmSs1q3gDZAK85qqyH+0/gbO6wfCAJtaV
5LgRd68Ep9FBedpdkCX99rakRXsNIL+NotjL1XhivdXmsljdNr/Euy7rbLmfXXLB
uwRCZPDbOUJGzXW3gdUJpeFtpUQHgiGHo6mbElgEBbjemnmebhNY92yHg365UjMH
TH5ujWUrKFM8MwihwokXf1RocDNA2CQWMA==
-----END CERTIFICATE-----
`

	ktSELF_SIGNED = `-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUJeAynTaX/TJdfCHpPYqljxv5BJ0wDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy
MDIzWhcNMjcwNzI3MTIyMDIzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAPb/6x5fTqssbH
0jKzOI90/MnENRaAfb4As4e5yse0Xrir2Kz/10O6GSH49lhdRa/csLqeH122m9gj
C4vCIvDJRTqz81s3yaLN7/4PnTbS1WOwp+PTwRajHXC8Xp5MPBEyZVNj+WjzCYE4
inlXuSJSFaTUB1Md1F91UaD/q+eOt/Rocg5Erq65Z6tWnAs03t3Sp8ZfBs/YlA5u
TP5BPgE3NQq6uwU1kBfQQpPiem+B/9NATbY094YH3cJwOFMF1Z69t80LO2ZvZ7u8
fQs0GHPpIE8n7mkGjleOwFypoDM9N+ZDtSeAQBGAk5ulV59lni2/xV1pQ0YDx8H6
t1ekfI8CAwEAAaNxMG8wHQYDVR0OBBYEFCUm5743U+xa/Rqr4rlRqDt/qJ8SMB8G
A1UdIwQYMBaAFCUm5743U+xa/Rqr4rlRqDt/qJ8SMAwGA1UdEwEB/wQCMAAwHwYD
VR0RBBgwFoIUcG0tcHJveHkuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB
AKbyz1Vu4MhL49dXoCQPdyXj+m332HIAMtQDDRJubbFTm+x0KQLOCgb3ZBvi6x1k
WertFs3Mqs4g/72BvfU96aCmCYJ4iZi0XT3ZC/1j36dJjxpk1EDM75pW5KLnfDDo
qWF7gtahB3uGqKM4uRpkodGE7OIelf/Hs/m/iSnnX6VEGCQIe9Ew87B2xtj4u891
ghWojgBCelZxEmN31Og6VFRYTZYLk/Xb4ya2Xq6g8jjwGKKYHZCs1gQ1vvZm4eof
GrFvts/fga0akW6kpc3vBLP1gMZFirHQ6WZnemsdEcXG1GKyM40O4KkPBYcnypT0
3lp9W8du2aYfDic7uDfw0Gg=
-----END CERTIFICATE-----
`

	ktFORGED_SELF_ISSUER = `-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUaOLIp1a0IjqqUa3rcq96FjkCnckwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy
OTEzWhcNMjcwNzI3MTIyOTEzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnoSdkhOkOC/yn9
kXurlalVTBiq6Ehlbi1W/54YtQEEpVoRyxvxn3kPRxYBUw7D/+56/xPv3Tyoc1d+
bjT6LDSm9h+XvHYTOjv19BngDiCa4zWPJlM4eOids1Q++0i2/30qsOloKsg7jx2B
zqDgylS9GZeED6Kfhg6radiM4L3WRxegxC5DtsfVm1UgvleMOuBEGBHwgQZUjzcL
9tm6ctttAnjzl5/GM1+zvoS+78u2uvBH/q7A3mYHgm5BSd9ePM0/2ETuY80PtcCv
oa2GrbISlIbxXOVtf5T2BJcnuzcDPchqn/M3OVbhffCtdJs9EtDvUzkbS62NRpHe
SgPhHPUCAwEAAaNxMG8wDAYDVR0TAQH/BAIwADAfBgNVHREEGDAWghRwbS1wcm94
eS5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUSz6ZZVLaCCNB7lb8q+EcNKNERuUwHwYD
VR0jBBgwFoAU0ElnM9xIbtVQ6tFCFdVpnCNlu4AwDQYJKoZIhvcNAQELBQADggEB
AGZk/S06rvOsIbLimjcHimr48llXdWvhIG7V38YlBTOCVG2L0Dt6S0FAuto5b/hd
LhgvNyvt+iUkywX/L8aR9LmQ05yU4g/6n4aGBQdEZDl7rTjgiJhfnxEINNwwX2IY
7BCy27oLdI0zRG7EVB1gT0ABkYUiD97ioadNoPcnTquTAsCKFXCYxR59tlR2JEbe
NNbe2Dqo4yQISUnZ8avZtFpYQsY8zO7CA68ipBp+AgZ0mBoCLGTngqWr4B8ezrmy
Lpe1XUpnzAUGW5vTCDWXux0uD19x/Cnf6TrQxSLCMVvYCPeOLS+DHiB4vosAHth2
EM9ft42Cnf06jKZdGfV5HOg=
-----END CERTIFICATE-----
`
)

// KT: TrustChainInspectionTest.kt#a smuggled trust anchor is reported — both Kotlin forms, on the Kotlin's own bytes
func TestInspectTrustChainReportsASmuggledAnchorOnTheKotlinFixtures(t *testing.T) {
	// Form 1: a real leaf + its real issuer + an UNRELATED self-signed certificate. The leaf verifies,
	// the chain does not: the extra certificate issues nothing, so it cannot ride along as an anchor.
	// It is CA:FALSE, so rule 4a names it before the signature check is ever reached.
	reason, bad := InspectTrustChain(ktCA_LEAF + ktISSUING_CA + ktSELF_SIGNED)
	if !bad {
		t.Fatal("an extra unrelated certificate appended to a verifying chain must be reported")
	}
	if !strings.Contains(reason, "certificate 2 is not a CA, so it cannot issue certificate 1") {
		t.Errorf("reason = %q, want it to name the appended certificate at index 2", reason)
	}

	// Form 2: the shorter one — a real leaf with an unrelated certificate appended INSTEAD of its own
	// issuer.
	reason, bad = InspectTrustChain(ktCA_LEAF + ktSELF_SIGNED)
	if !bad {
		t.Fatal("a leaf plus an unrelated certificate must be reported")
	}
	if !strings.Contains(reason, "certificate 1 is not a CA, so it cannot issue certificate 0") {
		t.Errorf("reason = %q, want it to name the appended certificate at index 1", reason)
	}

	// The control: the SAME leaf with its OWN issuer is accepted, so the two assertions above are about
	// the appended certificate and not about the fixture being unusable.
	if reason, bad := InspectTrustChain(ktCA_LEAF + ktISSUING_CA); bad {
		t.Fatalf("leaf + its real issuer must be accepted, got %q", reason)
	}
}

// 🔒 Issuance is checked by SIGNATURE, never by name. FORGED_SELF_ISSUER names itself as its own issuer
// but was signed by a different key, so a name-only self-signed test would accept it and the download
// route would hand a client an anchor it cannot verify anything with.
// KT: TrustChainInspectionTest.kt#a certificate that only CLAIMS to be its own issuer is reported
func TestInspectTrustChainReportsACertificateThatOnlyClaimsToBeItsOwnIssuer(t *testing.T) {
	reason, bad := InspectTrustChain(ktFORGED_SELF_ISSUER)
	if !bad {
		t.Fatal("a certificate that only NAMES itself as issuer must be reported — selfSigned() is a signature check")
	}
	if !strings.Contains(reason, "it is not self-signed") {
		t.Errorf("reason = %q, want the not-self-signed message", reason)
	}
	// The name-only trap, stated as an assertion: Issuer and Subject ARE equal here, so any port that
	// compared them instead of verifying the signature would have accepted this.
	certs, err := parsePEMChain(ktFORGED_SELF_ISSUER)
	if err != nil || len(certs) != 1 {
		t.Fatalf("fixture must parse to exactly one certificate, got %d certs err=%v", len(certs), err)
	}
	if certs[0].Issuer.String() != certs[0].Subject.String() {
		t.Fatalf("precondition: the fixture must NAME itself as issuer (issuer=%q subject=%q) — that is the trap",
			certs[0].Issuer, certs[0].Subject)
	}
	if selfSigned(certs[0]) {
		t.Fatal("selfSigned() accepted a forged self-issuer — it must be a SIGNATURE check, not a name comparison")
	}
}
