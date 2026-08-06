package grpcsvc

// TrustChainInspectionTest — the subset that exercises the three GO DIVERGENCE TRAPS 10-grpc.md §3.1
// names, since those are the failures a transliteration produces and the Kotlin's own suite cannot
// catch.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type issuedCert struct {
	der  []byte
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// mint issues a certificate signed by parent (or self-signed when parent is nil).
func mint(t *testing.T, name string, tmpl *x509.Certificate, parent *issuedCert) issuedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.Subject = pkix.Name{CommonName: name}
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)

	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", name, err)
	}
	return issuedCert{der: der, key: key, cert: cert}
}

func chainPEM(certs ...issuedCert) string {
	var b strings.Builder
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	}
	return b.String()
}

// TestInspectTrustChainAcceptsASelfSignedLeaf — the ordinary proxy case: one certificate that is its
// own anchor.
// KT: TrustChainInspectionTest.kt#a self-signed certificate is its own anchor
func TestInspectTrustChainAcceptsASelfSignedLeaf(t *testing.T) {
	leaf := mint(t, "proxy", &x509.Certificate{}, nil)
	if reason, bad := InspectTrustChain(chainPEM(leaf)); bad {
		t.Fatalf("self-signed leaf reported %q, want it accepted", reason)
	}
}

// TestInspectTrustChainRejectsALoneNonSelfSignedLeaf.
// KT: TrustChainInspectionTest.kt#a CA-issued leaf alone is reported because nothing anchors it
func TestInspectTrustChainRejectsALoneNonSelfSignedLeaf(t *testing.T) {
	ca := mint(t, "ca", &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := mint(t, "proxy", &x509.Certificate{}, &ca)
	reason, bad := InspectTrustChain(chainPEM(leaf))
	if !bad || !strings.Contains(reason, "it is not self-signed") {
		t.Fatalf("reason = %q bad = %v, want the append-the-issuing-CA message", reason, bad)
	}
}

// TestInspectTrustChainAcceptsALeafThenCA is the two-element happy path, and it is TRAP 3's guard: a
// naive Go port using CheckSignatureFrom would also enforce IsCA/KeyUsageCertSign here and produce a
// different message than the Kotlin for the failure cases below.
// KT: TrustChainInspectionTest.kt#a leaf with its issuer is a valid chain
func TestInspectTrustChainAcceptsALeafThenCA(t *testing.T) {
	ca := mint(t, "ca", &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := mint(t, "proxy", &x509.Certificate{}, &ca)
	if reason, bad := InspectTrustChain(chainPEM(leaf, ca)); bad {
		t.Fatalf("leaf+CA reported %q, want it accepted", reason)
	}
}

// TestInspectTrustChainRejectsANonCAIssuer is TRAP 1.
//
// 🔒 Kotlin's `basicConstraints < 0` means "the extension is ABSENT OR CA:FALSE", so the Go
// equivalent is !cert.IsCA — NOT cert.MaxPathLen < 0, which means something else entirely. A client
// enforces basicConstraints, so a chain whose issuer is CA:FALSE is rejected by OpenSSL as "invalid
// CA certificate"; accepting it here would store a chain no client can use.
// KT: TrustChainInspectionTest.kt#a chain whose issuer is not a CA is reported — the Kotlin's LEAF_ISSUED_BY_A_NON_CA + NON_CA_ISSUER is this same CA:FALSE-issuer shape
func TestInspectTrustChainRejectsANonCAIssuer(t *testing.T) {
	// A self-signed NON-CA that nonetheless signs the leaf: signature-valid, basicConstraints-invalid.
	notCA := mint(t, "not-a-ca", &x509.Certificate{}, nil)
	leaf := mint(t, "proxy", &x509.Certificate{}, &notCA)
	reason, bad := InspectTrustChain(chainPEM(leaf, notCA))
	if !bad || !strings.Contains(reason, "certificate 1 is not a CA") {
		t.Fatalf("reason = %q bad = %v, want the not-a-CA message; a pure signature check would ACCEPT this", reason, bad)
	}
}

// TestInspectTrustChainSkipsTheKeyUsageCheckWhenTheExtensionIsABSENT is TRAP 2, and it is the trap a
// Go port fails silently.
//
// 🔒 Kotlin's `keyUsage?.getOrNull(5) == false` fires ONLY when the extension is PRESENT and bit 5 is
// clear. A CA with NO KeyUsage extension has keyUsage == null, so the check is SKIPPED. Go's
// cert.KeyUsage is 0 when the extension is absent, so the naive
// `cert.KeyUsage & x509.KeyUsageCertSign == 0` would REJECT a CA that Kotlin ACCEPTS.
func TestInspectTrustChainSkipsTheKeyUsageCheckWhenTheExtensionIsABSENT(t *testing.T) {
	// IsCA with NO KeyUsage: Go omits the extension entirely when KeyUsage is 0.
	ca := mint(t, "ca-no-keyusage", &x509.Certificate{IsCA: true, BasicConstraintsValid: true}, nil)
	if hasKeyUsageExtension(ca.cert) {
		t.Fatal("test setup: expected a CA with NO KeyUsage extension")
	}
	leaf := mint(t, "proxy", &x509.Certificate{}, &ca)
	if reason, bad := InspectTrustChain(chainPEM(leaf, ca)); bad {
		t.Fatalf("reason = %q, want ACCEPTED: an absent KeyUsage extension SKIPS the check", reason)
	}
}

// TestInspectTrustChainRejectsAPresentKeyUsageWithoutCertSign is trap 2's other half: when the
// extension IS present and bit 5 is clear, the check fires.
func TestInspectTrustChainRejectsAPresentKeyUsageWithoutCertSign(t *testing.T) {
	ca := mint(t, "ca-no-certsign", &x509.Certificate{
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}, nil)
	if !hasKeyUsageExtension(ca.cert) {
		t.Fatal("test setup: expected a CA WITH a KeyUsage extension")
	}
	leaf := mint(t, "proxy", &x509.Certificate{}, &ca)
	reason, bad := InspectTrustChain(chainPEM(leaf, ca))
	if !bad || !strings.Contains(reason, "not permitted to sign certificates") {
		t.Fatalf("reason = %q bad = %v, want the cert-sign message", reason, bad)
	}
}

// TestInspectTrustChainRejectsASmuggledAnchor.
//
// 🔒 "A client pointed at this as sslrootcert / --ssl-ca TRUSTS EVERY CERTIFICATE IN IT, so an extra
// CA appended to a real leaf is worth flagging — it is not a link in the chain." Issuance is checked
// by SIGNATURE, never by name.
func TestInspectTrustChainRejectsASmuggledAnchor(t *testing.T) {
	realCA := mint(t, "real-ca", &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := mint(t, "proxy", &x509.Certificate{}, &realCA)
	strangerCA := mint(t, "stranger-ca", &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)

	reason, bad := InspectTrustChain(chainPEM(leaf, strangerCA))
	if !bad || !strings.Contains(reason, "does not issue certificate 0") {
		t.Fatalf("reason = %q bad = %v, want the signature-mismatch message", reason, bad)
	}
}

// TestInspectTrustChainRejectsGarbage covers trap 4: pem.Decode over "" and over non-PEM bytes
// returns NO block, and this port deliberately maps both to "contains no certificate".
// KT: TrustChainInspectionTest.kt#unparseable or empty input is reported
func TestInspectTrustChainRejectsGarbage(t *testing.T) {
	for _, input := range []string{"", "not a certificate at all", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"} {
		reason, bad := InspectTrustChain(input)
		if !bad {
			t.Errorf("InspectTrustChain(%q) accepted it, want a reason", input)
		}
		if reason == "" {
			t.Errorf("InspectTrustChain(%q) reported bad with no reason", input)
		}
	}
}
