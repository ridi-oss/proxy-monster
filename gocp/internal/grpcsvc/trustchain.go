package grpcsvc

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// keyUsageOID is X.509's KeyUsage extension, id-ce-keyUsage (2.5.29.15). Needed because Go's
// x509.Certificate.KeyUsage is 0 both when the extension is ABSENT and when every bit is clear — see
// [InspectTrustChain]'s divergence trap 2.
var keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// InspectTrustChain inspects a PEM certificate chain THE WAY A CLIENT WILL, returning ok=false (no
// reason) when it looks usable and a short reason when it does not.
//
// 🔒 THIS REPORTS; IT NEVER DECIDES. Callers log the reason and serve the chain regardless — the
// client performs the real verification and is the only party that can act on the outcome
// (INV-A10-28).
//
// The three load-bearing reasons, quoted from the Kotlin:
//   - Chain shape: "The chain must actually CHAIN: the first certificate is the leaf a client will be
//     presented, the last is the trust anchor, and each must be issued by the next. A single
//     certificate is only valid when it is self-signed."
//   - Smuggled anchor: "A client pointed at this as sslrootcert / --ssl-ca TRUSTS EVERY CERTIFICATE
//     IN IT, so an extra CA appended to a real leaf is worth flagging — it is not a link in the chain."
//   - Issuance is checked by SIGNATURE, never by name: "a certificate naming itself or its
//     predecessor as issuer proves nothing on its own."
//   - basicConstraints: "A signature alone is not enough: a client enforces basicConstraints, so a
//     chain whose issuer is CA:FALSE is rejected by OpenSSL as 'invalid CA certificate' — accepting it
//     here would store a chain no client can use, and would let a leaf that happens to hold a key be
//     presented as an issuer."
//
// ⚠️ THREE GO DIVERGENCE TRAPS, all of them silent if got wrong (10-grpc.md §3.1):
//  1. Kotlin's `basicConstraints < 0` means "the extension is ABSENT OR CA:FALSE". The Go equivalent
//     is `!cert.IsCA`, NOT `cert.MaxPathLen < 0`, which means something else entirely.
//  2. Kotlin's `keyUsage?.getOrNull(5) == false` fires ONLY when the extension is PRESENT and bit 5
//     is clear. A CA with NO KeyUsage extension has keyUsage == null, so the check is SKIPPED. Go's
//     cert.KeyUsage is 0 when absent, so a naive `KeyUsage & KeyUsageCertSign == 0` would REJECT a CA
//     Kotlin accepts. Hence the raw-extension presence test below.
//  3. Kotlin's `certs[i].verify(issuer.publicKey)` is a PURE SIGNATURE CHECK. Go's
//     CheckSignatureFrom additionally enforces IsCA and KeyUsageCertSign and returns different errors,
//     which would double up rules 4a/4b and change which message is produced. The faithful call is
//     issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature).
func InspectTrustChain(pemChain string) (reason string, bad bool) {
	certs, err := parsePEMChain(pemChain)
	if err != nil {
		return "is not a parseable PEM certificate chain", true
	}
	// 2. `generateCertificates` on input with no certificate yields an empty list. pem.Decode on "" or
	// on non-PEM bytes returns no block, which lands here — the Kotlin test only asserts non-null, and
	// this is the deliberate pick between the two candidate messages.
	if len(certs) == 0 {
		return "contains no certificate", true
	}
	// 3. A single certificate is its own anchor only when it is self-signed — the ordinary proxy case.
	if len(certs) == 1 {
		if selfSigned(certs[0]) {
			return "", false
		}
		return "carries one certificate and it is not self-signed, so it cannot be a trust anchor — append the issuing CA", true
	}
	// 4.
	for i := 0; i < len(certs)-1; i++ {
		issuer := certs[i+1]
		if !issuer.IsCA { // trap 1
			return fmt.Sprintf("is not a valid chain: certificate %d is not a CA, so it cannot issue certificate %d", i+1, i), true
		}
		if hasKeyUsageExtension(issuer) && issuer.KeyUsage&x509.KeyUsageCertSign == 0 { // trap 2
			return fmt.Sprintf("is not a valid chain: certificate %d is not permitted to sign certificates", i+1), true
		}
		if !signedBy(certs[i], issuer) { // trap 3
			return fmt.Sprintf("is not a valid chain: certificate %d does not issue certificate %d", i+1, i), true
		}
	}
	// 5.
	if !selfSigned(certs[len(certs)-1]) {
		return "does not end in a self-signed trust anchor, so a client could not verify the leaf", true
	}
	// 6.
	return "", false
}

// parsePEMChain is CertificateFactory.generateCertificates over a concatenated PEM bundle: Go needs a
// pem.Decode LOOP, and non-CERTIFICATE blocks are skipped exactly as the Java factory filters to
// X509Certificate.
func parsePEMChain(raw string) ([]*x509.Certificate, error) {
	rest := []byte(raw)
	out := []*x509.Certificate{}
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
}

// selfSigned is Kotlin's `cert.verify(cert.publicKey)` — a pure signature check against its own key.
func selfSigned(c *x509.Certificate) bool { return signedBy(c, c) }

// signedBy is the pure signature check of trap 3.
func signedBy(child, issuer *x509.Certificate) bool {
	return issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// hasKeyUsageExtension reports whether the KeyUsage extension is PRESENT, which is what makes trap 2's
// "absent ⇒ skip the check" behaviour reproducible.
func hasKeyUsageExtension(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(keyUsageOID) {
			return true
		}
	}
	return false
}
