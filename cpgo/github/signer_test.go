package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeKMS struct{ in *kms.SignInput }

func (k *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	k.in = in
	sig, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, in.Message)
	return &kms.SignOutput{Signature: sig}, err
}

func TestTheKMSSignerSignsTheJWTDigestWithRS256(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/contents/a.sql", ok("x"))
	k := &fakeKMS{}
	c, err := New(appID, f.srv.URL, kmsSigner{keyID: "alias/app", kms: k})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadFile(ctx, repo, "main", "a.sql"); err != nil {
		t.Fatal(err)
	}
	if *k.in.KeyId != "alias/app" || k.in.MessageType != types.MessageTypeDigest || k.in.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Fatalf("sign input %+v", k.in)
	}
	parts := strings.Split(strings.TrimPrefix(f.to("GET", "/repos/acme/shop/installation")[0].header.Get("Authorization"), "Bearer "), ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("a KMS-signed JWT must verify as RS256: %v", err)
	}
}

func TestTrustCAsLetsTheClientReachAGitHubBehindAPrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			_, _ = io.WriteString(w, `{"id":42}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			_, _ = io.WriteString(w, `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`)
		default:
			_, _ = io.WriteString(w, `{"status":"ahead"}`)
		}
	}))
	defer srv.Close()
	c, err := New(appID, srv.URL, pemSignerForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CompareCommits(ctx, repo, "a", "b"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an untrusted CA must fail: %v", err)
	}
	if err := c.TrustCAs(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})); err != nil {
		t.Fatal(err)
	}
	if rel, err := c.CompareCommits(ctx, repo, "a", "b"); err != nil || rel != Ahead {
		t.Fatalf("got %v %v", rel, err)
	}
	if err := c.TrustCAs([]byte("not a pem")); err == nil {
		t.Fatal("a file with no certificate must fail")
	}
}

func pemSignerForTest(t *testing.T) Signer {
	t.Helper()
	s, err := NewPEMSigner(pkcs8PEM())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
