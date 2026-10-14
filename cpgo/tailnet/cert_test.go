package tailnet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/youmark/pkcs8"
)

// fakeACM exports a fresh self-signed certificate for console.example.com, encrypting its key under the
// passphrase it is given, as ACM does.
type fakeACM struct {
	exports int
	fail    error
	keyFor  func() *ecdsa.PrivateKey
}

func (f *fakeACM) ExportCertificate(_ context.Context, in *acm.ExportCertificateInput, _ ...func(*acm.Options)) (*acm.ExportCertificateOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.exports++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(f.exports)), Subject: pkix.Name{CommonName: "console.example.com"},
		DNSNames: []string{"console.example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	served := key
	if f.keyFor != nil {
		served = f.keyFor()
	}
	enc, err := pkcs8.MarshalPrivateKey(served, in.Passphrase, nil)
	if err != nil {
		return nil, err
	}
	return &acm.ExportCertificateOutput{
		Certificate:      aws.String(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
		CertificateChain: aws.String(""),
		PrivateKey:       aws.String(string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc}))),
	}, nil
}

func TestCertExportsAndRenews(t *testing.T) {
	ctx := context.Background()
	f := &fakeACM{}
	c, err := newCert(ctx, "arn:aws:acm:us-east-1:111122223333:certificate/example", f)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := c.GetCertificate(nil)
	if first.Leaf.Subject.CommonName != "console.example.com" || first.PrivateKey == nil {
		t.Fatalf("served %+v", first.Leaf.Subject)
	}
	if err := c.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if second, _ := c.GetCertificate(nil); second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("a re-export is not served")
	}
	second, _ := c.GetCertificate(nil)
	f.fail = errors.New("throttled")
	if err := c.refresh(ctx); err == nil {
		t.Fatal("a failed export reported success")
	}
	if kept, _ := c.GetCertificate(nil); kept != second {
		t.Fatal("a failed export changed the served certificate")
	}
}

func TestCertRejectsAKeyThatDoesNotMatch(t *testing.T) {
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := newCert(context.Background(), "arn", &fakeACM{keyFor: func() *ecdsa.PrivateKey { return other }})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectName(t *testing.T) {
	c, err := newCert(context.Background(), "arn", &fakeACM{})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"console.example.com":    "console.example.com",
		"console.example.com:80": "console.example.com",
		"100.99.99.99":           "console.example.com",
		"other.example.com:80":   "console.example.com",
	} {
		if got := c.redirectName(host); got != want {
			t.Errorf("redirectName(%q) = %q, want %q", host, got, want)
		}
	}
}
