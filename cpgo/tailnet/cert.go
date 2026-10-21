package tailnet

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/youmark/pkcs8"
)

// exporter is the one ACM call the certificate needs.
type exporter interface {
	ExportCertificate(ctx context.Context, in *acm.ExportCertificateInput, opts ...func(*acm.Options)) (*acm.ExportCertificateOutput, error)
}

// Cert serves an exportable ACM certificate. ACM returns the key encrypted under a passphrase the caller
// picks, so each export uses a fresh random one and decrypts the key in memory.
type Cert struct {
	arn string
	acm exporter
	cur atomic.Pointer[tls.Certificate]
}

// NewCertFromACM exports the certificate once, so a bad ARN or a missing permission fails at start.
func NewCertFromACM(ctx context.Context, arn string) (*Cert, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("tailnet: AWS config: %w", err)
	}
	return newCert(ctx, arn, acm.NewFromConfig(cfg))
}

func newCert(ctx context.Context, arn string, x exporter) (*Cert, error) {
	c := &Cert{arn: arn, acm: x}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// GetCertificate is the tls.Config hook.
func (c *Cert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cur.Load(), nil
}

// redirectName is the name an http request to host is redirected to: host itself when the certificate
// covers it, or else the certificate's first exact name.
func (c *Cert) redirectName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	leaf := c.cur.Load().Leaf
	if leaf.VerifyHostname(host) != nil {
		for _, n := range leaf.DNSNames {
			if !strings.HasPrefix(n, "*.") {
				return n
			}
		}
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// KeepFresh exports again every interval, so a renewed certificate is served without a restart. A failed
// export keeps the current certificate.
func (c *Cert) KeepFresh(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.refresh(ctx); err != nil {
				slog.Warn("tailnet: re-exporting the certificate failed; serving the current one", "err", err)
			}
		}
	}
}

func (c *Cert) refresh(ctx context.Context) error {
	pass := rand.Text()
	out, err := c.acm.ExportCertificate(ctx, &acm.ExportCertificateInput{CertificateArn: aws.String(c.arn), Passphrase: []byte(pass)})
	if err != nil {
		return fmt.Errorf("tailnet: exporting %s: %w", c.arn, err)
	}
	cert, err := parseExport(aws.ToString(out.Certificate), aws.ToString(out.CertificateChain), aws.ToString(out.PrivateKey), pass)
	if err != nil {
		return fmt.Errorf("tailnet: certificate %s: %w", c.arn, err)
	}
	c.cur.Store(cert)
	return nil
}

// parseExport builds the served certificate from an export: the leaf, its chain, and the encrypted key.
func parseExport(certPEM, chainPEM, keyPEM, pass string) (*tls.Certificate, error) {
	var out tls.Certificate
	for rest := []byte(certPEM + "\n" + chainPEM); ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out.Certificate = append(out.Certificate, block.Bytes)
		}
	}
	if len(out.Certificate) == 0 {
		return nil, errors.New("no certificate in the export")
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("no private key in the export")
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(pass))
	if err != nil {
		return nil, fmt.Errorf("decrypting the private key: %w", err)
	}
	out.PrivateKey = key
	if out.Leaf, err = x509.ParseCertificate(out.Certificate[0]); err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	pub, same := out.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !same || !pub.Equal(signer.Public()) {
		return nil, errors.New("the private key does not match the certificate")
	}
	return &out, nil
}
