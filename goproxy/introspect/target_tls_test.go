package introspect

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/targettls"
)

func TestIntrospectsTLSOnlyTargets(t *testing.T) {
	for name, tc := range map[string]struct {
		db  dbtest.TargetDb
		run func(spi.TargetConfig) (*pb.CatalogRequest, error)
	}{
		"mysql":    {dbtest.MySQLTLS(t), runMySQL},
		"postgres": {dbtest.PostgresTLS(t), runPostgres},
	} {
		t.Run(name, func(t *testing.T) {
			config := spi.TargetConfig{Host: tc.db.Host, Port: tc.db.Port, Db: tc.db.DB, User: tc.db.User, Password: tc.db.Password}
			if _, err := tc.run(config); err == nil {
				t.Fatal("plaintext introspection of a TLS-only target succeeded")
			}
			config.TLS = dbtest.VerifyFullTLS(t, tc.db.Host)
			catalog, err := tc.run(config)
			if err != nil {
				t.Fatalf("introspect over TLS: %v", err)
			}
			if catalog.GetEngineVersion() == "" {
				t.Fatal("introspection over TLS returned no server version")
			}
			if config.TLS, err = targettls.Config(targettls.VerifyCA, dbtest.TLSCAFile(), "my-project:my-instance"); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.run(config); err != nil {
				t.Fatalf("introspect over verify-ca: %v", err)
			}
			if config.TLS, err = targettls.Config(targettls.VerifyCA, dbtest.OtherCAFile(), tc.db.Host); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.run(config); err == nil {
				t.Fatal("verify-ca introspection accepted a certificate from an unrelated CA")
			}
			config.TLS = dbtest.VerifyFullTLS(t, "not-the-san.example")
			if _, err := tc.run(config); err == nil {
				t.Fatal("introspection accepted a certificate that does not name the target host")
			}
			config.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), ServerName: tc.db.Host}
			if _, err := tc.run(config); err == nil {
				t.Fatal("introspection accepted a certificate from an untrusted CA")
			}
		})
	}
}
