package targettls

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

const testCA = "../internal/dbtest/testdata/tls/ca.crt"

func TestParseMode(t *testing.T) {
	for raw, want := range map[string]Mode{"": Disable, " disable ": Disable, "REQUIRE": Require, "verify-ca": VerifyCA, "verify-full": VerifyFull} {
		got, err := ParseMode(raw)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := ParseMode("prefer"); err == nil {
		t.Fatal("ParseMode(prefer) should fail")
	}
}

func TestConfig(t *testing.T) {
	if config, err := Config(Disable, "", "db"); config != nil || err != nil {
		t.Fatalf("disable = %v, %v; want nil, nil", config, err)
	}
	require, err := Config(Require, "", "db")
	if err != nil || !require.InsecureSkipVerify || require.ServerName != "db" {
		t.Fatalf("require = %+v, %v; want an unverified config", require, err)
	}
	verify, err := Config(VerifyFull, "", "db.example")
	if err != nil || verify.InsecureSkipVerify || verify.ServerName != "db.example" {
		t.Fatalf("verify-full = %+v, %v; want a config checked against db.example", verify, err)
	}
	if _, err := Config(VerifyFull, "", " "); err == nil {
		t.Fatal("verify-full without a host should fail")
	}
	verifyCA, err := Config(VerifyCA, testCA, "project:instance")
	if err != nil || verifyCA.VerifyConnection == nil || !verifyCA.InsecureSkipVerify {
		t.Fatalf("verify-ca = %+v, %v; want a chain-only check", verifyCA, err)
	}
	for _, cas := range []string{"", "system", "rds", testCA + ",rds", " system , " + testCA} {
		if _, err := Config(VerifyCA, cas, "db"); err == nil {
			t.Fatalf("verify-ca with PM_TARGET_CA=%q should fail: only a dedicated CA stands in for the hostname", cas)
		}
	}
	if _, err := Config(Require, "rds", "db"); err == nil {
		t.Fatal("PM_TARGET_CA outside verify-full should fail rather than be ignored")
	}
}

func TestRootPool(t *testing.T) {
	rds := x509.NewCertPool()
	if !rds.AppendCertsFromPEM(rdsBundle) || len(rds.Subjects()) < 100 {
		t.Fatalf("the embedded RDS bundle parses to %d roots, want the ~111 AWS publishes", len(rds.Subjects()))
	}
	file := x509.NewCertPool()
	file.AppendCertsFromPEM(read(t, testCA))
	both := x509.NewCertPool()
	both.AppendCertsFromPEM(rdsBundle)
	both.AppendCertsFromPEM(read(t, testCA))
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	systemRDS, _ := x509.SystemCertPool()
	systemRDS.AppendCertsFromPEM(rdsBundle)

	for cas, want := range map[string]*x509.CertPool{
		"rds":              rds,
		testCA:             file,
		" rds , " + testCA: both,
		"system":           system,
		DefaultCAs:         systemRDS,
		"rds,system":       systemRDS,
	} {
		got, err := rootPool(cas)
		if err != nil {
			t.Fatalf("rootPool(%q): %v", cas, err)
		}
		if !got.Equal(want) {
			t.Fatalf("rootPool(%q) holds the wrong roots", cas)
		}
	}

	t.Chdir(filepath.Dir(testCA))
	if got, err := rootPool(filepath.Base(testCA)); err != nil || !got.Equal(file) {
		t.Fatalf("relative path: %v", err)
	}

	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cas := range []string{notPEM, "/does/not/exist.pem", "rds,", "rds,,system"} {
		if _, err := rootPool(cas); err == nil {
			t.Fatalf("rootPool(%q) should fail", cas)
		}
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
