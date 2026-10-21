package dbtest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	mysqlTLSOnce sync.Once
	mysqlTLSB    TargetDb
	mysqlTLSErr  error

	pgTLSOnce sync.Once
	pgTLSB    TargetDb
	pgTLSErr  error
)

// TLSCAFile is the CA that signs the TLS-only target DBs' certificate (SANs localhost, 127.0.0.1, ::1).
func TLSCAFile() string { return tlsFixture("ca.crt") }

// OtherCAFile is a CA that signed nothing the test target DBs present.
func OtherCAFile() string { return tlsFixture("other-ca.crt") }

// VerifyFullTLS is a verify-full client config against TLSCAFile for host.
func VerifyFullTLS(t testing.TB, host string) *tls.Config {
	t.Helper()
	pem, err := os.ReadFile(TLSCAFile())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("test CA holds no certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
}

// MySQLTLS is a MySQL target DB that refuses plaintext (require_secure_transport), like RDS with TLS enforced.
func MySQLTLS(t testing.TB) TargetDb {
	t.Helper()
	mysqlTLSOnce.Do(func() { mysqlTLSB, mysqlTLSErr = startMySQLTLS() })
	if mysqlTLSErr != nil {
		t.Fatalf("TLS-only MySQL test container unavailable (Docker is required for DB-backed tests): %v", mysqlTLSErr)
	}
	return mysqlTLSB
}

// PostgresTLS is a Postgres target DB whose pg_hba accepts only hostssl, like RDS with rds.force_ssl=1.
func PostgresTLS(t testing.TB) TargetDb {
	t.Helper()
	pgTLSOnce.Do(func() { pgTLSB, pgTLSErr = startPostgresTLS() })
	if pgTLSErr != nil {
		t.Fatalf("TLS-only Postgres test container unavailable (Docker is required for DB-backed tests): %v", pgTLSErr)
	}
	return pgTLSB
}

func tlsFixture(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "tls", name)
}

func tlsFiles() []testcontainers.ContainerFile {
	var files []testcontainers.ContainerFile
	for _, name := range []string{"ca.crt", "server.crt", "server.key"} {
		files = append(files, testcontainers.ContainerFile{HostFilePath: tlsFixture(name), ContainerFilePath: "/tls/" + name, FileMode: 0o644})
	}
	return files
}

func startMySQLTLS() (TargetDb, error) {
	const user, pass, db = "root", "rootpw", "app"
	img := image("PM_TEST_MYSQL_IMAGE", defaultMySQLImage)
	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         containerName("pm-goproxy-it-mysql-tls", img),
		ExposedPorts: []string{"3306/tcp"},
		Env:          map[string]string{"MYSQL_ROOT_PASSWORD": pass, "MYSQL_DATABASE": db},
		Files:        tlsFiles(),
		Cmd: []string{
			"--require-secure-transport=ON",
			"--ssl-ca=/tls/ca.crt", "--ssl-cert=/tls/server.crt", "--ssl-key=/tls/server.key",
		},
		WaitingFor: wait.ForSQL("3306/tcp", "mysql", func(host string, port network.Port) string {
			return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?tls=skip-verify", user, pass, host, port.Port(), db)
		}).WithStartupTimeout(startupTimeout),
	}
	return start(req, "3306/tcp", user, pass, db)
}

func startPostgresTLS() (TargetDb, error) {
	const user, pass, db = "postgres", "pgpw", "app"
	img := image("PM_TEST_POSTGRES_IMAGE", defaultPostgresImage)
	// Postgres refuses a key readable by others, so it is copied to a postgres-owned 0600 file first.
	script := strings.Join([]string{
		"install -o postgres -m 600 /tls/server.key /tmp/server.key",
		"install -o postgres -m 644 /tls/server.crt /tmp/server.crt",
		`printf 'local all all trust\nhostssl all all all scram-sha-256\n' > /tmp/pg_hba.conf`,
		"exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c hba_file=/tmp/pg_hba.conf",
	}, " && ")
	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         containerName("pm-goproxy-it-pg-tls", img),
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_PASSWORD": pass, "POSTGRES_DB": db},
		Files:        tlsFiles(),
		Entrypoint:   []string{"sh", "-c", script},
		WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port network.Port) string {
			return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=require", user, pass, host, port.Port(), db)
		}).WithStartupTimeout(startupTimeout),
	}
	return start(req, "5432/tcp", user, pass, db)
}
