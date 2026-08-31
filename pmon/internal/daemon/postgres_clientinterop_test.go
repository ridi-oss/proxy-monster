//go:build e2e_clients

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
)

const postgresInteropImage = "postgres:16"

var (
	postgresBackendOnce sync.Once
	postgresBackendAddr string
	postgresBackendErr  error
)

func TestClientInteropPostgresCLI(t *testing.T) {
	h := newPostgresHarness(t)
	command := forContainer(conn.String(conn.CLI, postgresClientTarget(h.brokerPort))) +
		` -Atc "SELECT 'DB=' || current_database(); SELECT 'ROW=' || name FROM members WHERE id=1; SELECT 'PSQL_OK';"`
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: postgresInteropImage,
		Cmd:   []string{"sh", "-c", command},
	})
	assertPostgresClientResult(t, logs, "PSQL_OK")
}

const postgresJDBCProbeSource = `import java.sql.*;
public class Probe {
  public static void main(String[] a) throws Exception {
    try (Connection c = DriverManager.getConnection(a[0]); Statement s = c.createStatement()) {
      try (ResultSet r = s.executeQuery("SELECT current_database()")) { r.next(); System.out.println("DB=" + r.getString(1)); }
      try (ResultSet r = s.executeQuery("SELECT name FROM members WHERE id=1")) { r.next(); System.out.println("ROW=" + r.getString(1)); }
      int backendPid;
      try (ResultSet r = s.executeQuery("SELECT pg_backend_pid()")) { r.next(); backendPid = r.getInt(1); }
      if (!c.isValid(5)) throw new IllegalStateException("healthy connection reported invalid");
      System.out.println("VALID_OK");
      try (Connection killer = DriverManager.getConnection(a[0]); Statement ks = killer.createStatement()) {
        try (ResultSet r = ks.executeQuery("SELECT pg_terminate_backend(" + backendPid + ")")) {
          if (!r.next() || !r.getBoolean(1)) throw new IllegalStateException("target session was not terminated");
        }
      }
      if (c.isValid(5)) throw new IllegalStateException("terminated connection reported valid");
      System.out.println("INVALID_OK");
      System.out.println("JDBC_OK");
    }
  }
}
`

func TestClientInteropPostgresJDBC(t *testing.T) {
	h := newPostgresHarness(t)
	probe := writeTempFile(t, "Probe.java", postgresJDBCProbeSource)
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: "eclipse-temurin:24-jdk",
		Files: []testcontainers.ContainerFile{
			{HostFilePath: probe, ContainerFilePath: "/work/Probe.java", FileMode: 0o644},
			{HostFilePath: mavenJar(t, "org.postgresql", "postgresql", "42.7.5"), ContainerFilePath: "/work/driver.jar", FileMode: 0o644},
		},
		Env: map[string]string{"PM_URL": forContainer(conn.String(conn.JDBC, postgresClientTarget(h.brokerPort)))},
		Cmd: []string{"sh", "-c", `cd /work && javac Probe.java && java -cp .:driver.jar Probe "$PM_URL"`},
	})
	assertPostgresClientResult(t, logs, "JDBC_OK")
	mustContain(t, logs, "VALID_OK")
	mustContain(t, logs, "INVALID_OK")
}

func TestClientInteropPostgresGoPGX(t *testing.T) {
	h := newPostgresHarness(t)
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: postgresInteropImage,
		Files: []testcontainers.ContainerFile{{HostFilePath: buildPostgresGoClient(t), ContainerFilePath: "/pgclient", FileMode: 0o755}},
		Env:   map[string]string{"PM_DSN": forContainer(conn.String(conn.GoDSN, postgresClientTarget(h.brokerPort)))},
		Cmd:   []string{"/pgclient"},
	})
	assertPostgresClientResult(t, logs, "GO_OK")
	mustContain(t, logs, "CANCEL_OK")
}

const postgresNodeProbeSource = `const { Client } = require('pg');
(async () => {
  const c = new Client({ connectionString: process.env.PM_URL });
  await c.connect();
  const d = await c.query('SELECT current_database() AS db');
  console.log('DB=' + d.rows[0].db);
  const r = await c.query('SELECT name FROM members WHERE id=1');
  console.log('ROW=' + r.rows[0].name);
  console.log('NODE_OK');
  await c.end();
})().catch(e => { console.error('ERR', e && e.message ? e.message : e); process.exit(1); });
`

func TestClientInteropPostgresNode(t *testing.T) {
	h := newPostgresHarness(t)
	probe := writeTempFile(t, "probe.js", postgresNodeProbeSource)
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: "node:20",
		Files: []testcontainers.ContainerFile{{HostFilePath: probe, ContainerFilePath: "/work/probe.js", FileMode: 0o644}},
		Env:   map[string]string{"PM_URL": forContainer(conn.String(conn.URL, postgresClientTarget(h.brokerPort)))},
		Cmd:   []string{"sh", "-c", "cd /work && npm install --no-save --no-audit --no-fund pg@8 >/tmp/npm.log 2>&1 && node probe.js"},
	})
	assertPostgresClientResult(t, logs, "NODE_OK")
}

type postgresHarness struct{ brokerPort int }

func newPostgresHarness(t *testing.T) *postgresHarness {
	t.Helper()
	return &postgresHarness{brokerPort: startPostgresInteropBroker(t, startPostgresBackend(t))}
}

func postgresClientTarget(port int) conn.Target {
	return conn.Target{Engine: "postgres", DbName: itDatabase, Port: port, User: itPrincipal, Password: itLocalPassword}
}

func startPostgresBackend(t *testing.T) string {
	t.Helper()
	postgresBackendOnce.Do(func() { postgresBackendAddr, postgresBackendErr = createPostgresBackend() })
	if postgresBackendErr != nil {
		t.Fatalf("start backend PostgreSQL (Docker required for e2e_clients): %v", postgresBackendErr)
	}
	return postgresBackendAddr
}

func createPostgresBackend() (string, error) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        postgresInteropImage,
		Name:         "pm-pmon-clientinterop-postgres16",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":             itPrincipal,
			"POSTGRES_PASSWORD":         itToken,
			"POSTGRES_DB":               itDatabase,
			"POSTGRES_HOST_AUTH_METHOD": "password",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(180 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		return "", fmt.Errorf("start container: %w", err)
	}

	seed := "CREATE TABLE IF NOT EXISTS members (id INT PRIMARY KEY, name VARCHAR(64)); " +
		"INSERT INTO members (id, name) VALUES (1, 'ada') ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name;"
	exitCode, output, err := container.Exec(ctx, []string{"psql", "-v", "ON_ERROR_STOP=1", "-U", itPrincipal, "-d", itDatabase, "-c", seed})
	if err != nil {
		return "", fmt.Errorf("seed backend: %w", err)
	}
	if exitCode != 0 {
		body, _ := io.ReadAll(output)
		return "", fmt.Errorf("seed backend exited %d: %s", exitCode, body)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("backend host: %w", err)
	}
	mapped, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return "", fmt.Errorf("backend port: %w", err)
	}
	return net.JoinHostPort(host, mapped.Port()), nil
}

func startPostgresInteropBroker(t *testing.T, proxyAddr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = brokerPostgres(c, proxyAddr, "", false, itToken, itLocalPassword)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func buildPostgresGoClient(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pgclient")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join("testdata", "pgclient")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build PostgreSQL Go client: %v\n%s", err, out)
	}
	return bin
}

func assertPostgresClientResult(t *testing.T, logs, marker string) {
	t.Helper()
	mustContain(t, logs, "DB=app")
	mustContain(t, logs, "ROW=ada")
	mustContain(t, logs, marker)
}
