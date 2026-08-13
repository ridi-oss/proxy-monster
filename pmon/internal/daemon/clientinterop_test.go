//go:build e2e_clients

// Client-interop end-to-end tests: real client libraries (the mysql CLI, JDBC/Connector-J, the Go
// driver, Node, and PHP PDO_MySQL) connect through the REAL local broker (brokerMySQL) using the EXACT
// connection string `pmon show` prints, and must authenticate, select their database, and read a row
// back. This is
// the surface the DBeaver/JDBC bug lived on — a driver that writes its schema into the handshake was
// misrouted to mysql_clear_password — so the bar is the connection string "just works" for every client,
// not just the mysql CLI.
//
// Topology per test: client container ──(pmon conn string)──▶ brokerMySQL (host) ──▶ token-auth proxy
// stub (host) ──▶ real MySQL backend (container). The stub stands in for goproxy+control-plane, which is
// out of scope here: it answers the broker's clear-password/token handshake and then splices the command
// phase to a real backend, so clients run real queries and get real rows. The broker code under test is
// the real thing.
//
// Gated behind the `e2e_clients` build tag (it pulls several multi-hundred-MB client images); run with
// `mise run e2e-clients` or `go test -tags e2e_clients ./pmon/internal/daemon/ -run ClientInterop`.
package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/moby/moby/api/types/network"
	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/conn"
)

// The fixed identity the broker checks locally. The values are cosmetic to the upstream (the stub
// accepts any token), but they are what a client copy-pastes, so they exercise the real password check.
const (
	itPrincipal     = "alice"
	itLocalPassword = "pmlocalTESTpw123"
	itToken         = "brokered-wire-token"
	itDatabase      = "app"
	// dockerHostAlias is how a client container reaches a listener on the test host. host-gateway is
	// added to the container's /etc/hosts so this resolves on Linux CI as well as Docker Desktop.
	dockerHostAlias = "host.docker.internal"
)

// backendMySQLImage is pinned to 8.0 (not the repo's 8.4 default) because the proxy stub authenticates to
// the backend with a hand-rolled mysql_native_password handshake, and 8.4 ships that plugin disabled.
// The backend engine version is not what these tests exercise — the broker's client-facing handshake is.
const backendMySQLImage = "mysql:8.0"

var (
	backendOnce sync.Once
	backendAddr string
	backendUser string
	backendPass string
	backendErr  error
)

// startBackend returns the shared MySQL backend, started ONCE per test binary (the goproxy dbtest
// pattern) and shared across every client subtest, so a test's teardown never pulls the server out from
// under the next and — unlike a bare fixed-name Reuse — the run does not depend on testcontainers reuse
// being enabled to avoid a name collision. It fails the test if Docker is unavailable.
func startBackend(t *testing.T) (addr, user, pass string) {
	t.Helper()
	backendOnce.Do(func() { backendAddr, backendUser, backendPass, backendErr = createBackend() })
	if backendErr != nil {
		t.Fatalf("start backend MySQL (Docker required for e2e_clients): %v", backendErr)
	}
	return backendAddr, backendUser, backendPass
}

// createBackend brings up a MySQL backend with a native-password account the proxy stub can auth as, a
// seed table, and one row, and returns its host:port and that account's credentials.
func createBackend() (addr, user, pass string, err error) {
	ctx := context.Background()
	const rootPass = "rootpw"
	const proxyUser, proxyPass = "proxyuser", "proxypw"

	req := testcontainers.ContainerRequest{
		Image:        backendMySQLImage,
		Name:         "pm-pmon-clientinterop-mysql",
		ExposedPorts: []string{"3306/tcp"},
		Env:          map[string]string{"MYSQL_ROOT_PASSWORD": rootPass, "MYSQL_DATABASE": itDatabase},
		// Serve native by default so the stub's hand-rolled native handshake is accepted directly rather
		// than provoking an auth-switch. This is the stub's private backend hop, not the surface under test.
		Cmd: []string{"--default-authentication-plugin=mysql_native_password"},
		WaitingFor: wait.ForSQL("3306/tcp", "mysql", func(host string, port network.Port) string {
			return fmt.Sprintf("root:%s@tcp(%s:%s)/%s", rootPass, host, port.Port(), itDatabase)
		}).WithStartupTimeout(180 * time.Second),
	}
	// Reuse lets a separate test binary (a matrix leg) share this one rather than collide on the name; the
	// sync.Once above is what serializes creation WITHIN this binary, so a reuse-disabled host still works.
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true, Reuse: true})
	if err != nil {
		return "", "", "", fmt.Errorf("start container: %w", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("backend host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, "3306/tcp")
	if err != nil {
		return "", "", "", fmt.Errorf("backend port: %w", err)
	}
	addr = net.JoinHostPort(host, mapped.Port())

	db, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(%s)/%s", rootPass, addr, itDatabase))
	if err != nil {
		return "", "", "", fmt.Errorf("open backend: %w", err)
	}
	defer db.Close()
	for _, s := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'%%' IDENTIFIED WITH mysql_native_password BY '%s'", proxyUser, proxyPass),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%%'", proxyUser),
		"CREATE TABLE IF NOT EXISTS members (id INT PRIMARY KEY, name VARCHAR(64))",
		"INSERT INTO members (id, name) VALUES (1, 'ada') ON DUPLICATE KEY UPDATE name=VALUES(name)",
	} {
		if _, err := db.Exec(s); err != nil {
			return "", "", "", fmt.Errorf("seed backend (%q): %w", s, err)
		}
	}
	return addr, proxyUser, proxyPass, nil
}

// startProxyStub listens for the broker's upstream connection, answers the clear-password/token handshake
// the broker performs (proxyConnect), then splices the command phase to a fresh backend connection it
// authenticates itself. It returns the stub's listen address. One backend connection is opened per broker
// connection; the whole thing is a transparent relay once both handshakes complete.
func startProxyStub(t *testing.T, backendAddr, backendUser, backendPass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy stub: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveProxyStub(t, c, backendAddr, backendUser, backendPass)
		}
	}()
	return ln.Addr().String()
}

func serveProxyStub(t *testing.T, broker net.Conn, backendAddr, backendUser, backendPass string) {
	defer broker.Close()

	// Front half: play MySQL server to the broker. The broker sends its handshake response, we switch it
	// to mysql_clear_password, it replies with the token, we accept any. Mirror the broker's DEPRECATE_EOF
	// onto the backend connection so result-set framing lines up across the splice.
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return
	}
	if err := mysqlwire.WritePacket(broker, 0, mysqlwire.ServerGreeting(1, scramble, "8.0.40-proxy-stub", false)); err != nil {
		return
	}
	_, resp, err := mysqlwire.ReadPacket(broker) // handshake response (seq 1)
	if err != nil {
		return
	}
	frontCaps := uint32(0)
	if len(resp) >= 4 {
		frontCaps = uint32(resp[0]) | uint32(resp[1])<<8 | uint32(resp[2])<<16 | uint32(resp[3])<<24
	}
	if err := mysqlwire.WritePacket(broker, 2, mysqlwire.AuthSwitchClearPassword()); err != nil {
		return
	}
	if _, _, err := mysqlwire.ReadPacket(broker); err != nil { // token (seq 3), accepted as-is
		return
	}

	// Back half: connect to the real backend with native auth, mirroring DEPRECATE_EOF from the front.
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		_ = mysqlwire.WritePacket(broker, 4, mysqlwire.ErrPacket(1045, "proxy stub: dial backend"))
		return
	}
	defer backend.Close()
	if err := backendNativeAuth(backend, backendUser, backendPass, frontCaps&mysqlwire.CapDeprecateEOF); err != nil {
		_ = mysqlwire.WritePacket(broker, 4, mysqlwire.ErrPacket(1045, "proxy stub: backend auth: "+err.Error()))
		return
	}

	// Auth done for both hops: tell the broker OK, then relay the command phase in both directions.
	if err := mysqlwire.WritePacket(broker, 4, mysqlwire.OKPacket()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, broker); done <- struct{}{} }()
	go func() { _, _ = io.Copy(broker, backend); done <- struct{}{} }()
	<-done
}

// backendNativeAuth performs a mysql_native_password client handshake against a fresh backend connection,
// leaving it at the start of the command phase. deprecateEOF (0 or CapDeprecateEOF) is OR-ed into the caps
// so the backend frames result sets the way the client that will read them expects.
func backendNativeAuth(backend net.Conn, user, pass string, deprecateEOF uint32) error {
	_, greeting, err := mysqlwire.ReadPacket(backend) // greeting (seq 0)
	if err != nil {
		return err
	}
	g, err := mysqlwire.ParseHandshakeV10(greeting)
	if err != nil {
		return err
	}
	caps := uint32(mysqlwire.CapLongPassword|mysqlwire.CapProtocol41|mysqlwire.CapSecureConn|mysqlwire.CapPluginAuth|mysqlwire.CapTransactions) | deprecateEOF
	authResp := mysqlwire.NativePassword(pass, g.Scramble)
	if err := mysqlwire.WritePacket(backend, 1, mysqlwire.ClientHandshakeResponse(caps, user, authResp)); err != nil {
		return err
	}
	seq, res, err := mysqlwire.ReadPacket(backend) // OK, ERR, or AuthSwitchRequest
	if err != nil {
		return err
	}
	if len(res) > 0 && res[0] == 0xfe { // AuthSwitchRequest: resend the native digest under the new scramble
		plugin, sw := parseAuthSwitchRequest(res)
		if plugin != "mysql_native_password" {
			return fmt.Errorf("backend requested %q, want mysql_native_password", plugin)
		}
		if err := mysqlwire.WritePacket(backend, seq+1, mysqlwire.NativePassword(pass, sw)); err != nil {
			return err
		}
		if _, res, err = mysqlwire.ReadPacket(backend); err != nil {
			return err
		}
	}
	if len(res) > 0 && res[0] == 0xff {
		return fmt.Errorf("%s", mysqlwire.ErrString(res))
	}
	if len(res) == 0 || res[0] != 0x00 {
		return fmt.Errorf("backend native auth: unexpected reply % x", res)
	}
	return nil
}

// parseAuthSwitchRequest splits an AuthSwitchRequest (0xfe) into the plugin name and the scramble that
// follows it (trailing NUL, if present, dropped).
func parseAuthSwitchRequest(p []byte) (plugin string, scramble []byte) {
	body := p[1:]
	i := bytes.IndexByte(body, 0)
	if i < 0 {
		return string(body), nil
	}
	return string(body[:i]), bytes.TrimSuffix(body[i+1:], []byte{0})
}

// startBroker runs the REAL brokerMySQL in front of the proxy stub and returns the loopback port clients
// connect to. This is the code under test.
func startBroker(t *testing.T, proxyAddr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen broker: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Close the client conn when the session ends, as the daemon does (daemon.go's
			// `defer local.Close()`). Without it a client that quits gracefully — mysql2 awaits the
			// server's close after COM_QUIT — hangs forever waiting for a close that never comes.
			go func() {
				defer c.Close()
				_ = brokerMySQL(c, proxyAddr, "", false, itPrincipal, itToken, itLocalPassword)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// clientTarget is the pmon connection Target for the running broker, in the format a given client wants.
func clientTarget(port int) conn.Target {
	return conn.Target{Engine: "mysql", DbName: itDatabase, Port: port, User: itPrincipal, Password: itLocalPassword}
}

// forContainer rewrites the loopback host in a pmon connection string to the alias a client container
// uses to reach the test host. Everything else — port, credentials, parameters — is exactly what
// `pmon show` prints.
func forContainer(s string) string {
	return strings.ReplaceAll(s, conn.Host, dockerHostAlias)
}

// harness starts the backend, proxy stub, and broker once and hands tests the broker port.
type harness struct{ brokerPort int }

func newHarness(t *testing.T) *harness {
	t.Helper()
	backendAddr, backendUser, backendPass := startBackend(t)
	proxyAddr := startProxyStub(t, backendAddr, backendUser, backendPass)
	return &harness{brokerPort: startBroker(t, proxyAddr)}
}

// runClient runs a one-shot client container to completion and returns its combined logs, failing the
// test if it does not exit cleanly. hostExtra wires host.docker.internal to the host gateway.
func runClient(t *testing.T, req testcontainers.ContainerRequest) string {
	t.Helper()
	req.HostConfigModifier = func(hc *container.HostConfig) {
		hc.ExtraHosts = append(hc.ExtraHosts, dockerHostAlias+":host-gateway")
	}
	if req.WaitingFor == nil {
		req.WaitingFor = wait.ForExit().WithExitTimeout(120 * time.Second)
	}
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("start client container: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	rc, err := c.Logs(ctx)
	if err != nil {
		t.Fatalf("client logs: %v", err)
	}
	defer rc.Close()
	out, _ := io.ReadAll(rc)
	logs := stripDockerLogHeader(out)

	state, err := c.State(ctx)
	if err != nil {
		t.Fatalf("client state: %v", err)
	}
	if state.ExitCode != 0 {
		t.Fatalf("client exited %d\n%s", state.ExitCode, logs)
	}
	return logs
}

// stripDockerLogHeader drops the 8-byte multiplexing header the Docker log API prefixes to each frame
// when the container has no TTY, so assertions match on the real output.
func stripDockerLogHeader(b []byte) string {
	var sb strings.Builder
	for len(b) >= 8 && (b[0] == 1 || b[0] == 2) && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		n := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		sb.Write(b[:n])
		b = b[n:]
	}
	sb.Write(b)
	return sb.String()
}

// mustContain fails the test unless logs contain want — the marker a client prints only after it has
// authenticated, selected its database, and read the seed row.
func mustContain(t *testing.T, logs, want string) {
	t.Helper()
	if !strings.Contains(logs, want) {
		t.Fatalf("client output missing %q:\n%s", want, logs)
	}
}

// TestClientInteropMySQLCLI: the reference client. It defaults to caching_sha2_password, which the broker
// serves directly, and selects its database — the whole point being that the printed CLI string runs as-is.
func TestClientInteropMySQLCLI(t *testing.T) {
	h := newHarness(t)
	cli := forContainer(conn.String(conn.CLI, clientTarget(h.brokerPort)))
	// The printed command plus a query that proves auth + the right schema + the seed row.
	script := cli + ` -e "SELECT CONCAT('DB=', DATABASE()); SELECT CONCAT('ROW=', name) FROM members WHERE id=1;"`
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: backendMySQLImage,
		Cmd:   []string{"sh", "-c", script},
	})
	mustContain(t, logs, "DB=app")
	mustContain(t, logs, "ROW=ada")
}

// jdbcDrivers is the matrix of JDBC drivers the broker must interoperate with — several MySQL
// Connector/J versions (8.2.0 is the one that first surfaced both bugs; 9.x dropped the native-password
// client plugin, so it exercises the caching_sha2 path) plus MariaDB Connector/J, an independent
// implementation with its own handshake code and URL scheme. Each is fetched from Maven Central.
var jdbcDrivers = []struct {
	name     string
	group    string
	artifact string
	version  string
	scheme   string // JDBC URL sub-protocol: "mysql" or "mariadb"
}{
	{"mysql-connector-j-8.2.0", "com.mysql", "mysql-connector-j", "8.2.0", "mysql"},
	{"mysql-connector-j-8.4.0", "com.mysql", "mysql-connector-j", "8.4.0", "mysql"},
	{"mysql-connector-j-9.1.0", "com.mysql", "mysql-connector-j", "9.1.0", "mysql"},
	{"mariadb-java-client-3.3.3", "org.mariadb.jdbc", "mariadb-java-client", "3.3.3", "mariadb"},
}

const jdbcProbeSource = `import java.sql.*;
public class Probe {
  public static void main(String[] a) throws Exception {
    try (Connection c = DriverManager.getConnection(a[0]); Statement s = c.createStatement()) {
      try (ResultSet r = s.executeQuery("SELECT DATABASE()")) { r.next(); System.out.println("DB=" + r.getString(1)); }
      try (ResultSet r = s.executeQuery("SELECT name FROM members WHERE id=1")) { r.next(); System.out.println("ROW=" + r.getString(1)); }
      System.out.println("JDBC_OK");
    }
  }
}
`

// TestClientInteropJDBC drives every driver in jdbcDrivers — Connector/J is what first exposed both the
// mysql_clear_password misroute and the non-printable-scramble digest failure, and MariaDB Connector/J
// confirms the fixes are not Connector/J-specific. Each must connect over the plaintext loopback, land on
// its database, and read the row. MySQL drivers use the exact `pmon show --jdbc` URL; MariaDB uses its own
// sub-protocol against the same host/port/credentials.
func TestClientInteropJDBC(t *testing.T) {
	h := newHarness(t)
	probe := writeTempFile(t, "Probe.java", jdbcProbeSource)
	for _, d := range jdbcDrivers {
		d := d
		t.Run(d.name, func(t *testing.T) {
			logs := runClient(t, testcontainers.ContainerRequest{
				Image: "eclipse-temurin:24-jdk",
				Files: []testcontainers.ContainerFile{
					{HostFilePath: probe, ContainerFilePath: "/work/Probe.java", FileMode: 0o644},
					{HostFilePath: mavenJar(t, d.group, d.artifact, d.version), ContainerFilePath: "/work/driver.jar", FileMode: 0o644},
				},
				Cmd: []string{"sh", "-c", "cd /work && javac Probe.java && java -cp .:driver.jar Probe '" + jdbcURL(d.scheme, h.brokerPort) + "'"},
			})
			mustContain(t, logs, "DB=app")
			mustContain(t, logs, "ROW=ada")
			mustContain(t, logs, "JDBC_OK")
		})
	}
}

// jdbcURL builds the connection URL for a driver sub-protocol. The mysql form is exactly what
// `pmon show --jdbc` prints (host rewritten for the container); the mariadb driver registers for its own
// sub-protocol, so it gets an equivalent URL over the same host/port/credentials.
func jdbcURL(scheme string, port int) string {
	if scheme == "mysql" {
		return forContainer(conn.String(conn.JDBC, clientTarget(port)))
	}
	tgt := clientTarget(port)
	return fmt.Sprintf("jdbc:%s://%s:%d/%s?user=%s&password=%s", scheme, dockerHostAlias, port, tgt.DbName, tgt.User, tgt.Password)
}

// TestClientInteropGoDriver drives go-sql-driver/mysql against the exact `pmon show --go-dsn` DSN.
func TestClientInteropGoDriver(t *testing.T) {
	h := newHarness(t)
	dsn := forContainer(conn.String(conn.GoDSN, clientTarget(h.brokerPort)))
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: "alpine:3.20",
		Files: []testcontainers.ContainerFile{{HostFilePath: buildGoClient(t), ContainerFilePath: "/goclient", FileMode: 0o755}},
		Env:   map[string]string{"PM_DSN": dsn},
		Cmd:   []string{"/goclient"},
	})
	mustContain(t, logs, "DB=app")
	mustContain(t, logs, "ROW=ada")
	mustContain(t, logs, "GO_OK")
}

const nodeProbeSource = `const mysql = require('mysql2/promise');
(async () => {
  const c = await mysql.createConnection(process.env.PM_URL);
  const [[d]] = await c.query('SELECT DATABASE() AS db');
  console.log('DB=' + d.db);
  const [[r]] = await c.query('SELECT name FROM members WHERE id=1');
  console.log('ROW=' + r.name);
  console.log('NODE_OK');
  await c.end();
})().catch(e => { console.error('ERR', e && e.message ? e.message : e); process.exit(1); });
`

// TestClientInteropNode drives node mysql2, given the `pmon show --url` URI (mysql2 accepts a connection
// URI directly). mysql2 is npm-installed at run time, so this leg needs outbound network.
func TestClientInteropNode(t *testing.T) {
	h := newHarness(t)
	uri := forContainer(conn.String(conn.URL, clientTarget(h.brokerPort)))
	probe := writeTempFile(t, "probe.js", nodeProbeSource)
	script := "cd /work && npm install --no-save --no-audit --no-fund mysql2@3 >/tmp/npm.log 2>&1 && node probe.js"
	logs := runClient(t, testcontainers.ContainerRequest{
		Image: "node:20",
		Files: []testcontainers.ContainerFile{{HostFilePath: probe, ContainerFilePath: "/work/probe.js", FileMode: 0o644}},
		Env:   map[string]string{"PM_URL": uri},
		Cmd:   []string{"sh", "-c", script},
	})
	mustContain(t, logs, "DB=app")
	mustContain(t, logs, "ROW=ada")
	mustContain(t, logs, "NODE_OK")
}

// phpImages span the still-common 7.4 and the current 8.x lines. Both use PDO_MySQL over mysqlnd, whose
// default leading plugin differs by version — 7.4 mysql_native_password, 8.x caching_sha2_password — so
// the pair exercises both broker digest paths.
var phpImages = []string{"php:7.4-cli", "php:8.4-cli"}

const phpProbeSource = `<?php
$pdo = new PDO(getenv('PM_DSN'), getenv('PM_USER'), getenv('PM_PASS'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
echo 'DB=' . $pdo->query('SELECT DATABASE()')->fetchColumn() . "\n";
echo 'ROW=' . $pdo->query('SELECT name FROM members WHERE id=1')->fetchColumn() . "\n";
echo "PHP_OK\n";
`

// TestClientInteropPHP drives PDO_MySQL, PHP's standard MySQL driver. The PDO DSN is the usual
// `mysql:host=…;port=…;dbname=…` form with credentials passed separately, over the same broker port
// `pmon show` prints. pdo_mysql is a bundled extension, built from the image's own PHP source, so this
// leg needs no network.
func TestClientInteropPHP(t *testing.T) {
	h := newHarness(t)
	tgt := clientTarget(h.brokerPort)
	probe := writeTempFile(t, "probe.php", phpProbeSource)
	dsn := fmt.Sprintf("mysql:host=%s;port=%d;dbname=%s", dockerHostAlias, tgt.Port, tgt.DbName)
	for _, img := range phpImages {
		img := img
		t.Run(img, func(t *testing.T) {
			logs := runClient(t, testcontainers.ContainerRequest{
				Image:      img,
				Files:      []testcontainers.ContainerFile{{HostFilePath: probe, ContainerFilePath: "/work/probe.php", FileMode: 0o644}},
				Env:        map[string]string{"PM_DSN": dsn, "PM_USER": tgt.User, "PM_PASS": tgt.Password},
				Cmd:        []string{"sh", "-c", "docker-php-ext-install pdo_mysql >/tmp/ext.log 2>&1 && php /work/probe.php"},
				WaitingFor: wait.ForExit().WithExitTimeout(240 * time.Second), // building pdo_mysql from source
			})
			mustContain(t, logs, "DB=app")
			mustContain(t, logs, "ROW=ada")
			mustContain(t, logs, "PHP_OK")
		})
	}
}

// buildGoClient cross-compiles the testdata Go client for the container platform (a static binary, so a
// bare alpine runs it) and returns the host path.
func buildGoClient(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "goclient")
	cmd := exec.Command("go", "build", "-o", bin, "./internal/daemon/testdata/goclient")
	cmd.Dir = filepath.Join("..", "..") // package dir -> pmon module root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build go client: %v\n%s", err, out)
	}
	return bin
}

// mavenJar returns the host path to a Maven Central artifact jar, downloading it into a cross-run cache
// the first time so repeated runs don't refetch it.
func mavenJar(t *testing.T, group, artifact, version string) string {
	t.Helper()
	jar := artifact + "-" + version + ".jar"
	dest := filepath.Join(cacheDir(t), jar)
	url := "https://repo1.maven.org/maven2/" + strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + version + "/" + jar
	downloadIfAbsent(t, url, dest)
	return dest
}

func cacheDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(os.TempDir(), "pm-e2e-clientcache")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("cache dir: %v", err)
	}
	return d
}

func downloadIfAbsent(t *testing.T, url, dest string) {
	t.Helper()
	if _, err := os.Stat(dest); err == nil {
		return
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("download %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download %s: status %d", url, resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create %s: %v", tmp, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		t.Fatalf("write %s: %v", tmp, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		t.Fatalf("rename %s: %v", dest, err)
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}
