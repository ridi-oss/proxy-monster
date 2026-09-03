package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end tests over the REAL binary and a REAL spawned daemon, so the peer-symmetry claims are exercised
// through the actual control socket rather than an in-process fake: the CLI starts a daemon, logs in through
// it, reads status, renders connection strings, and stops it.

// buildPmon compiles the binary once per test run and returns its path.
//
// Built with the race detector whenever the tests are, because the daemon these tests drive runs as a
// separate process: instrumenting the test binary says nothing about the goroutines actually serving the
// control socket and brokering tokens. A race there aborts the daemon with exit 2 and a report on its
// stderr, which is the daemon log — see [assertNoDaemonRace].
func buildPmon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pmon")
	args := []string{"build", "-o", bin}
	if raceEnabled {
		args = append(args, "-race")
	}
	out, err := exec.Command("go", append(args, ".")...).CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// assertNoDaemonRace fails the test if the daemon logged a race report. The daemon is detached, so its
// failure never surfaces as a non-zero exit here: a race aborts it mid-run and the CLI sees only a daemon
// that stopped answering, which reads as a timeout in whatever the test was doing next.
func assertNoDaemonRace(t *testing.T, stateDir string) {
	t.Helper()
	if !raceEnabled {
		return
	}
	log, err := os.ReadFile(filepath.Join(stateDir, "daemon.log"))
	if err != nil {
		return // no log means the daemon never started, which the test's own assertions cover
	}
	if bytes.Contains(log, []byte("WARNING: DATA RACE")) {
		t.Errorf("the daemon reported a data race:\n%s", log)
	}
}

// env isolates a pmon invocation: its own state dir and its own broker port range, so it neither touches the
// real user config nor fights a running daemon for 6100+.
type env struct {
	bin      string
	stateDir string
	portBase int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{bin: buildPmon(t), stateDir: t.TempDir(), portBase: freeTCPPort(t)}
	t.Cleanup(func() {
		// Always stop the daemon this env may have started, or it outlives the test (it is detached by design).
		_, _ = e.run("stop", "--force")
		// After the stop, so the log holds everything the daemon ever wrote.
		assertNoDaemonRace(t, e.stateDir)
	})
	return e
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// run invokes pmon and returns its combined output.
func (e *env) run(args ...string) (string, error) {
	cmd := exec.Command(e.bin, args...)
	// PMON_NO_BROWSER: these drive a real login, and a real $BROWSER would open a tab per run.
	cmd.Env = append(os.Environ(),
		"PMON_CONFIG_DIR="+e.stateDir,
		fmt.Sprintf("PMON_PORT_BASE=%d", e.portBase),
		"PMON_NO_BROWSER=1",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mustRun fails the test if pmon exits non-zero.
func (e *env) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := e.run(args...)
	if err != nil {
		t.Fatalf("pmon %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// fakeCP serves the device-auth flow plus a datasource list.
func fakeCP(t *testing.T, datasources []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verificationUri":         "https://idp.example/activate",
				"verificationUriComplete": "https://idp.example/activate?c=1",
				"userCode":                "ABCD-EFGH", "handle": "h-1", "interval": 1,
			})
		case "/auth/device/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal": "you@example.com", "token": "pmk_tok",
				"expiresAt":    time.Now().Add(12 * time.Hour).Format(time.RFC3339),
				"renewalToken": "pmr_abc",
			})
		case "/api/datasources":
			_ = json.NewEncoder(w).Encode(datasources)
		default:
			t.Errorf("unexpected control-plane path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dummyProxy accepts and immediately closes, standing in for a proxy at an advertised address.
func dummyProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestPeerCommandsWorkWhenTheDaemonIsDown is the symmetry requirement's first half: every command must be
// usable with no daemon running, reporting the state and pointing at the fix rather than erroring opaquely.
func TestPeerCommandsWorkWhenTheDaemonIsDown(t *testing.T) {
	e := newEnv(t)

	out := e.mustRun(t, "status")
	if !strings.Contains(out, "not running") {
		t.Errorf("status with no daemon = %q, want it to say the daemon is not running", out)
	}
	if !strings.Contains(out, "pmon start") {
		t.Errorf("status with no daemon = %q, want it to point at `pmon start`", out)
	}

	// stop is idempotent: stopping nothing is success, not an error.
	if out := e.mustRun(t, "stop"); !strings.Contains(out, "not running") {
		t.Errorf("stop with no daemon = %q, want it to report nothing was running", out)
	}
	if out := e.mustRun(t, "logout"); !strings.Contains(out, "not running") {
		t.Errorf("logout with no daemon = %q, want it to report nothing was running", out)
	}
	// show cannot succeed, but it must explain what to do.
	out, err := e.run("show", "acme-mysql")
	if err == nil {
		t.Error("show with no daemon succeeded; expected a non-zero exit")
	}
	if !strings.Contains(out, "pmon login") {
		t.Errorf("show with no daemon = %q, want it to point at `pmon login`", out)
	}
}

// TestStartStopLifecycle covers a peer owning the daemon's lifecycle: start brings it up idle (no credentials
// is NOT a startup failure), and stop takes it down.
func TestStartStopLifecycle(t *testing.T) {
	e := newEnv(t)

	out := e.mustRun(t, "start")
	if !strings.Contains(out, "not logged in") {
		t.Errorf("start with no credentials = %q, want a running-but-idle daemon", out)
	}
	if out := e.mustRun(t, "status"); !strings.Contains(out, "running, idle") {
		t.Errorf("status after start = %q, want running+idle", out)
	}
	// A second start is a no-op rather than a second daemon.
	if out := e.mustRun(t, "start"); !strings.Contains(out, "already running") {
		t.Errorf("second start = %q, want it to report one is already running", out)
	}

	if out := e.mustRun(t, "stop"); !strings.Contains(out, "stopped") {
		t.Errorf("stop = %q, want it to confirm the daemon stopped", out)
	}
	if out := e.mustRun(t, "status"); !strings.Contains(out, "not running") {
		t.Errorf("status after stop = %q, want not running", out)
	}
}

// TestLoginStartsTheDaemonAndOpensBrokers is the headline behavior: `pmon login` alone — no daemon running, no
// separate brokering step — leaves a connectable local port and a renderable connection string.
func TestLoginStartsTheDaemonAndOpensBrokers(t *testing.T) {
	e := newEnv(t)
	proxy := dummyProxy(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-mysql", "engine": "mysql", "dbName": "my_database", "advertiseAddr": proxy},
	})

	out := e.mustRun(t, "login", "--url", cp.URL)
	if !strings.Contains(out, "ABCD-EFGH") {
		t.Errorf("login = %q, want the user code shown", out)
	}
	if !strings.Contains(out, "logged in as you@example.com") {
		t.Errorf("login = %q, want the principal confirmed", out)
	}
	if !strings.Contains(out, "1 datasource(s) brokered") {
		t.Errorf("login = %q, want it to report the broker came up", out)
	}

	status := e.mustRun(t, "status")
	if !strings.Contains(status, "acme-mysql") || !strings.Contains(status, "127.0.0.1:") {
		t.Errorf("status = %q, want the datasource on a local port", status)
	}

	// The port in the connection string really accepts connections.
	url := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql"))
	if !strings.HasPrefix(url, "mysql://") || !strings.Contains(url, "/my_database") {
		t.Fatalf("show = %q, want a mysql:// URI for my_database", url)
	}
	hostPort := url[strings.LastIndex(url, "@")+1 : strings.LastIndex(url, "/")]
	c, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial the brokered port %s from the connection string: %v", hostPort, err)
	}
	c.Close()
}

// TestShowFormats locks the four documented flavors, including --url as the default.
func TestShowFormats(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-mysql", "engine": "mysql", "dbName": "my_database", "advertiseAddr": dummyProxy(t)},
	})
	e.mustRun(t, "login", "--url", cp.URL)

	bare := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql"))
	explicit := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql", "--url"))
	if bare != explicit {
		t.Errorf("bare show = %q but --url = %q; --url must be the default", bare, explicit)
	}
	if !strings.HasPrefix(bare, "mysql://") {
		t.Errorf("--url = %q, want a mysql:// URI", bare)
	}

	jdbc := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql", "--jdbc"))
	if !strings.HasPrefix(jdbc, "jdbc:mysql://") || !strings.Contains(jdbc, "user=") {
		t.Errorf("--jdbc = %q, want a jdbc:mysql:// URL with credentials", jdbc)
	}
	if !strings.Contains(jdbc, "jdbcCompliantTruncation=false") {
		t.Errorf("--jdbc = %q, want the conservative JDBC diagnostic setting", jdbc)
	}
	jdbcDiagnostics := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql", "--jdbc", "--jdbc-with-truncation-diagnostics"))
	if strings.Contains(jdbcDiagnostics, "jdbcCompliantTruncation") {
		t.Errorf("--jdbc --jdbc-with-truncation-diagnostics = %q, want no JDBC compliant-truncation parameter", jdbcDiagnostics)
	}

	dsn := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql", "--go-dsn"))
	if !strings.Contains(dsn, "@tcp(127.0.0.1:") || !strings.Contains(dsn, "parseTime=true") {
		t.Errorf("--go-dsn = %q, want the go-sql-driver DSN form", dsn)
	}

	cli := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql", "--cli"))
	if !strings.HasPrefix(cli, "mysql -h 127.0.0.1") {
		t.Errorf("--cli = %q, want a mysql command line", cli)
	}

	// Output is the bare string, so it pipes straight into a client or an env var.
	for _, s := range []string{bare, jdbc, dsn, cli} {
		if strings.Count(s, "\n") != 0 {
			t.Errorf("show output %q spans multiple lines; it must be pipeable", s)
		}
	}
}

func TestShowJDBCTruncationDiagnosticsRequiresJDBC(t *testing.T) {
	e := newEnv(t)
	out, err := e.run("show", "acme-mysql", "--jdbc-with-truncation-diagnostics")
	if err == nil {
		t.Fatalf("show --jdbc-with-truncation-diagnostics succeeded, want an error")
	}
	if !strings.Contains(out, "--jdbc-with-truncation-diagnostics requires --jdbc") {
		t.Errorf("show --jdbc-with-truncation-diagnostics = %q, want a --jdbc requirement error", out)
	}
}

// TestShowRejectsAnUnknownDatasourceWithTheKnownOnes: a typo must list what IS available rather than just fail.
func TestShowRejectsAnUnknownDatasourceWithTheKnownOnes(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-mysql", "engine": "mysql", "dbName": "app", "advertiseAddr": dummyProxy(t)},
	})
	e.mustRun(t, "login", "--url", cp.URL)

	out, err := e.run("show", "acme-mysq")
	if err == nil {
		t.Fatal("show with a typo'd datasource succeeded")
	}
	if !strings.Contains(out, "acme-mysql") {
		t.Errorf("show error = %q, want it to list the known datasources", out)
	}
}

func TestPostgresShowFormats(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-postgres", "engine": "postgres", "dbName": "app", "advertiseAddr": dummyProxy(t)},
	})
	if out := e.mustRun(t, "login", "--url", cp.URL); !strings.Contains(out, "1 datasource(s) brokered") {
		t.Fatalf("login = %q, want the PostgreSQL broker to open", out)
	}

	cases := []struct {
		flag string
		want string
	}{
		{"", "postgresql://"},
		{"--jdbc", "jdbc:postgresql://"},
		{"--go-dsn", "host=127.0.0.1"},
		{"--cli", "psql 'host=127.0.0.1"},
	}
	for _, tc := range cases {
		args := []string{"show", "acme-postgres"}
		if tc.flag != "" {
			args = append(args, tc.flag)
		}
		if got := strings.TrimSpace(e.mustRun(t, args...)); !strings.HasPrefix(got, tc.want) {
			t.Errorf("pmon %s = %q, want prefix %q", strings.Join(args, " "), got, tc.want)
		}
	}
}

func TestShowExplainsAnUnsupportedDatasource(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "unsupported", "engine": "sqlite", "dbName": "app", "advertiseAddr": dummyProxy(t)},
	})
	e.mustRun(t, "login", "--url", cp.URL)

	out, err := e.run("show", "unsupported")
	if err == nil {
		t.Fatal("show for an unsupported datasource succeeded")
	}
	if !strings.Contains(out, "sqlite") {
		t.Errorf("show error = %q, want the unsupported engine named", out)
	}
}

// TestLogoutClosesBrokersAndKeepsTheDaemonUp: logging out must leave the daemon available to log back in
// through, which is what makes a menu-bar "Re-authenticate" work without a restart.
func TestLogoutClosesBrokersAndKeepsTheDaemonUp(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-mysql", "engine": "mysql", "dbName": "app", "advertiseAddr": dummyProxy(t)},
	})
	e.mustRun(t, "login", "--url", cp.URL)

	if out := e.mustRun(t, "logout"); !strings.Contains(out, "logged out") {
		t.Errorf("logout = %q, want a confirmation", out)
	}
	status := e.mustRun(t, "status")
	if !strings.Contains(status, "running") {
		t.Errorf("status after logout = %q, want the daemon still running", status)
	}
	if !strings.Contains(status, "not logged in") {
		t.Errorf("status after logout = %q, want it logged out", status)
	}

	// A second login reuses the same daemon and brings the brokers back.
	if out := e.mustRun(t, "login", "--url", cp.URL); !strings.Contains(out, "1 datasource(s) brokered") {
		t.Errorf("re-login = %q, want the broker to come back up", out)
	}
}

// TestRestartKeepsStickyPortsAndPassword is what makes a saved client connection survive: the local port and
// the password must be identical across a daemon restart.
func TestRestartKeepsStickyPortsAndPassword(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{
		{"name": "acme-mysql", "engine": "mysql", "dbName": "app", "advertiseAddr": dummyProxy(t)},
	})
	e.mustRun(t, "login", "--url", cp.URL)

	before := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql"))
	if out := e.mustRun(t, "restart"); !strings.Contains(out, "restarted") {
		t.Errorf("restart = %q, want a confirmation", out)
	}
	after := strings.TrimSpace(e.mustRun(t, "show", "acme-mysql"))
	if before != after {
		t.Errorf("connection string changed across a restart:\n before %q\n after  %q", before, after)
	}
}

// TestOnlyOneDaemonRunsAtATime locks the single-instance guard from the outside: a second foreground daemon
// must refuse rather than fight the first for the socket and the broker ports.
func TestOnlyOneDaemonRunsAtATime(t *testing.T) {
	e := newEnv(t)
	e.mustRun(t, "start")

	out, err := e.run("daemon")
	if err == nil {
		t.Fatal("a second daemon started alongside the first")
	}
	if !strings.Contains(out, "already running") {
		t.Errorf("second daemon = %q, want it to report one is already running", out)
	}
}
