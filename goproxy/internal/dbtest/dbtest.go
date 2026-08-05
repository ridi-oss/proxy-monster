// Package dbtest provides the ONE shared MySQL and PostgreSQL backend that every DB-backed test in the
// goproxy module uses. Each engine's container is started once and REUSED for the entire suite
// (testcontainers Reuse by fixed Name — the first test to need it starts it, every other test and
// package reuses the same running container). DB-backed tests are MANDATORY: if no Docker provider is
// available these helpers FAIL the test (t.Fatal), they never skip.
package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Backend is the connection info for a shared test database.
type Backend struct {
	Host     string
	Port     int
	User     string
	Password string
	DB       string
}

// MySQLDSN is a go-sql-driver/mysql DSN for this backend (for the given database, blank = the default).
func (b Backend) MySQLDSN(db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&multiStatements=true", b.User, b.Password, b.Host, b.Port, db)
}

// PostgresDSN is a pgx-stdlib DSN for this backend.
func (b Backend) PostgresDSN(db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", b.User, b.Password, b.Host, b.Port, db)
}

var (
	mysqlOnce sync.Once
	mysqlB    Backend
	mysqlErr  error

	pgOnce sync.Once
	pgB    Backend
	pgErr  error

	sysdateOnce sync.Once
	sysdateB    Backend
	sysdateErr  error

	partialRevokesOnce sync.Once
	partialRevokesB    Backend
	partialRevokesErr  error
)

// MySQL returns the shared MySQL 8 backend, starting it once and reusing it across the whole suite. It
// fails the test if no Docker provider is available.
func MySQL(t testing.TB) Backend {
	t.Helper()
	mysqlOnce.Do(func() { mysqlB, mysqlErr = startMySQL() })
	if mysqlErr != nil {
		t.Fatalf("shared MySQL test container unavailable (Docker is required for DB-backed tests): %v", mysqlErr)
	}
	return mysqlB
}

// Postgres returns the shared PostgreSQL 16 backend, starting it once and reusing it across the whole
// suite. It fails the test if no Docker provider is available.
func Postgres(t testing.TB) Backend {
	t.Helper()
	pgOnce.Do(func() { pgB, pgErr = startPostgres() })
	if pgErr != nil {
		t.Fatalf("shared Postgres test container unavailable (Docker is required for DB-backed tests): %v", pgErr)
	}
	return pgB
}

// MySQLSysdateIsNow returns a MySQL backend started with --sysdate-is-now, a supported server option
// that aliases SYSDATE() back to NOW(). It needs its own container because the option is set at
// startup, and its own name so it never shares one with the ordinary fixture.
//
// It exists because that aliasing silently re-arms the clock poisoning SYSDATE was chosen to prevent,
// and MySQL exposes no variable naming the option — the only way to observe it is to run against a
// server that has it.
func MySQLSysdateIsNow(t testing.TB) Backend {
	t.Helper()
	sysdateOnce.Do(func() { sysdateB, sysdateErr = startMySQLSysdateIsNow() })
	if sysdateErr != nil {
		t.Fatalf("MySQL --sysdate-is-now test container unavailable (Docker is required for DB-backed tests): %v", sysdateErr)
	}
	return sysdateB
}

// MySQLPartialRevokes returns a MySQL backend started with --partial-revokes=ON, the mode in which a
// per-database REVOKE can coexist with a global GRANT. It needs its own container: the ordinary fixture
// runs with the option OFF, and once any restriction exists the server refuses to turn it back off
// (error 3896), so a test that enabled it in place would permanently change the shared server.
func MySQLPartialRevokes(t testing.TB) Backend {
	t.Helper()
	partialRevokesOnce.Do(func() { partialRevokesB, partialRevokesErr = startMySQLPartialRevokes() })
	if partialRevokesErr != nil {
		t.Fatalf("MySQL --partial-revokes test container unavailable (Docker is required for DB-backed tests): %v", partialRevokesErr)
	}
	return partialRevokesB
}

// OpenMySQL opens (and pings) a *sql.DB against the shared MySQL backend for database db (blank = default).
func OpenMySQL(t testing.TB, db string) *sql.DB { return open(t, "mysql", MySQL(t).MySQLDSN(db)) }

// OpenPostgres opens (and pings) a *sql.DB against the shared Postgres backend for database db (blank = default).
func OpenPostgres(t testing.TB, db string) *sql.DB {
	return open(t, "pgx", Postgres(t).PostgresDSN(db))
}

func open(t testing.TB, driver, dsn string) *sql.DB {
	t.Helper()
	conn, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatalf("open %s: %v", driver, err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		t.Fatalf("ping %s: %v", driver, err)
	}
	t.Cleanup(func() { conn.Close() })
	// Every handle this package hands out is version-checked, so a test cannot accidentally run against
	// a server other than the one its image named. Doing it here rather than in each test is what makes
	// the guarantee hold for tests that never think about versions.
	switch driver {
	case "mysql":
		assertSeries(t, conn, "SELECT VERSION()", image("PM_TEST_MYSQL_IMAGE", defaultMySQLImage))
	case "pgx":
		assertSeries(t, conn, "SHOW server_version", image("PM_TEST_POSTGRES_IMAGE", defaultPostgresImage))
	}
	return conn
}

const startupTimeout = 180 * time.Second

// The default images: the newest supported series of each engine, per db-support.json.
const (
	defaultMySQLImage    = "mysql:8.4"
	defaultPostgresImage = "postgres:17"
)

// image resolves the container image for an engine. The default is the newest supported series, so a
// plain `go test ./...` covers the version most installs run; PM_TEST_MYSQL_IMAGE / PM_TEST_POSTGRES_IMAGE
// override it, which is how one CI matrix leg pins one version. The supported set is declared in
// db-support.json at the repo root.
func image(envVar, def string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return def
}

// containerName derives a per-image container name. The name is what testcontainers Reuse keys on, so
// two matrix legs (or a local run after switching PM_TEST_*_IMAGE) must not share one: reusing a
// container started from a different image would run the tests against the wrong version while
// reporting the version that was asked for.
//
// PM_TEST_CONTAINER_SUFFIX additionally partitions the name. Tests here seed fixed schema and row ids
// (it_pgproxy.people id 1), so two suites sharing one server collide on the seed ("duplicate key value
// violates unique constraint") rather than isolating. Legs that could run concurrently against the SAME
// image therefore need their own server, which is what the suffix gives them.
func containerName(prefix, img string) string {
	name := prefix + "-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(img)
	if s := os.Getenv("PM_TEST_CONTAINER_SUFFIX"); s != "" {
		name += "-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(s)
	}
	return name
}

func startMySQL() (Backend, error) { return startMySQLWith("pm-goproxy-it-mysql") }

func startMySQLSysdateIsNow() (Backend, error) {
	return startMySQLWith("pm-goproxy-it-mysql-sysdate", "--sysdate-is-now")
}

func startMySQLPartialRevokes() (Backend, error) {
	return startMySQLWith("pm-goproxy-it-mysql-partialrevokes", "--partial-revokes=ON")
}

// startMySQLWith starts one MySQL backend under the given server options. Each option set needs its own
// container name: the options are start-up-only, and a container reused under a different name's options
// would run the tests against a server configured for something else.
func startMySQLWith(namePrefix string, serverOptions ...string) (Backend, error) {
	const user, pass, db = "root", "rootpw", "app"
	img := image("PM_TEST_MYSQL_IMAGE", defaultMySQLImage)
	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         containerName(namePrefix, img),
		ExposedPorts: []string{"3306/tcp"},
		Env:          map[string]string{"MYSQL_ROOT_PASSWORD": pass, "MYSQL_DATABASE": db},
		Cmd:          serverOptions,
		WaitingFor: wait.ForSQL("3306/tcp", "mysql", func(host string, port nat.Port) string {
			return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, pass, host, port.Port(), db)
		}).WithStartupTimeout(startupTimeout),
	}
	return start(req, "3306/tcp", user, pass, db)
}

func startPostgres() (Backend, error) {
	const user, pass, db = "postgres", "pgpw", "app"
	img := image("PM_TEST_POSTGRES_IMAGE", defaultPostgresImage)
	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         containerName("pm-goproxy-it-pg", img),
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_PASSWORD": pass, "POSTGRES_DB": db},
		WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
			return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port.Port(), db)
		}).WithStartupTimeout(startupTimeout),
	}
	return start(req, "5432/tcp", user, pass, db)
}

// MySQLAuthPlugin is an auth plugin every supported MySQL series can create an account with. MySQL 8.4
// ships mysql_native_password DISABLED, so `IDENTIFIED WITH mysql_native_password` fails there with
// error 1524 while it still works on 8.0; a test needing a known plugin asks for this rather than
// naming one. The probe treats anything but an ACTIVE status — including an absent row — as disabled.
func MySQLAuthPlugin(t testing.TB, db *sql.DB) string {
	t.Helper()
	var status string
	err := db.QueryRow(
		"SELECT plugin_status FROM information_schema.plugins WHERE plugin_name = 'mysql_native_password'",
	).Scan(&status)
	if err == nil && strings.EqualFold(status, "ACTIVE") {
		return "mysql_native_password"
	}
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("probing mysql_native_password availability: %v", err)
	}
	return "caching_sha2_password"
}

// imageSeries is the version series an image tag names ("mysql:8.0" -> "8.0",
// "postgres:16-alpine" -> "16"), or "" when the tag pins no version ("latest", or no tag at all). The
// tag is what follows the last colon only if that colon comes after the last slash — otherwise the
// colon belongs to a registry port ("localhost:5000/postgres" has no tag). A variant suffix
// ("16-alpine") is dropped so the series compares against what the server reports.
func imageSeries(img string) string {
	tag := ""
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		tag = img[i+1:]
	}
	if tag == "" || tag[0] < '0' || tag[0] > '9' {
		return ""
	}
	if i := strings.IndexByte(tag, '-'); i >= 0 {
		tag = tag[:i]
	}
	return tag
}

// assertSeries fails the test unless the live server is in the series its configured image names. A
// container reused from another image, or a tag that resolved elsewhere, would otherwise let a leg
// report a pass for a version it never ran — indistinguishable from real coverage. Called from the
// shared fixtures below, so every consumer gets a verified backend rather than having to opt in.
func assertSeries(t testing.TB, db *sql.DB, query, img string) {
	t.Helper()
	want := imageSeries(img)
	if want == "" {
		return
	}
	var raw string
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatalf("probing server version: %v", err)
	}
	// The tag may be less precise than the reported version ("8.0" vs "8.0.44"), so compare on the
	// tag's own component count. Postgres reports things like "16.4 (Debian ...)", hence the field cut.
	got := strings.Fields(strings.TrimSpace(raw))[0]
	parts := len(strings.Split(want, "."))
	if c := strings.Split(got, "."); len(c) > parts {
		got = strings.Join(c[:parts], ".")
	}
	if got != want {
		t.Fatalf("image %s should serve a %s server but it reported %s — this leg is not testing the version it claims", img, want, raw)
	}
}

// lockShared takes an exclusive cross-process advisory lock keyed on a container name, and returns an
// unlock func. `go test` runs each package in its own process, so the sync.Once above only serializes
// creation within one binary; testcontainers' Reuse is not atomic across processes, so several package
// binaries racing to create the same-named container can leave one attached to a container another is
// still starting (the symptom is a mid-test "unexpected EOF" / "invalid connection"). Keyed on the name
// so runs against different versions serialize independently instead of blocking each other.
func lockShared(name string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open container lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock container: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// start creates or reuses (by Name) the container and returns its live host:port. Reuse means the
// container persists after the run and is shared across every test package/process.
func start(req testcontainers.ContainerRequest, port nat.Port, user, pass, db string) (Backend, error) {
	unlock, err := lockShared(req.Name)
	if err != nil {
		return Backend{}, err
	}
	defer unlock()

	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		return Backend{}, err
	}
	host, err := c.Host(ctx)
	if err != nil {
		return Backend{}, err
	}
	mapped, err := c.MappedPort(ctx, port)
	if err != nil {
		return Backend{}, err
	}
	return Backend{Host: host, Port: mapped.Int(), User: user, Password: pass, DB: db}, nil
}
