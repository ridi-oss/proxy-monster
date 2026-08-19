package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql" // database/sql driver "mysql" — the target engine
	_ "github.com/jackc/pgx/v5/stdlib"           // database/sql driver "pgx" — admin + target-side SQL
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// defaultPostgresImage and defaultMySQLImage are the newest supported series of each engine, per
// db-support.json at the repo root. Kept in sync by TestDefaultImagesTrackDbSupportJson, which reads
// that file — see doc.go "Images" for why the constants are duplicated rather than parsed.
const (
	defaultPostgresImage = "postgres:17"
	defaultMySQLImage    = "mysql:8.4"
)

// startupTimeout matches goproxy/internal/dbtest: a cold MySQL image on a loaded machine genuinely
// takes minutes to initialise, and a short timeout turns that into a flake indistinguishable from a
// real failure.
const startupTimeout = 180 * time.Second

// Postgres credentials. The control plane's own store is the only thing that connects here, so there
// is no non-root/service split to reproduce — unlike MySQL below.
const (
	pgUser     = "postgres"
	pgPassword = "pgpw"
	// pgAdminDB is the database CREATE DATABASE statements are issued from. It is never used as a
	// control-plane store: every suite gets its own fresh database (see FreshPostgresDatabase).
	pgAdminDB = "postgres"
	// pgMaxConnections reproduces TestDatabases.kt:88-92. Every DB-backed suite opens its own pool
	// (store.MaxPoolSize = 10) against this ONE shared container and holds it for the test's lifetime,
	// so the suite's peak concurrent connections scale with the number of DB test functions — which
	// outgrew Postgres's default of 100 on the Kotlin side ("FATAL: sorry, too many clients already").
	// Test-infra headroom only; it is not a production setting.
	pgMaxConnections = "500"
)

// MySQL credentials, matching Testcontainers-java's MySQLContainer defaults, which is what
// TestDatabases.kt inherits: a non-root service user `test`, and root sharing its password.
//
// The split is load-bearing, not cosmetic (TestDatabases.kt:176-178): the root connection is confined
// to this helper, and every fixture-owned target connection uses the non-root user — so a test cannot
// accidentally prove an enforcement property while holding privileges no real datasource has.
const (
	mysqlUser      = "test"
	mysqlPassword  = "test"
	mysqlAdminUser = "root"
	mysqlDefaultDB = "test"
)

// Backend is the connection info for a shared test database container.
type Backend struct {
	Host     string
	Port     int
	User     string
	Password string
	// DB is the container's own default database — `postgres` for the store backend, `test` for the
	// MySQL one. It is the database admin statements are issued against; a fixture works in a fresh
	// database of its own (FreshPostgresDatabase / FreshMySQLDatabase), never in this one.
	DB string

	// Image is the container image this backend was started from, e.g. "postgres:17".
	Image string

	// engine is "postgres" or "mysql" — the engine name the `datasource.engine` column takes.
	engine string

	// adminUser/adminPassword are the credentials CREATE DATABASE is issued with. On Postgres they are
	// the same as User; on MySQL they are root's, deliberately not exported so a fixture cannot reach
	// for them.
	adminUser     string
	adminPassword string
}

// Engine is the `datasource.engine` value for this backend: "postgres" or "mysql" (V2__catalog.sql
// declares that column as `postgres | mysql`). A fixture reads it instead of hardcoding a literal, so
// one fixture body can serve both engines.
func (b Backend) Engine() string { return b.engine }

// PostgresDSN is a pgx-stdlib / libpq connection URL for database db (blank = the backend default).
func (b Backend) PostgresDSN(db string) string {
	return b.postgresDSNAs(b.User, b.Password, db)
}

func (b Backend) postgresDSNAs(user, password, db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, password, b.Host, b.Port, db)
}

// PostgresJDBCURL is the PM_DB_URL shape the control plane's own configuration takes — a pgjdbc URL,
// not a libpq one (01-bootstrap.md §1). Handing this to store.New is what exercises
// store.TranslateJDBCURL on the real boot path rather than only in its unit test.
func (b Backend) PostgresJDBCURL(db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("jdbc:postgresql://%s:%d/%s", b.Host, b.Port, db)
}

// MySQLDSN is a go-sql-driver/mysql DSN for database db (blank = the backend default).
//
// parseTime and multiStatements match goproxy/internal/dbtest so one DSN shape serves the whole
// repo; multiStatements is what lets a fixture seed several tables in one Exec.
func (b Backend) MySQLDSN(db string) string {
	return b.mysqlDSNAs(b.User, b.Password, db)
}

func (b Backend) mysqlDSNAs(user, password, db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&multiStatements=true",
		user, password, b.Host, b.Port, db)
}

var (
	pgOnce sync.Once
	pgB    Backend
	pgErr  error

	mysqlOnce sync.Once
	mysqlB    Backend
	mysqlErr  error
)

// Postgres returns the shared PostgreSQL backend — the control plane's own store engine — starting it
// once and reusing it across the whole suite.
//
// 🔒 It FAILS the test when no Docker provider is available. It never skips. See doc.go rule 2.
func Postgres(t testing.TB) Backend {
	t.Helper()
	pgOnce.Do(func() { pgB, pgErr = startPostgres() })
	return requireBackend(t, "Postgres", pgB, pgErr)
}

// MySQL returns the shared MySQL backend — a *target* engine the enforcement suites broker queries to,
// never the control plane's own store (db-support.json declares PostgreSQL only under "storage").
//
// 🔒 It FAILS the test when no Docker provider is available. It never skips.
func MySQL(t testing.TB) Backend {
	t.Helper()
	mysqlOnce.Do(func() { mysqlB, mysqlErr = startMySQL() })
	return requireBackend(t, "MySQL", mysqlB, mysqlErr)
}

// requireBackend is the ONE place a missing (or wrong-version) backend is reported, and it reports it
// with t.Fatalf.
//
// 🔒 It must never call t.Skip. TestUnavailableBackendFailsAndNeverSkips pins that, which is why this
// is a function and not two inline `if err != nil` blocks: a contract stated in prose in doc.go and
// implemented twice is a contract that gets half-changed. The Kotlin's equivalent is the HARD gate
// requireDocker() (TestDatabases.kt:29-35), not the skipping requireDockerOrSkip().
func requireBackend(t testing.TB, engine string, b Backend, err error) Backend {
	t.Helper()
	if err != nil {
		t.Fatalf("shared %s test container unavailable: %v\n"+
			"Docker is REQUIRED for DB-backed tests and they FAIL rather than skip — a suite that "+
			"silently skipped its enforcement regressions would report a pass it never ran.", engine, err)
		return Backend{}
	}
	return b
}

func startPostgres() (Backend, error) {
	img := image("PM_TEST_POSTGRES_IMAGE", defaultPostgresImage)
	req := testcontainers.ContainerRequest{
		Image: img,
		Name:  containerName("pm-cp-it-pg", img),
		// The official image's entrypoint passes Cmd through to the server, so this is how
		// TestDatabases.kt's withCommand("postgres", "-c", "max_connections=500") ports.
		Cmd:          []string{"postgres", "-c", "max_connections=" + pgMaxConnections},
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_PASSWORD": pgPassword,
			"POSTGRES_DB":       pgAdminDB,
		},
		WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port network.Port) string {
			return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
				pgUser, pgPassword, host, port.Port(), pgAdminDB)
		}).WithStartupTimeout(startupTimeout),
	}
	b, err := start(req, "5432/tcp")
	if err != nil {
		return Backend{}, err
	}
	b.User, b.Password, b.DB = pgUser, pgPassword, pgAdminDB
	b.adminUser, b.adminPassword = pgUser, pgPassword
	b.engine = EnginePostgres
	return b, verifySeries(b, "pgx", b.PostgresDSN(""), "SHOW server_version")
}

func startMySQL() (Backend, error) {
	img := image("PM_TEST_MYSQL_IMAGE", defaultMySQLImage)
	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         containerName("pm-cp-it-mysql", img),
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": mysqlPassword,
			"MYSQL_DATABASE":      mysqlDefaultDB,
			"MYSQL_USER":          mysqlUser,
			"MYSQL_PASSWORD":      mysqlPassword,
		},
		WaitingFor: wait.ForSQL("3306/tcp", "mysql", func(host string, port network.Port) string {
			return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
				mysqlAdminUser, mysqlPassword, host, port.Port(), mysqlDefaultDB)
		}).WithStartupTimeout(startupTimeout),
	}
	// The wait strategy polls with the MySQL driver while the server is still initialising, and every
	// failed poll writes a "[mysql] packets.go:58 unexpected EOF" line to stderr — around thirty of
	// them on a cold start, which buries the actual test output. They are expected, not diagnostic, so
	// they are muted for the duration of the wait and the package default is restored afterwards. Any
	// driver error AFTER startup still prints.
	restore := muteMySQLDriverLog()
	b, err := start(req, "3306/tcp")
	restore()
	if err != nil {
		return Backend{}, err
	}
	b.User, b.Password, b.DB = mysqlUser, mysqlPassword, mysqlDefaultDB
	b.adminUser, b.adminPassword = mysqlAdminUser, mysqlPassword
	b.engine = EngineMySQL
	return b, verifySeries(b, "mysql", b.mysqlDSNAs(mysqlAdminUser, mysqlPassword, mysqlDefaultDB), "SELECT VERSION()")
}

// discardLogger swallows go-sql-driver/mysql's Print calls.
type discardLogger struct{}

func (discardLogger) Print(...any) {}

// muteMySQLDriverLog silences the MySQL driver's global logger and returns a func restoring the
// package default (log.New(os.Stderr, "[mysql] ", log.Ldate|log.Ltime|log.Lshortfile) — driver.go's
// own initialiser). There is no getter for the current logger, so "restore" means "put the default
// back": a caller that installed its own would lose it, which no caller in this repo does.
func muteMySQLDriverLog() func() {
	_ = mysqldriver.SetLogger(discardLogger{})
	return func() {
		_ = mysqldriver.SetLogger(log.New(os.Stderr, "[mysql] ", log.Ldate|log.Ltime|log.Lshortfile))
	}
}

// image resolves the container image for an engine: the env override if set, else the newest
// supported series. TestDatabases.kt:43-44 — `takeIf { it.isNotBlank() }`, so an empty override falls
// back rather than producing an image named "".
func image(envVar, def string) string {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		return v
	}
	return def
}

// containerName derives a per-image container name. The name is what testcontainers Reuse keys on, so
// two matrix legs (or a local run after switching PM_TEST_*_IMAGE) must not share one: reusing a
// container started from a different image would run the tests against the wrong version while
// reporting the version that was asked for.
//
// PM_TEST_CONTAINER_SUFFIX additionally partitions the name, matching goproxy's helper, so two suites
// that could run concurrently against the SAME image can each get their own server.
//
// The "pm-cp-" prefix keeps these containers disjoint from goproxy's "pm-goproxy-" ones on purpose.
// They are cheap to share and expensive to debug when shared: goproxy's suites seed fixed schema and
// row ids into their containers, and a control-plane fixture that introspected one would pick those
// up as catalog rows.
func containerName(prefix, img string) string {
	repl := strings.NewReplacer(":", "-", "/", "-", ".", "-")
	name := prefix + "-" + repl.Replace(img)
	if s := os.Getenv("PM_TEST_CONTAINER_SUFFIX"); s != "" {
		name += "-" + repl.Replace(s)
	}
	return name
}

// start creates or reuses (by Name) the container and returns its live host:port. Reuse means the
// container persists after the run and is shared across every test package and process — which is
// also why fresh database names must be unique per RUN, not per process. See freshName.
func start(req testcontainers.ContainerRequest, port string) (Backend, error) {
	disableRyuk()

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
	return Backend{Host: host, Port: int(mapped.Num()), Image: req.Image}, nil
}

// ryukDisabledEnv is the only switch testcontainers-go v0.34 offers for the resource reaper: it is
// read GLOBALLY from the environment (or ~/.testcontainers.properties) by config.Read(), and
// ContainerRequest.SkipReaper is deprecated and ignored (container.go:153).
const ryukDisabledEnv = "TESTCONTAINERS_RYUK_DISABLED"

var ryukOnce sync.Once

// disableRyuk turns off the Testcontainers resource reaper before the first container is created.
//
// 🔴 This is NOT optional, and it is not a tidiness setting — without it the suite fails in a way that
// looks like a database bug. Ryuk is SESSION-scoped: it reaps every container labelled with the test
// session about ten seconds after that session's process exits. Our containers are Reuse-by-name and
// deliberately OUTLIVE the process, so the previous `go test` invocation's reaper kills the container
// the NEXT invocation is already using. Measured here: a run that had just passed left a reaper
// behind, and eleven seconds into the following run the shared Postgres vanished mid-test —
// "dial tcp 127.0.0.1:49469: connect: connection refused", from a test that had done nothing wrong.
// The same shape hits two package binaries in one `go test ./...`, where the first to finish reaps the
// container the second is mid-query on.
//
// This is one of the five Testcontainers workarounds 00-INDEX.md:346-349 says to budget for rather
// than rediscover, and the Kotlin build already carries this exact one:
// control-plane/build.gradle.kts:133-135 sets TESTCONTAINERS_RYUK_DISABLED=true with the same
// reasoning ("the shared-container singletons never stop mid-run"). Read this session.
//
// The cost is that containers are never auto-removed. For a Reuse-by-name design that is the intent,
// not a leak: `docker rm -f $(docker ps -aq --filter name=pm-cp-it-)` clears them.
//
// An explicitly-set value is respected, so a CI that wants the reaper back can have it.
func disableRyuk() {
	ryukOnce.Do(func() {
		if _, set := os.LookupEnv(ryukDisabledEnv); !set {
			_ = os.Setenv(ryukDisabledEnv, "true")
		}
	})
}

// lockShared takes an exclusive cross-process advisory lock keyed on a container name, and returns an
// unlock func. `go test` runs each package in its own process, so the sync.Once above only serializes
// creation within one binary; testcontainers' Reuse is not atomic across processes, so several package
// binaries racing to create the same-named container can leave one attached to a container another is
// still starting (the symptom is a mid-test "unexpected EOF" / "invalid connection"). Keyed on the name
// so runs against different versions serialize independently instead of blocking each other.
//
// Carried over verbatim from goproxy/internal/dbtest/dbtest.go:251-264 — same problem, same repo, and
// the two container sets are started by the same `mise run test-go`.
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

// verifySeries fails backend startup unless the live server is in the series its configured image
// names. Called once per backend rather than per handle, so every DSN, pool and fixture derived from
// it inherits the guarantee without any test having to think about versions.
//
// The failure is returned as the backend's error, so it surfaces through Postgres(t)/MySQL(t)'s
// t.Fatal — a version mismatch must be as fatal as a missing Docker, for the same reason.
func verifySeries(b Backend, driver, dsn, query string) error {
	want := imageSeries(b.Image)
	if want == "" {
		// The image pins no version ("latest", or an untagged reference). Nothing to check: the
		// declaration guard in db-support.json is what refuses to let a supported version be declared
		// with such an image in the first place (TestDatabases.kt:66-68).
		return nil
	}
	got, err := serverSeries(driver, dsn, query, want)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf(
			"image %s should serve a %s server but it reported %s — this leg is not testing the version it claims",
			b.Image, want, got)
	}
	return nil
}

// Series returns the live server's version series ("17", "8.4") for the backend, for a test that
// wants to assert which version a run covered. It is the port of TestDatabases.kt's
// SharedPostgres.serverSeries() / SharedMySql.serverSeries().
func (b Backend) Series(t testing.TB) string {
	t.Helper()
	// The precision argument is the image's own tag, so the probe truncates to exactly the number of
	// components the declared series carries — "17" for Postgres, "8.4" for MySQL — rather than to a
	// hardcoded depth that a future series could contradict.
	driver, dsn, query := "pgx", b.PostgresDSN(""), "SHOW server_version"
	if b.engine == EngineMySQL {
		driver, dsn, query = "mysql", b.MySQLDSN(""), "SELECT VERSION()"
	}
	precision := imageSeries(b.Image)
	if precision == "" {
		precision = "0.0" // untagged image: report major.minor, the finest series any engine declares
	}
	got, err := serverSeries(driver, dsn, query, precision)
	if err != nil {
		t.Fatalf("probing %s server version: %v", driver, err)
	}
	return got
}

// serverSeries reads the server's reported version and truncates it to the same number of dotted
// components as `precision`. The image tag may be less precise than the version the server reports
// ("8.0" vs "8.0.44"), and Postgres reports things like "16.4 (Debian ...)", hence the field cut.
func serverSeries(driver, dsn, query, precision string) (string, error) {
	conn, err := sql.Open(driver, dsn)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", driver, err)
	}
	defer conn.Close()

	var raw string
	if err := conn.QueryRow(query).Scan(&raw); err != nil {
		return "", fmt.Errorf("probing %s server version: %w", driver, err)
	}
	got := strings.Fields(strings.TrimSpace(raw))[0]
	want := len(strings.Split(precision, "."))
	if c := strings.Split(got, "."); len(c) > want {
		got = strings.Join(c[:want], ".")
	}
	return got, nil
}

// imageSeries is the version series an image tag names ("mysql:8.0" -> "8.0",
// "postgres:16-alpine" -> "16"), or "" when the tag pins no version ("latest", or no tag at all).
//
// The tag is what follows the last colon only if that colon comes after the last slash — otherwise the
// colon belongs to a registry port ("localhost:5000/postgres" has no tag). A variant suffix
// ("16-alpine") is dropped so the series compares against what the server reports.
// TestDatabases.kt:53-58.
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
