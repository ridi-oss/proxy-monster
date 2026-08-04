package dbtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// The two engine names V2__catalog.sql's `datasource.engine` column accepts.
const (
	EnginePostgres = "postgres"
	EngineMySQL    = "mysql"
)

// keepDatabasesEnv retains the per-test databases instead of dropping them, for post-mortem
// inspection of a failing run. Off by default: the containers are REUSED across runs, so without a
// drop a week of `go test` leaves hundreds of pm_meta_* databases behind on a developer's machine.
const keepDatabasesEnv = "PM_TEST_KEEP_DATABASES"

// runToken makes fresh-database names unique per RUN, not merely per process.
//
// ⚠️ This is where the Go harness cannot copy the Kotlin. TestDatabases.kt:85 uses a bare
// AtomicInteger, which is safe there because the container dies with the JVM (Ryuk), so `pm_meta_1`
// is free again on the next run. Here the container is REUSED across runs and across package
// binaries, so a bare counter collides with the previous run's databases on its second invocation —
// "database \"pm_meta_1\" already exists", from the fixture, on a suite that changed nothing. A PID
// would also collide eventually (PIDs are recycled); 8 bytes of crypto/rand does not.
var runToken = func() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("dbtest: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}()

var freshCounter atomic.Uint64

// identifierPrefix is TestDatabases.kt:180's guard, applied to BOTH engines rather than only MySQL.
// Neither Postgres nor MySQL parameterises a database name, so CREATE DATABASE has to interpolate;
// the prefix is always a Go string literal from a fixture, but a guard costs nothing and the
// alternative is an injection point in the one place the suite runs as an admin.
var identifierPrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

// freshName builds a collision-free database name from a prefix.
func freshName(t testing.TB, prefix string) string {
	t.Helper()
	if !identifierPrefix.MatchString(prefix) {
		t.Fatalf("unsafe database prefix %q — must match %s", prefix, identifierPrefix)
	}
	return fmt.Sprintf("%s_%s_%d", prefix, runToken, freshCounter.Add(1))
}

// FreshPostgresDatabase creates a uniquely-named database in the shared Postgres container and
// returns its name. It is the port of TestDatabases.kt's SharedPostgres.freshDatabase.
//
// Per-test isolation comes from a fresh logical database, never a fresh container: starting a
// database is the expensive part, and a suite that restarts one per test stops being run.
//
// The database is dropped at test cleanup unless PM_TEST_KEEP_DATABASES is set.
func FreshPostgresDatabase(t testing.TB, prefix string) string {
	t.Helper()
	b := Postgres(t)
	name := freshName(t, prefix)

	admin := openAdmin(t, EnginePostgres, b)
	if _, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("create Postgres database %s: %v", name, err)
	}
	t.Cleanup(func() {
		if keepDatabases() {
			t.Logf("%s set — keeping Postgres database %s", keepDatabasesEnv, name)
			return
		}
		// WITH (FORCE) terminates the leftover backends first (Postgres 13+; both supported series
		// have it). Without it a pool the test forgot to close makes the DROP fail, which would turn a
		// tidy-up into a spurious failure — hence best-effort logging rather than t.Error.
		if _, err := admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, name)); err != nil {
			t.Logf("dropping Postgres database %s: %v (set %s to silence)", name, err, keepDatabasesEnv)
		}
	})
	return name
}

// FreshMySQLDatabase creates a uniquely-named database in the shared MySQL container, grants the
// non-root service user access to it, and returns its name. Port of SharedMySql.freshDatabase
// (TestDatabases.kt:179-189).
//
// The root connection stays confined to this helper: fixtures dial the target as the non-root user,
// which is what keeps a target-side enforcement proof honest.
func FreshMySQLDatabase(t testing.TB, prefix string) string {
	t.Helper()
	b := MySQL(t)
	name := freshName(t, prefix)

	admin := openAdmin(t, EngineMySQL, b)
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE `%s`", name)); err != nil {
		t.Fatalf("create MySQL database %s: %v", name, err)
	}
	grant := fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%'", name, b.User)
	if _, err := admin.Exec(grant); err != nil {
		t.Fatalf("grant on MySQL database %s: %v", name, err)
	}
	t.Cleanup(func() {
		if keepDatabases() {
			t.Logf("%s set — keeping MySQL database %s", keepDatabasesEnv, name)
			return
		}
		if _, err := admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", name)); err != nil {
			t.Logf("dropping MySQL database %s: %v (set %s to silence)", name, err, keepDatabasesEnv)
		}
	})
	return name
}

func keepDatabases() bool { return os.Getenv(keepDatabasesEnv) != "" }

// MySQLAuthPlugin is an auth plugin every supported MySQL series can create an account with.
//
// Port of TestDatabases.kt:139-155. MySQL 8.4 ships mysql_native_password DISABLED, so
// `IDENTIFIED WITH mysql_native_password` is a hard error (1524) there while it still works on 8.0. A
// test that needs a service account with a known plugin asks for this rather than naming one, so one
// test body covers both series. Anything but an ACTIVE status — including an absent row — is disabled.
func MySQLAuthPlugin(t testing.TB) string {
	t.Helper()
	db := OpenMySQL(t, "")
	var status string
	err := db.QueryRow(
		`SELECT plugin_status FROM information_schema.plugins WHERE plugin_name = 'mysql_native_password'`,
	).Scan(&status)
	switch {
	case err == nil && strings.EqualFold(status, "ACTIVE"):
		return "mysql_native_password"
	case err != nil && err != sql.ErrNoRows:
		t.Fatalf("probing mysql_native_password availability: %v", err)
	}
	return "caching_sha2_password"
}

// openAdmin opens the privileged handle CREATE/DROP DATABASE runs on. Deliberately unexported.
func openAdmin(t testing.TB, engine string, b Backend) *sql.DB {
	t.Helper()
	switch engine {
	case EnginePostgres:
		return open(t, "pgx", b.postgresDSNAs(b.adminUser, b.adminPassword, b.DB))
	case EngineMySQL:
		return open(t, "mysql", b.mysqlDSNAs(b.adminUser, b.adminPassword, b.DB))
	default:
		t.Fatalf("unknown engine %q", engine)
		return nil
	}
}

// OpenPostgres opens (and pings) a database/sql handle on the shared Postgres backend, as the
// non-admin user. Closed at test cleanup.
func OpenPostgres(t testing.TB, db string) *sql.DB {
	t.Helper()
	return open(t, "pgx", Postgres(t).PostgresDSN(db))
}

// OpenMySQL opens (and pings) a database/sql handle on the shared MySQL backend, as the non-root
// service user. Closed at test cleanup.
func OpenMySQL(t testing.TB, db string) *sql.DB {
	t.Helper()
	return open(t, "mysql", MySQL(t).MySQLDSN(db))
}

// OpenTarget opens a handle on whichever engine the backend serves — the Go stand-in for the Kotlin
// fixture's engine-agnostic DriverManager.getConnection(jdbcUrl, …). One code path for both engines
// is what lets EnforcementFixture's Postgres and MySQL variants share a body.
func OpenTarget(t testing.TB, b Backend, db string) *sql.DB {
	t.Helper()
	switch b.engine {
	case EnginePostgres:
		return open(t, "pgx", b.PostgresDSN(db))
	case EngineMySQL:
		return open(t, "mysql", b.MySQLDSN(db))
	default:
		t.Fatalf("unknown engine %q", b.engine)
		return nil
	}
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
	return conn
}

// MigratedStore returns a control-plane store on a FRESH Postgres database with all ten Flyway
// migrations applied, and the database's name.
//
// This is the equivalent of EnforcementFixture.kt:166-174's `metadataStores()` first two lines
// (`SharedPostgres.freshDatabase("pm_meta")` + `Flyway.configure().dataSource(meta).load().migrate()`)
// — with the crucial difference that the migration is run by the PRODUCTION runner, internal/store's
// Migrate. That is deliberate: the Kotlin fixture calls Flyway, so its DB tests never exercise the
// migration code the control plane boots with; here they do, on every DB-backed test.
//
// It is also the first real exercise of internal/store against a live server, which
// internal/store/doc.go's TODO(A1) asks for: the pool, TranslateJDBCURL on the PM_DB_URL shape, the
// Flyway-compatible history table and the checksum reimplementation all run for real here.
//
// ⚠️ Still Unverified after this: that the checksums MATCH the ones a real Flyway 13.0.0 writes. This
// proves the Go runner is self-consistent (it can migrate, re-migrate and validate), not that a
// Kotlin-migrated deployment accepts it. That needs the docker-compose parity gate
// (99-library-decisions.md §5) and stays open.
func MigratedStore(t testing.TB) (*store.Db, string) {
	t.Helper()
	name := FreshPostgresDatabase(t, "pm_meta")
	return migratedStoreOn(t, name), name
}

func migratedStoreOn(t testing.TB, name string) *store.Db {
	t.Helper()
	b := Postgres(t)
	ctx := context.Background()

	db, err := store.New(ctx, store.Config{
		// The JDBC shape, not a libpq DSN: PM_DB_URL is a pgjdbc URL everywhere it is set
		// (01-bootstrap.md §1), so the fixture hands the store what the process really gets.
		DBURL:      b.PostgresJDBCURL(name),
		DBUser:     b.User,
		DBPassword: b.Password,
	})
	if err != nil {
		t.Fatalf("open control-plane store on %s: %v", name, err)
	}
	t.Cleanup(db.Close)

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate control-plane store on %s: %v", name, err)
	}
	return db
}
