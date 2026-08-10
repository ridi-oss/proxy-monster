package introspect

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// These are real DB-backed tests: the introspection path (namespace probes, the load-bearing MySQL
// current-database / lower_case_table_names checks, all-schema column capture, and the no-exclusion
// invariant) is only meaningfully exercised against a live server. They run against the module's shared
// dbtest containers (one MySQL + one Postgres, started once and REUSED across the whole suite), so every
// fixture is seeded under UNIQUE, per-test names and every assertion is a SUBSET check — the seeded
// objects (and the system catalogs) MUST be present, but the database is NOT assumed pristine or
// exclusive. dbtest FAILS the test when Docker is unavailable; it never skips.

// Per-test fixture names — unique so the shared, reused containers don't collide across tests/runs.
const (
	itMySQLSchema = "it_mysql_introspect" // a dedicated MySQL database/schema for this test
	itPGTable     = "it_pg_orders"        // a dedicated Postgres table in public for this test
	itPGRole      = "it_pg_reader"        // a dedicated Postgres login role (special-char password)
)

type mysqlTestOpener struct{}

func (mysqlTestOpener) OpenTarget(target spi.TargetDb) (*sql.DB, error) {
	return OpenMySQLTarget(target)
}
func (mysqlTestOpener) ProbeNamespace(conn *sql.Conn, targetDb string) ([]string, *int32, error) {
	return ProbeMySQLNamespace(conn, targetDb)
}
func (mysqlTestOpener) NewDb() engine.Db { return db.MySqlDb{} }

type pgTestOpener struct{}

func (pgTestOpener) OpenTarget(target spi.TargetDb) (*sql.DB, error) {
	return OpenPostgresTarget(target)
}
func (pgTestOpener) ProbeNamespace(conn *sql.Conn, targetDb string) ([]string, *int32, error) {
	return ProbePostgresNamespace(conn, targetDb)
}
func (pgTestOpener) NewDb() engine.Db { return db.PgDb{} }

// TestRunPinsOneConnectionOnDeadTarget is the regression test for the pinned-connection fix.
// Introspection acquires ONE physical connection (db.Conn) for the whole refresh, so a dead or
// misauthenticated target costs a single login attempt — not one per probe query (version,
// aurora_version, namespace, columns), which across the boot retries would multiply into many failed
// logins and risk service-account lockout.
//
// database/sql retries a handshake failure internally (its bad-conn retry), so the raw dial count for a
// single acquisition is an implementation detail we deliberately do NOT hard-code. Instead we measure the
// baseline — the dials one bare db.Conn makes against this same dead target — and assert Run makes exactly
// that many. Pre-fix (a dial per probe) Run would have dialed a multiple of the baseline. Needs no Docker.
func TestRunPinsOneConnectionOnDeadTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// The accept goroutine drops each connection immediately so the driver handshake fails fast, and
	// signals every accept on a channel. Because every dial for one operation is made synchronously before
	// that operation returns, draining the channel until it goes quiet yields that operation's exact dial
	// count without racing on when the goroutine observes each accept.
	accepted := make(chan struct{}, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	drainUntilQuiet := func() int {
		n := 0
		for {
			select {
			case <-accepted:
				n++
			case <-time.After(300 * time.Millisecond):
				return n
			}
		}
	}

	addr := ln.Addr().(*net.TCPAddr)
	target := spi.TargetDb{Host: "127.0.0.1", Port: addr.Port, Db: "appdb", User: "svc", Password: "pw"}

	// Baseline: the dials a single connection acquisition costs against this dead target.
	baseDB, err := OpenMySQLTarget(target)
	if err != nil {
		t.Fatalf("openTarget: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if conn, err := baseDB.Conn(ctx); err == nil {
		conn.Close()
		cancel()
		baseDB.Close()
		t.Fatal("db.Conn against a dead target = nil error, want a connection failure")
	}
	cancel()
	baseDB.Close()
	baseline := drainUntilQuiet()
	if baseline < 1 {
		t.Fatalf("baseline connection attempts = %d, want >= 1 (test listener not exercised)", baseline)
	}

	// Run must make exactly the baseline count — i.e. one connection acquisition for the whole refresh,
	// not one per probe query.
	if _, runErr := Run(mysqlTestOpener{}, target); runErr == nil {
		t.Fatal("Run against a dead target = nil error, want a connection failure")
	}
	runCount := drainUntilQuiet()
	if runCount != baseline {
		t.Errorf("Run made %d connection attempts, want %d (one pinned connection, not one per probe)", runCount, baseline)
	}
}

// hasColumn reports whether cols contains a column matching schema/table/column.
func hasColumn(cols []*pb.Column, schema, table, column string) bool {
	for _, c := range cols {
		if c.GetSchema() == schema && c.GetTable() == table && c.GetColumn() == column {
			return true
		}
	}
	return false
}

// hasSchema reports whether any column belongs to schema — the signal that a schema was captured (i.e.
// NOT excluded).
func hasSchema(cols []*pb.Column, schema string) bool {
	for _, c := range cols {
		if c.GetSchema() == schema {
			return true
		}
	}
	return false
}

func TestIntrospectMySQL(t *testing.T) {
	targetDb := dbtest.MySQL(t)

	// Seed a user table under a dedicated schema and a delimiter-bearing service account. All statements are
	// idempotent (IF NOT EXISTS / re-GRANT) because the container is shared and persists across runs. The
	// driver blank-imported by introspect.go registers "mysql", so dbtest's OpenMySQL handle works here.
	seed := dbtest.OpenMySQL(t, "")
	for _, stmt := range []string{
		`CREATE DATABASE IF NOT EXISTS ` + itMySQLSchema,
		`CREATE TABLE IF NOT EXISTS ` + itMySQLSchema + `.customers (id INT PRIMARY KEY, email VARCHAR(255) NOT NULL)`,
		// A username carrying the ':' DSN delimiter and a password carrying ':', '@', '/' — the exact
		// shape that FormatDSN()->sql.Open would corrupt. The plugin is whichever the server has (8.4
		// disables mysql_native_password), so this covers every supported series; go-sql-driver
		// completes caching_sha2's public-key exchange itself when that is what the server offers.
		`CREATE USER IF NOT EXISTS 'svc:reader'@'%' IDENTIFIED WITH ` + dbtest.MySQLAuthPlugin(t, seed) + ` BY 'p@s:s/w@rd'`,
		`ALTER USER 'svc:reader'@'%' IDENTIFIED WITH ` + dbtest.MySQLAuthPlugin(t, seed) + ` BY 'p@s:s/w@rd'`,
		`GRANT SELECT ON ` + itMySQLSchema + `.* TO 'svc:reader'@'%'`,
	} {
		if _, err := seed.Exec(stmt); err != nil {
			t.Fatalf("seed stmt %q: %v", stmt, err)
		}
	}

	t.Run("root captures seeded + system schemas and load-bearing facts", func(t *testing.T) {
		cat, err := Run(mysqlTestOpener{}, spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: itMySQLSchema, User: targetDb.User, Password: targetDb.Password})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := cat.GetDefaultSchemas(); len(got) != 1 || got[0] != itMySQLSchema {
			t.Errorf("DefaultSchemas = %v, want [%s] (current database)", got, itMySQLSchema)
		}
		if cat.MysqlLowerCaseTableNames == nil {
			t.Error("MysqlLowerCaseTableNames = nil, want a set value (MySQL always resolves @@lower_case_table_names)")
		} else if v := cat.GetMysqlLowerCaseTableNames(); v < 0 || v > 2 {
			t.Errorf("MysqlLowerCaseTableNames = %d, want 0..2", v)
		}
		if !strings.Contains(cat.GetEngineVersion(), ".") {
			t.Errorf("EngineVersion = %q, want a non-empty server version", cat.GetEngineVersion())
		}
		cols := cat.GetColumns()
		if !hasColumn(cols, itMySQLSchema, "customers", "email") {
			t.Errorf("columns missing %s.customers.email (user table not introspected)", itMySQLSchema)
		}
		// The no-exclusion invariant: system catalogs must be captured, not denylisted. Root can see them
		// in information_schema.columns. Subset check — extra schemas from the shared DB are fine.
		for _, sys := range []string{"information_schema", "mysql", "performance_schema", "sys"} {
			if !hasSchema(cols, sys) {
				t.Errorf("system schema %q absent from catalog — introspection must NOT exclude system schemas", sys)
			}
		}
	})

	t.Run("delimiter-bearing credentials authenticate (connector path, no DSN round-trip)", func(t *testing.T) {
		cat, err := Run(mysqlTestOpener{}, spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: itMySQLSchema, User: "svc:reader", Password: "p@s:s/w@rd"})
		if err != nil {
			t.Fatalf("Run with delimiter-bearing credentials: %v (FormatDSN round-trip would corrupt them)", err)
		}
		if got := cat.GetDefaultSchemas(); len(got) != 1 || got[0] != itMySQLSchema {
			t.Errorf("DefaultSchemas = %v, want [%s]", got, itMySQLSchema)
		}
		if !hasColumn(cat.GetColumns(), itMySQLSchema, "customers", "email") {
			t.Errorf("delimiter-cred introspection missing %s.customers.email", itMySQLSchema)
		}
	})

	t.Run("mixed-case column folds to canonical spelling", func(t *testing.T) {
		// MySQL column names fold UNCONDITIONALLY (regardless of lower_case_table_names), so this
		// proves normalizeColumns is wired into Run regardless of this shared container's configured
		// mode — a mixed-case CustomerID must come back canonical (lowercase), never verbatim.
		if _, err := seed.Exec(`CREATE TABLE IF NOT EXISTS ` + itMySQLSchema + `.orders (id INT PRIMARY KEY, CustomerID INT NOT NULL)`); err != nil {
			t.Fatalf("seed mixed-case column: %v", err)
		}
		cat, err := Run(mysqlTestOpener{}, spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: itMySQLSchema, User: targetDb.User, Password: targetDb.Password})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		cols := cat.GetColumns()
		if hasColumn(cols, itMySQLSchema, "orders", "CustomerID") {
			t.Errorf("catalog kept raw spelling %q.orders.CustomerID — column names must fold unconditionally", itMySQLSchema)
		}
		if !hasColumn(cols, itMySQLSchema, "orders", "customerid") {
			t.Errorf("catalog missing folded %q.orders.customerid — got columns %+v", itMySQLSchema, cols)
		}
	})
}

func TestIntrospectPostgres(t *testing.T) {
	targetDb := dbtest.Postgres(t)

	// Seed a user table under a unique name plus a login role whose password carries '@', '/', ':' — the
	// shape that exercises introspect's url.UserPassword escaping on the PG DSN path. Idempotent because the
	// container is shared and persists (CREATE ROLE has no IF NOT EXISTS, so guard it with a DO block). The
	// "pgx" driver blank-imported by introspect.go backs dbtest's OpenPostgres handle.
	seed := dbtest.OpenPostgres(t, "")
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS public.` + itPGTable + ` (id INT PRIMARY KEY, note TEXT)`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + itPGRole + `') THEN CREATE ROLE ` + itPGRole + ` LOGIN PASSWORD 'p@ss/w:rd'; END IF; END $$`,
		`GRANT USAGE ON SCHEMA public TO ` + itPGRole,
		`GRANT SELECT ON public.` + itPGTable + ` TO ` + itPGRole,
	} {
		if _, err := seed.Exec(stmt); err != nil {
			t.Fatalf("seed stmt %q: %v", stmt, err)
		}
	}

	t.Run("captures seeded + system schemas and load-bearing facts", func(t *testing.T) {
		cat, err := Run(pgTestOpener{}, spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: targetDb.DB, User: targetDb.User, Password: targetDb.Password})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		// current_schemas(true) includes the implicit pg_catalog plus the resolvable search_path schemas.
		if !contains(cat.GetDefaultSchemas(), "public") || !contains(cat.GetDefaultSchemas(), "pg_catalog") {
			t.Errorf("DefaultSchemas = %v, want to contain both public and pg_catalog", cat.GetDefaultSchemas())
		}
		if cat.MysqlLowerCaseTableNames != nil {
			t.Errorf("MysqlLowerCaseTableNames = %v, want nil for Postgres", cat.GetMysqlLowerCaseTableNames())
		}
		if !strings.Contains(cat.GetEngineVersion(), "PostgreSQL") {
			t.Errorf("EngineVersion = %q, want to contain PostgreSQL", cat.GetEngineVersion())
		}
		cols := cat.GetColumns()
		if !hasColumn(cols, "public", itPGTable, "note") {
			t.Errorf("columns missing public.%s.note (user table not introspected)", itPGTable)
		}
		// The no-exclusion invariant: pg_catalog / information_schema must be captured, never denylisted.
		// Subset check — extra schemas from the shared DB are fine.
		for _, sys := range []string{"pg_catalog", "information_schema"} {
			if !hasSchema(cols, sys) {
				t.Errorf("system schema %q absent from catalog — introspection must NOT exclude system schemas", sys)
			}
		}
	})

	t.Run("special-char credentials authenticate (url.UserPassword escaping)", func(t *testing.T) {
		// Auth failing here would flag broken url.UserPassword escaping of the special-char password.
		cat, err := Run(pgTestOpener{}, spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: targetDb.DB, User: itPGRole, Password: "p@ss/w:rd"})
		if err != nil {
			t.Fatalf("Run with special-char credentials: %v (a naive DSN would mangle them)", err)
		}
		if !contains(cat.GetDefaultSchemas(), "public") || !contains(cat.GetDefaultSchemas(), "pg_catalog") {
			t.Errorf("DefaultSchemas = %v, want to contain both public and pg_catalog", cat.GetDefaultSchemas())
		}
		if !hasColumn(cat.GetColumns(), "public", itPGTable, "note") {
			t.Errorf("special-char-cred introspection missing public.%s.note", itPGTable)
		}
	})
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
