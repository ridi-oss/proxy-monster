package introspect

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"strconv"
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
	itPGSchema    = "it_pg_introspect"    // a dedicated Postgres schema for this test
	itPGTable     = "it_pg_orders"        // a dedicated Postgres table for this test
	itPGRole      = "it_pg_reader"        // a dedicated Postgres login role (special-char password)
)

type mysqlTestOpener struct{}

func (mysqlTestOpener) OpenTarget(target spi.BackendTarget) (*sql.DB, error) {
	return OpenMySQLTarget(target)
}
func (mysqlTestOpener) ProbeNamespace(conn *sql.Conn, targetDb string) ([]string, *int32, error) {
	return ProbeMySQLNamespace(conn, targetDb)
}
func (mysqlTestOpener) NewDb() engine.Db { return db.MySqlDb{} }

type pgTestOpener struct{}

func (pgTestOpener) OpenTarget(target spi.BackendTarget) (*sql.DB, error) {
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
	target := spi.BackendTarget{Host: "127.0.0.1", Port: addr.Port, Db: "appdb", User: "svc", Password: "pw"}

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

func schemaHash(hashes []*pb.SchemaHash, schema string) *pb.SchemaHash {
	for _, hash := range hashes {
		if hash.GetSchema() == schema {
			return hash
		}
	}
	return nil
}

func assertCatalogMeasurements(t *testing.T, cat *pb.CatalogRequest) {
	t.Helper()
	if !cat.GetNamespaceComplete() {
		t.Error("NamespaceComplete = false, want true for a successful whole-server scan")
	}
	if cat.GetHashesOnly() {
		t.Error("HashesOnly = true, want false for step-1 whole-server content push")
	}
	if cat.GetDbClockMicros() <= 0 {
		t.Errorf("DbClockMicros = %d, want positive", cat.GetDbClockMicros())
	} else {
		measuredAt := time.UnixMicro(cat.GetDbClockMicros())
		if delta := time.Since(measuredAt); delta < -time.Minute || delta > 5*time.Minute {
			t.Errorf("DbClockMicros = %d (%s), want near wall clock (delta %s)", cat.GetDbClockMicros(), measuredAt, delta)
		}
	}
	if cat.GetBackendId() == "" {
		t.Error("BackendId = empty, want privileged server identity")
	}

	content := make(map[string]struct{}, len(cat.GetContentSchemas()))
	for _, schema := range cat.GetContentSchemas() {
		if _, duplicate := content[schema]; duplicate {
			t.Errorf("ContentSchemas contains duplicate %q", schema)
		}
		content[schema] = struct{}{}
		if schemaHash(cat.GetSchemaHashes(), schema) == nil {
			t.Errorf("ContentSchemas schema %q has no SchemaHash", schema)
		}
	}
	for _, column := range cat.GetColumns() {
		if _, exists := content[column.GetSchema()]; !exists {
			t.Errorf("column schema %q absent from ContentSchemas", column.GetSchema())
		}
	}
}

func directSchemaHash(t *testing.T, opener TargetOpener, target spi.BackendTarget, schema string) []byte {
	t.Helper()
	database, err := opener.OpenTarget(target)
	if err != nil {
		t.Fatalf("open direct hash target: %v", err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("connect direct hash target: %v", err)
	}
	defer conn.Close()

	adapter := opener.NewDb()
	var setupRows [][]*string
	if setupSQL := adapter.HashSetupProbeSQL(); setupSQL != "" {
		if rows, setupErr := queryStrings(conn, setupSQL, adapter.HashSetupColumns()); setupErr == nil {
			setupRows = rows
		}
	}
	statement, width, err := adapter.SchemaHashSQL(schema, setupRows)
	if err != nil {
		t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
	}
	rows, err := queryStrings(conn, statement, width)
	if err != nil {
		t.Fatalf("query direct SchemaHashSQL(%q): %v", schema, err)
	}
	observation, err := adapter.SchemaHashFromRows(rows)
	if err != nil {
		t.Fatalf("SchemaHashFromRows(%q): %v", schema, err)
	}
	if !observation.Trusted || len(observation.Hash) == 0 {
		t.Fatalf("direct SchemaHashSQL(%q) = trusted %v hash %x, want trusted non-empty", schema, observation.Trusted, observation.Hash)
	}
	return observation.Hash
}

func TestCoherentSchemaHashes(t *testing.T) {
	first := []engine.SchemaHashObservation{
		{Schema: "Stable", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true, DbClockMicros: 30, BackendID: "server-a"}},
		{Schema: "Changed", HashObservation: engine.HashObservation{Hash: []byte{2}, Trusted: true, DbClockMicros: 20, BackendID: "server-a"}},
		{Schema: "FirstOnly", HashObservation: engine.HashObservation{Hash: []byte{3}, Trusted: true, DbClockMicros: 10, BackendID: "server-a"}},
		{Schema: "Identity", HashObservation: engine.HashObservation{Hash: []byte{4}, Trusted: true, DbClockMicros: 0, BackendID: "server-a"}},
	}
	second := []engine.SchemaHashObservation{
		{Schema: "Stable", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true, BackendID: "server-a"}},
		{Schema: "Changed", HashObservation: engine.HashObservation{Hash: []byte{9}, Trusted: true, BackendID: "server-a"}},
		{Schema: "SecondOnly", HashObservation: engine.HashObservation{Hash: []byte{5}, Trusted: true, BackendID: "server-a"}},
		{Schema: "Identity", HashObservation: engine.HashObservation{Hash: []byte{4}, Trusted: true, BackendID: "server-b"}},
	}

	hashes, clock, backendID, err := coherentSchemaHashes(db.MySqlDb{}, 0, first, second)
	if err != nil {
		t.Fatalf("coherentSchemaHashes: %v", err)
	}
	if clock != 10 {
		t.Errorf("DbClockMicros = %d, want minimum nonzero first-measurement clock 10", clock)
	}
	if backendID != "server-a" {
		t.Errorf("BackendId = %q, want first non-empty first-measurement id server-a", backendID)
	}
	checks := map[string]struct {
		hash    []byte
		trusted bool
	}{
		"Stable": {hash: []byte{1}, trusted: true},
		// Concurrent DDL between the scans: the entry must carry measurement 1's hash, the same
		// measurement the request's clock and backend id come from, not scan 2's newer bytes.
		"Changed":    {hash: []byte{2}, trusted: false},
		"FirstOnly":  {hash: []byte{3}, trusted: false},
		"SecondOnly": {hash: []byte{5}, trusted: false},
		"Identity":   {hash: []byte{4}, trusted: false},
	}
	for schema, want := range checks {
		got := schemaHash(hashes, schema)
		if got == nil {
			t.Errorf("SchemaHashes missing %q", schema)
			continue
		}
		if !bytes.Equal(got.GetHash(), want.hash) || got.GetTrusted() != want.trusted {
			t.Errorf("SchemaHashes[%q] = hash %x trusted %v, want hash %x trusted %v", schema, got.GetHash(), got.GetTrusted(), want.hash, want.trusted)
		}
	}
}

func TestCoherentSchemaHashesUsesEmptyBackendIDsAsComparable(t *testing.T) {
	measurement := []engine.SchemaHashObservation{
		{Schema: "schema", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true}},
	}
	hashes, _, _, err := coherentSchemaHashes(db.PgDb{}, 0, measurement, measurement)
	if err != nil {
		t.Fatalf("coherentSchemaHashes: %v", err)
	}
	if len(hashes) != 1 || !hashes[0].GetTrusted() {
		t.Fatalf("empty==empty backend ids yielded %+v, want one trusted schema hash", hashes)
	}
}

func TestCoherentSchemaHashesRejectsCanonicalCollision(t *testing.T) {
	first := []engine.SchemaHashObservation{
		{Schema: "Foo", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true}},
		{Schema: "foo", HashObservation: engine.HashObservation{Hash: []byte{2}, Trusted: true}},
	}
	if _, _, _, err := coherentSchemaHashes(db.MySqlDb{}, 1, first, first); err == nil {
		t.Fatal("coherentSchemaHashes canonical collision = nil error, want degradation error")
	}
}

// namespace_complete licenses the manager to DELETE every schema absent from the push, so this asserts
// the flag itself, not the inputs that feed it: only a measurement that both produced hashes and ran on
// a connection guaranteed to see every schema may claim it.
func TestMeasureServerClaimsCompletenessOnlyWhenProven(t *testing.T) {
	good := []engine.SchemaHashObservation{
		{Schema: "app", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true, DbClockMicros: 5, BackendID: "server-a"}},
	}
	collision := []engine.SchemaHashObservation{
		{Schema: "Foo", HashObservation: engine.HashObservation{Hash: []byte{1}, Trusted: true}},
		{Schema: "foo", HashObservation: engine.HashObservation{Hash: []byte{2}, Trusted: true}},
	}
	failure := errors.New("grouped hash statement failed")
	for _, tc := range []struct {
		name                string
		lctnMode            int
		seesEverySchema     bool
		first, second       []engine.SchemaHashObservation
		firstErr, secondErr error
		wantHashes          bool
		wantComplete        bool
	}{
		{name: "first statement failed", seesEverySchema: true, first: nil, firstErr: failure, second: good},
		{name: "second statement failed", seesEverySchema: true, first: good, second: nil, secondErr: failure},
		{name: "canonical collision", lctnMode: 1, seesEverySchema: true, first: collision, second: collision},
		// The privilege-filtered case: the hashes are genuine and worth sending, but they enumerate only
		// what this account may see, so the push must not license deletion of the rest.
		{name: "partial catalog visibility", first: good, second: good, wantHashes: true},
		{name: "measured and fully visible", seesEverySchema: true, first: good, second: good, wantHashes: true, wantComplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := measureServer(db.MySqlDb{}, tc.lctnMode, tc.seesEverySchema, tc.first, tc.firstErr, tc.second, tc.secondErr)
			if got.namespaceComplete != tc.wantComplete {
				t.Fatalf("namespaceComplete = %v, want %v", got.namespaceComplete, tc.wantComplete)
			}
			if tc.wantHashes {
				if len(got.schemaHashes) == 0 || got.dbClockMicros == 0 || got.backendID == "" {
					t.Fatalf("measureServer = %+v; want a populated measurement", got)
				}
				return
			}
			if len(got.schemaHashes) != 0 || got.dbClockMicros != 0 || got.backendID != "" {
				t.Fatalf("degraded measurement leaked state: %+v", got)
			}
		})
	}
}

func TestIntrospectMySQL(t *testing.T) {
	backend := dbtest.MySQL(t)

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
		target := spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: itMySQLSchema, User: backend.User, Password: backend.Password}
		cat, err := Run(mysqlTestOpener{}, target)
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
		assertCatalogMeasurements(t, cat)
		measured := schemaHash(cat.GetSchemaHashes(), itMySQLSchema)
		if measured == nil {
			t.Fatalf("SchemaHashes missing stable schema %q", itMySQLSchema)
		}
		if !measured.GetTrusted() {
			t.Errorf("SchemaHashes[%q].Trusted = false, want true", itMySQLSchema)
		}
		if direct := directSchemaHash(t, mysqlTestOpener{}, target, itMySQLSchema); !bytes.Equal(measured.GetHash(), direct) {
			t.Errorf("SchemaHashes[%q].Hash = %x, direct SchemaHashSQL = %x", itMySQLSchema, measured.GetHash(), direct)
		}
	})

	t.Run("delimiter-bearing credentials authenticate (connector path, no DSN round-trip)", func(t *testing.T) {
		cat, err := Run(mysqlTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: itMySQLSchema, User: "svc:reader", Password: "p@s:s/w@rd"})
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

	// The same claim PostgreSQL asserts below, on the priority engine: completeness must track the
	// READER, not the server. Asserting both accounts against one backend is what separates a real
	// privilege check from a constant.
	t.Run("completeness tracks the reader's catalog visibility", func(t *testing.T) {
		hidden := "it_mysql_hidden_" + strconv.Itoa(os.Getpid())
		for _, stmt := range []string{
			`CREATE DATABASE IF NOT EXISTS ` + hidden,
			`CREATE TABLE IF NOT EXISTS ` + hidden + `.secret (id INT PRIMARY KEY)`,
		} {
			if _, err := seed.Exec(stmt); err != nil {
				t.Fatalf("seed stmt %q: %v", stmt, err)
			}
		}
		t.Cleanup(func() { _, _ = seed.Exec(`DROP DATABASE IF EXISTS ` + hidden) })

		privileged, err := Run(mysqlTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: itMySQLSchema, User: backend.User, Password: backend.Password})
		if err != nil {
			t.Fatalf("privileged Run: %v", err)
		}
		restricted, err := Run(mysqlTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: itMySQLSchema, User: "svc:reader", Password: "p@s:s/w@rd"})
		if err != nil {
			t.Fatalf("restricted Run: %v", err)
		}
		if !privileged.GetNamespaceComplete() {
			t.Error("privileged NamespaceComplete = false, want true for an account that sees every schema")
		}
		if restricted.GetNamespaceComplete() {
			t.Error("restricted NamespaceComplete = true, but its catalog view is privilege-filtered")
		}
		// A least-privilege reader still measures genuine hashes — they are what the manager verifies
		// content against — it just may not claim the set is the whole server.
		if schemaHash(restricted.GetSchemaHashes(), itMySQLSchema) == nil {
			t.Errorf("restricted SchemaHashes missing %q", itMySQLSchema)
		}
		// The concrete harm the flag guards: the restricted scan genuinely omits a schema that exists, so
		// a completeness claim over it would instruct the manager to delete that schema's rows.
		if schemaHash(privileged.GetSchemaHashes(), hidden) == nil {
			t.Errorf("privileged SchemaHashes missing %q, so this fixture proves nothing", hidden)
		}
		if got := schemaHash(restricted.GetSchemaHashes(), hidden); got != nil {
			t.Errorf("restricted SchemaHashes unexpectedly contains %q (%+v); pick a schema it truly cannot see", hidden, got)
		}
	})

	t.Run("mixed-case column folds to canonical spelling", func(t *testing.T) {
		// MySQL column names fold UNCONDITIONALLY (regardless of lower_case_table_names), so this
		// proves normalizeColumns is wired into Run regardless of this shared container's configured
		// mode — a mixed-case CustomerID must come back canonical (lowercase), never verbatim.
		if _, err := seed.Exec(`CREATE TABLE IF NOT EXISTS ` + itMySQLSchema + `.orders (id INT PRIMARY KEY, CustomerID INT NOT NULL)`); err != nil {
			t.Fatalf("seed mixed-case column: %v", err)
		}
		cat, err := Run(mysqlTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: itMySQLSchema, User: backend.User, Password: backend.Password})
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
	backend := dbtest.Postgres(t)

	// Seed a user table under a unique name plus a login role whose password carries '@', '/', ':' — the
	// shape that exercises introspect's url.UserPassword escaping on the PG DSN path. Idempotent because the
	// container is shared and persists (CREATE ROLE has no IF NOT EXISTS, so guard it with a DO block). The
	// "pgx" driver blank-imported by introspect.go backs dbtest's OpenPostgres handle.
	seed := dbtest.OpenPostgres(t, "")
	for _, stmt := range []string{
		`CREATE SCHEMA IF NOT EXISTS ` + itPGSchema,
		`CREATE TABLE IF NOT EXISTS ` + itPGSchema + `.` + itPGTable + ` (id INT PRIMARY KEY, note TEXT)`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + itPGRole + `') THEN CREATE ROLE ` + itPGRole + ` LOGIN PASSWORD 'p@ss/w:rd'; END IF; END $$`,
		`GRANT USAGE ON SCHEMA ` + itPGSchema + ` TO ` + itPGRole,
		`GRANT SELECT ON ` + itPGSchema + `.` + itPGTable + ` TO ` + itPGRole,
	} {
		if _, err := seed.Exec(stmt); err != nil {
			t.Fatalf("seed stmt %q: %v", stmt, err)
		}
	}

	t.Run("captures seeded + system schemas and load-bearing facts", func(t *testing.T) {
		target := spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: backend.DB, User: backend.User, Password: backend.Password}
		cat, err := Run(pgTestOpener{}, target)
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
		if !hasColumn(cols, itPGSchema, itPGTable, "note") {
			t.Errorf("columns missing %s.%s.note (user table not introspected)", itPGSchema, itPGTable)
		}
		// The no-exclusion invariant: pg_catalog / information_schema must be captured, never denylisted.
		// Subset check — extra schemas from the shared DB are fine.
		for _, sys := range []string{"pg_catalog", "information_schema"} {
			if !hasSchema(cols, sys) {
				t.Errorf("system schema %q absent from catalog — introspection must NOT exclude system schemas", sys)
			}
		}
		assertCatalogMeasurements(t, cat)
		measured := schemaHash(cat.GetSchemaHashes(), itPGSchema)
		if measured == nil {
			t.Fatalf("SchemaHashes missing stable schema %q", itPGSchema)
		}
		if !measured.GetTrusted() {
			t.Errorf("SchemaHashes[%q].Trusted = false, want true", itPGSchema)
		}
		if direct := directSchemaHash(t, pgTestOpener{}, target, itPGSchema); !bytes.Equal(measured.GetHash(), direct) {
			t.Errorf("SchemaHashes[%q].Hash = %x, direct SchemaHashSQL = %x", itPGSchema, measured.GetHash(), direct)
		}
	})

	t.Run("special-char credentials authenticate (url.UserPassword escaping)", func(t *testing.T) {
		// Auth failing here would flag broken url.UserPassword escaping of the special-char password.
		cat, err := Run(pgTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: backend.DB, User: itPGRole, Password: "p@ss/w:rd"})
		if err != nil {
			t.Fatalf("Run with special-char credentials: %v (a naive DSN would mangle them)", err)
		}
		if !contains(cat.GetDefaultSchemas(), "public") || !contains(cat.GetDefaultSchemas(), "pg_catalog") {
			t.Errorf("DefaultSchemas = %v, want to contain both public and pg_catalog", cat.GetDefaultSchemas())
		}
		if !hasColumn(cat.GetColumns(), itPGSchema, itPGTable, "note") {
			t.Errorf("special-char-cred introspection missing %s.%s.note", itPGSchema, itPGTable)
		}
		// A least-privilege reader still measures real hashes — they are what the manager verifies
		// content against — but information_schema shows it only what it may see, so this push must not
		// claim to enumerate the server. Claiming it would tell the manager every schema this account
		// cannot read has been dropped.
		if schemaHash(cat.GetSchemaHashes(), itPGSchema) == nil {
			t.Errorf("restricted-reader SchemaHashes missing %q", itPGSchema)
		}
		if cat.GetNamespaceComplete() {
			t.Error("restricted-reader NamespaceComplete = true, but its catalog view is privilege-filtered")
		}
	})

	// The completeness claim must track the READER, not the server: the same database introspected by a
	// privileged account claims a complete namespace and by a least-privilege account does not. Asserting
	// both against one backend is what distinguishes a real privilege check from a constant.
	t.Run("completeness tracks the reader's catalog visibility", func(t *testing.T) {
		hidden := "it_pg_hidden_" + strconv.Itoa(os.Getpid())
		for _, stmt := range []string{
			`CREATE SCHEMA IF NOT EXISTS ` + hidden,
			`CREATE TABLE IF NOT EXISTS ` + hidden + `.secret (id INT PRIMARY KEY)`,
			`REVOKE ALL ON SCHEMA ` + hidden + ` FROM PUBLIC`,
		} {
			if _, err := seed.Exec(stmt); err != nil {
				t.Fatalf("seed stmt %q: %v", stmt, err)
			}
		}
		t.Cleanup(func() { _, _ = seed.Exec(`DROP SCHEMA IF EXISTS ` + hidden + ` CASCADE`) })

		privileged, err := Run(pgTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: backend.DB, User: backend.User, Password: backend.Password})
		if err != nil {
			t.Fatalf("privileged Run: %v", err)
		}
		restricted, err := Run(pgTestOpener{}, spi.BackendTarget{Host: backend.Host, Port: backend.Port, Db: backend.DB, User: itPGRole, Password: "p@ss/w:rd"})
		if err != nil {
			t.Fatalf("restricted Run: %v", err)
		}
		if !privileged.GetNamespaceComplete() {
			t.Error("privileged NamespaceComplete = false, want true for an account that sees every schema")
		}
		if restricted.GetNamespaceComplete() {
			t.Error("restricted NamespaceComplete = true, want false for a privilege-filtered catalog view")
		}
		// The concrete harm the flag guards: the restricted scan genuinely omits a schema that exists,
		// so a completeness claim over it would instruct the manager to delete that schema's rows.
		if schemaHash(privileged.GetSchemaHashes(), hidden) == nil {
			t.Errorf("privileged SchemaHashes missing %q, so this fixture proves nothing", hidden)
		}
		if got := schemaHash(restricted.GetSchemaHashes(), hidden); got != nil {
			t.Errorf("restricted SchemaHashes unexpectedly contains %q (%+v); pick a schema it truly cannot see", hidden, got)
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
