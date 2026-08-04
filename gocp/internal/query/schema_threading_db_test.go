package query_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// SchemaThreadingDbTest.kt — 698 LOC, 17 cases (06-query-decision.md §7; `docs/schema-threading-problem.md`).
//
// The suite about IDENTITY: a column's classification belongs to a PHYSICAL (catalog, schema, table,
// column), and every path that resolves a name — bare, qualified, aliased, composite, star-expanded,
// CTE-bound, or pivoted by a live search path — must land on the same physical identity or fail
// closed. The fixture is deliberately adversarial about it: TWO `users` tables with the SAME shape,
// one in the default namespace with `rrn` classified pii+masked, one in `analytics` with no
// classification at all and a DIFFERENT sentinel value. Any confusion between them shows up as the
// wrong sentinel in a row.
//
// ⚠️ Structure, as in the Kotlin: an abstract contract (`SchemaThreadingDbContract`, 8 cases) run
// once per engine, plus `SchemaThreadingPostgresDbTest` (6 more) and `SchemaThreadingMysqlDbTest`
// (3 more) — 17 case definitions, 25 executions. [TestSchemaThreadingPostgresDb] and
// [TestSchemaThreadingMysqlDb] are the two leaf classes and each runs the contract itself, exactly as
// the Kotlin's inheritance does; [runSchemaThreadingContract] is the abstract half.
//
// # Where the fixture lives, and why
//
// `SchemaThreadingFixtures` is defined INSIDE SchemaThreadingDbTest.kt, not in `support/` — so is this
// one. It is NOT a second harness: it assembles a [dbtest.EnforcementFixture] from internal/dbtest's
// exported parts and then uses THAT harness's Decide / DecisionRecord / Run, so the decision and the
// audit row are the production ones for exactly the reason internal/dbtest/doc.go gives. The only
// thing added here is the two-schema target and the engine-shaped SQL the cases need.
//
// One case (`decideAndAudit threads and audits the live search path`) needs the audit INSERT as well.
// internal/dbtest cannot import internal/audit — internal/audit's DB tests are in-package and import
// internal/dbtest, so it would be an import cycle (the same constraint internal/query's doc.go records
// for policy and identity) — so [schemaThreadingFixture.decideAndAudit] composes the production
// [query.DecisionRecord] with the production *audit.Store here, where the import is legal.

const (
	schemaReaderPrincipal = "schema-reader@example.com"
	schemaWriterPrincipal = "schema-writer@example.com"
	schemaReaderRole      = "schema-reader"
	schemaWriterRole      = "schema-writer"
)

// schemaThreadingFixture is the Kotlin's `data class SchemaThreadingFixture`.
type schemaThreadingFixture struct {
	t  *testing.T
	fx *dbtest.EnforcementFixture

	engine          string
	catalog         string
	defaultSchema   string
	analyticsSchema string
	defaultRRN      string
	analyticsRRN    string

	auditStore *audit.Store
}

func (f *schemaThreadingFixture) defaultTable() string   { return f.defaultSchema + ".users" }
func (f *schemaThreadingFixture) analyticsTable() string { return f.analyticsSchema + ".users" }

// subtest is `t.Run(name, body)` with the fixture's failure reporter REBOUND to the running subtest.
//
// ⚠️ Both `f.t` and the harness's [dbtest.EnforcementFixture.T] are bound once, at construction — the
// PARENT test, since the Kotlin's `@BeforeAll` lifecycle maps to one fixture per Go test function. The
// fixture reports some failures itself (a target query that errors, a decision that returns an error
// rather than a DENY), so without the rebinding those land on the parent and the failing CASE is never
// named. See [asSubtest] in enforcement_db_test.go for the measurement that showed it.
func (f *schemaThreadingFixture) subtest(t *testing.T, name string, body func(t *testing.T)) {
	t.Run(name, func(t *testing.T) {
		prevT, prevFxT := f.t, f.fx.T
		f.t, f.fx.T = t, t
		defer func() { f.t, f.fx.T = prevT, prevFxT }()
		body(t)
	})
}

// run is `fun run(sql, principal = READER_PRINCIPAL)` — the harness's decide → execute → mask path.
func (f *schemaThreadingFixture) run(sqlText string) query.QueryResponse {
	return f.runAs(schemaReaderPrincipal, sqlText)
}

func (f *schemaThreadingFixture) runAs(principal, sqlText string) query.QueryResponse {
	f.t.Helper()
	return f.fx.Run(principal, sqlText, 100)
}

// decide is `fun decide(sql, principal = WRITER_PRINCIPAL, liveSearchPath = null)`.
func (f *schemaThreadingFixture) decide(sqlText string) query.DecisionContext {
	return f.decideAs(schemaWriterPrincipal, sqlText, nil)
}

func (f *schemaThreadingFixture) decideAs(principal, sqlText string, liveSearchPath *[]string) query.DecisionContext {
	f.t.Helper()
	return f.fx.DecideWith(query.DecideQueryInput{
		Principal:      principal,
		SQL:            sqlText,
		Channel:        query.ChannelEditor,
		LiveSearchPath: liveSearchPath,
	})
}

// rowJson is the Kotlin helper of the same name — whole-row JSON, spelled per engine.
func (f *schemaThreadingFixture) rowJSON(table string) string {
	if f.engine == dbtest.EnginePostgres {
		return "select row_to_json(u) from " + table + " u"
	}
	return "select json_object('id', u.id, 'email', u.email, 'rrn', u.rrn, 'region', u.region) from " + table + " u"
}

// aliasOrComposite is the Kotlin helper of the same name. PostgreSQL's `(u).rrn` composite projection
// has no MySQL spelling, so MySQL reads the plain alias — the shared point is that the alias must not
// launder the physical identity.
func (f *schemaThreadingFixture) aliasOrComposite(table string) string {
	if f.engine == dbtest.EnginePostgres {
		return "select (u).rrn as exposed_rrn from " + table + " u"
	}
	return "select u.rrn as exposed_rrn from " + table + " u"
}

func (f *schemaThreadingFixture) protectedUpdateSQL() string {
	if f.engine == dbtest.EnginePostgres {
		return "update users set rrn = rrn || '-blocked' where rrn = '" + f.defaultRRN + "'"
	}
	return "update users set rrn = concat(rrn, '-blocked') where rrn = '" + f.defaultRRN + "'"
}

func (f *schemaThreadingFixture) analyticsUpdateSQL() string {
	if f.engine == dbtest.EnginePostgres {
		return "update " + f.analyticsTable() + " set rrn = rrn || '-allowed' where rrn = '" + f.analyticsRRN + "'"
	}
	return "update " + f.analyticsTable() + " set rrn = concat(rrn, '-allowed') where rrn = '" + f.analyticsRRN + "'"
}

// executeRolledBack executes a real UPDATE, observes its mutation, rolls it back, then verifies a
// fresh connection sees no mutation.
//
// 🔒 This is what makes cases 7 and 8 a real proof rather than an assertion about a string: it shows
// the statement enforcement DENIES is one the backend would genuinely have executed, and the one
// enforcement ALLOWS genuinely mutates. A syntactically invalid statement would deny too, and would
// prove nothing.
func (f *schemaThreadingFixture) executeRolledBack(sqlText, table, before, after string) {
	f.t.Helper()
	tx, err := f.fx.Target.Begin()
	if err != nil {
		f.t.Fatalf("begin target transaction: %v", err)
	}
	committed := false
	func() {
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		res, err := tx.Exec(sqlText)
		if err != nil {
			f.t.Fatalf("target UPDATE failed: %v (%s)", err, sqlText)
		}
		n, err := res.RowsAffected()
		if err != nil || n <= 0 {
			f.t.Fatalf("expected a row-affecting backend UPDATE, count=%d err=%v: %s", n, err, sqlText)
		}
		if got := readRRN(f.t, tx, table); got != after {
			f.t.Fatalf("the backend did not execute the claimed mutation: %s (rrn=%q, want %q)", sqlText, got, after)
		}
	}()
	if got := readRRN(f.t, f.fx.Target, table); got != before {
		f.t.Fatalf("the test UPDATE escaped its rollback: %s (rrn=%q, want %q)", sqlText, got, before)
	}
}

// rowQueryer is the `*sql.DB` / `*sql.Tx` overlap readRRN needs.
type rowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

func readRRN(t *testing.T, q rowQueryer, table string) string {
	t.Helper()
	var rrn string
	if err := q.QueryRow("select rrn from " + table + " where id = 1").Scan(&rrn); err != nil {
		t.Fatalf("missing seeded row in %s: %v", table, err)
	}
	return rrn
}

// decideAndAudit is `support/EnforcementHarness.kt:46-73`'s config-catalog decision+audit path.
//
// ⚠️ The Kotlin's version reads `core.datasourceStore.catalog(ds.id)` — the GLOBAL catalog — and the
// doc comment there is explicit that this is why it is kept strictly in test scope: the production
// wire path is `decideConnection`'s per-connection held fragments, and the whole point of that design
// is that the enforcing path can never read the global catalog. [dbtest.EnforcementFixture.Decide]
// carries the same warning and the same restriction.
//
// It resolves roles server-side, selects `requester_ip` by channel (WIRE = the proxy-attested socket),
// runs the decision under the live search path, audits, and returns the verdict + audit id. The
// decision, the audit RECORD and the audit INSERT are all production functions; only the composition
// is here.
func (f *schemaThreadingFixture) decideAndAudit(
	principal, sqlText string, searchPath *[]string, clientAddr *string,
) (query.DecisionContext, int64) {
	f.t.Helper()
	started := time.Now()
	// channel == WIRE, so the requester IP is the proxy-attested socket address.
	requesterIP := query.ParseRequesterIp(clientAddr)
	ctx := f.fx.DecideWith(query.DecideQueryInput{
		Principal:      principal,
		SQL:            sqlText,
		Channel:        query.ChannelWire,
		Context:        authz.AuthzContext{RequesterIP: requesterIP},
		LiveSearchPath: searchPath,
	})
	ms := time.Since(started).Milliseconds()
	// `searchPath ?: ds.defaultSchemas`
	namespace := f.fx.DatasourceRow.DefaultSchemas
	if searchPath != nil {
		namespace = *searchPath
	}
	id, err := f.auditStore.Insert(context.Background(),
		f.fx.DecisionRecord(principal, sqlText, clientAddr, ctx, ms, namespace, query.ChannelWire))
	if err != nil {
		f.t.Fatalf("audit insert: %v", err)
	}
	return ctx, id
}

// auditFor is `fx.auditStore.recent(100).single { it.statement == sql }`.
func (f *schemaThreadingFixture) auditFor(sqlText string) types.AuditEvent {
	f.t.Helper()
	events, err := f.auditStore.Recent(context.Background(), 100)
	if err != nil {
		f.t.Fatalf("read recent audit events: %v", err)
	}
	var found []types.AuditEvent
	for _, e := range events {
		if e.Statement == sqlText {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		f.t.Fatalf("audit rows for %q = %d, want exactly 1", sqlText, len(found))
	}
	return found[0]
}

// ---- fixtures (SchemaThreadingFixtures, SchemaThreadingDbTest.kt:139-353) ----------------------

func newSchemaThreadingPostgres(t *testing.T) *schemaThreadingFixture {
	t.Helper()
	backend := dbtest.Postgres(t)
	database := dbtest.FreshPostgresDatabase(t, "pm_schema_target")
	target := dbtest.OpenTarget(t, backend, database)

	const defaultRRN, analyticsRRN = "PG_DEFAULT_RRN_1111", "PG_ANALYTICS_RRN_9999"
	mustExec(t, target, "CREATE SCHEMA analytics")
	createUsers(t, target, "public.users", defaultRRN)
	createUsers(t, target, "analytics.users", analyticsRRN)

	return finishSchemaThreading(t, schemaThreadingSpec{
		engine:          dbtest.EnginePostgres,
		backend:         backend,
		target:          target,
		dsName:          "schema-pg",
		dbName:          database,
		catalog:         database,
		defaultSchema:   "public",
		analyticsSchema: "analytics",
		defaultRRN:      defaultRRN,
		analyticsRRN:    analyticsRRN,
	})
}

func newSchemaThreadingMySQL(t *testing.T) *schemaThreadingFixture {
	t.Helper()
	backend := dbtest.MySQL(t)
	// MySQL has no schema-inside-a-database, so the two namespaces are two DATABASES. That is the
	// whole reason the analyzer's namespace segments differ per engine (catalog "def" + database as
	// schema on MySQL), and it is why this suite must run on both.
	database := dbtest.FreshMySQLDatabase(t, "pm_schema_app")
	analytics := dbtest.FreshMySQLDatabase(t, "pm_schema_analytics")
	target := dbtest.OpenTarget(t, backend, database)
	analyticsTarget := dbtest.OpenTarget(t, backend, analytics)

	const defaultRRN, analyticsRRN = "MYSQL_DEFAULT_RRN_2222", "MYSQL_ANALYTICS_RRN_8888"
	createUsers(t, target, database+".users", defaultRRN)
	createUsers(t, analyticsTarget, analytics+".users", analyticsRRN)

	return finishSchemaThreading(t, schemaThreadingSpec{
		engine:          dbtest.EngineMySQL,
		backend:         backend,
		target:          target,
		dsName:          "schema-mysql",
		dbName:          database,
		catalog:         "def",
		defaultSchema:   database,
		analyticsSchema: analytics,
		defaultRRN:      defaultRRN,
		analyticsRRN:    analyticsRRN,
	})
}

type schemaThreadingSpec struct {
	engine                                    string
	backend                                   dbtest.Backend
	target                                    *sql.DB
	dsName, dbName, catalog, defaultSchema    string
	analyticsSchema, defaultRRN, analyticsRRN string
}

// createUsers is the Kotlin's private helper of the same name. `rrn` is VARCHAR(128) here, not (32):
// the protected-update case appends `-blocked` to it on the backend.
func createUsers(t *testing.T, db *sql.DB, table, rrn string) {
	t.Helper()
	mustExec(t, db, fmt.Sprintf(
		"CREATE TABLE %s (id BIGINT PRIMARY KEY, email VARCHAR(64), rrn VARCHAR(128), region VARCHAR(16))", table))
	mustExec(t, db, fmt.Sprintf(
		"INSERT INTO %s VALUES (1, 'sentinel@example.com', '%s', 'KR')", table, rrn))
}

func mustExec(t *testing.T, db *sql.DB, stmt string) {
	t.Helper()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("target setup (%s): %v", stmt, err)
	}
}

// finishSchemaThreading is `SchemaThreadingFixtures.finish` — the catalog push, the classification,
// the two roles, and the shared enforcement graph built over the already-seeded policy rows.
func finishSchemaThreading(t *testing.T, spec schemaThreadingSpec) *schemaThreadingFixture {
	t.Helper()

	metaStore, _ := dbtest.MigratedStore(t)
	seed := dbtest.NewSeed(t, metaStore)
	dsID := seed.Datasource(dbtest.DatasourceSpec{
		Name:   spec.dsName,
		Engine: spec.engine,
		Host:   spec.backend.Host,
		Port:   spec.backend.Port,
		DBName: spec.dbName,
	})
	seed.IntrospectTargetInto(dsID, spec.engine, spec.target, spec.dbName)

	fx := &dbtest.EnforcementFixture{
		T:              t,
		Store:          metaStore,
		Seed:           seed,
		Backend:        spec.backend,
		Target:         spec.target,
		DatasourceID:   dsID,
		DatasourceName: spec.dsName,
		Engine:         spec.engine,
		DBName:         spec.dbName,
		Catalog:        spec.catalog,
		Schema:         spec.defaultSchema,
	}
	fx.DatasourceStore = datasource.NewDatasourceStore(metaStore)

	// The catalog push must have captured BOTH namespaces, or every case below would be asserting
	// against a catalog that cannot tell them apart.
	schemas := map[string]bool{}
	for _, c := range fx.CatalogRows() {
		if c.Table == "users" {
			schemas[c.Schema] = true
		}
	}
	if !schemas[spec.defaultSchema] {
		t.Fatalf("catalog push missed default schema %s: %v", spec.defaultSchema, schemas)
	}
	if !schemas[spec.analyticsSchema] {
		t.Fatalf("catalog push missed analytics schema %s: %v", spec.analyticsSchema, schemas)
	}

	// ONLY the default namespace's rrn is classified. `analytics.users.rrn` is the same column name in
	// the same shape and carries NO classification — which is what makes a cross-namespace confusion
	// visible as a returned sentinel rather than as a silent pass.
	maskFnID := seed.MaskFn("schema-last4", "LAST_N")
	seed.Classify(dsID, spec.defaultSchema, "users", "rrn", []string{"pii"}, &maskFnID)

	defaultEUID := fmt.Sprintf("%s/%s/%s/users", spec.dsName, spec.catalog, spec.defaultSchema)
	analyticsEUID := fmt.Sprintf("%s/%s/%s/users", spec.dsName, spec.catalog, spec.analyticsSchema)
	seedSchemaThreadingRole(seed, schemaReaderRole, schemaReaderPrincipal, spec.dsName,
		[]string{"sql.select"}, defaultEUID, analyticsEUID)
	seedSchemaThreadingRole(seed, schemaWriterRole, schemaWriterPrincipal, spec.dsName,
		[]string{"sql.update", "sql.insert"}, defaultEUID, analyticsEUID)

	// Built AFTER the policy rows are committed, so the Cedar engine's first Authorize reads them.
	policyStore := dbtest.NewDBPolicyStore(t, metaStore.Pool)
	fx.PolicyStore = policyStore
	fx.RoleSource = dbtest.NewDBRoleSource(t, metaStore.Pool)
	cedar, err := authz.NewCedarEngine(policyStore)
	if err != nil {
		t.Fatalf("build Cedar engine over the seeded policies: %v", err)
	}
	fx.CedarEngine = cedar
	fx.Authz = authz.New(cedar, policyStore, fx.RoleSource)

	// The datasource row AFTER IntrospectTargetInto stamped default_schemas / engine_version /
	// lower_case_table_names onto it — decideQuery reads all three.
	row, found, err := fx.DatasourceStore.Get(context.Background(), dsID)
	if err != nil || !found {
		t.Fatalf("read back seeded datasource %d: found=%v err=%v", dsID, found, err)
	}
	fx.DatasourceRow = row

	// A6's three store seams, at the PRODUCTION stores (see enforcement_db_test.go).
	wireProductionSeams(fx)

	return &schemaThreadingFixture{
		t:               t,
		fx:              fx,
		engine:          spec.engine,
		catalog:         spec.catalog,
		defaultSchema:   spec.defaultSchema,
		analyticsSchema: spec.analyticsSchema,
		defaultRRN:      spec.defaultRRN,
		analyticsRRN:    spec.analyticsRRN,
		auditStore:      audit.New(metaStore.Pool),
	}
}

// seedSchemaThreadingRole is the Kotlin's private `seedRole`.
//
// ⚠️ The analytics permit carries NO `unless { resource in Tag::"pii" }` clause — deliberately. The
// analytics table has no pii classification, so the point of the pair is that the DEFAULT table's
// masked/unmasked split does not follow the name `users` across namespaces.
func seedSchemaThreadingRole(
	seed *dbtest.Seed, roleName, principal, dsName string,
	sqlActions []string, defaultEUID, analyticsEUID string,
) {
	roleID := seed.Role(roleName)
	seed.AssignRole(principal, roleID)

	actions := make([]string, 0, len(sqlActions)+1)
	for _, a := range append([]string{"datasource.connect"}, sqlActions...) {
		actions = append(actions, fmt.Sprintf("Action::%q", a))
	}
	seed.CedarPolicy(roleName+"-connect-kind", fmt.Sprintf(
		`permit(principal in Role::%q, action in [%s], resource in Datasource::%q);`,
		roleName, strings.Join(actions, ", "), dsName))
	seed.CedarPolicy(roleName+"-default-unmasked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`,
		roleName, defaultEUID))
	seed.CedarPolicy(roleName+"-default-masked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.masked", resource in Table::%q) when { resource in Tag::"pii" };`,
		roleName, defaultEUID))
	seed.CedarPolicy(roleName+"-analytics-unmasked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q);`,
		roleName, analyticsEUID))
}

// ---- assertions ---------------------------------------------------------------------------------

// assertNoCleartextSentinel is the Kotlin's private `assertNoCleartext`.
func assertNoCleartextSentinel(t *testing.T, r query.QueryResponse, cleartext string) {
	t.Helper()
	for _, row := range r.Rows {
		for _, cell := range row {
			if cell != nil && strings.Contains(*cell, cleartext) {
				t.Fatalf("cleartext sentinel leaked in %v", r.Rows)
			}
		}
	}
}

// flatten is `response.rows.flatten()`.
func flatten(r query.QueryResponse) []*string {
	var out []*string
	for _, row := range r.Rows {
		out = append(out, row...)
	}
	return out
}

func containsValue(r query.QueryResponse, want string) bool {
	for _, cell := range flatten(r) {
		if cell != nil && *cell == want {
			return true
		}
	}
	return false
}

func containsSubstring(r query.QueryResponse, want string) bool {
	for _, cell := range flatten(r) {
		if cell != nil && strings.Contains(*cell, want) {
			return true
		}
	}
	return false
}

// ---- abstract class SchemaThreadingDbContract (:357) — 8 cases, run per engine -----------------
//
// The Kotlin's contract is ABSTRACT: it has no fixture of its own and never runs on its own. The two
// concrete classes inherit it, so each of these 8 cases runs exactly twice — once per engine, inside
// the leaf class's own fixture. Go has no inheritance, so the contract is a function the two leaf test
// functions call; running it a third time from a `TestSchemaThreadingContract` of its own would be a
// duplicate the Kotlin does not have (and a third pair of containers to pay for).

func runSchemaThreadingContract(t *testing.T, fx *schemaThreadingFixture) {
	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.explicit default schema masks while explicit analytics stays unmasked
	// 1. `explicit default schema masks while explicit analytics stays unmasked`
	fx.subtest(t, "explicit default schema masks while explicit analytics stays unmasked", func(t *testing.T) {
		protected := fx.run("select id, rrn from " + fx.defaultTable() + " order by id")
		if action(protected) != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", action(protected), respReason(protected))
		}
		if len(protected.Rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(protected.Rows))
		}
		assertNoCleartextSentinel(t, protected, fx.defaultRRN)

		analytics := fx.run("select id, rrn from " + fx.analyticsTable() + " order by id")
		if action(analytics) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(analytics), respReason(analytics))
		}
		if len(analytics.Rows) != 1 {
			t.Fatalf("analytics rows = %d, want 1", len(analytics.Rows))
		}
		got := analytics.Rows[0][1]
		if got == nil || *got != fx.analyticsRRN {
			t.Fatalf("analytics rrn = %s, want %q", dbtest.Cell(got), fx.analyticsRRN)
		}
		if *got == fx.defaultRRN {
			t.Fatal("the analytics read returned the DEFAULT namespace's sentinel")
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.bare users resolves to the captured default namespace and masks
	// 2. `bare users resolves to the captured default namespace and masks`
	fx.subtest(t, "bare users resolves to the captured default namespace and masks", func(t *testing.T) {
		r := fx.run("select rrn from users")
		if action(r) != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", action(r), respReason(r))
		}
		assertNoCleartextSentinel(t, r, fx.defaultRRN)
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.unknown table schema and foreign catalog deny without rows
	// 3. 🔒 `unknown table schema and foreign catalog deny without rows`
	fx.subtest(t, "unknown table schema and foreign catalog deny without rows", func(t *testing.T) {
		for _, q := range []string{
			"select rrn from missing_users",
			"select rrn from missing_schema.users",
			"select rrn from foreign_catalog." + fx.defaultSchema + ".users",
		} {
			r := fx.run(q)
			assertDenied(t, r, "must fail closed: "+q)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.qualified star preserves schema-specific classification
	// 4. `qualified star preserves schema-specific classification`
	fx.subtest(t, "qualified star preserves schema-specific classification", func(t *testing.T) {
		protected := fx.run("select u.* from " + fx.defaultTable() + " u")
		if action(protected) != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", action(protected), respReason(protected))
		}
		assertNoCleartextSentinel(t, protected, fx.defaultRRN)

		analytics := fx.run("select u.* from " + fx.analyticsTable() + " u")
		if action(analytics) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(analytics), respReason(analytics))
		}
		if !containsValue(analytics, fx.analyticsRRN) {
			t.Fatalf("analytics sentinel was not returned unchanged: %v", analytics.Rows)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.whole-row JSON cannot bypass default PII and analytics does not inherit it
	// 5. 🔒 `whole-row JSON cannot bypass default PII and analytics does not inherit it`
	fx.subtest(t, "whole-row JSON cannot bypass default PII and analytics does not inherit it", func(t *testing.T) {
		protected := fx.run(fx.rowJSON(fx.defaultTable()))
		if action(protected) != pb.EnfAction_DENY {
			t.Fatalf("whole-row PII is not field-maskable: decision = %v reason=%s",
				action(protected), respReason(protected))
		}
		assertReasonContains(t, protected, "rrn")
		assertNoCleartextSentinel(t, protected, fx.defaultRRN)

		analytics := fx.run(fx.rowJSON(fx.analyticsTable()))
		if action(analytics) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(analytics), respReason(analytics))
		}
		if !containsSubstring(analytics, fx.analyticsRRN) {
			t.Fatalf("analytics whole-row JSON did not carry its sentinel: %v", analytics.Rows)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.alias or composite resolution keeps the physical schema identity
	// 6. `alias or composite resolution keeps the physical schema identity`
	fx.subtest(t, "alias or composite resolution keeps the physical schema identity", func(t *testing.T) {
		protected := fx.run(fx.aliasOrComposite(fx.defaultTable()))
		if a := action(protected); a != pb.EnfAction_MASK && a != pb.EnfAction_DENY {
			t.Fatalf("default alias/composite read must be protected; decision = %v reason=%s",
				a, respReason(protected))
		}
		if action(protected) == pb.EnfAction_DENY {
			assertReasonContains(t, protected, "rrn")
		}
		assertNoCleartextSentinel(t, protected, fx.defaultRRN)

		analytics := fx.run(fx.aliasOrComposite(fx.analyticsTable()))
		if action(analytics) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(analytics), respReason(analytics))
		}
		if len(analytics.Rows) != 1 || len(analytics.Rows[0]) != 1 {
			t.Fatalf("analytics rows = %v, want exactly one single-column row", analytics.Rows)
		}
		if got := analytics.Rows[0][0]; got == nil || *got != fx.analyticsRRN {
			t.Fatalf("analytics alias read = %s, want %q", dbtest.Cell(got), fx.analyticsRRN)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.protected bare-target update is valid and mutating on the backend but enforcement denies it
	// 7. 🔒 `protected bare-target update is valid and mutating on the backend but enforcement denies it`
	fx.subtest(t, "protected bare-target update is valid and mutating on the backend but enforcement denies it", func(t *testing.T) {
		stmt := fx.protectedUpdateSQL()
		fx.executeRolledBack(stmt, fx.defaultTable(), fx.defaultRRN, fx.defaultRRN+"-blocked")

		d := fx.decide(stmt)
		if d.Action != pb.EnfAction_DENY {
			t.Fatalf("protected UPDATE was admitted: %s", stmt)
		}
		if !strings.Contains(reason(d), "rrn") {
			t.Errorf("deny reason did not identify the protected read: %s", reason(d))
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingDbContract.explicit analytics update is allowed executes and rolls back without persistence
	// 8. `explicit analytics update is allowed executes and rolls back without persistence`
	fx.subtest(t, "explicit analytics update is allowed executes and rolls back without persistence", func(t *testing.T) {
		original := fx.analyticsUpdateSQL()
		d := fx.decide(original)
		if d.Action != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", d.Action, reason(d))
		}
		executable := original
		if d.RewrittenSQL != nil {
			executable = *d.RewrittenSQL
		}
		fx.executeRolledBack(executable, fx.analyticsTable(), fx.analyticsRRN, fx.analyticsRRN+"-allowed")
	})
}

// ---- class SchemaThreadingPostgresDbTest (:471) — the contract + 6 more ------------------------

func TestSchemaThreadingPostgresDb(t *testing.T) {
	fx := newSchemaThreadingPostgres(t)

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.live search path pivots unqualified resolution without changing the default
	// 9. `live search path pivots unqualified resolution without changing the default`
	fx.subtest(t, "live search path pivots unqualified resolution without changing the default", func(t *testing.T) {
		def := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", nil)
		if def.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", def.Action, reason(def))
		}

		analytics := []string{"analytics"}
		a := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &analytics)
		if a.Action != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", a.Action, reason(a))
		}
		if len(a.Masks) != 0 {
			t.Errorf("masks = %d, want none — analytics.users.rrn carries no classification", len(a.Masks))
		}

		public := []string{"public"}
		p := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &public)
		if p.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", p.Action, reason(p))
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.invalid or unresolvable live search paths fail closed
	// 10. 🔒 `invalid or unresolvable live search paths fail closed`
	fx.subtest(t, "invalid or unresolvable live search paths fail closed", func(t *testing.T) {
		empty := []string{}
		e := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &empty)
		if e.Action != pb.EnfAction_DENY {
			t.Fatalf("empty live search path: decision = %v, want DENY", e.Action)
		}
		if stage(e) != "catalog" {
			t.Errorf("failedStage = %q, want %q", stage(e), "catalog")
		}

		blank := []string{" "}
		b := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &blank)
		if b.Action != pb.EnfAction_DENY {
			t.Fatalf("blank live search path: decision = %v, want DENY", b.Action)
		}
		if stage(b) != "catalog" {
			t.Errorf("failedStage = %q, want %q", stage(b), "catalog")
		}

		unknown := []string{"no_such_schema"}
		u := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &unknown)
		if u.Action != pb.EnfAction_DENY {
			t.Fatalf("unknown live search path: decision = %v, want DENY", u.Action)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.missing pg-temp catalog entry skips to the next live search path schema
	// 11. `missing pg-temp catalog entry skips to the next live search path schema`
	fx.subtest(t, "missing pg-temp catalog entry skips to the next live search path schema", func(t *testing.T) {
		path := []string{"pg_temp_3", "public"}
		d := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &path)
		if d.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", d.Action, reason(d))
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.decideAndAudit threads and audits the live search path
	// 12. `decideAndAudit threads and audits the live search path`
	fx.subtest(t, "decideAndAudit threads and audits the live search path", func(t *testing.T) {
		analyticsSQL := "SELECT rrn FROM users /* route_analytics */"
		analyticsPath := []string{"analytics"}
		analyticsDecision, _ := fx.decideAndAudit(schemaReaderPrincipal, analyticsSQL, &analyticsPath, nil)
		if analyticsDecision.Action != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", analyticsDecision.Action, reason(analyticsDecision))
		}
		if got := fx.auditFor(analyticsSQL).EffectiveNamespace; len(got) != 1 || got[0] != "analytics" {
			t.Errorf("audited effectiveNamespace = %v, want [analytics]", got)
		}

		defaultSQL := "SELECT rrn FROM users /* route_default */"
		defaultDecision, _ := fx.decideAndAudit(schemaReaderPrincipal, defaultSQL, nil, nil)
		if defaultDecision.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", defaultDecision.Action, reason(defaultDecision))
		}
		want := fx.fx.DatasourceRow.DefaultSchemas
		if got := fx.auditFor(defaultSQL).EffectiveNamespace; !equalStrings(got, want) {
			t.Errorf("audited effectiveNamespace = %v, want the datasource default %v", got, want)
		}

		emptySQL := "SELECT rrn FROM users /* route_empty */"
		emptyPath := []string{}
		emptyDecision, _ := fx.decideAndAudit(schemaReaderPrincipal, emptySQL, &emptyPath, nil)
		if emptyDecision.Action != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", emptyDecision.Action)
		}
		emptyAudit := fx.auditFor(emptySQL)
		if emptyAudit.FailedStage == nil || *emptyAudit.FailedStage != "catalog" {
			t.Errorf("audited failedStage = %v, want catalog", emptyAudit.FailedStage)
		}
		if len(emptyAudit.EffectiveNamespace) != 0 {
			t.Errorf("audited effectiveNamespace = %v, want empty", emptyAudit.EffectiveNamespace)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.relation-valued update returning cannot disclose protected rrn
	// 13. 🔒 `relation-valued update returning cannot disclose protected rrn`
	fx.subtest(t, "relation-valued update returning cannot disclose protected rrn", func(t *testing.T) {
		// The target has a scalar `region` column, so use a non-colliding alias to exercise relation lookup.
		stmt := "update " + fx.analyticsTable() + " as target\n" +
			"set rrn = ((source_row).sub).rrn\n" +
			"from (select users as sub from users) as source_row\n" +
			"where target.id = 1\n" +
			"returning ((source_row).sub).rrn"

		// First prove the statement really discloses the protected value on the backend — otherwise the
		// DENY below would be indistinguishable from denying a statement that never worked.
		tx, err := fx.fx.Target.Begin()
		if err != nil {
			t.Fatalf("begin target transaction: %v", err)
		}
		func() {
			defer func() { _ = tx.Rollback() }()
			var returned string
			if err := tx.QueryRow(stmt).Scan(&returned); err != nil {
				t.Fatalf("UPDATE RETURNING did not expose the mutated row: %v", err)
			}
			if returned != fx.defaultRRN {
				t.Fatalf("UPDATE RETURNING did not expose the protected value: %q", returned)
			}
			if got := readRRN(t, tx, fx.analyticsTable()); got != fx.defaultRRN {
				t.Fatalf("the backend did not persist the protected value in the transaction: %q", got)
			}
		}()
		if got := readRRN(t, fx.fx.Target, fx.analyticsTable()); got != fx.analyticsRRN {
			t.Fatalf("the test UPDATE escaped its rollback: %q", got)
		}

		d := fx.decide(stmt)
		if d.Action != pb.EnfAction_DENY {
			t.Fatalf("relation-valued UPDATE RETURNING was admitted: %s", stmt)
		}
		if !strings.Contains(reason(d), "rrn") {
			t.Errorf("deny reason did not identify rrn: %s", reason(d))
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingPostgresDbTest.system catalogs are introspected as first-class resources, not shadowed
	// 14. `system catalogs are introspected as first-class resources, not shadowed`
	fx.subtest(t, "system catalogs are introspected as first-class resources, not shadowed", func(t *testing.T) {
		// pg_catalog is on the effective search path, so excluding it from the mapping makes a bare name
		// the backend binds there fall through to a user schema (shadow leak). System schemas must be
		// introspected — this assertion fails if the NOT IN (...) exclusion is re-added.
		schemas := map[string]bool{}
		for _, c := range fx.fx.CatalogRows() {
			schemas[c.Schema] = true
		}
		if !schemas["pg_catalog"] {
			t.Errorf("pg_catalog was excluded from introspection (shadowing): %v", keys(schemas))
		}
		if !schemas["information_schema"] {
			t.Errorf("information_schema was excluded from introspection: %v", keys(schemas))
		}
		// A bare reference to a pg_catalog table resolves THERE (pg_catalog is implicit-first) and is
		// deny-by-default — never a user-schema shadow, never unresolved.
		bare := fx.run("select rolname from pg_authid")
		assertDenied(t, bare, "bare pg_catalog name must resolve to pg_catalog + deny")
	})

	// The contract's 8, on PostgreSQL. Kept LAST so the six above do not pay for the writes case 7 and
	// case 8 roll back.
	runSchemaThreadingContract(t, fx)
}

// ---- class SchemaThreadingMysqlDbTest (:623) — the contract + 3 more ---------------------------

func TestSchemaThreadingMysqlDb(t *testing.T) {
	fx := newSchemaThreadingMySQL(t)

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingMysqlDbTest.live current database pivots unqualified resolution without changing the default
	// 15. `live current database pivots unqualified resolution without changing the default`
	fx.subtest(t, "live current database pivots unqualified resolution without changing the default", func(t *testing.T) {
		def := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", nil)
		if def.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", def.Action, reason(def))
		}

		analytics := []string{fx.analyticsSchema}
		a := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &analytics)
		if a.Action != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", a.Action, reason(a))
		}
		if len(a.Masks) != 0 {
			t.Errorf("masks = %d, want none", len(a.Masks))
		}

		original := []string{fx.defaultSchema}
		o := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &original)
		if o.Action != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", o.Action, reason(o))
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingMysqlDbTest.invalid or unresolvable live current databases fail closed
	// 16. 🔒 `invalid or unresolvable live current databases fail closed`
	fx.subtest(t, "invalid or unresolvable live current databases fail closed", func(t *testing.T) {
		empty := []string{}
		e := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &empty)
		if e.Action != pb.EnfAction_DENY {
			t.Fatalf("empty live current database: decision = %v, want DENY", e.Action)
		}
		if stage(e) != "catalog" {
			t.Errorf("failedStage = %q, want %q", stage(e), "catalog")
		}

		blank := []string{" "}
		b := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &blank)
		if b.Action != pb.EnfAction_DENY {
			t.Fatalf("blank live current database: decision = %v, want DENY", b.Action)
		}
		if stage(b) != "catalog" {
			t.Errorf("failedStage = %q, want %q", stage(b), "catalog")
		}

		unknown := []string{"no_such_db"}
		u := fx.decideAs(schemaReaderPrincipal, "SELECT rrn FROM users", &unknown)
		if u.Action != pb.EnfAction_DENY {
			t.Fatalf("unknown live current database: decision = %v, want DENY", u.Action)
		}
	})

	// KT: SchemaThreadingDbTest.kt#SchemaThreadingMysqlDbTest.lctn=0 CTE output-column write cannot smuggle masked rrn
	// 17. 🔒 `lctn=0 CTE output-column write cannot smuggle masked rrn`
	fx.subtest(t, "lctn=0 CTE output-column write cannot smuggle masked rrn", func(t *testing.T) {
		// Under lower_case_table_names=0 MySQL still resolves column and column-alias names
		// case-insensitively (lctn governs only table/db names), so a CTE's explicit output-column name
		// binds its consumer regardless of case. A fold that lowercased column REFERENCES but never the
		// CTE output-column LIST would resolve the write's payload to NO base column → empty lineage →
		// the write reading the masked default users.rrn ALLOWed (fail-open; live-verified on MySQL 8.4
		// lctn=0: the INSERT copies users.rrn verbatim). sqlglot-go's role-aware strategy folds the
		// output-column list, so the write's lineage carries the masked rrn and enforcement DENIES.
		// Guard the mode: the leak is mode-0-specific (lctn=1/2 folded everything already).
		var lctn int
		if err := fx.fx.Target.QueryRow("select @@lower_case_table_names").Scan(&lctn); err != nil {
			t.Fatalf("read @@lower_case_table_names: %v", err)
		}
		if lctn != 0 {
			t.Fatalf("this regression must exercise lower_case_table_names=0, got %d", lctn)
		}

		stmt := "insert into " + fx.analyticsTable() + " (id, email, rrn, region) " +
			"with cte (Secret) as (select rrn from " + fx.defaultTable() + ") " +
			"select 999, 'sink@example.com', secret, 'KR' from cte"
		d := fx.decide(stmt)
		if d.Action != pb.EnfAction_DENY {
			t.Fatalf("CTE output-column write smuggled masked rrn: decision = %v reason=%s",
				d.Action, reason(d))
		}
		if !strings.Contains(reason(d), "rrn") {
			t.Errorf("deny did not trace the masked rrn: %s", reason(d))
		}
	})

	// The contract's 8, on MySQL — the correctness bar (AGENTS.md:17-26).
	runSchemaThreadingContract(t, fx)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
