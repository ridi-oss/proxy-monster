package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// The fixture's fixed identities and values, from EnforcementFixture.kt:162-163 and :142.
const (
	// FixtureRole is the role the fixture's default principal holds.
	FixtureRole = "analyst"
	// FixturePrincipal is the principal seedPolicy grants FixtureRole to via a DIRECT principal_role
	// assignment. Role resolution is entirely server-side, never a client-asserted list.
	FixturePrincipal = "analyst@example.com"
	// FixtureNoConnectPrincipal holds sql.select + result.read.unmasked but NOT datasource.connect.
	FixtureNoConnectPrincipal = "reader@example.com"
	// FixtureDDLPrincipal holds datasource.connect + sql.ddl plus the users unmasked/masked-pii pair.
	FixtureDDLPrincipal = "writer@example.com"
	// FixtureInsertPrincipal holds datasource.connect + sql.insert but NOT sql.update.
	FixtureInsertPrincipal = "inserter@example.com"
)

// FixtureCleartextRRN are the two cleartext `users.rrn` values the target is seeded with, so a suite
// can assert that a masked read does NOT contain them. EnforcementFixture.kt:163.
var FixtureCleartextRRN = []string{"900101-1234567", "850202-2345678"}

// EnforcementFixture is a fully wired enforcement stack against real databases: a migrated PostgreSQL
// control-plane store plus a seeded target (PostgreSQL or MySQL) whose `users.rrn` is tagged pii and
// carries a last4 mask, with Cedar policies granting `analyst` cleartext on `users` EXCEPT pii (masked
// instead) — the "read table except pii" pattern (docs/authz-model.md).
//
// The target also has an UNGRANTED `orders` table (no Cedar grant covers it) so deny-by-default is
// provable end to end: a query touching it must DENY, never fall through to cleartext.
//
// Port of EnforcementFixture.kt:119-389.
//
// # What is wired, and what is not
//
// Wired for real, against the database: the store, the catalog, the classifications, the roles, the
// Cedar policy rows, a real [authz.CedarEngine] over those rows, and a real [authz.Authz] over a
// server-side role source. A suite can therefore drive the authorization half today.
//
// ✅ Wired as of A6: [EnforcementFixture.Decide], [EnforcementFixture.DecisionRecord] and
// [EnforcementFixture.Run] — the decide → execute → mask composition of EnforcementHarness.kt:106-169
// — in enforcement_run.go. They call the PRODUCTION query.DecideQuery and query.DecisionRecord
// directly, which is the ONLY reason the audit rows these suites assert on are the audit rows
// production writes. A harness that re-derives the record proves the harness agrees with itself and
// nothing else.
//
// The execution half needs no porting: [ExecOnTarget] over [EnforcementFixture.Target].
type EnforcementFixture struct {
	T testing.TB

	// Store is the migrated control-plane store — the analogue of the Kotlin fixture's `meta`
	// DataSource plus the ~9 stores hanging off it.
	Store *store.Db
	// Seed writes control-plane rows. Held so a suite can add to the fixture's seeding.
	Seed *Seed

	// Backend is the shared container the TARGET lives in.
	Backend Backend
	// Target is the target handle the TEST owns (container credentials). The control plane does not
	// store or dial these — it holds no service credentials — so ALLOW'd queries run here.
	Target *sql.DB

	// DatasourceID, DatasourceName, Engine, DBName, Catalog and Schema describe the seeded datasource.
	// Catalog and Schema are the analyzer's namespace segments (Engines.kt:50-63): MySQL pins the
	// catalog to "def" and takes the database as the schema; PostgreSQL takes the database as the
	// catalog and "public" as the schema.
	DatasourceID   int64
	DatasourceName string
	Engine         string
	DBName         string
	Catalog        string
	Schema         string

	// PolicyStore feeds the Cedar engine from the `policy` table. TODO(A2): replace with the
	// production CedarPolicyStore.
	PolicyStore *DBPolicyStore
	// RoleSource resolves roles server-side. TODO(A3): replace with the production RoleResolver.
	RoleSource authz.RoleSource
	// CedarEngine and Authz are the real production types, built over the two seams above.
	CedarEngine *authz.CedarEngine
	Authz       *authz.Authz

	// DatasourceStore and DatasourceRow are the PRODUCTION store and the row it reads back after
	// seeding — the analogue of the Kotlin fixture's `datasourceStore` / `datasource`. The row is
	// re-read (rather than reusing the create result) because IntrospectTargetInto writes the
	// namespace metadata — default_schemas, mysql_lower_case_table_names, engine_version — onto it
	// afterwards, and decideQuery reads all three.
	DatasourceStore *datasource.DatasourceStore
	DatasourceRow   datasource.Datasource

	// MaskFns, UserGroups and RoleResolver are A6's three store seams (see internal/query's doc.go on
	// why they are structural). They default to direct reads here — TODO(A9)/TODO(A3), see
	// [NewDBMaskFnLister] — and a suite that can import the production package should OVERWRITE the
	// field rather than grow the default.
	MaskFns      query.MaskFnLister
	UserGroups   query.UserGroupStore
	RoleResolver query.RoleResolver
}

// SetTags writes the datasource's posture tags and RE-READS the row, so the next Decide runs under
// them. It is the Go form of the gate suites' `setTags(tagsJson)` plus the
// `fx.datasourceStore.get(fx.datasource.id)!!` re-fetch every one of them performs on the next line.
//
// 🔒 The re-read is the load-bearing half, and skipping it is a silent no-op rather than a failure:
// [EnforcementFixture.DecideWith] passes DatasourceRow, so a suite that wrote tags but kept a stale
// row would decide under the OLD posture and its dev-relaxation assertions would still "pass" for
// the wrong reason. Kotlin's suites re-fetch inside `decide()` for exactly this reason.
func (f *EnforcementFixture) SetTags(tags ...string) {
	f.T.Helper()
	f.Seed.DatasourceTags(f.DatasourceID, tags)
	f.ReloadDatasource()
}

// SetEngineVersion writes `datasource.engine_version` and re-reads the row — the gate suites'
// `setEngineVersion(v)`. nil is the "version unreported" posture: no manifest governs, system
// schemas stay deny-by-default, and A6's step 13 hard-denies every utility.
func (f *EnforcementFixture) SetEngineVersion(version *string) {
	f.T.Helper()
	f.Seed.EngineVersion(f.DatasourceID, version)
	f.ReloadDatasource()
}

// ReloadDatasource re-reads [EnforcementFixture.DatasourceRow] through the PRODUCTION store, after
// something changed the row. See [EnforcementFixture.SetTags] on why this is not optional.
func (f *EnforcementFixture) ReloadDatasource() {
	f.T.Helper()
	row, found, err := f.DatasourceStore.Get(context.Background(), f.DatasourceID)
	if err != nil || !found {
		f.T.Fatalf("re-read datasource %d: found=%v err=%v", f.DatasourceID, found, err)
	}
	f.DatasourceRow = row
}

// AddCedarPolicy seeds an enabled USER-origin Cedar policy AND bumps the policy store's state
// version, so the already-built [authz.CedarEngine] rebuilds its cached policy set on the next
// authorize. It is the Go form of `fx.cedarPolicyStore.create(CedarPolicyInput(...), updatedBy)`.
//
// 🔒 The Bump is mandatory and its absence is invisible: CedarEngine caches its PolicySet and rebuilds
// only when StateVersion moves (INV-A2-19), so a suite that seeded a `sql.unanalyzable` permit without
// bumping would keep serving the PRE-permit policy set and its "then the permit relays it" assertion
// would fail as a floor DENY — or, worse, a suite asserting a permit does NOT apply would pass
// vacuously. In production the bump happens because the write goes through CedarPolicyStore.
//
// ⚠️ TODO(A2): re-point at the production CedarPolicyStore.create when A2's store half lands. It owns
// validate-on-write, the origin guards under a row lock and the SYSTEM-toggle sentinel audit row —
// none of which a fixture may reimplement, and all of which this bypasses today.
func (f *EnforcementFixture) AddCedarPolicy(name, cedarSrc string) {
	f.T.Helper()
	f.Seed.CedarPolicy(name, cedarSrc)
	f.PolicyStore.Bump()
}

// UsersTableEUID is the Cedar `Table::"…"` entity id for the fixture's users table:
// `<datasource>/<catalog>/<schema>/users` (EnforcementFixture.kt:196).
func (f *EnforcementFixture) UsersTableEUID() string { return f.TableEUID("users") }

// TableEUID builds the Cedar Table entity id for a table in the fixture's default schema.
func (f *EnforcementFixture) TableEUID(table string) string {
	return fmt.Sprintf("%s/%s/%s/%s", f.DatasourceName, f.Catalog, f.Schema, table)
}

// ExecOnTarget runs raw SQL directly against the target — test setup/teardown, no enforcement gate.
// Port of EnforcementFixture.kt:159.
func (f *EnforcementFixture) ExecOnTarget(query string) QueryRows {
	f.T.Helper()
	rows, err := ExecOnTarget(f.Target, query, 1000)
	if err != nil {
		f.T.Fatalf("target query failed: %v", err)
	}
	return rows
}

// NewEnforcementFixture builds the fixture against the given target engine (EnginePostgres or
// EngineMySQL) — the two Kotlin factories EnforcementFixture.postgres() and .mysql(), which differ
// only in which container the target lives in and in the datasource name.
//
// ⚠️ One deliberate divergence: the MySQL target gets a FRESH database (SharedMySql.freshDatabase),
// where EnforcementFixture.kt:337 reuses the container's shared `test` database and DROPs its tables
// first. The Kotlin shape means two MySQL enforcement suites running in the same JVM interfere by
// construction; `go test` runs package binaries in parallel by default, so reproducing it would make
// the suite flaky rather than faithful. The DROP TABLE IF EXISTS statements are kept anyway — they
// cost nothing and they keep the seed identical if the database is ever shared again.
func NewEnforcementFixture(t testing.TB, engine string) *EnforcementFixture {
	t.Helper()

	metaStore, _ := MigratedStore(t)
	seed := NewSeed(t, metaStore)

	var (
		backend  Backend
		targetDB string
		dsName   string
	)
	switch engine {
	case EnginePostgres:
		backend = Postgres(t)
		targetDB = FreshPostgresDatabase(t, "pm_target")
		dsName = "target-pg"
	case EngineMySQL:
		backend = MySQL(t)
		targetDB = FreshMySQLDatabase(t, "pm_target")
		dsName = "target-mysql"
	default:
		t.Fatalf("unknown engine %q", engine)
	}

	target := OpenTarget(t, backend, targetDB)
	seedTargetTables(t, target)

	dsID := seed.Datasource(DatasourceSpec{
		Name:   dsName,
		Engine: engine,
		Host:   backend.Host,
		Port:   backend.Port,
		DBName: targetDB,
	})
	// pushTestCatalog's Go twin: introspect the target the TEST owns and store the result, exactly as
	// the proxy pushes it. It also captures the static namespace metadata onto the datasource row,
	// which is why the Kotlin re-reads the datasource afterwards rather than reusing create()'s result.
	seed.IntrospectTargetInto(dsID, engine, target, targetDB)

	f := &EnforcementFixture{
		T:              t,
		Store:          metaStore,
		Seed:           seed,
		Backend:        backend,
		Target:         target,
		DatasourceID:   dsID,
		DatasourceName: dsName,
		Engine:         engine,
		DBName:         targetDB,
		Catalog:        catalogName(engine, targetDB),
		Schema:         defaultSchema(engine, targetDB),
	}
	f.seedPolicy()

	// Built AFTER seedPolicy has run, so correctness never depends on cache invalidation: the engine's
	// first Authorize builds its cached PolicySet from the already-seeded EnabledSources at the
	// post-seed state version, and no Cedar mutation happens during a run (EnforcementFixture.kt:372-376).
	f.PolicyStore = NewDBPolicyStore(t, metaStore.Pool)
	f.RoleSource = NewDBRoleSource(t, metaStore.Pool)
	engineInstance, err := authz.NewCedarEngine(f.PolicyStore)
	if err != nil {
		t.Fatalf("build Cedar engine over the seeded policies: %v", err)
	}
	f.CedarEngine = engineInstance
	f.Authz = authz.New(engineInstance, f.PolicyStore, f.RoleSource)

	// The production datasource store, and the row AFTER IntrospectTargetInto stamped the namespace
	// metadata onto it — the same re-read the Kotlin fixture performs for the same reason.
	f.DatasourceStore = datasource.NewDatasourceStore(metaStore)
	row, found, err := f.DatasourceStore.Get(context.Background(), dsID)
	if err != nil || !found {
		t.Fatalf("read back seeded datasource %d: found=%v err=%v", dsID, found, err)
	}
	f.DatasourceRow = row

	// A6's three store seams, at their fixture defaults. See [NewDBMaskFnLister].
	f.MaskFns = NewDBMaskFnLister(t, f)
	f.UserGroups = dbUserGroupStore{f: f}
	f.RoleResolver = dbRoleResolver{f: f}
	return f
}

// catalogName is Engines.kt:50 — the analyzer catalog segment. MySQL pins "def"; Postgres uses the
// database name.
//
// TODO(A5): delete in favour of the production extension once Engines is ported.
func catalogName(engine, dbName string) string {
	if engine == EngineMySQL {
		return "def"
	}
	return dbName
}

// defaultSchema is Engines.kt:61 — the schema an unqualified table lives under. A MySQL "database" IS
// the schema; Postgres defaults to "public".
//
// TODO(A5): delete in favour of the production extension once Engines is ported.
func defaultSchema(engine, dbName string) string {
	if engine == EngineMySQL {
		return dbName
	}
	return "public"
}

// seedTargetTables creates the two fixture tables. `users` carries the pii column every masking
// assertion is about; `orders` is UNGRANTED on purpose — no Cedar grant covers it, so a touched
// column there must resolve to DENIED and never fall through to cleartext
// (EnforcementFixture.kt:317-320).
func seedTargetTables(t testing.TB, target *sql.DB) {
	t.Helper()
	stmts := []string{
		`DROP TABLE IF EXISTS users`,
		`CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(64), rrn VARCHAR(32), region VARCHAR(8))`,
		fmt.Sprintf(`INSERT INTO users VALUES (1,'a@x','%s','KR'),(2,'b@x','%s','KR')`,
			FixtureCleartextRRN[0], FixtureCleartextRRN[1]),
		`DROP TABLE IF EXISTS orders`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, amount BIGINT)`,
		`INSERT INTO orders VALUES (1,100),(2,200)`,
	}
	for _, s := range stmts {
		if _, err := target.Exec(s); err != nil {
			t.Fatalf("seed target (%s): %v", s, err)
		}
	}
}

// seedPolicy is EnforcementFixture.kt:193-308, reproduced statement for statement.
//
// It classifies `users.rrn` as pii + last4-masked, grants `analyst` a direct role assignment, then
// seeds the Cedar "read table except pii" pair (docs/authz-model.md's worked example): cleartext on
// every `users` column NOT tagged pii, masked on the ones that are. Deny-by-default covers everything
// else — a column with no matching grant at all resolves to DENIED, never cleartext, which is what
// `non-sensitive query is allowed` actually proves: `region`/`id` are ungranted BY NAME but covered by
// the table-level permit.
//
// It also seeds the once-per-query `datasource.connect` / `sql.<kind>` gates and three more
// role/principal pairs that prove the gates' ordering and composition. Each is load-bearing; the
// comments say what breaks if one is dropped.
func (f *EnforcementFixture) seedPolicy() {
	f.T.Helper()
	s, ds, users := f.Seed, f.DatasourceName, f.UsersTableEUID()

	maskFnID := s.MaskFn("last4", "LAST_N")
	s.Classify(f.DatasourceID, f.Schema, "users", "rrn", []string{"pii"}, &maskFnID)

	roleID := s.Role(FixtureRole)
	s.AssignRole(FixturePrincipal, roleID)

	s.CedarPolicy("analyst-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`,
		FixtureRole, users))
	// Table-scoped, NOT a blanket `resource in Tag::"pii"`: the masked grant only covers pii columns OF
	// THE users table. A pii column in a table analyst has no grant on (the ungranted `orders`) must
	// therefore be DENIED, not blanket-masked.
	s.CedarPolicy("analyst-users-masked-pii", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.masked", resource in Table::%q) when { resource in Tag::"pii" };`,
		FixtureRole, users))
	s.CedarPolicy("analyst-connect-select", fmt.Sprintf(
		`permit(principal in Role::%q, action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::%q);`,
		FixtureRole, ds))

	// `no-connect-reader` — sql.select + result.read.unmasked on users, but deliberately NO
	// datasource.connect — proves the connect gate runs (and denies) before sql.<kind>/columns.
	noConnectID := s.Role("no-connect-reader")
	s.AssignRole(FixtureNoConnectPrincipal, noConnectID)
	s.CedarPolicy("no-connect-reader-select", fmt.Sprintf(
		`permit(principal in Role::"no-connect-reader", action == Action::"sql.select", resource in Datasource::%q);`, ds))
	s.CedarPolicy("no-connect-reader-unmasked", fmt.Sprintf(
		`permit(principal in Role::"no-connect-reader", action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`, users))

	// `ddl-writer` — datasource.connect + sql.ddl, plus the same users unmasked/masked-pii pair
	// `analyst` has, so a CTAS reading `rrn` resolves it to MASKED and the write-payload rule fires
	// even though sql.ddl itself is granted.
	ddlID := s.Role("ddl-writer")
	s.AssignRole(FixtureDDLPrincipal, ddlID)
	s.CedarPolicy("ddl-writer-connect-ddl", fmt.Sprintf(
		`permit(principal in Role::"ddl-writer", action in [Action::"datasource.connect", Action::"sql.ddl"], resource in Datasource::%q);`, ds))
	s.CedarPolicy("ddl-writer-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::"ddl-writer", action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`, users))
	s.CedarPolicy("ddl-writer-users-masked-pii", fmt.Sprintf(
		`permit(principal in Role::"ddl-writer", action == Action::"result.read.masked", resource in Table::%q) when { resource in Tag::"pii" };`, users))

	// `insert-writer` — datasource.connect + sql.insert (deliberately NO sql.update) + the same users
	// pair — proves an upsert INSERT (ON CONFLICT DO UPDATE / ON DUPLICATE KEY UPDATE) is denied even
	// though sql.insert alone is granted: an upsert can modify an EXISTING row, so admission requires
	// sql.update too.
	insertID := s.Role("insert-writer")
	s.AssignRole(FixtureInsertPrincipal, insertID)
	s.CedarPolicy("insert-writer-connect-insert", fmt.Sprintf(
		`permit(principal in Role::"insert-writer", action in [Action::"datasource.connect", Action::"sql.insert"], resource in Datasource::%q);`, ds))
	s.CedarPolicy("insert-writer-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::"insert-writer", action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`, users))
	s.CedarPolicy("insert-writer-users-masked-pii", fmt.Sprintf(
		`permit(principal in Role::"insert-writer", action == Action::"result.read.masked", resource in Table::%q) when { resource in Tag::"pii" };`, users))
}

// DBPolicyStore satisfies authz.PolicyStore by reading the `policy` table.
//
// TODO(A2): this is a stand-in for CedarPolicyStore's read half, which A2's increment did not include
// (internal/authz/engine.go:26-29 declares the interface and the TODO). Replace it — do not grow it.
// The production store also owns validate-on-write, the origin guards under a row lock and the
// SYSTEM-toggle sentinel audit row, none of which a fixture may reimplement.
type DBPolicyStore struct {
	t    testing.TB
	ctx  context.Context
	pool *pgxpool.Pool

	mu      sync.Mutex
	version int64
}

// NewDBPolicyStore builds a policy store over a migrated control-plane store.
func NewDBPolicyStore(t testing.TB, pool *pgxpool.Pool) *DBPolicyStore {
	return &DBPolicyStore{t: t, ctx: context.Background(), pool: pool}
}

// EnabledSources returns (id, cedar_src) for enabled = true, ORDER BY id — the stable order
// CedarEngine's policy-set build depends on.
func (p *DBPolicyStore) EnabledSources() []authz.PolicySource {
	p.t.Helper()
	rows, err := p.pool.Query(p.ctx, `SELECT id, cedar_src FROM policy WHERE enabled = TRUE ORDER BY id`)
	if err != nil {
		p.t.Fatalf("read enabled policies: %v", err)
	}
	defer rows.Close()

	var out []authz.PolicySource
	for rows.Next() {
		var src authz.PolicySource
		if err := rows.Scan(&src.ID, &src.Src); err != nil {
			p.t.Fatalf("read enabled policies: %v", err)
		}
		out = append(out, src)
	}
	if err := rows.Err(); err != nil {
		p.t.Fatalf("read enabled policies: %v", err)
	}
	return out
}

// StateVersion is bumped only AFTER a mutation commits (INV-A2-19). A fixture that seeds or toggles a
// policy AFTER the engine was built must call [DBPolicyStore.Bump], or the engine keeps serving its
// cached policy set — which is the production behaviour, not a fixture bug.
func (p *DBPolicyStore) StateVersion() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Bump advances the state version, invalidating the Cedar engine's cached policy set.
func (p *DBPolicyStore) Bump() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version++
}

// NewDBRoleSource resolves a principal's roles server-side from the control-plane store.
//
// 🔒 TODO(A3): this covers `principal_role` ∪ `group_role` (through `group_member`) only. The
// production RoleResolver.resolve ALSO unions active JIT grants and, crucially, SHORT-CIRCUITS TO THE
// EMPTY SET when the principal is deactivated — fail-closed across all role sources
// (RoleResolver.kt:45-54). Replace this with RoleResolver when A3 lands; do not add the missing arms
// here. A fixture that grows its own role resolution becomes a second source of truth for the one
// question authorization is about, and the two will disagree exactly where it matters.
func NewDBRoleSource(t testing.TB, pool *pgxpool.Pool) authz.RoleSource {
	ctx := context.Background()
	return authz.RoleSourceFunc(func(principal string) []string {
		t.Helper()
		rows, err := pool.Query(ctx,
			`SELECT r.name FROM principal_role pr JOIN app_role r ON r.id = pr.role_id
			  WHERE pr.principal = $1
			  UNION
			 SELECT r.name FROM app_user u
			   JOIN group_member gm ON gm.user_id = u.id
			   JOIN group_role gr ON gr.group_id = gm.group_id
			   JOIN app_role r ON r.id = gr.role_id
			  WHERE u.principal = $1`, principal)
		if err != nil {
			t.Fatalf("resolve roles for %s: %v", principal, err)
		}
		defer rows.Close()

		var out []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("resolve roles for %s: %v", principal, err)
			}
			out = append(out, name)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("resolve roles for %s: %v", principal, err)
		}
		return out
	})
}
