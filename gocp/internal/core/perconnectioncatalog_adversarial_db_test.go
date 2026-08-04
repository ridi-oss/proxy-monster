package core_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// PerConnectionCatalogAdversarialDbTest.kt — its three CONTRACT cases, the ones both engines run.
//
// The five engine-specific cases of that file (three MySQL, two PostgreSQL) are NOT here; see
// PerConnectionCatalogAdversarialDbTest's row in the port ledger. This file covers the contract, whose
// subject is the freshness/generation machinery rather than any one engine's DDL semantics:
//
//  1. an after-statement refetch that the proxy IGNORES blocks the next decision, and the block writes
//     NO audit row (🔒 INV-A5-49);
//  2. an `unchanged: true` reply quiets EXACTLY ONE authoritative version, and the next one re-gates
//     (🔒 INV-A5-37 rule 3 — the reason HeldSchema carries
//     RevalidatedAgainstAuthoritativeHash rather than a boolean);
//  3. closing a MUTATED connection cannot change a sibling's verdict.
//
// The Kotlin's `configureFlagship()` per-engine setup is reproduced only as far as the contract needs
// it: the two Cedar permits that let `analyst` run DDL and let `ddl-writer` run SELECT. The `accounts`
// table and the stored procedure exist only for the engine-specific cases.

// adversarialFixture is the contract's fixture plus the flagship permits the contract cases need.
func newAdversarialFixture(t *testing.T, engine string) *perConnCatalogFixture {
	t.Helper()
	fx := newPerConnCatalogFixture(t, engine)
	ds := fx.datasource.Name
	// `pccat-<engine>-analyst-ddl` — cases 2 and 3 have the ANALYST run CREATE TABLE.
	fx.enforcement.AddCedarPolicy("pccat-analyst-ddl", fmt.Sprintf(
		`permit(principal in Role::"%s", action == Action::"sql.ddl", resource in Datasource::%q);`,
		dbtest.FixtureRole, ds))
	// `pccat-<engine>-analyst-unanalyzable`. The Kotlin's reason, verbatim: "A bare `DROP TABLE` is
	// unanalyzable (no lineage for the DDL), so it relays only under a sql.unanalyzable permit — the
	// legitimate authorization these catalog-freshness tests exercise." A bare `CREATE TABLE (id BIGINT)`
	// is the same class: measured, its deny without this permit is `fail-closed: could not analyze
	// (validate)`, i.e. the fail-closed gate rather than a policy deny.
	fx.enforcement.AddCedarPolicy("pccat-analyst-unanalyzable", fmt.Sprintf(
		`permit(principal in Role::"%s", action == Action::"sql.unanalyzable", resource in Datasource::%q);`,
		dbtest.FixtureRole, ds))
	// `pccat-<engine>-writer-select` — case 1 has the DDL WRITER run a SELECT afterwards.
	fx.enforcement.AddCedarPolicy("pccat-writer-select", fmt.Sprintf(
		`permit(principal in Role::"ddl-writer", action == Action::"sql.select", resource in Datasource::%q);`, ds))
	return fx
}

// userSchema is the contract's `userSchema()`: MySQL's database, or PostgreSQL's first NON-system
// default schema.
func (f *perConnCatalogFixture) userSchema() string {
	f.t.Helper()
	if f.enforcement.Engine == dbtest.EngineMySQL {
		return f.datasource.DBName
	}
	for _, s := range f.datasource.DefaultSchemas {
		system, err := datasource.IsSystemSchema(f.datasource.Engine, s)
		if err != nil {
			f.t.Fatalf("IsSystemSchema(%q): %v", s, err)
		}
		if !system {
			return s
		}
	}
	f.t.Fatal("no non-system default schema")
	return ""
}

// qualified is the contract's `qualified(schema, table)`.
func (f *perConnCatalogFixture) qualified(schema, table string) string {
	if f.enforcement.Engine == dbtest.EngineMySQL {
		return "`" + schema + "`.`" + table + "`"
	}
	return `"` + schema + `"."` + table + `"`
}

// auditCount is the contract's `auditCount()`.
func (f *perConnCatalogFixture) auditCount() int64 {
	f.t.Helper()
	var n int64
	if err := f.enforcement.Store.Pool.QueryRow(
		context.Background(), "SELECT count(*) FROM audit_event").Scan(&n); err != nil {
		f.t.Fatalf("count audit_event: %v", err)
	}
	return n
}

// targetConn is the contract's `target()`: a connection the TEST owns, so its transaction-local state is
// what pushFromTarget observes.
func (f *perConnCatalogFixture) targetConn() *sql.Conn {
	f.t.Helper()
	conn, err := f.enforcement.Target.Conn(context.Background())
	if err != nil {
		f.t.Fatalf("borrow a target connection: %v", err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// openAndPushFromTarget is the contract's own `openAndPush(target, principal, schemas)` — note it pushes
// from the TARGET, unlike PerConnectionCatalogDbTest's, which pushes from the global catalog.
func (f *perConnCatalogFixture) openAndPushFromTarget(
	target *sql.Conn, principal string, schemas ...string,
) datasource.OpenConnection {
	f.t.Helper()
	opened := f.open(principal, schemas...)
	for _, schema := range distinct(schemas) {
		f.pushFromTarget(target, opened.ConnectionID, schema)
	}
	return opened
}

func wantVerdict(t *testing.T, outcome core.EnforcementOutcome, what string) core.OutcomeVerdict {
	t.Helper()
	verdict, ok := outcome.(core.OutcomeVerdict)
	if !ok {
		t.Fatalf("%s: outcome = %#v, want a Verdict", what, outcome)
	}
	return verdict
}

func wantBeforeDecide(t *testing.T, outcome core.EnforcementOutcome, what string) core.OutcomeBeforeDecide {
	t.Helper()
	before, ok := outcome.(core.OutcomeBeforeDecide)
	if !ok {
		t.Fatalf("%s: outcome = %#v, want a BeforeDecide", what, outcome)
	}
	return before
}

func hasSchema(commands []*pb.Refetch, schema string) bool {
	for _, c := range commands {
		if c.GetSchema() == schema {
			return true
		}
	}
	return false
}

func runPerConnectionCatalogAdversarialContract(t *testing.T, engine string) {
	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogAdversarialDbContract.ignored after-statement command blocks the next decision without auditing it
	t.Run("ignored after-statement command blocks the next decision without auditing it", func(t *testing.T) {
		fx := newAdversarialFixture(t, engine)
		held := fx.targetConn()
		schema := fx.userSchema()
		opened := fx.openAndPushFromTarget(held, dbtest.FixtureDDLPrincipal, schema)

		beforeDDL := fx.auditCount()
		ddl := wantVerdict(t, fx.decide(opened, dbtest.FixtureDDLPrincipal,
			"CREATE TABLE "+fx.qualified(schema, "pccat_ignored_after")+" AS SELECT id FROM users WHERE 1 = 0",
			[]string{schema}, false), "the CTAS")
		if ddl.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("CTAS action = %v, want ALLOW (denyReason=%v)", ddl.Ctx.Action, deref(ddl.Ctx.DenyReason))
		}
		if !hasSchema(ddl.AfterStatement, schema) {
			t.Errorf("afterStatement = %v, want it to name %q — a catalog-changing statement must schedule a refetch",
				refetchSchemas(ddl.AfterStatement), schema)
		}
		afterDDL := fx.auditCount()
		if afterDDL != beforeDDL+1 {
			t.Errorf("audit rows went %d → %d, want exactly one verdict row", beforeDDL, afterDDL)
		}

		// 🔒 The proxy IGNORES the refetch. The next decision must be BLOCKED, not decided against the
		// now-stale held structure — and the block must write NO audit row (INV-A5-49).
		blocked := fx.decide(opened, dbtest.FixtureDDLPrincipal, "SELECT id FROM users", []string{schema}, false)
		wantBeforeDecide(t, blocked, "the statement after an ignored refetch")
		if got := fx.auditCount(); got != afterDDL {
			t.Errorf("audit rows went %d → %d; before_decide must not create an audit verdict", afterDDL, got)
		}
	})

	// KT-DEFER: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogAdversarialDbContract.an unchanged reply quiets one authoritative version and the next version re-gates — blocked on an UNRESOLVED behavioural question, measured and written up in this file's trailing comment: the Kotlin case's second `pushFromTarget` requires the sibling's bare `CREATE TABLE (id BIGINT)` to have scheduled an after-statement refetch, and on the Go side that statement relays via sql.unanalyzable with catalogChanging=false, so ApplyPush answers "schema push has no pending REFETCH command". Porting it as written would need a fixture change that alters what the Kotlin asserts. Tracked as the divergence note below.

	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogAdversarialDbContract.closing a mutated connection never changes a sibling verdict
	t.Run("closing a mutated connection never changes a sibling verdict", func(t *testing.T) {
		fx := newAdversarialFixture(t, engine)
		targetA, targetB := fx.targetConn(), fx.targetConn()
		schema := fx.userSchema()
		a := fx.openAndPushFromTarget(targetA, dbtest.FixturePrincipal, schema)
		b := fx.openAndPushFromTarget(targetB, dbtest.FixturePrincipal, schema)

		before := wantVerdict(t, fx.decide(b, dbtest.FixturePrincipal, "SELECT id FROM users", []string{schema}, false),
			"B's verdict before A mutates anything")

		ddlSQL := "CREATE TABLE " + fx.qualified(schema, "pccat_close_hint") + " AS SELECT id FROM users WHERE 1 = 0"
		ddl := wantVerdict(t, fx.decide(a, dbtest.FixturePrincipal, ddlSQL, []string{schema}, false), "A's CTAS")
		if ddl.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("A's CTAS action = %v, want ALLOW (denyReason=%v)", ddl.Ctx.Action, deref(ddl.Ctx.DenyReason))
		}
		if _, err := targetA.ExecContext(context.Background(), ddlSQL); err != nil {
			t.Fatalf("execute A's CTAS on the target: %v", err)
		}
		fx.pushFromTarget(targetA, a.ConnectionID, schema)
		if closed := fx.core.ConnectionCatalog.Close(a.ConnectionID, fx.datasource.Name); func() bool {
			_, applied := closed.(datasource.Applied)
			return !applied
		}() {
			t.Fatalf("closing A was rejected: %#v", closed)
		}

		// 🔒 Closing the mutator may legitimately make B stale (its authoritative version moved), but it
		// must never change B's VERDICT. Fulfil the refetch if one is asked for, then compare.
		after := fx.decide(b, dbtest.FixturePrincipal, "SELECT id FROM users", []string{schema}, false)
		if stale, isStale := after.(core.OutcomeBeforeDecide); isStale {
			for _, cmd := range stale.Commands {
				fx.pushFromTarget(targetB, b.ConnectionID, cmd.GetSchema())
			}
			after = fx.decide(b, dbtest.FixturePrincipal, "SELECT id FROM users", []string{schema}, false)
		}
		verdict := wantVerdict(t, after, "B's verdict after A closed")
		if verdict.Ctx.Action != before.Ctx.Action {
			t.Errorf("B's action changed %v → %v because a SIBLING closed", before.Ctx.Action, verdict.Ctx.Action)
		}
		if !sameMasks(before.Ctx.Masks, verdict.Ctx.Masks) {
			t.Errorf("B's masks changed %v → %v because a sibling closed", before.Ctx.Masks, verdict.Ctx.Masks)
		}
		if deref(before.Ctx.RewrittenSQL) != deref(verdict.Ctx.RewrittenSQL) {
			t.Errorf("B's rewrittenSql changed %q → %q because a sibling closed",
				deref(before.Ctx.RewrittenSQL), deref(verdict.Ctx.RewrittenSQL))
		}
		// And B still holds real structure — the close must not have emptied its fragment.
		bConn := fx.core.ConnectionCatalog.Find(b.ConnectionID)
		if bConn == nil {
			t.Fatal("B disappeared")
		}
		found := false
		for _, row := range fx.core.ConnectionCatalog.StructuralRows(bConn) {
			if row.Schema == schema && row.Table == "users" && row.Column == "id" {
				found = true
				break
			}
		}
		if !found {
			t.Error("B no longer holds users.id — closing a sibling emptied its fragment")
		}
	})
}

func sameMasks(a, b []*pb.ColumnMask) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetColumn() != b[i].GetColumn() || a[i].GetKind() != b[i].GetKind() ||
			a[i].GetOrdinal() != b[i].GetOrdinal() {
			return false
		}
	}
	return true
}

func TestPerConnectionCatalogMysqlAdversarialDb(t *testing.T) {
	runPerConnectionCatalogAdversarialContract(t, dbtest.EngineMySQL)

	// PerConnectionCatalogMysqlAdversarialDbTest's own cases (declared on the MySQL subclass, not the
	// contract).
	//
	// KT-DEFER: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogMysqlAdversarialDbTest.allowed MySQL CALL carries after-statement refetch — the KOTLIN ITSELF disables this case, with the reason "literal CALL is classified catalog-changing but the OTHER kind gate makes its ALLOW arm unreachable" (@Disabled, PerConnectionCatalogAdversarialDbTest.kt:317). Its ALLOW arm is unreachable on both sides, so a Go port would assert an outcome no input can produce; the reachable half is the DENY case below, which IS ported. Blocked on the OTHER-kind gate gaining a CALL permit, i.e. a product decision, not a port task.

	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogMysqlAdversarialDbTest.literal MySQL CALL is denied before it can create a stale-catalog window
	t.Run("literal MySQL CALL is denied before it can create a stale-catalog window", func(t *testing.T) {
		fx := newAdversarialFixture(t, dbtest.EngineMySQL)
		// The flagship's stored procedure. It is never CALLed successfully — the point is that the deny
		// happens at admission, so the procedure's existence must not be what saves us.
		fx.enforcement.ExecOnTarget("DROP PROCEDURE IF EXISTS pccat_refresh")
		fx.enforcement.ExecOnTarget("CREATE PROCEDURE pccat_refresh() SELECT 1")

		held := fx.targetConn()
		schema := fx.userSchema()
		opened := fx.openAndPushFromTarget(held, dbtest.FixtureDDLPrincipal, schema)

		call := wantVerdict(t, fx.decide(opened, dbtest.FixtureDDLPrincipal, "CALL pccat_refresh()",
			[]string{schema}, false), "a literal CALL")
		if call.Ctx.Action != pb.EnfAction_DENY {
			t.Errorf("action = %v, want DENY", call.Ctx.Action)
		}
		if reason := deref(call.Ctx.DenyReason); !strings.Contains(reason, "statement kind 'other' is not permitted") {
			t.Errorf("denyReason = %q, want it to contain %q", reason, "statement kind 'other' is not permitted")
		}
		// 🔒 The stale-catalog window is the point: a DENIED catalog-changing statement must schedule NO
		// after-statement refetch. Scheduling one would leave the connection blocked on a refetch for a
		// statement that never ran.
		if len(call.AfterStatement) != 0 {
			t.Errorf("afterStatement = %v, want empty — a denied statement schedules no refetch",
				refetchSchemas(call.AfterStatement))
		}
	})

	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogMysqlAdversarialDbTest.MySQL implicit-commit DROP cannot leave a stale allow
	//
	// 🔒 MySQL COMMITS DDL IMPLICITLY, so the moment the DROP runs the table is gone on the target for
	// everyone — there is no transaction to roll back and no window in which the old catalog is still
	// truthful. The after-statement REFETCH the catalog-changing DROP scheduled must therefore EVICT
	// `accounts` from the held fragment when it is fulfilled. If a stale entry survived, the next SELECT
	// would resolve `accounts` against it and ALLOW a read of a table that no longer exists — the exact
	// stale-allow this whole suite exists to rule out.
	t.Run("MySQL implicit-commit DROP cannot leave a stale allow", func(t *testing.T) {
		fx := newAdversarialFixture(t, dbtest.EngineMySQL)
		fx.enforcement.AddCedarPolicy("pccat-accounts-read", fmt.Sprintf(
			`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q);`,
			dbtest.FixtureRole, fx.enforcement.TableEUID("accounts")))

		held := fx.targetConn()
		schema := fx.userSchema()
		fx.enforcement.ExecOnTarget("DROP TABLE IF EXISTS accounts")
		fx.enforcement.ExecOnTarget("CREATE TABLE accounts (id BIGINT PRIMARY KEY)")
		fx.enforcement.ExecOnTarget("INSERT INTO accounts VALUES (1)")

		opened := fx.openAndPushFromTarget(held, dbtest.FixturePrincipal, schema)
		initial := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal,
			"SELECT accounts.id FROM accounts", []string{schema}, false), "the pre-DROP SELECT")
		if initial.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("pre-DROP action = %v, want ALLOW (%v)", initial.Ctx.Action, deref(initial.Ctx.DenyReason))
		}

		const ddlSQL = "DROP TABLE accounts"
		ddl := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal, ddlSQL,
			[]string{schema}, false), "the DROP")
		if ddl.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("DROP action = %v, want ALLOW under the sql.unanalyzable permit (%v)",
				ddl.Ctx.Action, deref(ddl.Ctx.DenyReason))
		}
		if !hasSchema(ddl.AfterStatement, schema) {
			t.Fatalf("afterStatement = %v, want it to name %q — a catalog-changing DROP must schedule "+
				"a refetch", refetchSchemas(ddl.AfterStatement), schema)
		}

		// Run it for real, then fulfil the scheduled refetch off the same held connection.
		if _, err := held.ExecContext(context.Background(), ddlSQL); err != nil {
			t.Fatalf("execute the DROP on the target: %v", err)
		}
		fx.pushFromTarget(held, opened.ConnectionID, schema)

		conn := fx.core.ConnectionCatalog.Find(opened.ConnectionID)
		if conn == nil {
			t.Fatal("the connection vanished")
		}
		for _, row := range fx.core.ConnectionCatalog.StructuralRows(conn) {
			if row.Schema == schema && row.Table == "accounts" {
				t.Fatal("the refreshed held catalog still lists the dropped `accounts`; a later SELECT " +
					"could resolve and ALLOW against it")
			}
		}
	})
}

func TestPerConnectionCatalogPostgresAdversarialDb(t *testing.T) {
	runPerConnectionCatalogAdversarialContract(t, dbtest.EnginePostgres)

	// PerConnectionCatalogPostgresAdversarialDbTest's own cases (declared on the PG subclass).
	//
	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogPostgresAdversarialDbTest.PostgreSQL SELECT invoking a function carries after-statement refetch
	t.Run("PostgreSQL SELECT invoking a function carries after-statement refetch", func(t *testing.T) {
		fx := newAdversarialFixture(t, dbtest.EnginePostgres)
		held := fx.targetConn()
		schema := fx.userSchema()
		opened := fx.openAndPushFromTarget(held, dbtest.FixturePrincipal, schema)

		// 🔒 A plain SELECT that CALLS A FUNCTION is treated as catalog-changing, because a function body
		// can perform DDL and PostgreSQL gives the control plane no way to know that it did not. This is a
		// deliberate over-approximation — a needless refetch is cheap, a stale catalog is not — and it is
		// the reason the relay arms compute `catalogChanging = facts.catalogChanging || functions > 0`
		// rather than reading catalogChanging alone.
		functionSelect := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal,
			"SELECT lower(email) FROM users", []string{schema}, false), "a function-invoking SELECT")
		if functionSelect.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW (denyReason=%v)",
				functionSelect.Ctx.Action, deref(functionSelect.Ctx.DenyReason))
		}
		if !functionSelect.Ctx.CatalogChanging {
			t.Error("catalogChanging = false; a SELECT invoking a function must be treated as catalog-changing")
		}
		if !hasSchema(functionSelect.AfterStatement, schema) {
			t.Errorf("afterStatement = %v, want it to name %q",
				refetchSchemas(functionSelect.AfterStatement), schema)
		}
	})

	// KT: PerConnectionCatalogAdversarialDbTest.kt#PerConnectionCatalogPostgresAdversarialDbTest.transaction-local DROP changes bare-name resolution before commit
	//
	// 🔒 A DROP CAN SILENTLY REPOINT A BARE NAME. With `search_path = safe, restricted` and an
	// `accounts` table in BOTH, the bare name resolves to `safe.accounts`. Dropping `safe.accounts`
	// makes the SAME statement resolve to `restricted.accounts` — a different table, with different
	// grants. The connection must re-resolve after the refetch and DENY, naming the restricted table.
	//
	// PostgreSQL's DDL is transactional, so this is observable BEFORE COMMIT on the same connection —
	// which is precisely why the refetch is scheduled per-connection rather than globally.
	t.Run("transaction-local DROP changes bare-name resolution before commit", func(t *testing.T) {
		fx := newAdversarialFixture(t, dbtest.EnginePostgres)
		fx.enforcement.ExecOnTarget("CREATE SCHEMA IF NOT EXISTS safe")
		fx.enforcement.ExecOnTarget("CREATE SCHEMA IF NOT EXISTS restricted")
		fx.enforcement.ExecOnTarget("DROP TABLE IF EXISTS safe.accounts")
		fx.enforcement.ExecOnTarget("DROP TABLE IF EXISTS restricted.accounts")
		fx.enforcement.ExecOnTarget("CREATE TABLE safe.accounts (id BIGINT PRIMARY KEY)")
		fx.enforcement.ExecOnTarget("CREATE TABLE restricted.accounts (id BIGINT PRIMARY KEY)")
		// Only the SAFE copy is readable. That asymmetry is what makes the re-resolution observable.
		fx.enforcement.AddCedarPolicy("pccat-safe-accounts-read", fmt.Sprintf(
			`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q);`,
			dbtest.FixtureRole,
			fmt.Sprintf("%s/%s/safe/accounts", fx.enforcement.DatasourceName, fx.enforcement.Catalog)))

		held := fx.targetConn()
		if _, err := held.ExecContext(context.Background(), "SET search_path = safe, restricted"); err != nil {
			t.Fatalf("set search_path: %v", err)
		}
		schemas := []string{"safe", "restricted"}
		opened := fx.openAndPushFromTarget(held, dbtest.FixturePrincipal, schemas...)

		initial := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal,
			"SELECT accounts.id FROM accounts", schemas, false), "the pre-DROP SELECT")
		if initial.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("pre-DROP action = %v, want ALLOW — the bare name must resolve to safe.accounts (%v)",
				initial.Ctx.Action, deref(initial.Ctx.DenyReason))
		}

		const ddlSQL = "DROP TABLE safe.accounts"
		ddl := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal, ddlSQL,
			[]string{"safe"}, false), "the DROP")
		if ddl.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("DROP action = %v, want ALLOW (%v)", ddl.Ctx.Action, deref(ddl.Ctx.DenyReason))
		}
		if !hasSchema(ddl.AfterStatement, "safe") {
			t.Fatalf("afterStatement = %v, want it to name \"safe\"", refetchSchemas(ddl.AfterStatement))
		}

		if _, err := held.ExecContext(context.Background(), ddlSQL); err != nil {
			t.Fatalf("execute the DROP on the target: %v", err)
		}
		fx.pushFromTarget(held, opened.ConnectionID, "safe")

		next := wantVerdict(t, fx.decide(opened, dbtest.FixturePrincipal,
			"SELECT accounts.id FROM accounts", schemas, false), "the post-DROP SELECT")
		if next.Ctx.Action != pb.EnfAction_DENY {
			t.Errorf("post-DROP action = %v, want DENY — the bare name now resolves to "+
				"restricted.accounts, which is not readable", next.Ctx.Action)
		}
		if reason := deref(next.Ctx.DenyReason); !strings.Contains(reason, ".restricted.accounts.") {
			t.Errorf("denyReason = %q, want it to name the RESTRICTED table — that is the proof the "+
				"bare name was re-resolved rather than merely invalidated", reason)
		}
	})
}

// Keep the query import honest: ChannelWire is used through the fixture's decide, and this reference
// documents that the contract decides on the WIRE channel like every case in the Kotlin file.
var _ = query.ChannelWire

// ---------------------------------------------------------------------------------------------
// DIVERGENCE NOTE — why contract case 2 is KT-DEFERred rather than ported.
//
// The Kotlin case (PerConnectionCatalogAdversarialDbTest.kt:106-156) does, in order:
//
//	1. sibling decides `CREATE TABLE <schema>.pccat_version_one (id BIGINT)`, asserts ALLOW;
//	2. runs that DDL on the sibling's own backend connection;
//	3. calls fixture.pushFromTarget(siblingTarget, sibling.connectionId, schema).
//
// Step 3 goes through applyPush, and BOTH implementations reject a push with no pending refetch:
//
//	ConnectionCatalog.kt:225-229   "schema push has no pending REFETCH command"
//	internal/datasource/connectioncatalog.go (applyPushLocked) — same rejection, same wording
//
// So step 3 needs step 1 to have scheduled an after-statement refetch on the sibling. MEASURED on Go
// (MySQL 8.4, fixture datasource, analyst + the two flagship permits above):
//
//	CREATE TABLE `db`.`diag_bare` (id BIGINT)
//	  -> action=ALLOW catalogChanging=false afterStatement=[]
//	     detail="unanalyzable relay (sql.unanalyzable): fail-closed: could not analyze (validate)"
//	CREATE TABLE `db`.`diag_ctas` AS SELECT id FROM users WHERE 1 = 0
//	  -> action=ALLOW catalogChanging=true  afterStatement=[db]  detail="ok"
//
// A bare CREATE TABLE with a column list is UNANALYZABLE (no lineage), so it takes the sql.unanalyzable
// relay, and that arm computes catalogChanging as
//
//	facts.catalogChanging || facts.functionsList.isNotEmpty()      Query.kt:515
//	facts.GetCatalogChanging() || len(facts.GetFunctions()) > 0    internal/query/decide.go:561
//
// which are the SAME expression, over facts from the SAME sqlglot-go probe. For a failed-validate
// analysis the probe reports catalogChanging=false, so no refetch is scheduled — and by that identity
// the Kotlin cannot be scheduling one either.
//
// I could not resolve what makes the Kotlin's step 3 succeed. The three candidates, none verified:
// (a) the Kotlin's probe build reports catalogChanging=true for this statement; (b) the sibling still
// holds an UNCONSUMED on-open refetch that its `openAndPush` did not clear; (c) the Kotlin case does not
// currently pass. Settling it needs a Kotlin run, which is outside this module.
//
// What was NOT done, deliberately: making the DDL a CTAS so a refetch gets scheduled. That would make
// the test green while asserting something the Kotlin does not — the whole point of the case is a
// structure change with NO lineage. INV-A5-37 rule 3 (one unchanged reply quiets exactly ONE
// authoritative version) therefore has no Go coverage yet on the decideConnection path;
// PerConnectionCatalogStateTest.kt's "a hash marker quiets one authoritative version and retriggers on
// the next" covers the registry half, in internal/datasource/connectioncatalog_test.go.
