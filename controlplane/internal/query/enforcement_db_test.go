package query_test

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/access"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/identity"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// EnforcementDbTest.kt — 392 LOC, 35 cases (06-query-decision.md §7, "Decision core").
//
// The adversarial suite: it runs the PRODUCTION decision through internal/dbtest's enforcement
// harness against a REAL target database, so every case proves the leak it names is denied AND that
// no rows left the proxy — not merely that a verdict was DENY.
//
// ⚠️ STRUCTURE. The Kotlin file holds TWO top-level classes, `EnforcementPostgresDbTest` (:20, 23
// cases) and `EnforcementMysqlDbTest` (:258, 12 cases). Many case names REPEAT across them; they are
// DIFFERENT tests against different engines and the split is kept here for the reason AGENTS.md:17-26
// gives — MySQL is the correctness bar for shipping, so a dedupe-by-name would silently drop the
// MySQL leg. [TestEnforcementPostgresDb] and [TestEnforcementMysqlDb] are the two classes; each
// Kotlin case name is carried VERBATIM as its subtest name so the two files map 1:1.
//
// ⚠️ OVERLAP, deliberate. pipeline_db_test.go already carries Go forms of three of these PG cases
// (`masked query returns masked rrn`, `ungranted table denied end-to-end`, `sql.select without
// datasource.connect denied first`). Those are HARNESS pins — they assert that the harness's audit row
// is byte-identical to production's [query.DecisionRecord], and that the connect gate fires before the
// statement-kind gate — and they are not this suite. This file is the suite: all 35 cases, in the
// Kotlin's order, asserting what the Kotlin asserts.
//
// The Kotlin's `@BeforeAll` + `PER_CLASS` lifecycle is one fixture per class; each Go test function
// builds one fixture and runs its cases as subtests, which is the same shape (and the same sharing —
// so the one case that WRITES to the target still cleans up after itself, exactly as the Kotlin does).

// newEnforcementFixture is the Kotlin's `EnforcementFixture.postgres()` / `.mysql()`, with A6's three
// store seams wired to the PRODUCTION stores rather than the fixture's direct-SQL defaults.
//
// 🔒 The wiring is not incidental. internal/dbtest's defaults are documented stand-ins (TODO(A9) /
// TODO(A3) in enforcement_run.go): the role default is missing active JIT grants and the
// deactivated-principal short-circuit. The Kotlin fixture hands `decideQuery` the real
// PolicyStore/UserGroupStore/RoleResolver, so a port that decided against the stand-ins would be
// asserting a different stack than the one the Kotlin suite asserts against.
func newEnforcementFixture(t *testing.T, engine string) *dbtest.EnforcementFixture {
	t.Helper()
	fx := dbtest.NewEnforcementFixture(t, engine)
	wireProductionSeams(fx)
	return fx
}

// wireProductionSeams overwrites [dbtest.EnforcementFixture]'s three seam defaults with the production
// stores. Shared with newGrantLoopFixture, which is where the adapters it uses live.
func wireProductionSeams(fx *dbtest.EnforcementFixture) {
	pool := fx.Store.Pool
	fx.MaskFns = maskFnsOf(policy.NewPolicyStore(pool))
	userGroups := identity.NewUserGroupStore(pool)
	fx.UserGroups = userGroups
	fx.RoleResolver = identity.NewRoleResolver(pool, userGroups, grantRolesOf(access.NewStore(pool)))
}

// asSubtest points the fixture's failure reporter at the RUNNING subtest, and restores it after.
//
// ⚠️ [dbtest.EnforcementFixture.T] is bound once, at construction — the PARENT test, since the Kotlin's
// `@BeforeAll` lifecycle maps to one fixture per Go test function. The fixture reports failures itself
// (a target query that errors, or a decision that returns an error rather than a DENY), so without
// this every such failure is attributed to the parent and the failing case is never named. Measured
// while mutation-testing this suite: a mutation that made `(select 1) union select 1 into @v` ALLOW
// printed `--- FAIL: TestEnforcementMysqlDb` with no case under it, because the harness's
// "target query failed" landed on the parent's `t`.
//
// Usage is `defer asSubtest(t, fx)()` at the top of a case.
func asSubtest(t *testing.T, fx *dbtest.EnforcementFixture) func() {
	prev := fx.T
	fx.T = t
	return func() { fx.T = prev }
}

// run is the Kotlin's `fx.run(sql, principal = "analyst@example.com")` — maxRows 100.
func run(t *testing.T, fx *dbtest.EnforcementFixture, sql string) query.QueryResponse {
	t.Helper()
	return runAs(t, fx, dbtest.FixturePrincipal, sql)
}

// runAs is `fx.run(sql, principal = …)`.
func runAs(t *testing.T, fx *dbtest.EnforcementFixture, principal, sql string) query.QueryResponse {
	t.Helper()
	defer asSubtest(t, fx)()
	return fx.Run(principal, sql, 100)
}

func action(r query.QueryResponse) pb.EnfAction { return pb.EnfAction(r.Decision) }

// respReason renders `r.denyReason` for an assertion message. Named apart from the file-local `reason`
// in statement_facts_grant_loop_db_test.go, which takes a DecisionContext.
func respReason(r query.QueryResponse) string {
	if r.DenyReason == nil {
		return "<nil>"
	}
	return *r.DenyReason
}

// assertDenied is the Kotlin's recurring pair
//
//	assertEquals(EnfAction.DENY, r.decision, "…")
//	assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
//
// 🔒 Both halves, always. A DENY that still streamed rows is the failure this whole suite exists to
// catch, and asserting only the verdict would not see it.
func assertDenied(t *testing.T, r query.QueryResponse, msg string) {
	t.Helper()
	if action(r) != pb.EnfAction_DENY {
		t.Fatalf("%s: decision = %v, want DENY (reason=%s)", msg, action(r), respReason(r))
	}
	if len(r.Rows) != 0 {
		t.Fatalf("%s: a DENY must not return rows, got %d", msg, len(r.Rows))
	}
}

// assertReasonContains is `assertTrue(r.denyReason!!.contains(…))`.
func assertReasonContains(t *testing.T, r query.QueryResponse, want string) {
	t.Helper()
	if !strings.Contains(respReason(r), want) {
		t.Errorf("deny reason: %s — want it to contain %q", respReason(r), want)
	}
}

// assertNoCleartextRRN is `assertTrue(fx.cleartextRrn.none { c -> r.rows.any { row -> c in row } })`.
//
// The Kotlin has two spellings of this — cell EQUALITY (`c in row`) and cell CONTAINMENT
// (`row.any { it != null && c in it }`, case 23). Containment is the strictly stronger one, so it is
// what is asserted here: a cleartext RRN embedded in a longer string is a leak too.
func assertNoCleartextRRN(t *testing.T, r query.QueryResponse) {
	t.Helper()
	for _, row := range r.Rows {
		for _, cell := range row {
			if cell == nil {
				continue
			}
			for _, clear := range dbtest.FixtureCleartextRRN {
				if strings.Contains(*cell, clear) {
					t.Fatalf("cleartext rrn %q leaked in cell %q", clear, *cell)
				}
			}
		}
	}
}

// ---- class EnforcementPostgresDbTest (EnforcementDbTest.kt:20) — 23 cases ----------------------

func TestEnforcementPostgresDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)

	// 1. `masked query returns masked rrn, never cleartext`
	t.Run("masked query returns masked rrn, never cleartext", func(t *testing.T) {
		r := run(t, fx, "select id, rrn from users order by id")
		if action(r) != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", action(r), respReason(r))
		}
		assertNoCleartextRRN(t, r)
		for _, row := range r.Rows {
			if row[1] == nil || !strings.HasPrefix(*row[1], "*") {
				t.Errorf("expected masked rrn values, got %s", dbtest.Cell(row[1]))
			}
		}
		anyLast4 := false
		for _, row := range r.Rows {
			if row[1] != nil && strings.HasSuffix(*row[1], "4567") {
				anyLast4 = true
			}
		}
		if !anyLast4 {
			t.Errorf("expected LAST_N to keep the last 4, got %v", r.Rows)
		}
	})

	// 2. `scalar subquery leak is denied and returns no rows`
	t.Run("scalar subquery leak is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "select u.id, (select rrn from users where id = 1) as x from users u")
		assertDenied(t, r, "scalar-subquery rrn leak must be denied")
		assertReasonContains(t, r, "subquery")
	})

	// 3. `IN subquery oracle is denied`
	t.Run("IN subquery oracle is denied", func(t *testing.T) {
		r := run(t, fx, "select id from users where region in (select rrn from users)")
		assertDenied(t, r, "IN (SELECT rrn ...) oracle must be denied")
	})

	// 4. `correlated subquery oracle over rrn is denied and returns no rows`
	t.Run("correlated subquery oracle over rrn is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "select u.id from users u where exists (select 1 from users v where v.region = u.region and u.rrn = '900101-1234567')")
		assertDenied(t, r, "correlated rrn oracle must be denied")
	})

	// 5. `INTERSECT membership oracle over rrn is denied and returns no rows`
	t.Run("INTERSECT membership oracle over rrn is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "select region from users intersect select rrn from users")
		assertDenied(t, r, "INTERSECT membership oracle must be denied")
	})

	// 6. `no-FROM query_to_xml data reader is denied and returns no rows`
	t.Run("no-FROM query_to_xml data reader is denied and returns no rows", func(t *testing.T) {
		// Admission-layer bypass: query_to_xml reads users.rrn via a string arg (no FROM, invisible to
		// lineage). Must be denied before execution — no cleartext XML.
		r := run(t, fx, "select query_to_xml('SELECT rrn FROM users WHERE id = 1', true, false, '')")
		assertDenied(t, r, "no-FROM query_to_xml must be denied")
	})

	// 7. `no-FROM metadata chatter still runs`
	t.Run("no-FROM metadata chatter still runs", func(t *testing.T) {
		// The gate must not break benign connection chatter — version() executes and returns a row.
		r := run(t, fx, "select version()")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(r), respReason(r))
		}
		if len(r.Rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(r.Rows))
		}
	})

	// 8. 🔒 `a principal with zero grants cannot enumerate schema via readonly-meta passthrough`
	t.Run("a principal with zero grants cannot enumerate schema via readonly-meta passthrough", func(t *testing.T) {
		// Security regression: datasource.connect must be checked BEFORE the passthrough switch. If it
		// were checked after, READONLY_META (SHOW/DESCRIBE/no-FROM metadata SELECTs) and
		// TX_CONTROL/SESSION_MUTATING on WIRE would ALLOW unconditionally — a principal with NO grant at
		// all could still enumerate schema metadata. `ghost@example.com` resolves to zero roles
		// (RoleResolver fails closed on an unknown principal) — every passthrough class must now DENY.
		meta := runAs(t, fx, "ghost@example.com", "select version()")
		if action(meta) != pb.EnfAction_DENY {
			t.Fatalf("READONLY_META must require datasource.connect; decision = %v reason=%s",
				action(meta), respReason(meta))
		}
		assertReasonContains(t, meta, "no access to datasource")
	})

	// 9. `non-sensitive query is allowed and returns rows`
	t.Run("non-sensitive query is allowed and returns rows", func(t *testing.T) {
		r := run(t, fx, "select id, region from users order by id")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(r), respReason(r))
		}
		if len(r.Rows) != 2 {
			t.Fatalf("rows = %d, want 2", len(r.Rows))
		}
	})

	// 10. 🔒 `a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext`
	t.Run("a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext", func(t *testing.T) {
		// `orders` has no Cedar grant at all. Its columns are unclassified, so a populator that only
		// authorized classified columns would let them fall through as cleartext (the exact bug the
		// deny-by-default inversion fixes). authorizeColumns must return DENIED for every touched
		// column, and the evaluator must turn that into a DENY with no rows.
		r := run(t, fx, "select id, amount from orders order by id")
		assertDenied(t, r, "an ungranted table must be denied")
	})

	// 11. `LATERAL correlated leak of rrn is denied and returns no rows`
	t.Run("LATERAL correlated leak of rrn is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "select l.x from users u, lateral (select rrn as x) l")
		assertDenied(t, r, "LATERAL rrn leak must be denied")
	})

	// 12. `recursive CTE anchoring on rrn is denied and returns no rows`
	t.Run("recursive CTE anchoring on rrn is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "with recursive c(x) as (select rrn from users union all select x from c) select x from c")
		assertDenied(t, r, "recursive CTE rrn leak must be denied")
	})

	// 13. `benign correlated exists is allowed`
	t.Run("benign correlated exists is allowed", func(t *testing.T) {
		r := run(t, fx, "select u.id from users u where exists (select 1 from users v where v.region = u.region and v.id <> u.id) order by u.id")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("benign correlated EXISTS must not over-deny; decision = %v reason=%s",
				action(r), respReason(r))
		}
	})

	// --- The two once-per-query Cedar gates (datasource.connect, then sql.<kind>) ---

	// 14. `an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure`
	t.Run("an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure", func(t *testing.T) {
		r := run(t, fx, "insert into users values (3,'c@x','x','KR')")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "no sql.insert grant")
	})

	// 15. 🔒 `a principal with sql select but no datasource connect is denied first`
	t.Run("a principal with sql select but no datasource connect is denied first", func(t *testing.T) {
		// reader@example.com holds sql.select + result.read.unmasked on users but NOT datasource.connect —
		// proves connect is checked before sql.<kind>/columns even though the rest would pass.
		r := runAs(t, fx, dbtest.FixtureNoConnectPrincipal, "select id, region from users")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "no access to datasource")
	})

	// 16. `DDL without a sql ddl grant is denied with a clean reason, not a parse-failure`
	t.Run("DDL without a sql ddl grant is denied with a clean reason, not a parse-failure", func(t *testing.T) {
		r := run(t, fx, "create table t (id int)")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "no sql.ddl grant")
	})

	// 17. `CTAS that reads a masked column is denied even with a sql ddl grant`
	t.Run("CTAS that reads a masked column is denied even with a sql ddl grant", func(t *testing.T) {
		// writer@example.com HAS sql.ddl — the kind gate passes — but the write-payload rule in the grant
		// walk still denies: a CTAS may not copy a masked/denied column into an unmasked persisted table
		// (docs/authz-model.md's exfiltration walk-through).
		r := runAs(t, fx, dbtest.FixtureDDLPrincipal, "create table leaked as select rrn from users")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "write references protected")
		assertReasonContains(t, r, "rrn")
	})

	// 18. `CTAS over non-sensitive columns is allowed with a sql ddl grant`
	t.Run("CTAS over non-sensitive columns is allowed with a sql ddl grant", func(t *testing.T) {
		// Positive control: composition of the two gates + the write-payload rule is not always-deny.
		r := runAs(t, fx, dbtest.FixtureDDLPrincipal, "create table ddl_allow_probe as select id, region from users")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW (reason=%s)", action(r), respReason(r))
		}
	})

	// 19. 🔒 `a no-FROM SELECT INTO cannot bypass the sql ddl gate via readonly-meta passthrough`
	t.Run("a no-FROM SELECT INTO cannot bypass the sql ddl gate via readonly-meta passthrough", func(t *testing.T) {
		// Regression (integration seam): `SELECT .. INTO` with no FROM was passthrough-classified
		// READONLY_META and ALLOW'd ahead of the gates, so an analyst (connect + sql.select, NO sql.ddl)
		// could create a table. It's a write (DDL): the connect gate passes, the sql.ddl gate must DENY —
		// and it must never reach the target DB.
		r := run(t, fx, "select 1 into stmt_gate_bypass")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("SELECT INTO must be gated, not passthrough-allowed; decision = %v reason=%s",
				action(r), respReason(r))
		}
		assertReasonContains(t, r, "no sql.ddl grant")
		// The Kotlin asserts the verdict; this asserts the consequence the comment claims — the table
		// was never created, so the statement genuinely never reached the backend.
		if _, err := dbtest.ExecOnTarget(fx.Target, "select 1 from stmt_gate_bypass", 1); err == nil {
			t.Error("the denied SELECT INTO reached the backend — stmt_gate_bypass exists")
		}
	})

	// 20. 🔒 `a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext rrn`
	t.Run("a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext rrn", func(t *testing.T) {
		// Red-team regression (integration seam): `SELECT … UNION TABLE users` reads users.rrn with NO
		// FROM word — it was readonly-meta passthrough-ALLOW'd ahead of the gates, streaming cleartext
		// rrn. Must be denied at admission (fail-closed), before role resolution, with no rows.
		r := run(t, fx, "select 0,'x','x','x' union table users")
		assertDenied(t, r, "UNION TABLE read must be denied")
		assertNoCleartextRRN(t, r)
	})

	// 21. `an upsert INSERT is denied without sql update, even though sql insert is granted`
	t.Run("an upsert INSERT is denied without sql update, even though sql insert is granted", func(t *testing.T) {
		// Security regression: insert-writer holds sql.insert but deliberately NOT sql.update. A plain
		// insert works for them; an upsert (ON CONFLICT DO UPDATE) can modify an EXISTING row, so it
		// must be denied — sql.insert alone must not license that.
		//
		// The plain insert below (id=9) is a real, ALLOW'd write against the shared target — clean it up
		// so sibling cases' row-count assertions (case 9, which expects exactly the 2 seeded users) stay
		// valid regardless of execution order. Raw target execution: this is test teardown, not a
		// principal's query (the control plane does not dial the target; the test owns this connection).
		defer fx.ExecOnTarget("delete from users where id = 9")

		plain := runAs(t, fx, dbtest.FixtureInsertPrincipal,
			"insert into users (id, email, rrn, region) values (9, 'z@x', 'z', 'US')")
		if action(plain) != pb.EnfAction_ALLOW {
			t.Fatalf("a plain insert (no upsert clause) must be allowed; decision = %v reason=%s",
				action(plain), respReason(plain))
		}

		upsert := runAs(t, fx, dbtest.FixtureInsertPrincipal,
			"insert into users (id, email, rrn, region) values (1, 'z@x', 'z', 'US') "+
				"on conflict (id) do update set region = excluded.region")
		if action(upsert) != pb.EnfAction_DENY {
			t.Fatalf("an upsert must be denied without sql.update; decision = %v reason=%s",
				action(upsert), respReason(upsert))
		}
		assertReasonContains(t, upsert, "no sql.update grant")
	})

	// 22. `UPDATE and DELETE without their sql grants are denied with a clean reason`
	t.Run("UPDATE and DELETE without their sql grants are denied with a clean reason", func(t *testing.T) {
		// analyst holds only sql.select (+ result.read.*) — proves the sql.update / sql.delete gates are
		// real, not just sql.insert/sql.ddl (the only kinds the other gate cases exercise).
		upd := run(t, fx, "update users set region = 'US' where id = 1")
		if action(upd) != pb.EnfAction_DENY {
			t.Fatalf("UPDATE: decision = %v, want DENY", action(upd))
		}
		assertReasonContains(t, upd, "no sql.update grant")

		del := run(t, fx, "delete from users where id = 1")
		if action(del) != pb.EnfAction_DENY {
			t.Fatalf("DELETE: decision = %v, want DENY", action(del))
		}
		assertReasonContains(t, del, "no sql.delete grant")
	})

	// 23. `a provably-total transform of a masked column redacts in full and the rest of the row returns`
	t.Run("a provably-total transform of a masked column redacts in full and the rest of the row returns", func(t *testing.T) {
		// The headline behavior end-to-end against a real backend: upper(rrn) is a provably-total
		// transform → the derived cell is blanked to NULL, but the statement is ALLOWed (MASK) and the
		// non-sensitive columns still return — unlike a DENY. Exercises the harness NULL-redaction path
		// for a derived cell.
		r := run(t, fx, "select id, upper(rrn) from users")
		if action(r) != pb.EnfAction_MASK {
			t.Fatalf("upper(rrn) is a total transform → redact, not deny; decision = %v reason=%s",
				action(r), respReason(r))
		}
		if len(r.Rows) == 0 {
			t.Fatal("a redact-and-return must return rows (a DENY would not)")
		}
		for _, row := range r.Rows {
			if row[1] != nil {
				t.Errorf("the derived upper(rrn) cell must be NULL-redacted: %s", dbtest.Cell(row[1]))
			}
			if row[0] == nil {
				t.Errorf("the non-sensitive id column is returned intact: %v", row)
			}
		}
		assertNoCleartextRRN(t, r)
	})
}

// ---- class EnforcementMysqlDbTest (EnforcementDbTest.kt:258) — 12 cases ------------------------
//
// 🔒 NOT a subset of the Postgres class. Nine case names repeat verbatim across the two and every one
// of them is a different test: different SQL dialect, different analyzer configuration (MySQL alone
// carries `lower_case_table_names` and the ANSI_QUOTES mode), different backend. Per AGENTS.md:17-26
// MySQL is the correctness bar for shipping, so this is the leg that must be green first.

func TestEnforcementMysqlDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EngineMySQL)

	// 1. `masked query returns masked rrn, never cleartext`
	t.Run("masked query returns masked rrn, never cleartext", func(t *testing.T) {
		r := run(t, fx, "select id, rrn from users order by id")
		if action(r) != pb.EnfAction_MASK {
			t.Fatalf("decision = %v, want MASK (reason=%s)", action(r), respReason(r))
		}
		assertNoCleartextRRN(t, r)
		anyLast4 := false
		for _, row := range r.Rows {
			if row[1] != nil && strings.HasSuffix(*row[1], "4567") {
				anyLast4 = true
			}
		}
		if !anyLast4 {
			t.Errorf("expected LAST_N masking, got %v", r.Rows)
		}
	})

	// 2. `scalar subquery leak is denied and returns no rows`
	t.Run("scalar subquery leak is denied and returns no rows", func(t *testing.T) {
		r := run(t, fx, "select u.id, (select rrn from users where id = 1) as x from users u")
		assertDenied(t, r, "scalar-subquery rrn leak must be denied")
	})

	// 3. `IN subquery oracle is denied`
	t.Run("IN subquery oracle is denied", func(t *testing.T) {
		r := run(t, fx, "select id from users where region in (select rrn from users)")
		assertDenied(t, r, "IN (SELECT rrn ...) oracle must be denied")
	})

	// 4. 🔒 `error-based extraction via extractvalue over a masked column is denied end-to-end`
	t.Run("error-based extraction via extractvalue over a masked column is denied end-to-end", func(t *testing.T) {
		// A MySQL error-based exfiltration technique: extractvalue() puts a stored value into a 1105
		// XPATH error message. rrn (masked pii) is read in a NON-OUTPUT position — a function-argument
		// subquery, and the ORDER BY oracle predicate — so admission must DENY before the statement
		// reaches the backend to produce that error. This is the primary defense, ahead of the proxy's
		// DIAG error-message strip (which is the backstop if enforcement ever had a gap).
		viaArg := run(t, fx, "select extractvalue(1, concat(0x7e, (select rrn from users limit 1)))")
		assertDenied(t, viaArg, "extractvalue over a masked column must be denied")
		assertNoCleartextRRN(t, viaArg)

		// A coercing/transformed read of a masked column — CAST-to-UNSIGNED, `rrn+0` — is DENIED, not
		// redacted (docs/derived-masking.md): only PROVABLY-TOTAL string transforms (upper/substr/…) are
		// redactable; a cast or arithmetic can fault (or warn) on the value, so executing it would leak
		// the raw value through the error-presence / SQLSTATE / warning-count channel that output
		// redaction cannot touch. So these stay denied and never reach the backend.
		cast := run(t, fx, "select cast(rrn as unsigned) from users")
		assertDenied(t, cast, "cast(rrn) is a value-dependent-fault-capable transform → denied")
		arith := run(t, fx, "select rrn + 0 from users")
		if action(arith) != pb.EnfAction_DENY {
			t.Fatalf("rrn+0 (implicit cast) → denied; decision = %v reason=%s", action(arith), respReason(arith))
		}

		// The exact shape to guard: extract a benign column while using the masked one as an ORDER BY
		// oracle to pin a chosen row.
		viaOrderBy := run(t, fx,
			"select extractvalue(1, concat(0x7e, (select id from users order by (rrn='900101-1234567') desc limit 1)))")
		assertDenied(t, viaOrderBy, "a masked column in an ORDER BY predicate must be denied")
	})

	// 5. 🔒 `SET user-variable from a subquery is denied (session-state exfiltration)`
	t.Run("SET user-variable from a subquery is denied (session-state exfiltration)", func(t *testing.T) {
		// SET @x = (SELECT rrn ...) would stash cleartext in session state for a later `SELECT @x`.
		r := run(t, fx, "set @pm_leak = (select rrn from users limit 1)")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("SET carrying a subquery must be denied; decision = %v reason=%s",
				action(r), respReason(r))
		}
	})

	// 6. `a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext`
	t.Run("a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext", func(t *testing.T) {
		// `orders` has no Cedar grant; deny-by-default must return DENY with no rows (see the Postgres
		// twin for the full rationale).
		r := run(t, fx, "select id, amount from orders order by id")
		assertDenied(t, r, "an ungranted table must be denied")
	})

	// --- The two once-per-query Cedar gates (datasource.connect, then sql.<kind>) — MySQL parity ---

	// 7. `an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure`
	t.Run("an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure", func(t *testing.T) {
		r := run(t, fx, "insert into users values (3,'c@x','x','KR')")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "no sql.insert grant")
	})

	// 8. 🔒 `a principal with sql select but no datasource connect is denied first`
	t.Run("a principal with sql select but no datasource connect is denied first", func(t *testing.T) {
		r := runAs(t, fx, dbtest.FixtureNoConnectPrincipal, "select id, region from users")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "no access to datasource")
	})

	// 9. `CTAS that reads a masked column is denied even with a sql ddl grant`
	t.Run("CTAS that reads a masked column is denied even with a sql ddl grant", func(t *testing.T) {
		r := runAs(t, fx, dbtest.FixtureDDLPrincipal, "create table leaked as select rrn from users")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", action(r))
		}
		assertReasonContains(t, r, "write references protected")
		assertReasonContains(t, r, "rrn")
	})

	// 10. 🔒 `a no-FROM SELECT INTO OUTFILE cannot bypass the sql ddl gate (MySQL file-write)`
	t.Run("a no-FROM SELECT INTO OUTFILE cannot bypass the sql ddl gate (MySQL file-write)", func(t *testing.T) {
		// MySQL parity for the passthrough-bypass regression: `SELECT .. INTO OUTFILE` writes a server
		// file with no FROM, and was READONLY_META-classified (ALLOW) ahead of the gates. It's a write
		// (DDL); analyst (connect + sql.select, NO sql.ddl) must be DENIED at the sql.ddl gate before it
		// can ever reach the backend.
		r := run(t, fx, "select 1 into outfile '/tmp/pm_stmt_gate_bypass'")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("SELECT INTO OUTFILE must be gated; decision = %v reason=%s", action(r), respReason(r))
		}
		assertReasonContains(t, r, "no sql.ddl grant")
	})

	// 11. 🔒 `a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext rrn`
	t.Run("a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext rrn", func(t *testing.T) {
		// MySQL parity for the UNION TABLE red-team regression (a live cleartext leak):
		// `SELECT … UNION TABLE users` reads users.rrn with no FROM word and must be denied at admission,
		// never reaching the backend.
		r := run(t, fx, "select 0,'x','x','x' union table users")
		assertDenied(t, r, "UNION TABLE read must be denied")
		assertNoCleartextRRN(t, r)
	})

	// 12. 🔒 `SELECT INTO after a parenthesized branch cannot bypass the sql ddl gate`
	t.Run("SELECT INTO after a parenthesized branch cannot bypass the sql ddl gate", func(t *testing.T) {
		// Regression for the leading-wrapper INTO-depth fix (the exact MySQL case): `(SELECT 1) UNION
		// SELECT 1 INTO @a` mutates @a (a write) but was READONLY_META-classified and passthrough-ALLOW'd
		// ahead of the gates — the leading paren branch drove the INTO scan's depth negative and hid the
		// top-level INTO. It's DDL: analyst (connect + sql.select, NO sql.ddl) must be denied at the
		// sql.ddl gate, before it can ever reach the backend.
		r := run(t, fx, "(select 1) union select 1 into @pm_p3_branch")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("branch SELECT INTO must be gated; decision = %v reason=%s", action(r), respReason(r))
		}
		assertReasonContains(t, r, "no sql.ddl grant")
	})
}
