package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// RedTeamDmlTest.kt — 46 LOC, 2 cases (06-query-decision.md §7: step 24's write branch).
//
// "Red-team write regressions through the production StatementFacts grant walk." Both cases run
// against BOTH engines in one loop, exactly as the Kotlin's `for (fixture in listOf(postgres, mysql))`
// does — so unlike EnforcementDbTest there is no class split to preserve here; the split is inside
// each case.
//
// The stated subject is INV-A6-11's WRITE half: a masked column may not be laundered into a persisted
// unmasked destination, whether through a plain read-set copy, a predicate, or a provably-total
// transform that would be REDACTABLE on a read path. `upper(rrn)` is the sharp one — case 23 of
// EnforcementPostgresDbTest proves that same expression MASKs (redacts to NULL) when it is merely
// SELECTed, so the write branch is what separates the two.
//
// ⚠️ FINDING — measured this session, and reported rather than "fixed" (PORT POLICY: REPRODUCE).
// 06-query-decision.md §7's suite table files `RedTeamDmlTest` under "step 24 write branch", but with
// the fixture the Kotlin hands it these four statements never reach step 24. `writer@example.com` is
// the fixture's `ddl-writer`: datasource.connect + sql.ddl, and deliberately NOT sql.insert or
// sql.update. So all four deny at STEP 15, the statement-kind gate, with `no sql.insert grant for
// datasource 'target-pg'` / `no sql.update grant …` — observed on both engines. Two independent
// mutations confirm it: deleting the step-15 datasource-action gate leaves these cases GREEN (step
// 24's write branch then catches them), and deleting step 24's write branch ALSO leaves them green
// (step 15 catches them). Only removing both flips the suite. It is a genuine end-to-end regression
// — the exfiltration is denied and no rows leave — but it is not, today, a test of the write branch;
// `StatementFactsGrantLoopTest`'s case 5 and the unmasked-temp linchpin are.

// redTeamDenied is the Kotlin's private `denied(fixture, sql)` — writer@example.com holds sql.ddl,
// sql.insert is NOT granted to it, and every statement here must deny with no rows regardless.
func redTeamDenied(t *testing.T, fx *dbtest.EnforcementFixture, sql string) {
	t.Helper()
	r := runAs(t, fx, dbtest.FixtureDDLPrincipal, sql)
	if action(r) != pb.EnfAction_DENY {
		t.Fatalf("must deny write exfiltration: %s; decision = %v reason=%s", sql, action(r), respReason(r))
	}
	if len(r.Rows) != 0 {
		t.Fatalf("a denied write returned %d rows: %s", len(r.Rows), sql)
	}
}

func TestRedTeamDml(t *testing.T) {
	// The Kotlin's @BeforeAll builds BOTH fixtures for the one class.
	postgres := newEnforcementFixture(t, dbtest.EnginePostgres)
	mysql := newEnforcementFixture(t, dbtest.EngineMySQL)
	fixtures := []*dbtest.EnforcementFixture{postgres, mysql}

	// KT: RedTeamDmlTest.kt#writes cannot persist masked source values
	// 1. `writes cannot persist masked source values`
	t.Run("writes cannot persist masked source values", func(t *testing.T) {
		for _, fx := range fixtures {
			redTeamDenied(t, fx, "insert into users(email) select rrn from users")
			redTeamDenied(t, fx, "update users set email = rrn")
		}
	})

	// KT: RedTeamDmlTest.kt#write predicates and transformed payloads remain non-maskable
	// 2. `write predicates and transformed payloads remain non-maskable`
	t.Run("write predicates and transformed payloads remain non-maskable", func(t *testing.T) {
		for _, fx := range fixtures {
			redTeamDenied(t, fx, "update users set email = 'x' where rrn = 'secret'")
			redTeamDenied(t, fx, "insert into users(email) select upper(rrn) from users")
		}
	})
}
