package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// ScannedTableMySqlTest.kt — 48 LOC, 4 cases (06-query-decision.md §7, step 25).
//
// Scanned-table enforcement on MySQL (docs/facts-emission.md: "Verify both CTE bindings live on
// PostgreSQL and MySQL"). The PostgreSQL half lives in [TestKnownGaps]; this proves the same
// deny-by-default holds through the real MySQL decision path — the dialect, the `def`/db namespace and
// the case folding all differ, the gate does not.
//
// ⚠️ The overlap with [TestKnownGaps] is DELIBERATE and both are kept. 06-query-decision.md §7 says so
// explicitly, and AGENTS.md:17-26 makes MySQL the correctness bar for shipping: a "these are the same
// four cases" dedupe would leave the gate proven only on the experimental engine.
//
// Fixture: `analyst@example.com` holds `result.read` on the `users` table; `orders` is UNGRANTED.
func TestScannedTableMySql(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EngineMySQL)

	// `count(star) on an ungranted table is denied`
	t.Run("count(star) on an ungranted table is denied", func(t *testing.T) {
		if got := action(run(t, fx, "select count(*) from orders")); got != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", got)
		}
	})

	// `count(star) on a table the principal can read is allowed`
	t.Run("count(star) on a table the principal can read is allowed", func(t *testing.T) {
		if got := action(run(t, fx, "select count(*) from users")); got != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW", got)
		}
	})

	// `a pure CTE shadow of the ungranted table is allowed`
	t.Run("a pure CTE shadow of the ungranted table is allowed", func(t *testing.T) {
		r := run(t, fx, "with orders as (select 1) select count(*) from orders")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("decision = %v, want ALLOW: %s", action(r), respReason(r))
		}
	})

	// `a CTE body scanning the real ungranted table is denied`
	t.Run("a CTE body scanning the real ungranted table is denied", func(t *testing.T) {
		got := action(run(t, fx, "with o as (select count(*) as c from orders) select c from o"))
		if got != pb.EnfAction_DENY {
			t.Fatalf("decision = %v, want DENY", got)
		}
	})
}
