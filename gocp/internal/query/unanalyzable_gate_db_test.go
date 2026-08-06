package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// UnanalyzableGateDbTest.kt — 67 LOC, 1 case (06-query-decision.md §7, step 16).
//
// The unanalyzable-statement gate (docs/facts-emission.md) end to end on real PostgreSQL + real Cedar.
// The analyzer cannot prove lineage for a NATURAL JOIN — shared-column lineage is ambiguous — so
// `resolved=false`, and decideQuery asks the DATASOURCE for the `sql.unanalyzable` exception:
//
//   - the production floor (no exception policy) → DENY, fail-closed; and
//   - a datasource that shipped a `sql.unanalyzable` permit → ALLOW, relaying the ORIGINAL statement
//     verbatim (passthrough, no masks) — the permissive development-datasource posture.
//
// The gate fires BEFORE the column/table/function gates (an unresolved probe emits no facts for them),
// so a missing read grant on the referenced tables is irrelevant here; this isolates the analyzable
// decision. That is also why the statement scans the UNGRANTED `orders` table without that mattering.
func TestUnanalyzableGateDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)

	// Admitted (a single SELECT, so it passes the sql.select kind gate) but unanalyzable: the probe
	// rejects NATURAL JOIN early, before catalog resolution, so this is `resolved=false` regardless of
	// the schema.
	const unanalyzable = "select count(*) from orders natural join users"

	// ⚠️ ONE FUSED CASE, and the fusing is deliberate — the Kotlin's comment says so in as many words.
	// The permit created in part 2 PERSISTS on the shared fixture, so the floor DENY must be observed
	// BEFORE it exists. Splitting these into two Go subtests would leave the order to whoever edits the
	// file next, and the failure mode is silent: part 1 would still "pass" as a DENY only until someone
	// reordered them, after which it would fail for a reason that looks like a decideQuery regression.
	// KT: UnanalyzableGateDbTest.kt#unanalyzable denies on the floor, then a sql-unanalyzable permit relays it verbatim
	t.Run("unanalyzable denies on the floor, then a sql-unanalyzable permit relays it verbatim", func(t *testing.T) {
		// 1. Production floor — no exception policy → deny-by-default (fail-closed).
		floor := gateDecide(fx, dbtest.FixturePrincipal, unanalyzable, nil)
		wantAction(t, floor, pb.EnfAction_DENY, "no sql.unanalyzable policy → deny-by-default")
		wantDetailContains(t, floor, "could not analyze", "the fail-closed reason is preserved")

		// 2. A datasource that shipped the exception (the permissive development posture) → relay
		//    verbatim. AddCedarPolicy also bumps the policy-store state version, without which the
		//    already-built CedarEngine would keep serving its cached pre-permit policy set.
		fx.AddCedarPolicy("test-dev-unanalyzable",
			`permit(principal, action == Action::"sql.unanalyzable", resource == Datasource::"`+fx.DatasourceName+`");`)

		permitted := gateDecide(fx, dbtest.FixturePrincipal, unanalyzable, nil)
		wantAction(t, permitted, pb.EnfAction_ALLOW, "sql.unanalyzable permit → relay the original statement verbatim")
		if !permitted.Passthrough {
			t.Error("an unanalyzable relay is a verbatim passthrough (no rewrite, no masks)")
		}
		if len(permitted.Masks) != 0 {
			t.Errorf("no masks are applied to an unanalyzable relay, got %d", len(permitted.Masks))
		}
		wantDetailContains(t, permitted, "sql.unanalyzable", "the ALLOW is attributed to the exception")
	})
}
