package query_test

import (
	"reflect"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// CatalogCoverageGateDbTest.kt — 121 LOC, 2 cases (06-query-decision.md §7, step 18).
//
// Catalog coverage as a CEDAR decision ("authorization belongs to Cedar"). When the analyzer resolves
// a statement and traces a column with NO row in the catalog index, decideQuery does not hard-deny. It
// routes the miss through the SAME `sql.unanalyzable` escape hatch as an unanalyzable statement,
// carrying catalogMiss + the qualifier so the connection layer still runs its bounded refetch-first
// retry:
//
//   - the production floor (no exception policy) → DENY, fail-closed. A non-admin never holds
//     `sql.unanalyzable`, so a regular analyst ALWAYS lands here — that is the safety property.
//   - a datasource that shipped a `sql.unanalyzable` permit → ALLOW, relaying verbatim (passthrough, no
//     masks) — the admin escape hatch, unmasked as that grant already means.
//
// ⚠️ Why the facts are SYNTHETIC. A genuine coverage miss is an analyzer↔control-plane KEY-RENDERING
// divergence — a contract bug — that a real resolved statement cannot reproduce: a column truly absent
// from the catalog fails to RESOLVE (the analyzer is built from the same catalog) and takes the
// `!resolved` route at step 16 instead. So the uncatalogued column is injected through the
// `factsOverride` seam: a real `users` catalog+schema+table with a column name that exists nowhere.
//
// Run on BOTH engines. The gate is engine-agnostic, but MySQL is the priority engine (AGENTS.md:17-26)
// so it is exercised explicitly rather than assumed.
func TestCatalogCoverageGateDb(t *testing.T) {
	pg := newEnforcementFixture(t, dbtest.EnginePostgres)
	my := newEnforcementFixture(t, dbtest.EngineMySQL)

	// `postgres coverage miss denies on the floor, then a sql-unanalyzable permit relays it`
	t.Run("postgres coverage miss denies on the floor, then a sql-unanalyzable permit relays it", func(t *testing.T) {
		runCoverageGate(t, pg, "test-coverage-unanalyzable-pg")
	})

	// `mysql coverage miss denies on the floor, then a sql-unanalyzable permit relays it`
	t.Run("mysql coverage miss denies on the floor, then a sql-unanalyzable permit relays it", func(t *testing.T) {
		runCoverageGate(t, my, "test-coverage-unanalyzable-my")
	})
}

// coverageMissFacts is the Kotlin's private helper of the same name: a RESOLVED, ANALYZED statement
// whose single column grant names a column that is not in the catalog.
func coverageMissFacts(t *testing.T, fx *dbtest.EnforcementFixture) *probepb.StatementFacts {
	t.Helper()
	users := col(t, fx.CatalogRows(), "users", "rrn")
	return &probepb.StatementFacts{
		Resolved:                  true,
		StatementClass:            probepb.StatementClass_STATEMENT_CLASS_ANALYZED,
		Detail:                    "synthetic coverage miss",
		SchemaQualifierCandidates: []string{users.Schema},
		RequiredGrants: []*probepb.RequiredGrant{{
			Action: probepb.GrantAction_GRANT_ACTION_RESULT_READ,
			Resource: &probepb.RequiredGrant_Column{Column: &probepb.ColumnResource{
				Catalog: users.Catalog,
				Identity: &probepb.RelationIdentity{
					Schema: users.Schema, Table: users.Table, Column: "ghost_uncovered_column",
				},
			}},
			// Any valid, SPECIFIED disposition: coverage (step 18) is checked BEFORE the
			// disposition-driven grant walk (step 24), so this value never decides the outcome — and the
			// "absent from catalog" detail assertion below is what proves the coverage gate, rather than
			// a disposition deny, produced the verdict.
			MaskedDisposition: probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		}},
	}
}

// runCoverageGate is the Kotlin's private `runGate(fx, permitName)`.
//
// ⚠️ ORDERED WITHIN ONE SUBTEST per engine, exactly as the Kotlin fuses it into one method: the floor
// DENY must be observed BEFORE the permit is created, because the permit persists on the per-engine
// fixture. Each engine has its own fixture, so one engine's permit cannot contaminate the other.
func runCoverageGate(t *testing.T, fx *dbtest.EnforcementFixture, permitName string) {
	t.Helper()
	missSchema := col(t, fx.CatalogRows(), "users", "rrn").Schema
	facts := coverageMissFacts(t, fx)

	decide := func() query.DecisionContext {
		return fx.DecideWith(query.DecideQueryInput{
			Principal:     dbtest.FixturePrincipal,
			SQL:           "-- synthetic coverage miss --",
			Channel:       query.ChannelWire,
			FactsOverride: facts,
		})
	}

	// 1. No exception policy → fail-closed deny, carrying catalogMiss + the qualifier so the connection
	//    layer refetches and retries before this verdict can stand (INV-A6-14). A regular analyst has no
	//    sql.unanalyzable.
	floor := decide()
	wantAction(t, floor, pb.EnfAction_DENY, "no sql.unanalyzable policy → coverage miss denies fail-closed")
	if !floor.CatalogMiss {
		t.Error("the deny carries catalogMiss so decideConnection refetches + retries first")
	}
	if !reflect.DeepEqual(floor.SchemaCandidates, []string{missSchema}) {
		t.Errorf("schemaCandidates = %v, want [%s] — the miss surfaces its qualifier schema for the refetch",
			floor.SchemaCandidates, missSchema)
	}
	wantDetailContains(t, floor, "absent from catalog", "the fail-closed reason is preserved")

	// 2. A datasource that shipped the sql.unanalyzable exception → relay the uncovered read verbatim.
	fx.AddCedarPolicy(permitName,
		`permit(principal, action == Action::"sql.unanalyzable", resource == Datasource::"`+fx.DatasourceName+`");`)

	permitted := decide()
	wantAction(t, permitted, pb.EnfAction_ALLOW, "sql.unanalyzable permit → relay the uncovered read")
	if !permitted.Passthrough {
		t.Error("an uncovered-column relay is a verbatim passthrough (no rewrite, no masks)")
	}
	if len(permitted.Masks) != 0 {
		t.Errorf("no masks are applied to a relayed uncovered read, got %d", len(permitted.Masks))
	}
	if !permitted.CatalogMiss {
		t.Error("the relay still carries catalogMiss so refetch-first runs before it stands")
	}
	wantDetailContains(t, permitted, "sql.unanalyzable", "the ALLOW is attributed to the exception")
}
