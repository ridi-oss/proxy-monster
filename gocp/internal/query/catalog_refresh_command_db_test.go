package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// CatalogRefreshCommandDbTest.kt — 74 LOC, 5 cases.
//
// decideQuery's `catalogChanging` flag: the signal the proxy reads to know that a statement it is about
// to relay may change persistent catalog structure, so the per-connection catalog it holds must be
// refetched after the statement completes. Nothing else in the Go suite asserted this field at all
// (`grep -rn CatalogChanging --include='*_test.go'` found zero hits before this file), so all five cases
// were live gaps rather than re-labellings.
//
// Why the flag matters in both directions:
//   - false on an allowed catalog-changing DDL is a STALE-CATALOG window: the connection keeps deciding
//     against structure the statement just replaced.
//   - true on anything else is a needless refetch on the hot path.
//
// The Kotlin decides on Channel.WIRE with the SHIPPED SystemClassificationService, which is what
// gate_support_test.go's gateDecide + shippedClassifier provide. The fixture is MySQL — CREATE
// TEMPORARY TABLE is the MySQL spelling the temporary-CTAS case turns on.
//
// The Kotlin class is @TestInstance(PER_CLASS) with one @BeforeAll fixture, so this is one Go test with
// five subtests over one fixture, in the Kotlin's declaration order.
func TestCatalogRefreshCommandDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EngineMySQL)
	classifier := shippedClassifier(t)

	// The Kotlin's `decide(sql, principal = "writer@example.com")`: the DDL principal is the DEFAULT
	// here, and the two cases that want an ALLOW-less answer pass the analyst instead.
	decide := func(sql string) query.DecisionContext {
		return gateDecide(fx, dbtest.FixtureDDLPrincipal, sql, classifier)
	}
	decideAs := func(principal, sql string) query.DecisionContext {
		return gateDecide(fx, principal, sql, classifier)
	}
	wantRefresh := func(t *testing.T, got query.DecisionContext, want bool) {
		t.Helper()
		if got.CatalogChanging != want {
			t.Errorf("catalogChanging = %v, want %v (denyReason=%q)",
				got.CatalogChanging, want, reason(got))
		}
	}

	// KT: CatalogRefreshCommandDbTest.kt#allowed non-temporary DDL carries a catalog refresh command
	t.Run("allowed non-temporary DDL carries a catalog refresh command", func(t *testing.T) {
		decision := decide("CREATE TABLE catalog_refresh_probe AS SELECT id, region FROM users")
		wantAction(t, decision, pb.EnfAction_ALLOW, "an allowed CTAS")
		wantRefresh(t, decision, true)
	})

	// KT: CatalogRefreshCommandDbTest.kt#allowed SELECT carries no catalog refresh command
	t.Run("allowed SELECT carries no catalog refresh command", func(t *testing.T) {
		decision := decideAs(dbtest.FixturePrincipal, "SELECT id FROM users")
		wantAction(t, decision, pb.EnfAction_ALLOW, "an allowed SELECT")
		wantRefresh(t, decision, false)
	})

	// KT: CatalogRefreshCommandDbTest.kt#denied DDL carries no catalog refresh command
	t.Run("denied DDL carries no catalog refresh command", func(t *testing.T) {
		decision := decideAs(dbtest.FixturePrincipal, "CREATE TABLE denied_catalog_refresh_probe (id BIGINT)")
		wantAction(t, decision, pb.EnfAction_DENY, "the analyst holds no sql.ddl")
		wantRefresh(t, decision, false)
	})

	// KT: CatalogRefreshCommandDbTest.kt#allowed temporary CTAS carries no catalog refresh command
	t.Run("allowed temporary CTAS carries no catalog refresh command", func(t *testing.T) {
		// A TEMPORARY table is session-local, so it changes no PERSISTENT structure and the held catalog
		// stays valid. Flagging it would refetch the whole catalog for a scratch table.
		decision := decide("CREATE TEMPORARY TABLE temp_catalog_refresh_probe AS SELECT id, region FROM users")
		wantAction(t, decision, pb.EnfAction_ALLOW, "an allowed TEMPORARY CTAS")
		wantRefresh(t, decision, false)
	})

	// KT: CatalogRefreshCommandDbTest.kt#bare PREPARE is denied without a catalog refresh command
	t.Run("bare PREPARE is denied without a catalog refresh command", func(t *testing.T) {
		decision := decide("PREPARE stmt FROM 'SELECT 1'")
		wantAction(t, decision, pb.EnfAction_DENY, "a bare PREPARE")
		wantRefresh(t, decision, false)
	})
}
