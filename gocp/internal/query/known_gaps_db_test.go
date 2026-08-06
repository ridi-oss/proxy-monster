package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// KnownGapsTest.kt — 96 LOC, 7 cases (06-query-decision.md §7, step 25).
//
// Scanned-table deny-by-default (docs/facts-emission.md). The per-column authz in decideQuery
// (`authorizeColumns` / the mask-binding loop) only ever sees columns a query TRACES, so a table
// scanned with ZERO traced columns — `count(*)`, `SELECT 1`, `EXISTS(...)`, or a cross-join side that
// only multiplies cardinality — is never asked about by the per-column path and would leak an
// ungranted table's existence and row count (reaching system catalogs like `pg_authid`). The analyzer
// emits every scanned physical relation as a source, and step 25 requires a `result.read` grant on
// every UNCOVERED one, DENY otherwise.
//
// Two safety properties this file locks:
//
//  1. **Scope-aware, not a name set.** A CTE that SHADOWS a real table name does NOT read the physical
//     table, so it emits no source and ALLOWs; a CTE BODY that reads the real table DOES, and is
//     gated. That falls out of the analyzer's resolution report (Physical vs CTE/Derived), never a
//     flat global CTE-name subtraction.
//  2. **Per-tableID coverage.** A table is covered once any of its columns is a traced fact — the
//     column grant already exposes that table's cardinality — so a table the principal legitimately
//     reads a column of still ALLOWs; only a table with no traced column AND no table grant is denied.
//
// ⚠️ This suite and [TestScannedTableMySql] OVERLAP DELIBERATELY: 06-query-decision.md §7 records that
// `KnownGapsTest` covers the gate on PostgreSQL and `ScannedTableMySqlTest` covers it on MySQL,
// because the dialect, the `def`/db namespace and the case folding all differ while the gate does not.
// AGENTS.md:17-26 makes MySQL the correctness bar. KEEP BOTH — a dedupe silently drops the MySQL leg.
//
// Fixture: `analyst@example.com` holds `result.read` on the `users` table (unmasked except the pii
// `rrn`) plus `datasource.connect`/`sql.select`; `orders` is UNGRANTED.
func TestKnownGaps(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)

	// KT: KnownGapsTest.kt#count(star) on an ungranted table is denied
	// `count(star) on an ungranted table is denied`
	t.Run("count(star) on an ungranted table is denied", func(t *testing.T) {
		r := run(t, fx, "select count(*) from orders")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("count(*) on an ungranted table must be denied; got %v", action(r))
		}
	})

	// KT: KnownGapsTest.kt#select 1 on an ungranted table is denied
	// `select 1 on an ungranted table is denied`
	t.Run("select 1 on an ungranted table is denied", func(t *testing.T) {
		r := run(t, fx, "select 1 from orders")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("select 1 on an ungranted table must be denied; got %v", action(r))
		}
	})

	// KT: KnownGapsTest.kt#EXISTS over an ungranted table is denied
	// `EXISTS over an ungranted table is denied`
	t.Run("EXISTS over an ungranted table is denied", func(t *testing.T) {
		r := run(t, fx, "select exists(select 1 from orders)")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("EXISTS over an ungranted table must be denied; got %v", action(r))
		}
	})

	// KT: KnownGapsTest.kt#a cross-join scanning an ungranted table is denied even when only the granted side is projected
	// `a cross-join scanning an ungranted table is denied even when only the granted side is projected`
	t.Run("a cross-join scanning an ungranted table is denied even when only the granted side is projected", func(t *testing.T) {
		r := run(t, fx, "select u.id from users u, orders o")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("a cross-join touching an ungranted table must be denied; got %v", action(r))
		}
	})

	// KT: KnownGapsTest.kt#a CTE that shadows a real ungranted table name is allowed - the physical table is not read
	// `a CTE that shadows a real ungranted table name is allowed - the physical table is not read`
	//
	// The `orders` in the outer query binds to the CTE (SELECT 1), NOT the backend table, so nothing
	// physical is scanned — ALLOW (analyst holds datasource.connect + sql.select). A naive
	// global-CTE-name fix would either leak the real table or wrongly deny this.
	t.Run("a CTE that shadows a real ungranted table name is allowed - the physical table is not read", func(t *testing.T) {
		r := run(t, fx, "with orders as (select 1) select count(*) from orders")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("a pure CTE shadow reads no physical table and must be allowed; got %v: %s",
				action(r), respReason(r))
		}
	})

	// KT: KnownGapsTest.kt#a CTE body that reads the real ungranted table is denied
	// `a CTE body that reads the real ungranted table is denied`
	//
	// Mirror image of the shadow case: the CTE BODY's `from orders` resolves to the physical table,
	// scanned via count(*) with zero traced columns → uncovered → DENY without an orders grant.
	t.Run("a CTE body that reads the real ungranted table is denied", func(t *testing.T) {
		r := run(t, fx, "with o as (select count(*) as c from orders) select c from o")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("a CTE body scanning the real ungranted table must be denied; got %v", action(r))
		}
	})

	// KT: KnownGapsTest.kt#count(star) on a table the principal has a read grant on is allowed
	// `count(star) on a table the principal has a read grant on is allowed`
	//
	// Behaviour preservation + per-tableID coverage: analyst holds result.read on the users TABLE, so
	// a zero-column scan of users is authorized by that grant — the table gate must not over-deny it.
	t.Run("count(star) on a table the principal has a read grant on is allowed", func(t *testing.T) {
		r := run(t, fx, "select count(*) from users")
		if action(r) != pb.EnfAction_ALLOW {
			t.Fatalf("count(*) on a table the principal can read must be allowed; got %v: %s",
				action(r), respReason(r))
		}
	})
}
