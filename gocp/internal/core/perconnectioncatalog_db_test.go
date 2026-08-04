package core_test

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// PerConnectionCatalogDbTest.kt — 110 LOC, 3 cases in an abstract contract that two per-engine
// subclasses instantiate. Per internal/tracing/doc.go's rule for that shape the @Test appears once in
// the Kotlin, so the marker appears once here, on the CONTRACT — and ScanModule attributes it to every
// test that reaches it, which is both engine tests.
//
// Two of the three cases open with `if (fixture.datasource.engine.isPostgres) return@runBlocking`, i.e.
// they are MySQL-ONLY bodies living in a two-engine contract. That is REPRODUCED: the PG instantiation
// really does run them as no-ops, and collapsing them to a MySQL-only test would silently drop the
// Kotlin's (admittedly vacuous) PG leg. The guard is stated per case so it reads as deliberate.

func runPerConnectionCatalogContract(t *testing.T, engine string) {
	fx := newPerConnCatalogFixture(t, engine)
	isPostgres := engine == dbtest.EnginePostgres

	// KT: PerConnectionCatalogDbTest.kt#decision uses held structure after global catalog rows are deleted
	t.Run("decision uses held structure after global catalog rows are deleted", func(t *testing.T) {
		if isPostgres {
			t.Skip("the Kotlin body is `if (engine.isPostgres) return@runBlocking` — a no-op on this engine")
		}
		schema := fx.datasource.DefaultSchemas[0]
		opened := fx.openAndPush(dbtest.FixturePrincipal, schema)

		// 🔒 The point of the case: the connection's HELD fragment is the structure a decision resolves
		// against, INDEPENDENTLY of the global catalog rows. Emptying catalog_column must not turn a held
		// ALLOW into a catalog-miss deny.
		if _, err := fx.enforcement.Store.Pool.Exec(context.Background(),
			"DELETE FROM catalog_column WHERE datasource_id = $1", fx.datasource.ID); err != nil {
			t.Fatalf("delete the global catalog rows: %v", err)
		}

		outcome := fx.decide(opened, dbtest.FixturePrincipal, "select id from users", []string{schema}, false)
		verdict, ok := outcome.(core.OutcomeVerdict)
		if !ok {
			t.Fatalf("outcome = %#v, want a Verdict", outcome)
		}
		if verdict.Ctx.Action != pb.EnfAction_ALLOW {
			t.Errorf("action = %v, want ALLOW (denyReason=%v)", verdict.Ctx.Action, deref(verdict.Ctx.DenyReason))
		}
		// 🔒 INV-A5-48 — the generation stamped on the verdict is the one it was ANALYZED under. One
		// accepted push means generation 1.
		if verdict.Generation != 1 {
			t.Errorf("generation = %d, want 1", verdict.Generation)
		}
	})

	// KT: PerConnectionCatalogDbTest.kt#ANSI_QUOTES threads through decideConnection so a double-quoted pii column masks
	t.Run("ANSI_QUOTES threads through decideConnection so a double-quoted pii column masks", func(t *testing.T) {
		if isPostgres {
			t.Skip("the Kotlin body is `if (engine.isPostgres) return@runBlocking` — a no-op on this engine")
		}
		// The ANSI_QUOTES seam: the gRPC handler forwards the proxy's observed sql_mode=ANSI_QUOTES as
		// decideConnection(ansiQuotes=true), which must reach the analyzer's EngineConfig so `"rrn"` is read
		// as the masked pii COLUMN, not a string literal — MASK, not a cleartext leak. With the flag false
		// (default mode) `"rrn"` is the constant string 'rrn' (no pii column touched) → ALLOW.
		schema := fx.datasource.DefaultSchemas[0]
		// Introspect the fragment straight FROM THE TARGET rather than through openAndPush, which reads
		// the global catalog the sibling subtest above deletes — and this also mirrors the proxy's real
		// push flow exactly.
		opened := fx.open(dbtest.FixturePrincipal, schema)
		conn, err := fx.enforcement.Target.Conn(context.Background())
		if err != nil {
			t.Fatalf("borrow a target connection: %v", err)
		}
		defer conn.Close()
		fx.pushFromTarget(conn, opened.ConnectionID, schema)

		masked := fx.decide(opened, dbtest.FixturePrincipal, `select "rrn" from users`, []string{schema}, true)
		maskedVerdict, ok := masked.(core.OutcomeVerdict)
		if !ok {
			t.Fatalf("ansiQuotes=true outcome = %#v, want a Verdict", masked)
		}
		if maskedVerdict.Ctx.Action != pb.EnfAction_MASK {
			t.Errorf("ansiQuotes=true action = %v, want MASK (denyReason=%v) — `\"rrn\"` must read as the pii COLUMN",
				maskedVerdict.Ctx.Action, deref(maskedVerdict.Ctx.DenyReason))
		}

		allowed := fx.decide(opened, dbtest.FixturePrincipal, `select "rrn" from users`, []string{schema}, false)
		allowedVerdict, ok := allowed.(core.OutcomeVerdict)
		if !ok {
			t.Fatalf("ansiQuotes=false outcome = %#v, want a Verdict", allowed)
		}
		if allowedVerdict.Ctx.Action != pb.EnfAction_ALLOW {
			t.Errorf("ansiQuotes=false action = %v, want ALLOW (denyReason=%v) — `\"rrn\"` is the string 'rrn'",
				allowedVerdict.Ctx.Action, deref(allowedVerdict.Ctx.DenyReason))
		}
	})

	// KT: PerConnectionCatalogDbTest.kt#missing search path fragment returns before-decide without audit
	t.Run("missing search path fragment returns before-decide without audit", func(t *testing.T) {
		// Opened holding NOTHING, then asked to decide against a schema it does not hold: the freshness
		// pre-gate must answer BeforeDecide naming that schema, BEFORE any analysis and any audit row
		// (🔒 INV-A5-49).
		opened := fx.open(dbtest.FixturePrincipal)
		outcome := fx.decide(opened, dbtest.FixturePrincipal, "select id from users", []string{"missing_schema"}, false)
		before, ok := outcome.(core.OutcomeBeforeDecide)
		if !ok {
			t.Fatalf("outcome = %#v, want a BeforeDecide", outcome)
		}
		got := refetchSchemas(before.Commands)
		if len(got) != 1 || got[0] != "missing_schema" {
			t.Errorf("commands = %v, want [missing_schema]", got)
		}
	})
}

func TestPerConnectionCatalogMysqlDb(t *testing.T) {
	runPerConnectionCatalogContract(t, dbtest.EngineMySQL)
}

func TestPerConnectionCatalogPostgresDb(t *testing.T) {
	runPerConnectionCatalogContract(t, dbtest.EnginePostgres)
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
