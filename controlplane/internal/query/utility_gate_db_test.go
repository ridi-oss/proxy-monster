package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// UtilityGateDbTest.kt — 131 LOC, 2 cases (06-query-decision.md §7, step 13).
//
// The utility gate end to end on real MySQL + real Cedar: a data-bearing SHOW command (SHOW
// PROCESSLIST / BINLOG EVENTS / WARNINGS) is admitted with a Utility FACT and DENIED by the shipped
// `system:activity` / `system:data-leak` guards, which a `system:development` datasource can relax.
// Ordinary metadata (SHOW TABLES) carries no utility fact, so the gate is inert and it still passes
// through. A datasource with NO governing manifest DENIES a recognized utility deny-by-default
// (fail-closed — utilities are token-recognized, so this needs no function catalog).
func TestUtilityGateDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EngineMySQL)
	classifier := shippedClassifier(t)

	decide := func(sql string) query.DecisionContext {
		return gateDecide(fx, dbtest.FixturePrincipal, sql, classifier)
	}
	version := func(v string) *string { return &v }

	// `a data-bearing SHOW is denied on the floor and relaxed on a preset-development datasource`
	t.Run("a data-bearing SHOW is denied on the floor and relaxed on a preset-development datasource", func(t *testing.T) {
		fx.SetEngineVersion(version("8.0.44"))
		fx.SetTags("system:production")

		// Floor: forbidden by the shipped system:activity / system:data-leak guards.
		wantAction(t, decide("SHOW PROCESSLIST"), pb.EnfAction_DENY, "SHOW PROCESSLIST (system:activity) denies on the floor")
		wantAction(t, decide("SHOW FULL PROCESSLIST"), pb.EnfAction_DENY, "SHOW FULL PROCESSLIST denies on the floor")
		wantAction(t, decide("SHOW BINLOG EVENTS"), pb.EnfAction_DENY, "SHOW BINLOG EVENTS (system:data-leak) denies on the floor")
		wantAction(t, decide("SHOW WARNINGS"), pb.EnfAction_DENY, "SHOW WARNINGS (system:data-leak) denies on the floor")
		// GET DIAGNOSTICS launders a diagnostic string into a user variable. It is denied on the floor
		// as an UNPERMITTED STATEMENT KIND, so the read-back path is closed at control-plane admission,
		// not at the proxy.
		wantAction(t, decide("GET DIAGNOSTICS @n = NUMBER"), pb.EnfAction_DENY, "GET DIAGNOSTICS denied on the floor")

		// Ordinary metadata carries no utility fact → the gate is inert → passthrough ALLOW (unchanged).
		wantAction(t, decide("SHOW TABLES"), pb.EnfAction_ALLOW, "ordinary SHOW TABLES still passthrough-allows")
		wantAction(t, decide("SHOW STATUS"), pb.EnfAction_ALLOW, "SHOW STATUS (never hardcode-denied) still passthrough-allows")

		// SET GLOBAL / SET PASSWORD are system:critical utilities and the -130 guard is UNCONDITIONAL —
		// denied on the floor, and NOT relaxed even on a dev datasource (a server-state mutation is
		// never a dev convenience). The SET slice denies these through POLICY, not a hardcoded scan list.
		wantAction(t, decide("SET GLOBAL max_connections=1"), pb.EnfAction_DENY, "SET GLOBAL (system:critical) denies on the floor")
		wantAction(t, decide("SET PASSWORD='x'"), pb.EnfAction_DENY, "SET PASSWORD (system:critical) denies on the floor")
		// SET PERSIST / PERSIST_ONLY persist a global to mysqld-auto.cnf — also system:critical, so they
		// are gated here, not relayed as a SESSION_MUTATING passthrough.
		wantAction(t, decide("SET PERSIST max_connections=5000"), pb.EnfAction_DENY, "SET PERSIST (system:critical) denies on the floor")
		wantAction(t, decide("SET PERSIST_ONLY max_connections=5000"), pb.EnfAction_DENY, "SET PERSIST_ONLY (system:critical) denies on the floor")

		// Dev datasource: the -110/-120 activity/data-leak permits fire (role-agnostic) → the SHOW is
		// allowed.
		fx.SetTags("system:development")
		wantAction(t, decide("SHOW PROCESSLIST"), pb.EnfAction_ALLOW, "SHOW PROCESSLIST relaxed on a dev datasource")
		wantAction(t, decide("SHOW BINLOG EVENTS"), pb.EnfAction_ALLOW, "SHOW BINLOG EVENTS relaxed on a dev datasource")
		// SHOW WARNINGS relaxes on a dev datasource too (dev has no PII, so its diagnostics buffer
		// carries nothing to leak) — matching the production-posture diagnostic-redaction flag.
		wantAction(t, decide("SHOW WARNINGS"), pb.EnfAction_ALLOW, "SHOW WARNINGS relaxed on a dev datasource")
		// ...but system:critical SET GLOBAL / SET PERSIST are NEVER relaxed, even on a dev datasource.
		wantAction(t, decide("SET GLOBAL max_connections=1"), pb.EnfAction_DENY,
			"SET GLOBAL stays denied even on a dev datasource (critical, unconditional)")
		wantAction(t, decide("SET PERSIST max_connections=5000"), pb.EnfAction_DENY,
			"SET PERSIST stays denied even on a dev datasource (critical, unconditional)")

		fx.SetTags("system:production")
	})

	// 🔒 `an unclassifiable utility is hard-denied even against a broad Datasource read grant`
	//
	// ⚠️ THE ONLY TEST ANYWHERE of A2's INV-A2-11 utility-marshalling INVERSION, and 06-query-decision.md
	// §7 corrects 02-authz.md §10 on exactly this point: F4 is PARTIALLY covered — the utility half is
	// tested (here), the function half still is not.
	//
	// The inversion: with no manifest the utility is UNCLASSIFIED, i.e. it carries no `system:` tag. Its
	// Cedar entity still has a Datasource PARENT, so a Datasource-scoped `result.read.unmasked` grant —
	// the documented broad / no-masking posture — WOULD permit it, re-opening the very SHOW leak the old
	// hardcode blocked. For a UTILITY, absent does NOT mean safe (INV-A5-60), so decideQuery hard-denies
	// an unclassified recognized utility at step 13c, AHEAD of Cedar, and the grant cannot reach it.
	//
	// The case is only meaningful because the broad grant is proven LIVE first: an ordinary passthrough
	// SHOW allows for the same principal on the same datasource. Without that half, "DENY" would be
	// indistinguishable from deny-by-default and the test would assert nothing.
	t.Run("an unclassifiable utility is hard-denied even against a broad Datasource read grant", func(t *testing.T) {
		fx.SetEngineVersion(nil)
		fx.SetTags("system:production")

		const broad = "broad-util@example.com"
		grantNewRole(t, fx, broad, "broad-util-reader")
		fx.AddCedarPolicy("test-broad-util-grant",
			`permit(principal in Role::"broad-util-reader", action, resource in Datasource::"`+fx.DatasourceName+`");`)

		decideAsBroad := func(sql string) query.DecisionContext {
			return gateDecide(fx, broad, sql, classifier)
		}

		// The broad grant is genuinely load-bearing: an ordinary passthrough SHOW (no utility fact) allows.
		wantAction(t, decideAsBroad("SHOW TABLES"), pb.EnfAction_ALLOW,
			"broad grant permits ordinary metadata (proves it's live)")

		// ...but the unclassified dangerous SHOW is HARD-denied ahead of Cedar — the grant cannot reach it.
		processlist := decideAsBroad("SHOW PROCESSLIST")
		wantAction(t, processlist, pb.EnfAction_DENY,
			"no manifest → unclassified utility hard-denied even WITH a Datasource read grant")
		wantAction(t, decideAsBroad("SHOW BINLOG EVENTS"), pb.EnfAction_DENY,
			"no manifest → hard-denied despite the broad grant")

		// And the analyst (no grant at all) is denied too — deny-by-default AND the hard-deny both hold.
		wantAction(t, decide("SHOW PROCESSLIST"), pb.EnfAction_DENY, "no manifest → denied with no grant")

		fx.SetEngineVersion(version("8.0.44"))
	})
}
