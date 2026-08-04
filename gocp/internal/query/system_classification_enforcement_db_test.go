package query_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// SystemClassificationEnforcementDbTest.kt — 212 LOC, 7 cases (06-query-decision.md §7, steps 21/22).
//
// End-to-end system classification on real PostgreSQL + real Cedar: the shipped `system:catalog`
// permit makes system STRUCTURE browsable, while the dangerous tags
// (`system:critical`/`data-leak`/`activity`) are forbidden on the production floor by the shipped
// forbids — the forbid OVERRIDING even a broad grant. `system:critical` is never relaxed;
// `system:activity`/`data-leak` are relaxed on `system:development`.
//
// The classifier keys off `datasource.engine_version` (set here to a PG-17 `version()` string). A
// datasource with NO version resolves to no manifest → no system tag → deny-by-default (system
// schemas closed) — the transitional, fail-closed posture.
//
// Running this suite at all also proves the shipped SYSTEM policies COMPILE against schema.cedarschema
// at boot, since the fixture's CedarEngine loads them.
func TestSystemClassificationEnforcementDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)
	classifier := shippedClassifier(t)
	ctx := context.Background()

	const pg17 = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"
	version := func(v string) *string { return &v }
	decide := func(sql string) query.DecisionContext {
		return gateDecide(fx, dbtest.FixturePrincipal, sql, classifier)
	}

	// KT: SystemClassificationEnforcementDbTest.kt#a user column classification cannot claim a reserved system tag
	// `a user column classification cannot claim a reserved system tag`
	//
	// 🔒 A2 INV-A2-7. The `system:` namespace is owned by the shipped manifests, so a user-authored
	// column tag must be rejected AT WRITE TIME (fail-closed) — not silently stored to be ignored later
	// at Cedar marshalling, where "ignored" would depend on a marshaller nobody re-reads.
	t.Run("a user column classification cannot claim a reserved system tag", func(t *testing.T) {
		_, err := fx.DatasourceStore.UpsertClassification(ctx, fx.DatasourceID, datasource.ClassificationInput{
			Schema: version("public"), Table: "users", Column: "rrn",
			Tags: []string{"pii", "system:critical"},
		})
		if err == nil {
			t.Fatal("a user classification claiming a reserved system tag must be refused")
		}
		if !errors.Is(err, datasource.ErrReservedTag) {
			t.Errorf("error = %v, want it to be a reserved-tag refusal", err)
		}
		if !strings.Contains(err.Error(), "system:critical") {
			t.Errorf("the error must name the reserved tag: %v", err)
		}

		// A non-reserved tag still writes fine (positive control — the guard only rejects the `system:`
		// prefix).
		//
		// ⚠️ This write DROPS the fixture's `last4` mask_fn from `users.rrn`, because ClassificationInput
		// carries no MaskFnID and the upsert's DO UPDATE sets mask_fn_id = EXCLUDED.mask_fn_id. The
		// Kotlin case does exactly the same thing and the later cases in this class never mask rrn, so
		// it is reproduced rather than "fixed" — but it is why no case below may assume the mask.
		ok, err := fx.DatasourceStore.UpsertClassification(ctx, fx.DatasourceID, datasource.ClassificationInput{
			Schema: version("public"), Table: "users", Column: "rrn", Tags: []string{"pii"},
		})
		if err != nil {
			t.Fatalf("a non-reserved tag must still write: %v", err)
		}
		if !reflect.DeepEqual(ok.Tags, []string{"pii"}) {
			t.Errorf("tags = %v, want [pii]", ok.Tags)
		}
	})

	// KT: SystemClassificationEnforcementDbTest.kt#on a PG-17 datasource, catalog structure browses and dangerous surfaces deny
	// `on a PG-17 datasource, catalog structure browses and dangerous surfaces deny`
	t.Run("on a PG-17 datasource, catalog structure browses and dangerous surfaces deny", func(t *testing.T) {
		fx.SetEngineVersion(version(pg17))

		// system:catalog — structure is browsable (the shipped system:catalog permit), via the TABLE gate
		// (count(*)) AND the COLUMN path (a projected column inherits the Table's system:catalog tag).
		wantAction(t, decide("select count(*) from pg_catalog.pg_class"), pb.EnfAction_ALLOW,
			"pg_class (system:catalog) must browse")
		wantAction(t, decide("select relname from pg_catalog.pg_class"), pb.EnfAction_ALLOW,
			"a system:catalog column must read")

		// dangerous tags — forbidden on the production floor by the shipped critical/data-leak/activity
		// forbids.
		wantAction(t, decide("select count(*) from pg_catalog.pg_authid"), pb.EnfAction_DENY,
			"pg_authid (system:critical) must deny")
		wantAction(t, decide("select count(*) from pg_catalog.pg_stats"), pb.EnfAction_DENY,
			"pg_stats (system:data-leak) must deny")
		wantAction(t, decide("select count(*) from pg_catalog.pg_stat_activity"), pb.EnfAction_DENY,
			"pg_stat_activity (system:activity) must deny")
	})

	// KT: SystemClassificationEnforcementDbTest.kt#the dangerous forbids override even a broad datasource read grant
	// 🔒 `the dangerous forbids override even a broad datasource read grant`
	//
	// The DENY cases above are deny-by-default for an ungranted analyst — true whether or not the
	// forbids exist. THIS case is what makes them LOAD-BEARING: a principal with a broad any-action
	// grant on the whole datasource. Without the shipped forbids the dangerous tags would ALLOW via
	// that grant; with them, Cedar's forbid overrides the permit.
	t.Run("the dangerous forbids override even a broad datasource read grant", func(t *testing.T) {
		fx.SetEngineVersion(version(pg17))
		const broad = "broad@example.com"
		grantNewRole(t, fx, broad, "broad-reader")
		fx.AddCedarPolicy("test-broad-reader-grant",
			`permit(principal in Role::"broad-reader", action, resource in Datasource::"`+fx.DatasourceName+`");`)

		decideAsBroad := func(sql string) query.DecisionContext { return gateDecide(fx, broad, sql, classifier) }

		// The broad grant genuinely permits: system:catalog browses.
		wantAction(t, decideAsBroad("select count(*) from pg_catalog.pg_class"), pb.EnfAction_ALLOW,
			"broad grant permits system:catalog")
		// ...but the shipped forbids OVERRIDE that broad grant on every dangerous tag (production floor).
		wantAction(t, decideAsBroad("select count(*) from pg_catalog.pg_authid"), pb.EnfAction_DENY,
			"critical forbid overrides the broad grant")
		wantAction(t, decideAsBroad("select count(*) from pg_catalog.pg_stats"), pb.EnfAction_DENY,
			"data-leak forbid overrides the broad grant")
		wantAction(t, decideAsBroad("select count(*) from pg_catalog.pg_stat_activity"), pb.EnfAction_DENY,
			"activity forbid overrides the broad grant")
		wantAction(t, decideAsBroad("select rolname from pg_catalog.pg_authid"), pb.EnfAction_DENY,
			"forbid overrides on the column path too")
	})

	// KT: SystemClassificationEnforcementDbTest.kt#without an engine_version, system schemas stay deny-by-default
	// `without an engine_version, system schemas stay deny-by-default`
	t.Run("without an engine_version, system schemas stay deny-by-default", func(t *testing.T) {
		fx.SetEngineVersion(nil)
		// No version → no manifest → no system tag → the object is ungranted → deny-by-default (safe).
		// Even the otherwise-open pg_class is denied, because there is no classification to permit it.
		wantAction(t, decide("select count(*) from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"no version → no system:catalog permit → deny")
		wantAction(t, decide("select count(*) from pg_catalog.pg_authid"), pb.EnfAction_DENY,
			"no version → still denied (fail-closed)")
	})

	// KT: SystemClassificationEnforcementDbTest.kt#a dangerous system function denies by policy on a versioned datasource
	// `a dangerous system function denies by policy on a versioned datasource`
	//
	// A query calling a dangerous builtin is DENIED by the shipped system:data-leak / critical forbid,
	// via the Cedar Function resource the classifier marshals from the emitted bare call name. These two
	// functions are NOT in the old dangerousFuncs admission backstop, so the DENY here proves the POLICY
	// path — the net-new coverage — and not the pre-existing hardcode. The FROM clause lets the statement
	// pass admission (the no-FROM guard) and reach the function gate; the table (pg_class,
	// system:catalog) is itself browsable, so absent the function the query would ALLOW.
	t.Run("a dangerous system function denies by policy on a versioned datasource", func(t *testing.T) {
		fx.SetEngineVersion(version(pg17))
		// Safe baseline: the same browsable table with a SAFE function still ALLOWs — the gate is
		// specific to dangerous functions, it does not deny every function.
		wantAction(t, decide("select now() from pg_catalog.pg_class"), pb.EnfAction_ALLOW,
			"a safe function must not trip the gate")
		wantAction(t, decide("select pg_terminate_backend(1) from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"pg_terminate_backend (system:critical) must deny by policy")
		wantAction(t, decide("select get_raw_page('pg_class', 0) from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"get_raw_page (system:data-leak) must deny by policy")

		// No version → no classification → the function gate is INERT. This DENY is deny-by-default for
		// the ungranted table scan, not the function forbid — proven by the safe-baseline ALLOW above
		// flipping to DENY here.
		fx.SetEngineVersion(nil)
		wantAction(t, decide("select now() from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"no version → table scan itself denies (function gate inert)")
	})

	// KT: SystemClassificationEnforcementDbTest.kt#the dangerous function forbid overrides even a broad datasource read grant
	// 🔒 `the dangerous function forbid overrides even a broad datasource read grant`
	//
	// Load-bearing forbid, mirroring the table case: the broad grant permits the browsable table AND
	// (via the Datasource parent) the Function resource, but Cedar's forbid on system:critical /
	// data-leak overrides the permit → DENY.
	t.Run("the dangerous function forbid overrides even a broad datasource read grant", func(t *testing.T) {
		fx.SetEngineVersion(version(pg17))
		const broadFn = "broad-fn@example.com"
		grantNewRole(t, fx, broadFn, "broad-fn-reader")
		fx.AddCedarPolicy("test-broad-fn-reader-grant",
			`permit(principal in Role::"broad-fn-reader", action, resource in Datasource::"`+fx.DatasourceName+`");`)

		decideAsBroadFn := func(sql string) query.DecisionContext { return gateDecide(fx, broadFn, sql, classifier) }

		// The broad grant genuinely permits: a safe function over the table ALLOWs.
		wantAction(t, decideAsBroadFn("select now() from pg_catalog.pg_class"), pb.EnfAction_ALLOW,
			"broad grant permits a safe function")
		// ...but the forbid OVERRIDES that broad grant on a dangerous function (critical AND data-leak).
		wantAction(t, decideAsBroadFn("select pg_terminate_backend(1) from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"forbid overrides the broad grant (critical function)")
		wantAction(t, decideAsBroadFn("select get_raw_page('pg_class', 0) from pg_catalog.pg_class"), pb.EnfAction_DENY,
			"forbid overrides the broad grant (data-leak function)")
	})

	// KT: SystemClassificationEnforcementDbTest.kt#the dangerous-function deny wins over the uncovered-table deny
	// `the dangerous-function deny wins over the uncovered-table deny`
	//
	// DENY PRECEDENCE, and it is an ordering assertion the verdict alone cannot make. The dangerous-
	// function gate (step 22) runs AHEAD of the uncovered-table gate (step 25), so when a query trips
	// BOTH the deny must attribute to the function, not to a bland uncovered-table scan.
	// `get_raw_page('users',0) from users` traces no column, so `users` scans uncovered; a principal with
	// connect+select but NO table read reaches BOTH gates, which is what makes the winning reason
	// observable. Both orderings deny — only the function-first ordering NAMES the function, which is
	// the clearer audit/approval reason and the guard that the function gate is not reordered below the
	// data gates.
	t.Run("the dangerous-function deny wins over the uncovered-table deny", func(t *testing.T) {
		fx.SetEngineVersion(version(pg17))
		const who = "fngate@example.com"
		grantNewRole(t, fx, who, "fngate-connect-only")
		// connect + select ONLY — no table read on `users`, so the uncovered-table gate WOULD also deny.
		fx.AddCedarPolicy("test-fngate-connect-select",
			`permit(principal in Role::"fngate-connect-only", action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::"`+
				fx.DatasourceName+`");`)

		d := gateDecide(fx, who, "select get_raw_page('users', 0) from users", classifier)
		wantAction(t, d, pb.EnfAction_DENY, "a dangerous function over an uncovered table denies")
		why := reason(d)
		if !strings.Contains(why, "get_raw_page") {
			t.Errorf("the deny reason must name the dangerous function (function gate first): %s", why)
		}
		if strings.Contains(why, "no read grant for scanned table") {
			t.Errorf("the uncovered-table gate must NOT win — the function gate runs first: %s", why)
		}
	})
}
