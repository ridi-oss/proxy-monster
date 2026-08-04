package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// BaselineDangerousFunctionEnforcementDbTest.kt — 225 LOC, 7 cases (06-query-decision.md §7, steps
// 16/22).
//
// Dangerous-function enforcement on real PostgreSQL/MySQL + real Cedar (docs/facts-emission.md).
// Enforcement runs ENTIRELY through the control-plane function gate, backed by the per-version
// manifest AND the version-independent BaselineDangerousFunctions floor.
//
// 🔒 WHY THE `now()` BASELINE IS IN EVERY CASE. The datasource grants `analyst@example.com` a read on
// `users`, so a FROM'd function-of-literals over `users` scans the table UNCOVERED but the table gate
// PASSES — which is what makes each DENY attributable to the FUNCTION gate rather than a missing table
// grant. Drop the `now()`/`count(*)` ALLOW and every DENY below becomes unfalsifiable.
//
// Every former `dangerousFuncs` name is asserted DENY twice:
//   - on a GOVERNED datasource (engine_version set)     → the manifest classifies it; and
//   - on a NO-manifest datasource (engine_version null) → the baseline floor classifies it.
//
// That per-state PARITY is the security property the retired hardcode used to provide, now provided by
// policy.
func TestBaselineDangerousFunctionEnforcementDb(t *testing.T) {
	pg := newEnforcementFixture(t, dbtest.EnginePostgres)
	my := newEnforcementFixture(t, dbtest.EngineMySQL)
	classifier := shippedClassifier(t)

	const (
		pg17    = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"
		mysql80 = "8.0.44"
	)
	version := func(v string) *string { return &v }

	// configure is the Kotlin's private helper: engine_version + posture tags, then the row re-read
	// every decide depends on.
	configure := func(fx *dbtest.EnforcementFixture, v *string, tags ...string) {
		fx.SetEngineVersion(v)
		fx.SetTags(tags...)
	}
	decide := func(fx *dbtest.EnforcementFixture, sql string) query.DecisionContext {
		return gateDecide(fx, dbtest.FixturePrincipal, sql, classifier)
	}

	// The former probe.go `dangerousFuncs`, PostgreSQL members (load_file is MySQL, asserted
	// separately). Each is used WITH a FROM — that mirrors the real gated shape, since the no-FROM form
	// is denied earlier by admission's unchanged allowlist. Args are SHAPE-ONLY: the statement is never
	// executed, it DENYs at decide time.
	pgDangerousCalls := []string{
		"dblink('c', 'SELECT 1')",
		"dblink_exec('c', 'SELECT 1')",
		"dblink_open('c')",
		"dblink_fetch('c')",
		"dblink_send_query('c', 'SELECT 1')",
		"pg_read_file('/etc/passwd')",
		"pg_read_binary_file('/etc/passwd')",
		"pg_ls_dir('/')",
		"pg_stat_file('/etc/passwd')",
		"lo_import('/etc/passwd')",
		"lo_export(16384, '/tmp/x')",
		"query_to_xml('SELECT 1', true, false, '')",
		"query_to_xml_and_xmlschema('SELECT 1', true, false, '')",
		"xpath_table('a', 'b', 'c', 'd', 'e')",
	}

	// Dangerous PG functions the shipped manifest classifies (exact names + `functionFamilies`
	// prefixes) but the hand-curated 15-name baseline floor MISSED — the cleartext-PII leak class. Each
	// is a whole-table/page/large-object/backend reader that reads data INVISIBLE to lineage (its data
	// source is a string/regclass/oid ARGUMENT, not a scanned column), so on a no-manifest datasource a
	// flat 15-name baseline would return null → ALLOW → the backend would stream e.g. the entire `users`
	// table as XML, cleartext rrn included.
	pgManifestOnlyDangerousCalls := []string{
		"table_to_xml('public.users'::regclass, true, false, '')",      // table_to_xml* family (the canonical dump)
		"query_to_xmlschema('SELECT rrn FROM users', true, false, '')", // query_to_xml* family (NOT the baseline's two exact names)
		"get_raw_page('users', 0)",                                     // pageinspect, exact
		"pg_terminate_backend(1)",                                      // critical, exact
		"lo_get(16384)",                                                // large-object read, exact
	}

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#a null classifier service STILL denies a dangerous builtin via the static baseline
	// 🔒 `a null classifier service STILL denies a dangerous builtin via the static baseline`
	//
	// Retiring the analyzer's dangerousFuncs walk left a LATENT FAIL-OPEN: the function gate used to be
	// guarded by `systemClassification != null`, so a decideQuery caller that wired NO classifier
	// service skipped the gate entirely and relayed a dangerous builtin. The fix classifies via the
	// STATIC baseline when no service is present — `classifyFunctions`' elvis is a FLOOR, not a fallback
	// chain (INV-A5-59). Every production path passes a service today; this proves the floor holds even
	// if one didn't.
	t.Run("a null classifier service STILL denies a dangerous builtin via the static baseline", func(t *testing.T) {
		configure(pg, version(pg17), "system:production")
		decideNoService := func(sql string) query.DecisionContext {
			return gateDecide(pg, dbtest.FixturePrincipal, sql, nil) // no service wired
		}
		wantAction(t, decideNoService("select now() from users"), pb.EnfAction_ALLOW,
			"a safe function must still ALLOW with no service (no over-deny)")
		wantAction(t, decideNoService("select pg_read_file('/etc/passwd') from users"), pb.EnfAction_DENY,
			"a dangerous builtin DENIES via the static baseline even with no classifier service")
		wantAction(t, decideNoService("select dblink_exec('x') from users"), pb.EnfAction_DENY,
			"a critical baseline function DENIES with no service")
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#every former dangerousFuncs name denies WITH a FROM on a governed PG datasource
	// `every former dangerousFuncs name denies WITH a FROM on a governed PG datasource`
	t.Run("every former dangerousFuncs name denies WITH a FROM on a governed PG datasource", func(t *testing.T) {
		configure(pg, version(pg17), "system:production")
		// The table gate is not the reason: a safe function over the SAME readable table ALLOWs.
		wantAction(t, decide(pg, "select now() from users"), pb.EnfAction_ALLOW, "safe function baseline must ALLOW")
		for _, call := range pgDangerousCalls {
			d := decide(pg, "select "+call+" from users")
			wantAction(t, d, pb.EnfAction_DENY, "governed PG: %q must DENY (manifest function forbid)", call)
			wantDetailContains(t, d, "dangerous system function", "DENY names the function gate")
		}
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#every former dangerousFuncs name STILL denies on a no-manifest PG datasource (the baseline)
	// `every former dangerousFuncs name STILL denies on a no-manifest PG datasource (the baseline)`
	t.Run("every former dangerousFuncs name STILL denies on a no-manifest PG datasource (the baseline)", func(t *testing.T) {
		// no engine_version → no governing manifest → baseline floor only.
		configure(pg, nil, "system:production")
		// The user table stays readable without a manifest, so a safe function over it ALLOWs — the
		// DENYs below are the baseline function forbid, not a table-scan deny.
		wantAction(t, decide(pg, "select now() from users"), pb.EnfAction_ALLOW,
			"no-manifest safe function must still ALLOW")
		for _, call := range pgDangerousCalls {
			d := decide(pg, "select "+call+" from users")
			wantAction(t, d, pb.EnfAction_DENY, "no-manifest PG: %q must STILL DENY (baseline floor)", call)
			wantDetailContains(t, d, "dangerous system function", "DENY names the function gate")
		}
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#manifest-only dangerous functions deny on a no-manifest datasource via the union floor
	// `manifest-only dangerous functions deny on a no-manifest datasource via the union floor`
	//
	// 🔒 INV-A13-29. A no-manifest datasource does NOT fall back to the thin 15-name baseline for
	// functions — it unions ClassifyBareFunction across every SHIPPED manifest of the engine (pg 16 ∪
	// 17), so the manifest's whole dangerous set (including the `table_to_xml*` / pageinspect / `lo_*`
	// families) classifies there too. The assertion is PARITY: each call DENIES on a no-manifest
	// datasource AND on an uncertified one AND on a certified one.
	t.Run("manifest-only dangerous functions deny on a no-manifest datasource via the union floor", func(t *testing.T) {
		for _, v := range []*string{nil, version("PostgreSQL 15.6 on x86_64-pc-linux-gnu"), version(pg17)} {
			label := "no-manifest"
			if v != nil {
				label = *v
			}
			configure(pg, v, "system:production")
			wantAction(t, decide(pg, "select now() from users"), pb.EnfAction_ALLOW,
				"[%s] safe fn still ALLOWs (no over-deny)", label)
			for _, call := range pgManifestOnlyDangerousCalls {
				d := decide(pg, "select "+call+" from users")
				wantAction(t, d, pb.EnfAction_DENY,
					"[%s]: %q must DENY (union floor / manifest function forbid)", label, call)
				wantDetailContains(t, d, "dangerous system function", "["+label+"] DENY names the function gate")
			}
		}
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#safe functions and a user UDF are unaffected by the function gate
	// `safe functions and a user UDF are unaffected by the function gate`
	//
	// The gate is specific to the dangerous SET, not "any function": an unclassified name is ABSENT, and
	// for a function absent means SAFE (the opposite of a utility — INV-A5-56 vs INV-A5-60).
	t.Run("safe functions and a user UDF are unaffected by the function gate", func(t *testing.T) {
		configure(pg, version(pg17), "system:production")
		wantAction(t, decide(pg, "select now() from users"), pb.EnfAction_ALLOW, "now() unaffected")
		wantAction(t, decide(pg, "select count(*) from users"), pb.EnfAction_ALLOW, "count(*) unaffected")
		wantAction(t, decide(pg, "select lower(email) from users"), pb.EnfAction_ALLOW, "lower(email) unaffected")
		wantAction(t, decide(pg, "select my_udf(id) from users"), pb.EnfAction_ALLOW, "a user UDF is not classified/denied")
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#a dangerous function is denied on a preset-development datasource, not relayed via sql-unanalyzable
	// 🔒 `a dangerous function is denied on a preset-development datasource, not relayed via sql-unanalyzable`
	//
	// The improvement this case locks: BEFORE the change, dangerousFuncs made a FROM'd dangerous call
	// `resolved=false`, so on a dev datasource that permits `sql.unanalyzable` it RELAYED VERBATIM —
	// i.e. executed the function. Now the call resolves, emits a function fact, and is forbidden by the
	// function gate. `system:critical` (lo_export) is forbidden UNCONDITIONALLY by -130, even under
	// system:development.
	t.Run("a dangerous function is denied on a preset-development datasource, not relayed via sql-unanalyzable", func(t *testing.T) {
		configure(pg, version(pg17), "system:development")

		// Control: the sql.unanalyzable relay path IS live on this dev datasource — an actually
		// unanalyzable statement (NATURAL JOIN) is relayed verbatim. This is the path the dangerous call
		// would take without the function gate, and asserting it is what makes the DENYs below mean
		// "the gate fired" rather than "the relay was never available".
		relay := decide(pg, "select count(*) from orders natural join users")
		wantAction(t, relay, pb.EnfAction_ALLOW, "dev datasource relays an unanalyzable statement via sql.unanalyzable")
		if !relay.Passthrough {
			t.Error("the unanalyzable relay is a verbatim passthrough")
		}

		// RESOLVED forms: a projected/scalar dangerous call RESOLVES + emits a function fact → DENIED by
		// the function gate, NOT relayed, even on dev (lo_export is critical → -130).
		critical := decide(pg, "select lo_export(16384, '/tmp/x') from users")
		wantAction(t, critical, pb.EnfAction_DENY, "a resolved critical function is denied on dev, not relayed verbatim")
		wantDetailContains(t, critical, "dangerous system function", "the DENY is the function gate, not the relay")

		// RESOLVED=FALSE forms. The set-returning shape `SELECT * FROM dblink(...)` analyzes
		// resolved=false (unexpandable `*`), but the analyzer emits the function fact even on a
		// post-parse failure, so step 16 runs the SAME function policy the resolved path does — BEFORE
		// the sql.unanalyzable relay.
		//
		//   - dblink is system:data-leak → the system:development relaxation applies (consistent with a
		//     RESOLVED dblink on dev), so it proceeds to the verbatim relay.
		dataLeak := decide(pg, "select * from dblink('h','SELECT 1') as t(c text)")
		wantAction(t, dataLeak, pb.EnfAction_ALLOW,
			"a resolved=false data-leak function follows the dev relaxation, consistent with the resolved form")
		if !dataLeak.Passthrough {
			t.Error("the data-leak dev relaxation proceeds to the sql.unanalyzable verbatim relay")
		}
		//   - but a system:critical function (dblink_exec) HIDING IN a resolved=false statement DENIES
		//     even on a system:development datasource: the function gate runs ahead of the relay, so a
		//     critical builtin is NEVER relayed verbatim (-130 is unconditional). This is the residue
		//     that change CLOSED.
		criticalUnresolved := decide(pg, "select dblink_exec('c','s') from users natural join users")
		wantAction(t, criticalUnresolved, pb.EnfAction_DENY,
			"a resolved=false critical function is denied even on a system:development datasource (not relayed via sql.unanalyzable)")
		wantDetailContains(t, criticalUnresolved, "dangerous system function",
			"the DENY is the function gate, not the relay")

		// Both resolved=false forms DENY on the production floor (no sql.unanalyzable permit).
		configure(pg, version(pg17), "system:production")
		wantAction(t, decide(pg, "select * from dblink('h','SELECT 1') as t(c text)"), pb.EnfAction_DENY,
			"resolved=false data-leak denies on the floor")
		wantAction(t, decide(pg, "select dblink_exec('c','s') from users natural join users"), pb.EnfAction_DENY,
			"resolved=false critical denies on the floor")

		// ⚠️ BOUNDARY, explicit and NOT a gap this closes: the function-fact backfill only fires on a
		// POST-PARSE failure. A statement sqlglot cannot PARSE emits no function facts, so a critical
		// builtin inside a parse-failing statement the backend still accepts takes the sql.unanalyzable
		// verbatim relay on a system:development datasource (it DENIES on the floor). That is the
		// accepted `sql.unanalyzable ⊇ exec` posture an operator opts into with system:development —
		// pre-existing, unclosable via function facts, and the multi-statement route into it is already
		// shut, since admission rejects >1-statement batches.
	})

	// KT: BaselineDangerousFunctionEnforcementDbTest.kt#MySQL load_file denies WITH a FROM on both a governed and a no-manifest datasource
	// `MySQL load_file denies WITH a FROM on both a governed and a no-manifest datasource`
	t.Run("MySQL load_file denies WITH a FROM on both a governed and a no-manifest datasource", func(t *testing.T) {
		// Governed: the manifest classifies load_file (__builtin__) system:data-leak.
		configure(my, version(mysql80), "system:production")
		wantAction(t, decide(my, "select count(*) from users"), pb.EnfAction_ALLOW, "safe function baseline must ALLOW")
		wantAction(t, decide(my, "select load_file('/etc/passwd') from users"), pb.EnfAction_DENY,
			"governed MySQL: load_file must DENY")

		// No governing manifest: an UNCERTIFIED but parseable MySQL version keeps analysis live while
		// selecting no shipped classifier, so this still isolates the version-independent floor.
		configure(my, version("5.7.44"), "system:production")
		wantAction(t, decide(my, "select count(*) from users"), pb.EnfAction_ALLOW,
			"no-manifest safe function must still ALLOW")
		wantAction(t, decide(my, "select load_file('/etc/passwd') from users"), pb.EnfAction_DENY,
			"no-manifest MySQL: load_file must STILL DENY (baseline)")
	})
}
