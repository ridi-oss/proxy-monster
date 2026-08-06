package datasource

import "testing"

// Cases 2-6 of SystemClassificationServiceTest.kt, ported against the REAL BUNDLED MANIFESTS.
//
// systemclass_test.go says why they were not here before: "🔴 TODO(A13): cases 2-6 construct
// `SystemClassificationService()` over THE REAL CLASSPATH MANIFESTS, so they prove
// parse→resolve→classify end to end. internal/engine is not ported, so the manifests do not exist in Go
// yet. … When A13 lands, re-point cases 2-6 at the real store; a fake-only suite proves the service
// agrees with itself and nothing else."
//
// A13 HAS landed (internal/engine, with the four embedded manifests) and systemclass_bundled.go is the
// wiring, so this file is that re-pointing. The fake-store tests in systemclass_test.go stay: they pin
// the floor combinator and the two absence polarities over a fixture the shipped manifests cannot
// express. They are NOT these cases — a fake store with two synthetic postgres manifests and no mysql
// manifest at all cannot assert "Aurora MySQL 3.x resolves to the MySQL 8.0 manifest", which is the
// whole point of cases 2 and 6.
//
// Kotlin constructs the service as bare `SystemClassificationService()`, whose two default arguments
// are the shipped bundle and the static baseline, and whose allowFallback defaults to FALSE
// (INV-A13-27). bundledService is that spelling.

func bundledService(t *testing.T) *SystemClassificationService {
	t.Helper()
	svc, err := NewBundledSystemClassificationService(false)
	if err != nil {
		t.Fatalf("the bundled manifests must load, validate and index: %v", err)
	}
	return svc
}

// tagForTable / tagForFunction mirror the Kotlin's nullable String return, so the assertions below read
// the way the Kotlin ones do: a tag id, or "" for null.
func tagForTable(t *testing.T, svc *SystemClassificationService, e Engine, version *string, catalog, schema, table string) string {
	t.Helper()
	tag, ok := svc.TagForTable(e, version, catalog, schema, table)
	if !ok {
		return ""
	}
	return tag
}

func tagForFunction(t *testing.T, svc *SystemClassificationService, e Engine, version *string, name string) string {
	t.Helper()
	tag, ok := svc.TagForFunction(e, version, name)
	if !ok {
		return ""
	}
	return tag
}

// Case 2 — 🔒 INV-A5-61 end to end. The Kotlin's own comment: "Before the fix this returned null (regex
// grabbed 3.04.0 → no manifest) → classification inert." That is the whole reason the case exists, and it
// is only observable through the REAL mysql/8.0 manifest — a parse test alone cannot see it.
// KT: SystemClassificationServiceTest.kt#Aurora MySQL 3_x version() resolves to the MySQL 8_0 manifest and classifies
func TestAuroraMySQL3xVersionResolvesToTheMySQL80ManifestAndClassifies(t *testing.T) {
	svc := bundledService(t)
	auroraMysql := strptr("8.0.mysql_aurora.3.04.0 (aurora 3.04.0)")
	if got := tagForTable(t, svc, EngineMySQL, auroraMysql, "def", "mysql", "user"); got != "system:critical" {
		t.Errorf("mysql.user = %q, want system:critical", got)
	}
	if got := tagForTable(t, svc, EngineMySQL, auroraMysql, "def", "information_schema", "COLUMN_STATISTICS"); got != "system:data-leak" {
		t.Errorf("information_schema.COLUMN_STATISTICS = %q, want system:data-leak", got)
	}
	if got := tagForTable(t, svc, EngineMySQL, auroraMysql, "def", "information_schema", "TABLES"); got != "system:catalog" {
		t.Errorf("information_schema.TABLES = %q, want system:catalog", got)
	}
}

// Case 3.
// KT: SystemClassificationServiceTest.kt#Aurora PostgreSQL resolves to the PG major manifest
func TestAuroraPostgreSQLResolvesToThePGMajorManifest(t *testing.T) {
	svc := bundledService(t)
	auroraPg := strptr("PostgreSQL 17.4 on x86_64 (aurora 17.4...)")
	if got := tagForTable(t, svc, EnginePostgres, auroraPg, "acme", "pg_catalog", "pg_authid"); got != "system:critical" {
		t.Errorf("pg_authid = %q, want system:critical", got)
	}
	if got := tagForTable(t, svc, EnginePostgres, auroraPg, "acme", "pg_catalog", "pg_class"); got != "system:catalog" {
		t.Errorf("pg_class = %q, want system:catalog", got)
	}
	// no version → no manifest → absent (deny-by-default)
	if got := tagForTable(t, svc, EnginePostgres, nil, "acme", "pg_catalog", "pg_authid"); got != "" {
		t.Errorf("no version must yield no tag, got %q", got)
	}
}

// Case 4 — 🔒 INV-A5-57 (bare names only) + INV-A5-58 (the no-manifest union reaches the FULL manifest
// dangerous set, not the thin baseline).
// KT: SystemClassificationServiceTest.kt#tagForFunction classifies dangerous PostgreSQL builtins from the bare name
func TestTagForFunctionClassifiesDangerousPostgreSQLBuiltinsFromTheBareName(t *testing.T) {
	svc := bundledService(t)
	pg := strptr("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
	tag := func(n string) string { return tagForFunction(t, svc, EnginePostgres, pg, n) }

	// pg_catalog family (pg_read_) + exacts, resolved despite the missing qualifier.
	for _, name := range []string{"pg_read_file", "pg_read_binary_file", "pg_stat_file"} {
		if got := tag(name); got != "system:data-leak" {
			t.Errorf("%s = %q, want system:data-leak", name, got)
		}
	}
	// pg_catalog critical exacts NOT in the dangerousFuncs backstop — the net-new policy coverage.
	for _, name := range []string{"pg_terminate_backend", "pg_cancel_backend", "set_config", "current_setting"} {
		if got := tag(name); got != "system:critical" {
			t.Errorf("%s = %q, want system:critical", name, got)
		}
	}
	// Cross-schema (`*`) extension functions: exacts (dblink family) + pageinspect families.
	for _, name := range []string{"dblink", "dblink_get_result", "get_raw_page", "heap_page_items"} {
		if got := tag(name); got != "system:data-leak" {
			t.Errorf("%s = %q, want system:data-leak", name, got)
		}
	}
	// Case-insensitive (PG folds unquoted identifiers).
	if got := tag("PG_TERMINATE_BACKEND"); got != "system:critical" {
		t.Errorf("PG_TERMINATE_BACKEND = %q, want system:critical", got)
	}
	// Safe builtins / unclassified user functions → absent (never marshalled, never denied).
	for _, safe := range []string{"now", "count", "lower", "my_udf"} {
		if got := tag(safe); got != "" {
			t.Errorf("%s = %q, want no tag", safe, got)
		}
	}
	// No manifest / no version → the version-INDEPENDENT union floor over every shipped manifest of the
	// engine classifies the FULL manifest dangerous set, not just the thin baseline.
	for _, tc := range []struct{ name, want string }{
		{"pg_read_file", "system:data-leak"},
		{"set_config", "system:critical"},
		{"table_to_xml", "system:data-leak"}, // table_to_xml* family, not in the baseline
		{"get_raw_page", "system:data-leak"}, // pageinspect exact, not in the baseline
		{"pg_terminate_backend", "system:critical"},
	} {
		if got := tagForFunction(t, svc, EnginePostgres, nil, tc.name); got != tc.want {
			t.Errorf("no-manifest %s = %q, want %s", tc.name, got, tc.want)
		}
	}
	// A safe builtin / UDF still stays absent on a no-manifest datasource — the union floor only raises the
	// manifests' DANGEROUS classifications, it does not deny-by-default every function.
	for _, safe := range []string{"now", "my_udf"} {
		if got := tagForFunction(t, svc, EnginePostgres, nil, safe); got != "" {
			t.Errorf("no-manifest %s = %q, want no tag", safe, got)
		}
	}
}

// Case 5 — 🔒 INV-A5-59. The version-independent baseline is a FLOOR that classifies the
// cross-engine-stable dangerous IO/exec builtins on EVERY datasource state, governed or not, with the
// SAME tag the manifests assign, so removing the hardcode leaves none of them ungated.
// KT: SystemClassificationServiceTest.kt#the baseline floor classifies every former dangerousFuncs name with or without a manifest
func TestTheBaselineFloorClassifiesEveryFormerDangerousFuncsNameWithOrWithoutAManifest(t *testing.T) {
	svc := bundledService(t)
	pg := strptr("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
	my := strptr("8.0.44")

	dataLeak := []string{
		"dblink", "dblink_open", "dblink_fetch", "dblink_send_query",
		"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import",
		"query_to_xml", "query_to_xml_and_xmlschema", "xpath_table",
	}
	critical := []string{"dblink_exec", "lo_export"}
	for _, fn := range dataLeak {
		// Governed PG: manifest ∪ baseline (floor) = the shared tag.
		if got := tagForFunction(t, svc, EnginePostgres, pg, fn); got != "system:data-leak" {
			t.Errorf("%s governed = %q, want system:data-leak", fn, got)
		}
		// No manifest (nil version): the baseline alone still classifies it.
		if got := tagForFunction(t, svc, EnginePostgres, nil, fn); got != "system:data-leak" {
			t.Errorf("%s no-manifest baseline = %q, want system:data-leak", fn, got)
		}
	}
	for _, fn := range critical {
		if got := tagForFunction(t, svc, EnginePostgres, pg, fn); got != "system:critical" {
			t.Errorf("%s governed = %q, want system:critical", fn, got)
		}
		if got := tagForFunction(t, svc, EnginePostgres, nil, fn); got != "system:critical" {
			t.Errorf("%s no-manifest baseline = %q, want system:critical", fn, got)
		}
	}
	// MySQL load_file — governed and un-governed both classify via the baseline.
	if got := tagForFunction(t, svc, EngineMySQL, my, "load_file"); got != "system:data-leak" {
		t.Errorf("load_file governed = %q, want system:data-leak", got)
	}
	if got := tagForFunction(t, svc, EngineMySQL, nil, "load_file"); got != "system:data-leak" {
		t.Errorf("load_file no-manifest baseline = %q, want system:data-leak", got)
	}
	// The floor never classifies a safe function, on any datasource state.
	for _, safe := range []string{"now", "count", "lower", "concat", "my_udf"} {
		if got := tagForFunction(t, svc, EnginePostgres, pg, safe); got != "" {
			t.Errorf("%s governed = %q, want no tag", safe, got)
		}
		if got := tagForFunction(t, svc, EnginePostgres, nil, safe); got != "" {
			t.Errorf("%s no-manifest = %q, want no tag", safe, got)
		}
	}
}

// Case 6 — 🔒 INV-A5-57. The analyzer drops the `mysql.` qualifier, so the bare `rds_kill` must still
// resolve against the mysql system schema (the resolver iterates every system schema).
// KT: SystemClassificationServiceTest.kt#tagForFunction classifies dangerous MySQL builtins including Aurora rds_ from the bare name
func TestTagForFunctionClassifiesDangerousMySQLBuiltinsIncludingAuroraRdsFromTheBareName(t *testing.T) {
	svc := bundledService(t)
	my := strptr("8.0.mysql_aurora.3.04.0 (aurora 3.04.0)")
	tag := func(n string) string { return tagForFunction(t, svc, EngineMySQL, my, n) }

	// __builtin__ logical schema: load_file exact + keyring_ family.
	if got := tag("load_file"); got != "system:data-leak" {
		t.Errorf("load_file = %q, want system:data-leak", got)
	}
	if got := tag("keyring_key_generate"); got != "system:critical" {
		t.Errorf("keyring_key_generate = %q, want system:critical", got)
	}
	// mysql.rds_ family.
	for _, name := range []string{"rds_kill", "rds_set_configuration"} {
		if got := tag(name); got != "system:critical" {
			t.Errorf("%s = %q, want system:critical", name, got)
		}
	}
	for _, safe := range []string{"concat", "my_udf"} {
		if got := tag(safe); got != "" {
			t.Errorf("%s = %q, want no tag", safe, got)
		}
	}
}
