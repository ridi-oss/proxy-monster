package datasource

import (
	"testing"
)

// The typed-engine domain API (engine.go) — pure, no DB. Pins the parse/serialize round-trip and the
// fail-closed edges the "engine is a type, not a string" contract depends on, plus the per-engine
// namespace facts and the SystemSchemas / IsFixedSystemSchema / IsSystemSchema split.
//
// Port of EnginesTest.kt (122 LOC, 13 cases) — 05-datasources-catalog.md §9. All 13 are pure and
// need nothing: "Port them first" (§9's note on cases 7-13).

// case 1
func TestEngineFromWireAcceptsCanonicalSpellingsCaseInsensitively(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Engine
	}{
		{"mysql", EngineMySQL},
		{"MySQL", EngineMySQL},
		{"postgres", EnginePostgres},
		{"POSTGRES", EnginePostgres},
	} {
		got, err := EngineFromWire(tc.raw)
		if err != nil {
			t.Fatalf("EngineFromWire(%q): unexpected error %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("EngineFromWire(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// case 2 — 🔒 INV-A5-7
func TestEngineFromWireIsFailClosedOnUnknownEnginesAndThePostgresqlAlias(t *testing.T) {
	for _, raw := range []string{"postgresql", "oracle", ""} {
		if _, ok := EngineFromWireOrNull(raw); ok {
			t.Errorf("EngineFromWireOrNull(%q) resolved; Kotlin and Go both accept exactly {mysql, postgres}", raw)
		}
	}
	for _, raw := range []string{"postgresql", "sqlite"} {
		if _, err := EngineFromWire(raw); err == nil {
			t.Errorf("EngineFromWire(%q) did not fail", raw)
		}
	}
}

// case 3
func TestEngineWireCodecRoundTripsAsTheExactWireString(t *testing.T) {
	for _, tc := range []struct {
		engine Engine
		wire   string
	}{
		{EngineMySQL, `"mysql"`},
		{EnginePostgres, `"postgres"`},
	} {
		encoded, err := MarshalEngineJSON(tc.engine)
		if err != nil {
			t.Fatalf("MarshalEngineJSON(%v): %v", tc.engine, err)
		}
		if string(encoded) != tc.wire {
			t.Errorf("MarshalEngineJSON(%v) = %s, want %s", tc.engine, encoded, tc.wire)
		}
		decoded, err := UnmarshalEngineJSON([]byte(tc.wire))
		if err != nil {
			t.Fatalf("UnmarshalEngineJSON(%s): %v", tc.wire, err)
		}
		if decoded != tc.engine {
			t.Errorf("UnmarshalEngineJSON(%s) = %v, want %v", tc.wire, decoded, tc.engine)
		}
	}
}

// case 4
func TestWireNameAndDialectAreTheCanonicalMappings(t *testing.T) {
	if got := MustWireName(EngineMySQL); got != "mysql" {
		t.Errorf("wireName(MYSQL) = %q", got)
	}
	if got := MustWireName(EnginePostgres); got != "postgres" {
		t.Errorf("wireName(POSTGRES) = %q", got)
	}
	mysqlDialect, err := EngineDialect(EngineMySQL)
	if err != nil || mysqlDialect != DialectMySQL {
		t.Errorf("dialect(MYSQL) = %v, %v", mysqlDialect, err)
	}
	pgDialect, err := EngineDialect(EnginePostgres)
	if err != nil || pgDialect != DialectPostgres {
		t.Errorf("dialect(POSTGRES) = %v, %v", pgDialect, err)
	}
}

// case 5
func TestCatalogNameDefaultSchemaAndResolveSchemaFollowEachEnginesNamespaceModel(t *testing.T) {
	mustString := func(v string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return v
	}
	if got := mustString(CatalogName(EngineMySQL, "app")); got != "def" {
		t.Errorf("catalogName(MYSQL, app) = %q", got)
	}
	if got := mustString(CatalogName(EnginePostgres, "app")); got != "app" {
		t.Errorf("catalogName(POSTGRES, app) = %q", got)
	}
	// In ANSI terms a MySQL "database" is the schema, so the default schema is the database name;
	// Postgres defaults to "public".
	if got := mustString(DefaultSchema(EngineMySQL, "app")); got != "app" {
		t.Errorf("defaultSchema(MYSQL, app) = %q", got)
	}
	if got := mustString(DefaultSchema(EnginePostgres, "app")); got != "public" {
		t.Errorf("defaultSchema(POSTGRES, app) = %q", got)
	}
	// resolveSchema: the "public" default selector maps to the default schema; any other value is an
	// explicit schema/database used as-is — so MySQL addresses every database, not only "app".
	if got := mustString(ResolveSchema(EngineMySQL, "public", "app")); got != "app" {
		t.Errorf("resolveSchema(MYSQL, public, app) = %q", got)
	}
	if got := mustString(ResolveSchema(EngineMySQL, "reporting", "app")); got != "reporting" {
		t.Errorf("resolveSchema(MYSQL, reporting, app) = %q", got)
	}
	if got := mustString(ResolveSchema(EnginePostgres, "public", "app")); got != "public" {
		t.Errorf("resolveSchema(POSTGRES, public, app) = %q", got)
	}
	if got := mustString(ResolveSchema(EnginePostgres, "reporting", "app")); got != "reporting" {
		t.Errorf("resolveSchema(POSTGRES, reporting, app) = %q", got)
	}
}

// case 6 — 🔒 INV-A5-4: engine mappings are total-or-throw, never defaulted.
func TestValueReturningEngineFunctionsFailClosedOnAnUnspecifiedEngine(t *testing.T) {
	if _, err := WireName(EngineUnspecified); err == nil {
		t.Error("wireName did not fail closed")
	}
	if _, err := EngineDialect(EngineUnspecified); err == nil {
		t.Error("dialect did not fail closed")
	}
	if _, err := CatalogName(EngineUnspecified, "db"); err == nil {
		t.Error("catalogName did not fail closed")
	}
	if _, err := DefaultSchema(EngineUnspecified, "db"); err == nil {
		t.Error("defaultSchema did not fail closed")
	}
	if _, err := SystemSchemas(EngineUnspecified); err == nil {
		t.Error("systemSchemas did not fail closed")
	}
	if _, err := IsFixedSystemSchema(EngineUnspecified, "x"); err == nil {
		t.Error("isFixedSystemSchema did not fail closed")
	}
}

// ADDED (not in EnginesTest): §9 "Coverage gaps in A5" names the three untested `else -> error` arms
// and says requireCaseMode is "the one worth adding — it has TWO fail-closed paths (the
// unspecified-engine error and the requireNotNull of INV-A5-5) and neither is pinned."
func TestRequireCaseModeHasTwoFailClosedPaths(t *testing.T) {
	if _, err := RequireCaseMode(EngineUnspecified, nil); err == nil {
		t.Error("requireCaseMode did not fail closed on an unspecified engine")
	}
	if _, err := RequireCaseMode(EngineMySQL, nil); err == nil {
		t.Error("MySQL must refuse to analyze without a captured lower_case_table_names (INV-A5-5)")
	}
	// 0 is a VALID mode, not "absent" — the whole reason the signature is (*int, error).
	zero := 0
	got, err := RequireCaseMode(EngineMySQL, &zero)
	if err != nil {
		t.Fatalf("requireCaseMode(MYSQL, 0): %v", err)
	}
	if got == nil || *got != 0 {
		t.Errorf("requireCaseMode(MYSQL, 0) = %v, want 0", got)
	}
	pg, err := RequireCaseMode(EnginePostgres, nil)
	if err != nil || pg != nil {
		t.Errorf("requireCaseMode(POSTGRES, nil) = %v, %v; want nil, nil", pg, err)
	}
	// The other two untested arms, for completeness of INV-A5-4.
	if _, err := IsSystemSchema(EngineUnspecified, "x"); err == nil {
		t.Error("isSystemSchema did not fail closed")
	}
	if _, err := CatalogIsConnectionIndependent(EngineUnspecified); err == nil {
		t.Error("catalogIsConnectionIndependent did not fail closed")
	}
}

// case 7
func TestSystemSchemasIsTheConcreteEnumerableSetPerEngine(t *testing.T) {
	assertSet := func(t *testing.T, e Engine, want ...string) {
		t.Helper()
		got, err := SystemSchemas(e)
		if err != nil {
			t.Fatalf("systemSchemas(%v): %v", e, err)
		}
		if len(got) != len(want) {
			t.Fatalf("systemSchemas(%v) has %d entries, want %d: %v", e, len(got), len(want), got)
		}
		for _, w := range want {
			if _, ok := got[w]; !ok {
				t.Errorf("systemSchemas(%v) missing %q", e, w)
			}
		}
	}
	assertSet(t, EngineMySQL, "information_schema", "mysql", "performance_schema", "sys")
	assertSet(t, EnginePostgres, "pg_catalog", "information_schema")
}

// case 8
func TestMySQLSystemSchemasMatchCaseInsensitively(t *testing.T) {
	for _, schema := range []string{
		"information_schema", "INFORMATION_SCHEMA", "Information_Schema",
		"mysql", "MySQL", "performance_schema", "PERFORMANCE_SCHEMA", "sys", "SYS",
	} {
		ok, err := IsSystemSchema(EngineMySQL, schema)
		if err != nil {
			t.Fatalf("isSystemSchema(MYSQL, %q): %v", schema, err)
		}
		if !ok {
			t.Errorf("isSystemSchema(MYSQL, %q) = false", schema)
		}
	}
}

// case 9
func TestMySQLNonSystemSchemaDoesNotMatch(t *testing.T) {
	for _, schema := range []string{"app", "acme"} {
		ok, _ := IsSystemSchema(EngineMySQL, schema)
		if ok {
			t.Errorf("isSystemSchema(MYSQL, %q) = true", schema)
		}
	}
}

// case 10
func TestPostgresSystemSchemasRequireExactLowercaseSpellingUnlikeMySQL(t *testing.T) {
	// The Postgres branch does NOT fold case at all.
	for _, schema := range []string{"pg_catalog", "information_schema"} {
		ok, _ := IsSystemSchema(EnginePostgres, schema)
		if !ok {
			t.Errorf("isSystemSchema(POSTGRES, %q) = false", schema)
		}
	}
	for _, schema := range []string{"PG_CATALOG", "INFORMATION_SCHEMA"} {
		ok, _ := IsSystemSchema(EnginePostgres, schema)
		if ok {
			t.Errorf("isSystemSchema(POSTGRES, %q) = true; the Postgres branch does not fold case", schema)
		}
	}
}

// case 11
func TestPostgresTempAndToastSchemasMatchIsSystemSchemaByPrefixButAreNotFixed(t *testing.T) {
	// isSystemSchema includes the ephemeral per-session schemas; isFixedSystemSchema (the
	// enumerable / poolable set) deliberately excludes them.
	for _, schema := range []string{"pg_temp_5", "pg_toast_16384"} {
		if ok, _ := IsSystemSchema(EnginePostgres, schema); !ok {
			t.Errorf("isSystemSchema(POSTGRES, %q) = false", schema)
		}
		if ok, _ := IsFixedSystemSchema(EnginePostgres, schema); ok {
			t.Errorf("isFixedSystemSchema(POSTGRES, %q) = true", schema)
		}
	}
	if ok, _ := IsSystemSchema(EnginePostgres, "pg_temp"); ok {
		t.Error(`isSystemSchema(POSTGRES, "pg_temp") = true; the prefix requires a trailing suffix`)
	}
}

// case 12
func TestIsFixedSystemSchemaKeepsEachEnginesCasingButDropsThePrefixes(t *testing.T) {
	if ok, _ := IsFixedSystemSchema(EnginePostgres, "pg_catalog"); !ok {
		t.Error(`isFixedSystemSchema(POSTGRES, "pg_catalog") = false`)
	}
	if ok, _ := IsFixedSystemSchema(EngineMySQL, "INFORMATION_SCHEMA"); !ok {
		t.Error("MySQL folds")
	}
	if ok, _ := IsFixedSystemSchema(EnginePostgres, "PG_CATALOG"); ok {
		t.Error("Postgres matches exactly")
	}
}

// case 13
func TestPostgresNonSystemSchemaDoesNotMatch(t *testing.T) {
	for _, schema := range []string{"public", "app"} {
		if ok, _ := IsSystemSchema(EnginePostgres, schema); ok {
			t.Errorf("isSystemSchema(POSTGRES, %q) = true", schema)
		}
	}
}
