package engine

import (
	"errors"
	"strings"
	"testing"
)

// Port of engine/src/test/.../classification/SystemClassificationTest.kt — 289 LOC, 19 cases.
//
// Header, quoted: "Unit proof for the system-classification mechanism (docs/system-classification.md):
// the strongest-tag-first classifier, boot validation that fail-closes on a malformed manifest, and the
// version resolver with the opt-in unsupported-version fallback. Uses synthetic manifests — the real
// curated Aurora manifests are proven separately."
//
// Four sections: classifier · boot validation · version resolution · the real bundled manifests. Cases
// 13-19 exercise the REAL SHIPPED MANIFESTS and are the closest thing the area has to a golden posture
// test — they are the regression net for any hand-edit of the JSON, so they run against the embedded
// files unchanged.
//
// The tests appended after case 19 close coverage gaps 13-engine.md §6 names explicitly; each says which.

func mustClassifier(t *testing.T, m SystemManifest) *SystemClassifier {
	t.Helper()
	c, err := NewSystemClassifier(m)
	if err != nil {
		t.Fatalf("manifest unexpectedly rejected: %v", err)
	}
	return c
}

// assertManifestRejected is Kotlin's assertFailsWith<SystemManifestException>.
func assertManifestRejected(t *testing.T, m SystemManifest) *SystemManifestError {
	t.Helper()
	_, err := NewSystemClassifier(m)
	if err == nil {
		t.Fatal("expected the manifest to be rejected at boot, but it validated")
	}
	var manifestErr *SystemManifestError
	if !errors.As(err, &manifestErr) {
		t.Fatalf("expected a *SystemManifestError, got %T: %v", err, err)
	}
	return manifestErr
}

func assertTag(t *testing.T, want SystemTag, gotTag SystemTag, gotOK bool, msg string) {
	t.Helper()
	if !gotOK {
		t.Errorf("%s: expected %v, got no tag", msg, want)
		return
	}
	if gotTag != want {
		t.Errorf("%s: expected %v, got %v", msg, want, gotTag)
	}
}

func assertNoTag(t *testing.T, gotTag SystemTag, gotOK bool, msg string) {
	t.Helper()
	if gotOK {
		t.Errorf("%s: expected no tag, got %v", msg, gotTag)
	}
}

// ---- classifier ----------------------------------------------------------------------------------

// Case 1 — INV-A13-18, INV-A13-22.
// KT: SystemClassificationTest.kt#a relation in a system schema defaults to catalog, exact and family raise it to the strongest
func TestRelationInASystemSchemaDefaultsToCatalogExactAndFamilyRaiseItToTheStrongest(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		SystemSchemas:    []SystemSchema{{"*", "pg_catalog"}},
		Relations:        []ObjectRule{{"pg_catalog", "pg_authid", "system:critical"}},
		RelationFamilies: []FamilyRule{{"pg_catalog", "pg_stat_", "system:activity"}},
	})
	tag, ok := c.ClassifyRelation("acme", "pg_catalog", "pg_class")
	assertTag(t, TagCatalog, tag, ok, "an unlisted system relation is catalog (open)")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_authid")
	assertTag(t, TagCritical, tag, ok, "exact critical wins")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_stat_activity")
	assertTag(t, TagActivity, tag, ok, "family activity applies")
	tag, ok = c.ClassifyRelation("acme", "public", "users")
	assertNoTag(t, tag, ok, "a user schema is not a system schema → no system tag")
}

// Case 2 — INV-A13-25, INV-A13-26.
// KT: SystemClassificationTest.kt#case-insensitive within a system schema, catalog wildcard vs pinned
func TestCaseInsensitiveWithinASystemSchemaCatalogWildcardVsPinned(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "mysql", Series: "8.0", ManifestVersion: 1, CuratedThrough: "8.0.44",
		SystemSchemas: []SystemSchema{{"def", "mysql"}},
		Relations:     []ObjectRule{{"mysql", "user", "system:critical"}},
	})
	tag, ok := c.ClassifyRelation("def", "MySQL", "USER")
	assertTag(t, TagCritical, tag, ok, "match folds case")
	tag, ok = c.ClassifyRelation("otherdb", "mysql", "user")
	assertNoTag(t, tag, ok, "a pinned catalog must match")
}

// Case 3 — INV-A13-24.
// KT: SystemClassificationTest.kt#a cross-schema function rule applies in any schema, catalog default only in a system schema
func TestACrossSchemaFunctionRuleAppliesInAnySchemaCatalogDefaultOnlyInASystemSchema(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		SystemSchemas:    []SystemSchema{{"*", "pg_catalog"}},
		Functions:        []ObjectRule{{"*", "dblink", "system:data-leak"}},
		FunctionFamilies: []FamilyRule{{"pg_catalog", "pg_read_", "system:data-leak"}},
	})
	tag, ok := c.ClassifyFunction("acme", "public", "dblink")
	assertTag(t, TagDataLeak, tag, ok, "cross-schema dangerous function classified anywhere")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "pg_read_file")
	assertTag(t, TagDataLeak, tag, ok, "family in a system schema")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "lower")
	assertTag(t, TagCatalog, tag, ok, "an ordinary system-schema builtin is catalog")
	tag, ok = c.ClassifyFunction("acme", "public", "my_udf")
	assertNoTag(t, tag, ok, "a user function is not shipped-classified")
}

// Case 4.
// KT: SystemClassificationTest.kt#a utility command maps to its resource tag
func TestAUtilityCommandMapsToItsResourceTag(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "mysql", Series: "8.0", ManifestVersion: 1, CuratedThrough: "8.0.44",
		Commands: []CommandRule{{"SHOW_PROCESSLIST", "information_schema/PROCESSLIST", "system:activity"}},
	})
	tag, ok := c.ClassifyCommand("SHOW_PROCESSLIST")
	assertTag(t, TagActivity, tag, ok, "a mapped command carries its resource tag")
	tag, ok = c.ClassifyCommand("SHOW_TABLES")
	assertNoTag(t, tag, ok, "an unmapped command has no tag")
}

// ---- boot validation (fail-closed) --------------------------------------------------------------

// Case 5 — 🔒 INV-A13-19.
// KT: SystemClassificationTest.kt#a non-system tag aborts
func TestANonSystemTagAborts(t *testing.T) {
	err := assertManifestRejected(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		Relations: []ObjectRule{{"pg_catalog", "pg_authid", "pii"}},
	})
	// The message shape is wire-invisible but operator-visible at boot; pin it so a refactor of
	// requireTag's `where` strings is deliberate.
	if want := "postgres/17: relation pg_catalog.pg_authid has non-system tag 'pii'"; err.Error() != want {
		t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
	}
}

// Case 6 — 🔒 INV-A13-19.
// KT: SystemClassificationTest.kt#a duplicate exact identity with conflicting tags aborts
func TestADuplicateExactIdentityWithConflictingTagsAborts(t *testing.T) {
	err := assertManifestRejected(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		Relations: []ObjectRule{
			{"pg_catalog", "pg_authid", "system:critical"},
			{"pg_catalog", "pg_authid", "system:activity"},
		},
	})
	if want := "postgres/17: duplicate exact relation pg_catalog.pg_authid with conflicting tags CRITICAL/ACTIVITY"; err.Error() != want {
		t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
	}
}

// Case 7 — 🔒 INV-A13-21.
// KT: SystemClassificationTest.kt#an exact rule that would downgrade a stronger family aborts
func TestAnExactRuleThatWouldDowngradeAStrongerFamilyAborts(t *testing.T) {
	err := assertManifestRejected(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		SystemSchemas:    []SystemSchema{{"*", "pg_catalog"}},
		Relations:        []ObjectRule{{"pg_catalog", "pg_secret_thing", "system:activity"}},
		RelationFamilies: []FamilyRule{{"pg_catalog", "pg_secret_", "system:critical"}},
	})
	if !strings.Contains(err.Error(), "would rely on match ordering") {
		t.Errorf("expected the no-downgrade message, got %q", err.Error())
	}
}

// Case 8 — 🔒 INV-A13-19.
//
// ⚠️ This manifest has ONLY relationFamilies, so it passes THROUGH the F29 shadowing hole rather than
// exposing it: with no functionFamilies, nothing shadows pg_catalog's relation list. See
// TestOverlappingRelationFamiliesAreNotValidatedWhenTheSchemaAlsoHasFunctionFamilies below, which is the
// case 13-engine.md §6 says is missing.
// KT: SystemClassificationTest.kt#overlapping families with conflicting tags abort
func TestOverlappingFamiliesWithConflictingTagsAbort(t *testing.T) {
	assertManifestRejected(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		RelationFamilies: []FamilyRule{
			{"pg_catalog", "pg_stat_activity_", "system:critical"},
			{"pg_catalog", "pg_stat_", "system:activity"},
		},
	})
}

// ---- version resolution + fallback --------------------------------------------------------------

func syntheticStore(t *testing.T) *SystemClassificationStore {
	t.Helper()
	s, err := SystemClassificationStoreOf([]SystemManifest{
		{Engine: "postgres", Series: "16", ManifestVersion: 1, CuratedThrough: "16.9"},
		{Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6"},
		{Engine: "mysql", Series: "8.0", ManifestVersion: 1, CuratedThrough: "8.0.44"},
		{Engine: "mysql", Series: "8.4", ManifestVersion: 1, CuratedThrough: "8.4.7"},
	})
	if err != nil {
		t.Fatalf("synthetic store: %v", err)
	}
	return s
}

// Case 9.
// KT: SystemClassificationTest.kt#an exact major and a newer minor both resolve to the series manifest, no fallback
func TestAnExactMajorAndANewerMinorBothResolveToTheSeriesManifestNoFallback(t *testing.T) {
	s := syntheticStore(t)
	r := s.Resolve("postgres", "17.9", false)
	if r == nil {
		t.Fatal("postgres 17.9 must resolve")
	}
	if r.ResolvedSeries != "17" || r.IsFallback {
		t.Errorf("got %+v, want series 17 without fallback", r)
	}
	r = s.Resolve("mysql", "8.0.44", false)
	if r == nil {
		t.Fatal("mysql 8.0.44 must resolve")
	}
	if r.ResolvedSeries != "8.0" || r.IsFallback {
		t.Errorf("got %+v, want series 8.0 without fallback", r)
	}
}

// Case 10 — 🔒 INV-A13-27, INV-A13-28.
// KT: SystemClassificationTest.kt#an unsupported major is unavailable without fallback, and falls back to the nearest lower with it
func TestAnUnsupportedMajorIsUnavailableWithoutFallbackAndFallsBackToTheNearestLowerWithIt(t *testing.T) {
	s := syntheticStore(t)
	if r := s.Resolve("postgres", "18.3", false); r != nil {
		t.Errorf("uncertified major → no manifest (fail-closed), got %+v", r)
	}
	r := s.Resolve("postgres", "18.3", true)
	if r == nil {
		t.Fatal("fallback must resolve")
	}
	if r.RequestedSeries != "18" || r.ResolvedSeries != "17" || !r.IsFallback {
		t.Errorf("got %+v, want requested 18 → resolved 17 (nearest lower supported major), fallback", r)
	}
}

// Case 11 — INV-A13-28.
// KT: SystemClassificationTest.kt#a datasource older than every supported major falls back to the lowest
func TestADatasourceOlderThanEverySupportedMajorFallsBackToTheLowest(t *testing.T) {
	r := syntheticStore(t).Resolve("postgres", "14.22", true)
	if r == nil {
		t.Fatal("fallback must resolve")
	}
	if r.ResolvedSeries != "16" || !r.IsFallback {
		t.Errorf("got %+v, want the lowest supported (16), since 14 < all", r)
	}
}

// Case 12 — INV-A13-28.
// KT: SystemClassificationTest.kt#mysql 8_4 falls back to 8_0 nearest-lower reasoning stays within engine
func TestMysql84FallsBackTo80NearestLowerReasoningStaysWithinEngine(t *testing.T) {
	s := syntheticStore(t)
	if r := s.Resolve("mysql", "9.0.0", false); r != nil {
		t.Errorf("uncertified mysql major without fallback must be absent, got %+v", r)
	}
	r := s.Resolve("mysql", "9.0.0", true)
	if r == nil {
		t.Fatal("fallback must resolve")
	}
	if r.ResolvedSeries != "8.4" || !r.IsFallback {
		t.Errorf("got %+v, want 8.4 — the nearest lower mysql family; it must never cross to postgres", r)
	}
}

// ---- the real bundled Aurora manifests ----------------------------------------------------------

func mustLoad(t *testing.T) *SystemClassificationStore {
	t.Helper()
	s, err := LoadSystemClassificationStore()
	if err != nil {
		t.Fatalf("the bundled manifests must load, validate and index: %v", err)
	}
	return s
}

// Case 13 — the boot check.
// KT: SystemClassificationTest.kt#all four bundled Aurora manifests load, validate, and index
func TestAllFourBundledAuroraManifestsLoadValidateAndIndex(t *testing.T) {
	s := mustLoad(t) // fails on any manifest validation failure → this is the boot check
	want := []EngineSeries{{"mysql", "8.0"}, {"mysql", "8.4"}, {"postgres", "16"}, {"postgres", "17"}}
	got := s.Supported()
	if len(got) != len(want) {
		t.Fatalf("supported: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("supported: got %v, want %v", got, want)
		}
	}
	if len(s.Checksum()) != 64 {
		t.Errorf("a sha-256 checksum is exposed for diagnostics, got %q", s.Checksum())
	}
}

// Case 14.
// KT: SystemClassificationTest.kt#real PostgreSQL classifications (incl Aurora) are correct
func TestRealPostgreSQLClassificationsInclAuroraAreCorrect(t *testing.T) {
	c := mustLoad(t).ClassifierFor("postgres", "17")
	if c == nil {
		t.Fatal("postgres/17 must be indexed")
	}
	tag, ok := c.ClassifyRelation("acme", "pg_catalog", "pg_authid")
	assertTag(t, TagCritical, tag, ok, "pg_authid")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_stats")
	assertTag(t, TagDataLeak, tag, ok, "pg_stats")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_stat_activity")
	assertTag(t, TagActivity, tag, ok, "pg_stat_activity")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_stat_progress_vacuum")
	assertTag(t, TagActivity, tag, ok, "family")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "pg_class")
	assertTag(t, TagCatalog, tag, ok, "ordinary catalog stays open")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "set_config")
	assertTag(t, TagCritical, tag, ok, "set_config")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "pg_read_file")
	assertTag(t, TagDataLeak, tag, ok, "pg_read_ family")
	tag, ok = c.ClassifyFunction("acme", "public", "dblink")
	assertTag(t, TagDataLeak, tag, ok, "cross-schema extension fn")
	tag, ok = c.ClassifyFunction("acme", "public", "dblink_exec")
	assertTag(t, TagCritical, tag, ok, "cross-schema mutation")
	// Aurora proprietary
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "aurora_replica_status")
	assertTag(t, TagActivity, tag, ok, "aurora_replica_status")
	tag, ok = c.ClassifyRelation("acme", "pg_catalog", "aurora_stat_io")
	assertTag(t, TagActivity, tag, ok, "aurora_stat_ family")
}

// Case 15.
// KT: SystemClassificationTest.kt#real MySQL classifications (incl Aurora rds_) are correct
func TestRealMySQLClassificationsInclAuroraRdsAreCorrect(t *testing.T) {
	c := mustLoad(t).ClassifierFor("mysql", "8.0")
	if c == nil {
		t.Fatal("mysql/8.0 must be indexed")
	}
	tag, ok := c.ClassifyRelation("def", "mysql", "user")
	assertTag(t, TagCritical, tag, ok, "mysql.user")
	tag, ok = c.ClassifyRelation("def", "information_schema", "USER_PRIVILEGES")
	assertTag(t, TagCritical, tag, ok, "USER_PRIVILEGES")
	tag, ok = c.ClassifyRelation("def", "information_schema", "COLUMN_STATISTICS")
	assertTag(t, TagDataLeak, tag, ok, "COLUMN_STATISTICS")
	tag, ok = c.ClassifyRelation("def", "information_schema", "PROCESSLIST")
	assertTag(t, TagActivity, tag, ok, "PROCESSLIST")
	tag, ok = c.ClassifyRelation("def", "performance_schema", "events_statements_current")
	assertTag(t, TagActivity, tag, ok, "family")
	tag, ok = c.ClassifyRelation("def", "information_schema", "TABLES")
	assertTag(t, TagCatalog, tag, ok, "structure stays open")
	tag, ok = c.ClassifyFunction("def", "__builtin__", "load_file")
	assertTag(t, TagDataLeak, tag, ok, "load_file")
	tag, ok = c.ClassifyFunction("def", "__builtin__", "now")
	assertTag(t, TagCatalog, tag, ok, "ordinary builtin is catalog")
	// Aurora proprietary management procedures (mysql.rds_* family → critical)
	tag, ok = c.ClassifyFunction("def", "mysql", "rds_kill")
	assertTag(t, TagCritical, tag, ok, "rds_kill")
	tag, ok = c.ClassifyFunction("def", "mysql", "rds_set_configuration")
	assertTag(t, TagCritical, tag, ok, "rds_set_configuration")
	tag, ok = c.ClassifyCommand("SHOW_PROCESSLIST")
	assertTag(t, TagActivity, tag, ok, "SHOW_PROCESSLIST")
}

// Case 16 — 🔒 pins INV-A13-31's tag-equality property. BaselineDangerousFunctions.kt:33-34 names this
// test as the verification, so the two must be read together.
// KT: SystemClassificationTest.kt#the PostgreSQL manifest is a superset of the old dangerousFuncs (must hold before that map retires)
func TestThePostgreSQLManifestIsASupersetOfTheOldDangerousFuncs(t *testing.T) {
	c := mustLoad(t).ClassifierFor("postgres", "17")
	if c == nil {
		t.Fatal("postgres/17 must be indexed")
	}
	// The dangerous PostgreSQL builtins (load_file is MySQL, checked below). None may classify as
	// catalog/none.
	for _, fn := range []string{"dblink", "dblink_exec", "dblink_open", "dblink_fetch", "dblink_send_query"} {
		tag, ok := c.ClassifyFunction("acme", "public", fn)
		if !ok || tag == TagCatalog {
			t.Errorf("old dangerousFunc %s must be dangerous-classified, was %v (present=%v)", fn, tag, ok)
		}
	}
	for _, fn := range []string{
		"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import", "lo_export",
		"query_to_xml", "query_to_xml_and_xmlschema", "xpath_table",
	} {
		tag, ok := c.ClassifyFunction("acme", "pg_catalog", fn)
		if !ok || tag == TagCatalog {
			t.Errorf("old dangerousFunc %s must be dangerous-classified, was %v (present=%v)", fn, tag, ok)
		}
	}
	mysql := mustLoad(t).ClassifierFor("mysql", "8.4")
	if mysql == nil {
		t.Fatal("mysql/8.4 must be indexed")
	}
	tag, ok := mysql.ClassifyFunction("def", "__builtin__", "load_file")
	if !ok || tag == TagCatalog {
		t.Errorf("load_file must be dangerous-classified, was %v (present=%v)", tag, ok)
	}
}

// Case 17 — 🔒 gate regressions.
// KT: SystemClassificationTest.kt#gate regressions - stat-getter, pageinspect, and aurora_stat functions are dangerous, not open
func TestGateRegressionsStatGetterPageinspectAndAuroraStatFunctionsAreDangerousNotOpen(t *testing.T) {
	c := mustLoad(t).ClassifierFor("postgres", "17")
	if c == nil {
		t.Fatal("postgres/17 must be indexed")
	}
	// pg_stat_get_backend_activity(pid) returns another backend's query text — the datum pg_stat_activity
	// (activity) exposes; it must not classify as CATALOG/open.
	tag, ok := c.ClassifyFunction("acme", "pg_catalog", "pg_stat_get_backend_activity")
	assertTag(t, TagActivity, tag, ok, "pg_stat_get_backend_activity")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "pg_stat_get_activity")
	assertTag(t, TagActivity, tag, ok, "pg_stat_get_activity")
	// pageinspect page-decode functions read page bytes directly (cross-schema extension).
	tag, ok = c.ClassifyFunction("acme", "public", "bt_page_items")
	assertTag(t, TagDataLeak, tag, ok, "bt_page_items")
	tag, ok = c.ClassifyFunction("acme", "public", "heap_page_items")
	assertTag(t, TagDataLeak, tag, ok, "heap_page_items")
	tag, ok = c.ClassifyFunction("acme", "public", "page_header")
	assertTag(t, TagDataLeak, tag, ok, "page_header")
	// aurora_stat_* are functions, not relations.
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "aurora_stat_system_waits")
	assertTag(t, TagActivity, tag, ok, "aurora_stat_system_waits")
	tag, ok = c.ClassifyFunction("acme", "pg_catalog", "aurora_stat_backend_waits")
	assertTag(t, TagActivity, tag, ok, "aurora_stat_backend_waits")
}

// Case 18 — 🔒 INV-A13-20.
// KT: SystemClassificationTest.kt#a wildcard-schema relation rule is rejected at boot
func TestAWildcardSchemaRelationRuleIsRejectedAtBoot(t *testing.T) {
	err := assertManifestRejected(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		Relations: []ObjectRule{{"*", "pg_authid", "system:critical"}},
	})
	if want := `postgres/17: wildcard schema "*" is only valid on a function rule, not a relation`; err.Error() != want {
		t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
	}
}

// Case 19.
// KT: SystemClassificationTest.kt#real version resolution + Aurora fallback
func TestRealVersionResolutionPlusAuroraFallback(t *testing.T) {
	s := mustLoad(t)
	if r := s.Resolve("postgres", "17.9", false); r == nil || r.ResolvedSeries != "17" {
		t.Errorf("postgres 17.9: got %+v, want series 17", r)
	}
	if r := s.Resolve("mysql", "8.0.44", false); r == nil || r.ResolvedSeries != "8.0" {
		t.Errorf("mysql 8.0.44: got %+v, want series 8.0", r)
	}
	// Aurora PG 18 has no manifest yet → nearest-lower fallback to 17
	if r := s.Resolve("postgres", "18.3", false); r != nil {
		t.Errorf("postgres 18.3 without fallback must be absent, got %+v", r)
	}
	if r := s.Resolve("postgres", "18.3", true); r == nil || r.ResolvedSeries != "17" || !r.IsFallback {
		t.Errorf("postgres 18.3 with fallback: got %+v, want 17 as a fallback", r)
	}
}

// ---- coverage gaps 13-engine.md §6 names, closed here -------------------------------------------

// 🔒 F32 / INV-A13-35 — REPRODUCE + PIN, first half. "Add a manifest with a repeated command id carrying a
// weaker tag; it must abort." It does NOT abort: commandTags is built with Kotlin `associate`, which is
// last-pair-wins with no conflict check. This test asserts the BUGGY behaviour deliberately, so that
// folding commandTags into exactMap's reject-on-conflict path has to change this test on purpose.
func TestDuplicateCommandIDSilentlyKeepsTheLastTagEvenWhenItIsWeaker(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "mysql", Series: "8.0", ManifestVersion: 1, CuratedThrough: "8.0.44",
		Commands: []CommandRule{
			{"SHOW_GRANTS", "mysql/user", "system:critical"},
			{"SHOW_GRANTS", "mysql/user", "system:catalog"},
		},
	})
	tag, ok := c.ClassifyCommand("SHOW_GRANTS")
	assertTag(t, TagCatalog, tag, ok,
		"F32: last-pair-wins silently DOWNGRADES a credential surface at boot with no error")
	if tag == TagCritical {
		t.Error("if this now reports CRITICAL the finding was fixed — update the test deliberately, and 13-engine.md Q9")
	}
}

// 🔒 F32 / INV-A13-35 — second half: two cross-schema (schema "*") function rules with the same name and
// different tags get NO duplicate check anywhere, because exactMap explicitly skips "*" rules so they are
// never keyed there either. Last-pair-wins, pinned.
func TestDuplicateCrossSchemaFunctionRuleSilentlyKeepsTheLastTag(t *testing.T) {
	c := mustClassifier(t, SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		Functions: []ObjectRule{
			{"*", "dblink_exec", "system:critical"},
			{"*", "dblink_exec", "system:catalog"},
		},
	})
	tag, ok := c.ClassifyBareFunction("dblink_exec")
	assertTag(t, TagCatalog, tag, ok, "F32: the LAST cross-schema rule wins, even when weaker")
}

// 🔒 F29 — REPRODUCE + PIN. "The F29 shadowing hole is untested and, by construction, unreachable by case
// 8. A manifest with a conflicting relation-family pair in a schema that ALSO has function families would
// load." It does load: validate() iterates `relationFamilies + functionFamilies`, a Kotlin Map.plus whose
// right operand wins per key, so pg_catalog's relation families are never overlap-validated once
// pg_catalog also appears in functionFamilies. Present in all four shipped manifests.
func TestOverlappingRelationFamiliesAreNotValidatedWhenTheSchemaAlsoHasFunctionFamilies(t *testing.T) {
	// The SAME conflicting relation-family pair case 8 rejects, plus one unrelated function family in the
	// same schema. Case 8's manifest aborts; this one loads.
	m := SystemManifest{
		Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
		RelationFamilies: []FamilyRule{
			{"pg_catalog", "pg_stat_activity_", "system:critical"},
			{"pg_catalog", "pg_stat_", "system:activity"},
		},
		FunctionFamilies: []FamilyRule{{"pg_catalog", "pg_read_", "system:data-leak"}},
	}
	c, err := NewSystemClassifier(m)
	if err != nil {
		t.Fatalf("F29: this manifest is expected to LOAD (the shadowing hole). If it now aborts, the hole "+
			"was closed — update this test deliberately and see 13-engine.md Q6. Got: %v", err)
	}
	// The runtime combinator still prevents a wrong tag, which is why the hole is latent rather than
	// live-wrong: the stronger of the two matching families wins at match time.
	tag, ok := c.ClassifyRelation("acme", "pg_catalog", "pg_stat_activity_x")
	assertNoTag(t, tag, ok, "no systemSchemas declared, so the relation is outside the system surface")
	withSchema := m
	withSchema.SystemSchemas = []SystemSchema{{"*", "pg_catalog"}}
	c2 := mustClassifier(t, withSchema)
	tag, ok = c2.ClassifyRelation("acme", "pg_catalog", "pg_stat_activity_x")
	assertTag(t, TagCritical, tag, ok, "strongest-first still wins at match time despite the unvalidated overlap")
}

// INV-A13-30 — "the checksum value is unpinned: only its LENGTH is asserted, so a port could reorder
// BUNDLED and change every operator's logged checksum without failing a test." Pinned here: the digest is
// over BUNDLED.sorted() order (mysql/8.0, mysql/8.4, postgres/16, postgres/17) and over the RAW FILE TEXT.
// Independently reproducible:
//
//	cat manifests/mysql/8.0.json manifests/mysql/8.4.json manifests/postgres/16.json \
//	    manifests/postgres/17.json | shasum -a 256
func TestBundleChecksumIsOverSortedStemsAndRawText(t *testing.T) {
	const want = "e6928b0bc6b523ca2387bddd46c51f67a10821efbd578c21260d72a78c9339b7"
	if got := mustLoad(t).Checksum(); got != want {
		t.Errorf("bundle checksum:\n got %s\nwant %s\n"+
			"A manifest edit changes this legitimately; a change in stem ORDER or in the hashed unit "+
			"(text vs parsed model) does not — INV-A13-30.", got, want)
	}
}

// The duplicate-manifest guard in load() is a guard on the CONSTANT, not on the data: the path ↔
// declaration check pins (engine, series) to the stem, so the only way to reach it is a repeated stem.
// 13-engine.md §4.4: "A Go embed.FS port should keep it that way (assert the embedded stem list is a set)."
func TestBundledStemListIsASet(t *testing.T) {
	seen := make(map[string]struct{}, len(bundledManifestStems))
	for _, stem := range bundledManifestStems {
		if _, dup := seen[stem]; dup {
			t.Errorf("duplicate bundled stem %q — load() would fail with 'duplicate manifest for …'", stem)
		}
		seen[stem] = struct{}{}
	}
	if len(bundledManifestStems) != 4 {
		t.Errorf("expected the four certified stems, got %v", bundledManifestStems)
	}
}

// F26 — REPRODUCE + PIN. SystemClassificationStoreOf omits load()'s duplicate (engine, series) check, so a
// later manifest silently OVERWRITES an earlier one where the same content on disk would abort boot.
func TestStoreOfSilentlyOverwritesADuplicateEngineSeries(t *testing.T) {
	s, err := SystemClassificationStoreOf([]SystemManifest{
		{Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6",
			SystemSchemas: []SystemSchema{{"*", "pg_catalog"}},
			Relations:     []ObjectRule{{"pg_catalog", "pg_authid", "system:critical"}}},
		{Engine: "postgres", Series: "17", ManifestVersion: 1, CuratedThrough: "17.6"},
	})
	if err != nil {
		t.Fatalf("F26: `of` has no duplicate guard, so this must NOT fail: %v", err)
	}
	c := s.ClassifierFor("postgres", "17")
	if c == nil {
		t.Fatal("postgres/17 must be indexed")
	}
	tag, ok := c.ClassifyRelation("acme", "pg_catalog", "pg_authid")
	assertNoTag(t, tag, ok, "F26: the SECOND (empty) manifest overwrote the first — no systemSchemas left")
}

// `classifierFor` lowercases engine but NOT series — an untested asymmetry, REPRODUCEd and pinned.
func TestClassifierForLowercasesEngineButNotSeries(t *testing.T) {
	s := mustLoad(t)
	if s.ClassifierFor("POSTGRES", "17") == nil {
		t.Error("engine is folded, so POSTGRES must resolve")
	}
	if s.ClassifierFor("postgres", "17 ") != nil {
		t.Error("series is NOT folded or trimmed")
	}
}

// seriesKey edges, unreachable today only because A5 pre-validates the version string — which is a
// DIFFERENT area's guard, so pin them here.
func TestSeriesResolutionEdges(t *testing.T) {
	s := syntheticStore(t)

	// A non-numeric series keys to 0, so with fallback on there is no notNewer candidate and it resolves
	// to the LOWEST supported major.
	if r := s.Resolve("postgres", "unknown", true); r == nil || r.ResolvedSeries != "16" || !r.IsFallback {
		t.Errorf("non-numeric series: got %+v, want the lowest supported (16) as a fallback", r)
	}
	// MySQL "8" and "8.0" both key to 8000, so a single-component MySQL version misses the exact lookup
	// and falls back to 8.0.
	if r := s.Resolve("mysql", "8", false); r != nil {
		t.Errorf(`mysql "8" must miss the exact lookup, got %+v`, r)
	}
	if r := s.Resolve("mysql", "8", true); r == nil || r.ResolvedSeries != "8.0" || !r.IsFallback {
		t.Errorf(`mysql "8" with fallback: got %+v, want 8.0`, r)
	}
	// SeriesOf's else branch is the PostgreSQL rule AND the rule for any unknown engine name.
	for _, tc := range []struct{ engine, version, want string }{
		{"mysql", "8.0.44", "8.0"},
		{"mysql", "8.4.7", "8.4"},
		{"mysql", "8", "8"},
		{"postgres", "17.9", "17"},
		{"postgres", "17", "17"},
		{"oracle", "19.3.0", "19"},
	} {
		if got := SeriesOf(tc.engine, tc.version); got != tc.want {
			t.Errorf("SeriesOf(%q, %q) = %q, want %q", tc.engine, tc.version, got, tc.want)
		}
	}
}

// INV-A13-29 — the no-manifest function floor is DERIVED, never hand-listed. ClassifiersForEngine is the
// mechanism A5 unions over, so pin that it returns every certified series of one engine and never crosses
// engines.
func TestClassifiersForEngineNeverCrossesEngines(t *testing.T) {
	s := mustLoad(t)
	if got := len(s.ClassifiersForEngine("postgres")); got != 2 {
		t.Errorf("postgres classifiers: got %d, want 2", got)
	}
	if got := len(s.ClassifiersForEngine("MySQL")); got != 2 {
		t.Errorf("mysql classifiers (engine is folded): got %d, want 2", got)
	}
	if got := len(s.ClassifiersForEngine("oracle")); got != 0 {
		t.Errorf("an engine with no bundled manifest must be empty, got %d", got)
	}
	// The union over these is what closes the no-manifest function leak: a family the thin hand-curated
	// baseline missed must still classify through them.
	var strongest SystemTag
	var have bool
	for _, c := range s.ClassifiersForEngine("postgres") {
		if tag, ok := c.ClassifyBareFunction("table_to_xml"); ok {
			strongest, have = combine(strongest, have, tag)
		}
	}
	if !have || strongest == TagCatalog {
		t.Errorf("table_to_xml must be dangerous through the derived union floor, got %v (present=%v)", strongest, have)
	}
	if _, ok := ClassifyBaselineDangerousFunction("table_to_xml"); ok {
		t.Error("table_to_xml is exactly the family the hand-curated baseline MISSED — INV-A13-29")
	}
}

// 🔒 INV-A13-23 — ClassifyBareFunction must NOT add the CATALOG default, unlike ClassifyFunction. If it
// ever did, every now() and lower() in every query would be marshalled as a Cedar Function with no permit
// and deny-by-default would break every query in the system (A2 INV-A2-11).
func TestClassifyBareFunctionNeverAddsTheCatalogDefault(t *testing.T) {
	c := mustLoad(t).ClassifierFor("postgres", "17")
	if c == nil {
		t.Fatal("postgres/17 must be indexed")
	}
	for _, safe := range []string{"now", "count", "lower"} {
		tag, ok := c.ClassifyBareFunction(safe)
		assertNoTag(t, tag, ok, "an ordinary safe builtin stays UNCLASSIFIED: "+safe)
		// The same name through ClassifyFunction in a system schema DOES get the CATALOG default — the two
		// must not be unified.
		tag, ok = c.ClassifyFunction("acme", "pg_catalog", safe)
		assertTag(t, TagCatalog, tag, ok, "ClassifyFunction still applies the in-schema catalog floor: "+safe)
	}
	// A dangerous bare name resolves against the "*" rules AND every system/logical schema.
	tag, ok := c.ClassifyBareFunction("pg_read_file")
	if !ok || tag == TagCatalog {
		t.Errorf("a dangerous bare name must classify, got %v (present=%v)", tag, ok)
	}
}

// 🔒 INV-A13-31 — the baseline is a floor that only ever RAISES (or matches) the manifest classification.
// The tag-equality half: every baseline entry carries the SAME tag the shipped manifests assign it, so the
// baseline can never DISAGREE with a governing manifest.
func TestBaselineDangerousFunctionsAgreeWithTheShippedManifests(t *testing.T) {
	s := mustLoad(t)
	for name, baselineTag := range baselineDangerousFunctions {
		engine, schema := "postgres", "pg_catalog"
		if name == "load_file" {
			engine, schema = "mysql", "__builtin__"
		}
		for _, c := range s.ClassifiersForEngine(engine) {
			manifestTag, ok := c.ClassifyFunction("acme", schema, name)
			if !ok {
				// dblink* live only as cross-schema rules; they classify from any schema.
				manifestTag, ok = c.ClassifyFunction("acme", "public", name)
			}
			if !ok {
				t.Errorf("%s: no manifest classification at all — the baseline would be the only floor", name)
				continue
			}
			if manifestTag != baselineTag {
				t.Errorf("%s: baseline says %v but the %s manifest says %v — the baseline must never DISAGREE",
					name, baselineTag, engine, manifestTag)
			}
		}
	}
	// It is deliberately NOT a general denylist.
	if _, ok := ClassifyBaselineDangerousFunction("now"); ok {
		t.Error("a safe builtin must stay unclassified")
	}
	// Matching is a case-insensitive fold, by bare name only.
	if tag, ok := ClassifyBaselineDangerousFunction("LO_EXPORT"); !ok || tag != TagCritical {
		t.Errorf("case-insensitive fold: got %v (present=%v), want CRITICAL", tag, ok)
	}
}

// 🔒 INV-A13-18 — the declaration order IS the strength order. A string comparison would not reproduce it,
// so pin the lattice itself.
func TestSystemTagStrengthOrder(t *testing.T) {
	order := []SystemTag{TagCritical, TagDataLeak, TagActivity, TagCatalog}
	ids := []string{"system:critical", "system:data-leak", "system:activity", "system:catalog"}
	for i, tag := range order {
		if tag.Strength() != i {
			t.Errorf("%v ordinal = %d, want %d — reordering the enum inverts every precedence decision", tag, tag.Strength(), i)
		}
		if tag.ID() != ids[i] {
			t.Errorf("%v id = %q, want %q", tag, tag.ID(), ids[i])
		}
		got, ok := SystemTagFromID(ids[i])
		if !ok || got != tag {
			t.Errorf("SystemTagFromID(%q) = %v (present=%v), want %v", ids[i], got, ok, tag)
		}
	}
	if _, ok := SystemTagFromID("pii"); ok {
		t.Error("a non-system tag must not resolve")
	}
	// stronger keeps the LOWER ordinal, and ties keep a.
	if got := StrongerTag(TagActivity, TagCritical); got != TagCritical {
		t.Errorf("StrongerTag(ACTIVITY, CRITICAL) = %v, want CRITICAL", got)
	}
	if got := StrongerTag(TagCatalog, TagCatalog); got != TagCatalog {
		t.Errorf("StrongerTag(CATALOG, CATALOG) = %v, want CATALOG", got)
	}
}

// F30 — logicalFunctionSchemas never consults catalog, unlike systemSchemas. A MySQL manifest's `def` pin
// on def/__builtin__ is inert: a function in schema __builtin__ under ANY catalog takes the CATALOG
// default plus the in-schema rules. The direction is fail-safe (over-classify), so it is REPRODUCEd.
func TestLogicalFunctionSchemasIgnoreTheirPinnedCatalog(t *testing.T) {
	c := mustLoad(t).ClassifierFor("mysql", "8.0")
	if c == nil {
		t.Fatal("mysql/8.0 must be indexed")
	}
	tag, ok := c.ClassifyFunction("def", "__builtin__", "now")
	assertTag(t, TagCatalog, tag, ok, "the pinned catalog matches")
	tag, ok = c.ClassifyFunction("some_other_catalog", "__builtin__", "now")
	assertTag(t, TagCatalog, tag, ok,
		"F30: the pin is inert — any catalog takes the CATALOG default in a logical function schema")
	// Contrast: systemSchemas DOES check the catalog (INV-A13-26).
	tag, ok = c.ClassifyRelation("some_other_catalog", "mysql", "user")
	assertNoTag(t, tag, ok, "INV-A13-26: a pinned system-schema catalog must match")
}
