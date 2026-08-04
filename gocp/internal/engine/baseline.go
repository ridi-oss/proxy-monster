package engine

import "strings"

// baselineDangerousFunctions is a version-INDEPENDENT floor of dangerous-builtin function
// classifications (docs/facts-emission.md). Every per-version SystemManifest governs only the engine
// majors it is certified for; a datasource whose engine_version is absent or an uncertified major
// resolves to NO manifest, so ClassifyBareFunction can classify nothing there — the cross-engine-stable
// IO/exec builtins would go unclassified → un-forbidden.
//
// The PRIMARY no-manifest mechanism is the version-independent UNION FLOOR in A5's
// SystemClassificationService.tagForFunction — the union of ClassifyBareFunction across every shipped
// manifest of the engine (SystemClassificationStore.ClassifiersForEngine), which covers the FULL manifest
// dangerous set (families incl. table_to_xml*/pageinspect/lo_*) on a no-manifest datasource, at parity
// with certified. This baseline is a belt-and-suspenders floor: it still classifies its curated set even
// for an engine with ZERO shipped manifests. Both are consumed unconditionally, on every call, by A5's
// tagForFunction, and independently by A6 (Query.kt:492 and :594) — so the port must not delete one of
// the two.
//
// 🔒 INV-A13-31 — the baseline is a FLOOR that only ever RAISES (or matches) a manifest classification,
// and it classifies NO safe function. Each entry carries the SAME tag the shipped manifests assign it, so
// the baseline can never DISAGREE with a governing manifest (A5 unions the two strongest-first). And it is
// deliberately NOT a general denylist: a bare name absent here is untouched — an ordinary safe builtin or
// a user UDF stays UNCLASSIFIED → not marshalled → not forbidden. The tag-equality half is asserted by
// TestPostgresManifestIsASupersetOfTheOldDangerousFuncs (SystemClassificationTest case 16).
var baselineDangerousFunctions = map[string]SystemTag{
	// PostgreSQL dblink — runs SQL on a remote server (exec) / fetches its results (leak).
	"dblink":            TagDataLeak,
	"dblink_exec":       TagCritical,
	"dblink_open":       TagDataLeak,
	"dblink_fetch":      TagDataLeak,
	"dblink_send_query": TagDataLeak,
	// PostgreSQL server-side file & large-object IO.
	"pg_read_file":        TagDataLeak,
	"pg_read_binary_file": TagDataLeak,
	"pg_ls_dir":           TagDataLeak,
	"pg_stat_file":        TagDataLeak,
	"lo_import":           TagDataLeak,
	"lo_export":           TagCritical,
	// PostgreSQL arbitrary-SQL-string readers.
	"query_to_xml":               TagDataLeak,
	"query_to_xml_and_xmlschema": TagDataLeak,
	"xpath_table":                TagDataLeak,
	// MySQL server-side file read.
	"load_file": TagDataLeak,
}

// ClassifyBaselineDangerousFunction returns the floor system tag for a bare function name, or ok=false
// when it is not a cross-engine dangerous builtin. Ports `BaselineDangerousFunctions.classify`.
//
// Matching is a case-insensitive fold, like the classifier, and by BARE NAME ONLY — same reason as
// ClassifyBareFunction: sqlglot drops a function's schema qualifier at parse time, and over-classifying a
// same-named user function is safe (fail-closed).
func ClassifyBaselineDangerousFunction(name string) (SystemTag, bool) {
	t, ok := baselineDangerousFunctions[strings.ToLower(name)]
	return t, ok
}
