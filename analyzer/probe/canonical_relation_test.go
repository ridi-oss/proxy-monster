package probe

import "testing"

// CanonicalMySQLRelation is the per-row form of NormalizeMySQLColumns, which every direct Go-to-Go caller
// (goproxy's introspect.go and goproxy/db's schema-fragment refetch path) uses — the single place
// PII-classification-key normalization happens, before a catalog ever reaches the control plane.
// These tests pin its behavior directly, in isolation from any caller.
func TestCanonicalMySQLRelationOrdinaryTableUnderMode0StaysCaseSensitive(t *testing.T) {
	schema, table, column := CanonicalMySQLRelation(0, "App", "Users", "ID")
	if schema != "App" || table != "Users" {
		t.Fatalf("got schema=%q table=%q, want App/Users unfolded under mode 0", schema, table)
	}
	if column != "id" {
		t.Fatalf("got column=%q, want id (columns always fold)", column)
	}
}

func TestCanonicalMySQLRelationInformationSchemaFoldsUnderMode0(t *testing.T) {
	cases := []struct {
		name, schemaIn, tableIn string
	}{
		{"raw lowercase", "information_schema", "schemata"},
		{"uppercase schema and table", "INFORMATION_SCHEMA", "SCHEMATA"},
		{"mixed case", "Information_Schema", "Schemata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schema, table, _ := CanonicalMySQLRelation(0, tc.schemaIn, tc.tableIn, "SCHEMA_NAME")
			if schema != "information_schema" || table != "schemata" {
				t.Fatalf("got schema=%q table=%q, want information_schema/schemata (folds under mode 0 exception)", schema, table)
			}
		})
	}
}

func TestCanonicalMySQLRelationModes1And2FoldEverything(t *testing.T) {
	for _, mode := range []int{1, 2} {
		schema, table, column := CanonicalMySQLRelation(mode, "App", "Users", "ID")
		if schema != "app" || table != "users" || column != "id" {
			t.Fatalf("mode %d: got schema=%q table=%q column=%q, want app/users/id", mode, schema, table, column)
		}
	}
}

// A catalog column named with the Kelvin sign U+212A, which MySQL's
// exact general_ci map folds to ASCII 'k' — a naive ASCII-only lowercase (treating 'K'..'Z' but
// missing this code point) would leave the Kelvin sign unfolded, diverging from what the analyzer's
// own query-side resolution treats as canonical and silently missing a PII match.
func TestCanonicalMySQLRelationKelvinSignFoldsToAsciiK(t *testing.T) {
	_, _, column := CanonicalMySQLRelation(1, "app", "t", "K")
	if column != "k" {
		t.Fatalf("Kelvin sign U+212A folded to %q, want ASCII k", column)
	}
}

// general_ci is accent-preserving (café ≠ cafe) even though it folds case — so a non-ASCII column
// folds by case only, never collapsing distinct accented identifiers together.
func TestCanonicalMySQLRelationAccentPreservingFold(t *testing.T) {
	_, _, column := CanonicalMySQLRelation(1, "app", "t", "CAFÉ") // CAFÉ
	if column != "café" {                                         // café (é, accent preserved)
		t.Fatalf("CAFÉ folded to %q, want café (accent-preserving, not ASCII-only)", column)
	}
}
