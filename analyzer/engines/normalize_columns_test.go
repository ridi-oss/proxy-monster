package engines

import "testing"

// NormalizeMySQLColumns is the batched, memoized form of CanonicalMySQLRelation used on wide schema
// fragments (goproxy/db's refetch and introspect's bulk catalog push). It must return, row for row,
// exactly what a per-row CanonicalMySQLRelation loop returns: the batching (one sqlglot parse per
// distinct (schema, table), column folded per row) is a performance optimization, never a semantic
// change. This pins that equivalence across every fold mode, with repeated (schema, table) pairs that
// exercise the memo cache, the information_schema exception, and non-ASCII column folding.
func TestNormalizeMySQLColumnsEqualsPerRowCanonical(t *testing.T) {
	schemas := []string{"App", "App", "App", "INFORMATION_SCHEMA", "Other", "Other"}
	tables := []string{"Users", "Users", "Orders", "SCHEMATA", "T", "T"}
	columns := []string{"ID", "Name", "Total", "SCHEMA_NAME", "K", "CAFÉ"}

	for _, mode := range []int{0, 1, 2} {
		gotS, gotT, gotC := NormalizeMySQLColumns(mode, schemas, tables, columns)
		if len(gotS) != len(schemas) || len(gotT) != len(schemas) || len(gotC) != len(schemas) {
			t.Fatalf("mode %d: result lengths %d/%d/%d, want %d each", mode, len(gotS), len(gotT), len(gotC), len(schemas))
		}
		for i := range schemas {
			wantS, wantT, wantC := CanonicalMySQLRelation(mode, schemas[i], tables[i], columns[i])
			if gotS[i] != wantS || gotT[i] != wantT || gotC[i] != wantC {
				t.Fatalf("mode %d row %d (%q.%q.%q): batch gave %q/%q/%q, per-row canonical gave %q/%q/%q",
					mode, i, schemas[i], tables[i], columns[i], gotS[i], gotT[i], gotC[i], wantS, wantT, wantC)
			}
		}
	}
}

func TestNormalizeMySQLColumnsEmptyInput(t *testing.T) {
	gotS, gotT, gotC := NormalizeMySQLColumns(0, nil, nil, nil)
	if len(gotS) != 0 || len(gotT) != 0 || len(gotC) != 0 {
		t.Fatalf("empty input produced %d/%d/%d rows, want 0/0/0", len(gotS), len(gotT), len(gotC))
	}
}
