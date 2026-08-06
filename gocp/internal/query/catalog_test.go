package query

import (
	"strings"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
)

// SchemaKeyWiringTest.kt case 1 — unit (06-query-decision.md §7; the suite was owned by no area and
// the reconciliation pass assigned it here). Cases 2-3 assert AnalyzerFor's own key-injectivity
// rejections and live with internal/engine, which already owns INV-A13-13.
//
// This is step 18's guard: an analyzer key that names no catalog row must NOT be resolvable by
// falling back to a same-named table in another schema.

func testCatalogColumn(catalog, schema, table, column string) datasource.CatalogColumn {
	return datasource.CatalogColumn{
		Catalog: catalog, Schema: schema, Table: table, Column: column,
		DataType: "character varying", SQLType: "VARCHAR", Ordinal: 1, Nullable: false,
	}
}

func specsFor(catalog []datasource.CatalogColumn) []*probepb.ColumnSpec {
	out := make([]*probepb.ColumnSpec, 0, len(catalog))
	for _, col := range catalog {
		out = append(out, &probepb.ColumnSpec{
			Catalog:  col.Catalog,
			Identity: &probepb.RelationIdentity{Schema: col.Schema, Table: col.Table, Column: col.Column},
			DataType: col.SQLType,
			Pii:      col.Classification != nil,
		})
	}
	return out
}

// `an emitted key absent from the catalog cannot fall back to a same-named table in another schema`
// KT: SchemaKeyWiringTest.kt#an emitted key absent from the catalog cannot fall back to a same-named table in another schema
func TestAnEmittedKeyAbsentFromTheCatalogCannotFallBackToAnotherSchema(t *testing.T) {
	namespace := &probepb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}
	catalog := []datasource.CatalogColumn{testCatalogColumn("acme", "public", "users", "rrn")}
	specs := specsFor(catalog)
	analyzer, err := engine.AnalyzerFor(namespace, specs, &probepb.EngineConfig{Engine: datasource.EnginePostgres})
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	index, err := BuildCatalogColumnIndex(catalog, specs, analyzer)
	if err != nil {
		t.Fatalf("BuildCatalogColumnIndex: %v", err)
	}

	denied := CoverageOf(index, []string{"acme.analytics.users.rrn"})
	if denied.Covered {
		t.Fatal("a key naming a schema with no catalog row must NOT be covered")
	}
	if !strings.Contains(denied.Reason, "absent from catalog") {
		t.Errorf("reason = %q, want it to contain %q", denied.Reason, "absent from catalog")
	}

	if covered := CoverageOf(index, []string{"acme.public.users.rrn"}); !covered.Covered {
		t.Fatalf("the real key must be covered, got %q", covered.Reason)
	}
}

// BuildCatalogColumnIndex's two defence-in-depth checks. Both are unreachable through DecideQuery —
// AnalyzerFor would already have failed (INV-A13-13) — so they are asserted directly. Their messages
// are WIRE-VISIBLE: step 3's catch renders them into denyReason.
func TestBuildCatalogColumnIndexRejectsAWiringBug(t *testing.T) {
	namespace := &probepb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}
	catalog := []datasource.CatalogColumn{
		testCatalogColumn("acme", "public", "users", "rrn"),
		testCatalogColumn("acme", "public", "users", "email"),
	}
	specs := specsFor(catalog)
	analyzer, err := engine.AnalyzerFor(namespace, specs, &probepb.EngineConfig{Engine: datasource.EnginePostgres})
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}

	// Count mismatch: the catalog and the analyzer's ColumnKeys must be the SAME list, in the same
	// order (INV-A13-16). Zipping a filtered or reordered catalog would silently mis-key every row.
	_, err = BuildCatalogColumnIndex(catalog[:1], specs, analyzer)
	if err == nil || !strings.Contains(err.Error(), "catalog/analyzer column count mismatch: 1 vs 2") {
		t.Fatalf("count mismatch error = %v, want the verbatim Kotlin message", err)
	}

	// Ambiguous key: two rows rendering to one analyzer key.
	dup := []datasource.CatalogColumn{
		testCatalogColumn("acme", "public", "users", "rrn"),
		testCatalogColumn("acme", "public", "users", "rrn"),
	}
	dupAnalyzer := &engine.Analyzer{ColumnKeys: []string{"acme.public.users.rrn", "acme.public.users.rrn"}}
	_, err = BuildCatalogColumnIndex(dup, specs, dupAnalyzer)
	if err == nil || !strings.Contains(err.Error(), "ambiguous normalized column key 'acme.public.users.rrn'") {
		t.Fatalf("ambiguous key error = %v, want the verbatim Kotlin message", err)
	}
}

// CoverageOf reports the FIRST missing key, in the caller's insertion order — `firstOrNull`. The order
// is what decides which key names the deny, so it is asserted rather than assumed.
func TestCoverageOfReportsTheFirstMissingKeyInOrder(t *testing.T) {
	index := &CatalogColumnIndex{RowsByKey: map[string]datasource.CatalogColumn{
		"acme.public.users.rrn": testCatalogColumn("acme", "public", "users", "rrn"),
	}}
	got := CoverageOf(index, []string{"acme.public.users.rrn", "acme.a.b.c", "acme.x.y.z"})
	if got.Covered {
		t.Fatal("want Denied")
	}
	if !strings.HasSuffix(got.Reason, "acme.a.b.c") {
		t.Errorf("reason = %q, want it to name the FIRST missing key", got.Reason)
	}
	if empty := CoverageOf(index, nil); !empty.Covered {
		t.Fatal("no touched keys is Covered")
	}
}
