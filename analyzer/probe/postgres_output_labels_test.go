package probe

import (
	"strings"
	"testing"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func labelFacts(t *testing.T, sql string) *pb.StatementFacts {
	t.Helper()
	return analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "pg_catalog", "pg_namespace", "oid", "OID"),
			columnSpec("acme", "pg_catalog", "pg_namespace", "nspname", "NAME"),
		},
	})
}

// pgJDBC's metadata queries read results by label, so a star-expansion rewrite must keep the
// output names PostgreSQL itself would assign — never Qualify's synthetic `_col_N`.
func TestPostgresRewriteKeepsNativeOutputLabels(t *testing.T) {
	cases := []struct {
		sql   string
		label string
	}{
		{"SELECT * FROM (SELECT current_database(), n.nspname FROM pg_catalog.pg_namespace n) c", "current_database"},
		{"SELECT * FROM (SELECT n.oid + 1, n.nspname FROM pg_catalog.pg_namespace n) c", "?column?"},
		{"SELECT * FROM (SELECT n.oid::text, n.nspname FROM pg_catalog.pg_namespace n) c", "oid"},
		{"SELECT * FROM (SELECT count(*), n.nspname FROM pg_catalog.pg_namespace n GROUP BY n.nspname) c", "count"},
		{"WITH t AS (SELECT current_database(), n.nspname FROM pg_catalog.pg_namespace n) SELECT * FROM t", "current_database"},
		// CASE takes its ELSE's strong name; a weak CASE name yields to a cast's type name.
		{"SELECT * FROM (SELECT CASE WHEN true THEN 'x' ELSE current_database() END, n.nspname FROM pg_catalog.pg_namespace n) c", "current_database"},
		{"SELECT * FROM (SELECT (CASE WHEN true THEN 1 END)::text, n.nspname FROM pg_catalog.pg_namespace n) c", "text"},
		{"SELECT * FROM (SELECT CASE WHEN true THEN 1 END, n.nspname FROM pg_catalog.pg_namespace n) c", "case"},
		// A scalar subquery inherits its single output's label.
		{"SELECT * FROM (SELECT (SELECT n2.nspname FROM pg_catalog.pg_namespace n2 LIMIT 1), n.oid FROM pg_catalog.pg_namespace n) c", "nspname"},
		// PostgreSQL permits duplicate output labels.
		{"SELECT * FROM (SELECT n.oid + 1, n.oid + 2, n.nspname FROM pg_catalog.pg_namespace n) c", "?column?|?column?"},
	}
	for _, tc := range cases {
		facts := labelFacts(t, tc.sql)
		if !facts.GetResolved() {
			t.Fatalf("%s: did not resolve: %q", tc.sql, facts.GetDetail())
		}
		rewrite := facts.GetRewrittenSql()
		if rewrite == "" {
			t.Fatalf("%s: expected a star-expansion rewrite", tc.sql)
		}
		// The client-visible labels are the outermost select list's aliases; inner synthetic
		// aliases stay (valid internal references).
		root, err := sqlglot.ParseOne(rewrite, dialects.Postgres())
		if err != nil {
			t.Fatalf("%s: reparse rewrite: %v", tc.sql, err)
		}
		labels := []string{}
		for _, projection := range root.Selects() {
			label := projection.AliasOrName()
			if strings.HasPrefix(label, "_col_") {
				t.Fatalf("%s: rewrite exposes a synthetic label: %s", tc.sql, rewrite)
			}
			labels = append(labels, label)
		}
		if !strings.Contains(strings.Join(labels, "|"), tc.label) {
			t.Fatalf("%s: rewrite lost the native label %q (labels %v): %s", tc.sql, tc.label, labels, rewrite)
		}
	}
}
