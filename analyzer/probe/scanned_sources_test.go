package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestScannedSources locks the scanned-source emission (docs/facts-emission.md): the probe emits every physical relation a
// statement scans, flagged covered/uncovered, so the control-plane can require a table-read grant for a
// scan that traces zero columns (`count(*)`, `SELECT 1`, `EXISTS`, a cross-join side). Coverage is
// per-TABLE, computed from the final emitted facts. The safety property that is easy to miss: a CTE
// that SHADOWS a real table name must not surface the physical table (it is not read), while a CTE BODY
// that reads the real table must — resolved by the scope graph, not a global name set.
func TestScannedSources(t *testing.T) {
	// PG-style catalog. orders/sink carry no PII; users.ssn is the protected column used elsewhere.
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
		columnSpec("acme", "public", "users", "email", "VARCHAR"),
		columnSpec("acme", "public", "orders", "id", "BIGINT"),
		columnSpec("acme", "public", "orders", "uid", "BIGINT"),
		columnSpec("acme", "public", "sink", "id", "BIGINT"),
		columnSpec("acme", "public", "sink", "data", "VARCHAR"),
	}
	ns := &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}

	u := "acme.public.users"
	o := "acme.public.orders"

	cases := []struct {
		name string
		sql  string
		// want maps each physical table expected in `sources` to its covered flag. A table absent from
		// `want` MUST be absent from `sources` (asserted), so CTE-shadow / write-target exclusion is
		// proven by omission, not just by a covered flag.
		want map[string]bool
	}{
		{"count(*) traces zero columns → uncovered", "SELECT count(*) FROM orders", map[string]bool{o: false}},
		{"SELECT 1 → uncovered", "SELECT 1 FROM orders", map[string]bool{o: false}},
		{"EXISTS subquery scan → uncovered", "SELECT EXISTS(SELECT 1 FROM orders)", map[string]bool{o: false}},
		{"projected column → covered", "SELECT ssn FROM users", map[string]bool{u: true}},
		{"cross-join: projected side covered, bare side uncovered", "SELECT u.id FROM users u, orders o", map[string]bool{u: true, o: false}},
		{"self-join, per-tableID: users covered by a.id (no separate grant)", "SELECT a.id FROM users a CROSS JOIN users b", map[string]bool{u: true}},
		{"join predicate reference covers the joined table", "SELECT u.id FROM users u JOIN orders o ON o.uid = u.id", map[string]bool{u: true, o: true}},
		{"WHERE reference covers the table", "SELECT u.id FROM users u, orders o WHERE o.uid = u.id", map[string]bool{u: true, o: true}},
		// The safety pair (docs/facts-emission.md):
		{"pure CTE shadow: real orders NOT scanned → no physical source", "WITH orders AS (SELECT 1) SELECT count(*) FROM orders", map[string]bool{}},
		{"CTE-body self-reference: real orders IS scanned, uncovered", "WITH o AS (SELECT count(*) AS c FROM orders) SELECT c FROM o", map[string]bool{o: false}},
		// Writes: target is not a scanned source; a read source in UPDATE..FROM is.
		{"INSERT target is not a scanned source", "INSERT INTO orders (id, uid) VALUES (1, 2)", map[string]bool{}},
		{"UPDATE..FROM: read source with no column ref → uncovered; target excluded", "UPDATE sink SET data = 'x' FROM orders WHERE sink.id = 1", map[string]bool{o: false}},
		{"UPDATE..FROM: read source referenced in predicate → covered", "UPDATE sink SET data = 'x' FROM orders WHERE sink.id = orders.id", map[string]bool{o: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, resolved := probeSources(t, tc.sql, "postgres", cols, ns)
			if !resolved {
				t.Fatalf("expected resolved=true (a resolved statement carries sources); sql=%s", tc.sql)
			}
			assertSources(t, tc.sql, tc.want, got)
		})
	}
}

// TestScannedSourcesMySQL re-runs the safety pair + the base leak on MySQL to prove the physical/CTE
// distinction holds on both engines (the resolution report drives it, not engine-specific parsing).
func TestScannedSourcesMySQL(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "id", "BIGINT"),
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
		columnSpec("def", "app", "orders", "id", "BIGINT"),
		columnSpec("def", "app", "orders", "uid", "BIGINT"),
	}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	o := "def.app.orders"

	cases := []struct {
		name string
		sql  string
		want map[string]bool
	}{
		{"count(*) uncovered", "SELECT count(*) FROM orders", map[string]bool{o: false}},
		{"pure CTE shadow → no physical source", "WITH orders AS (SELECT 1) SELECT count(*) FROM orders", map[string]bool{}},
		{"CTE-body self-reference → uncovered physical", "WITH o AS (SELECT count(*) AS c FROM orders) SELECT c FROM o", map[string]bool{o: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, resolved := probeSources(t, tc.sql, "mysql", cols, ns)
			if !resolved {
				t.Fatalf("expected resolved=true; sql=%s", tc.sql)
			}
			assertSources(t, tc.sql, tc.want, got)
		})
	}
}

// TestScannedSourcesDottedNameDoesNotPolluteSibling locks the coverage prefix-match behavior:
// a table literally named "x.foo" (a dot IN the name) must not make a clean sibling
// table `x` — scanned with zero traced columns — appear covered. The dotted name is pathological and
// denied downstream anyway, but the analyzer's `covered` flag must be correct on its own (fail-closed).
func TestScannedSourcesDottedNameDoesNotPolluteSibling(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "public", "x", "id", "BIGINT"),
		columnSpec("acme", "public", "x.foo", "id", "BIGINT"),
	}
	ns := &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}
	got, resolved := probeSources(t, `SELECT f.id FROM "x.foo" f CROSS JOIN x`, "postgres", cols, ns)
	if !resolved {
		t.Fatalf("expected resolved=true")
	}
	// `x.foo` is read via f.id → covered; the clean sibling `x` traces zero columns → must be UNCOVERED,
	// not polluted by `x.foo`'s base key `acme.public.x.foo.id` matching the `acme.public.x.` prefix.
	assertSources(t, "dotted-name sibling", map[string]bool{
		"acme.public.x.foo": true,
		"acme.public.x":     false,
	}, got)
}

func probeSources(t *testing.T, sql, dialect string, cols []*pb.ColumnSpec, ns *pb.Namespace) (map[string]bool, bool) {
	t.Helper()
	engineConfig := &pb.EngineConfig{Engine: pb.Engine_POSTGRES}
	if dialect == "mysql" {
		engineConfig = &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}
	}
	res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: sql, EngineConfig: engineConfig, Namespace: ns, Catalog: cols})
	got := map[string]bool{}
	for _, s := range res.Sources {
		key := s.Catalog + "." + s.Schema + "." + s.Table
		if _, dup := got[key]; dup {
			t.Fatalf("duplicate table %q in sources (must dedupe by tableID): %+v", key, res.Sources)
		}
		got[key] = s.Covered
	}
	return got, res.Resolved
}

func assertSources(t *testing.T, sql string, want, got map[string]bool) {
	t.Helper()
	for tbl, cov := range want {
		g, ok := got[tbl]
		if !ok {
			t.Fatalf("missing physical source %q (a scanned relation must be emitted)\n  sql=%s\n  got=%v", tbl, sql, keys(got))
		}
		if g != cov {
			t.Fatalf("source %q covered=%v, want %v\n  sql=%s", tbl, g, cov, sql)
		}
	}
	for tbl := range got {
		if _, ok := want[tbl]; !ok {
			t.Fatalf("UNEXPECTED physical source %q (a shadowed CTE / write target must NOT be emitted)\n  sql=%s\n  got=%v", tbl, sql, keys(got))
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
