package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// Locks the diagnostic_leak_columns contract: referenced columns, plus a PostgreSQL write's whole target
// row (the `DETAIL: Failing row contains (…)` dump). See docs/diagnostic-redaction.md.
func TestDiagnosticLeakColumns(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
		columnSpec("acme", "public", "users", "email", "VARCHAR"),
	}
	pgMapping, err := schemaMappingFromProto(cols)
	if err != nil {
		t.Fatalf("build pg schema: %v", err)
	}
	pgNs := NamespaceConfig{Catalog: "acme", SearchPath: []string{"public"}}
	pg := &pb.EngineConfig{Engine: pb.Engine_POSTGRES, EngineVersion: "16.0"}

	mysqlCols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "id", "BIGINT"),
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
		columnSpec("def", "app", "users", "email", "VARCHAR"),
	}
	mysqlMapping, err := schemaMappingFromProto(mysqlCols)
	if err != nil {
		t.Fatalf("build mysql schema: %v", err)
	}
	mysqlNs := NamespaceConfig{Catalog: "def", SearchPath: []string{"app"}}
	mysql := &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}

	t.Run("postgres write leaks the whole target row", func(t *testing.T) {
		facts := EmitFacts("UPDATE users SET id = 1 WHERE id = 5", pg, pgMapping, pgNs)
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %s", facts.GetDetail())
		}
		assertLeak(t, facts, []string{
			"acme.public.users.email",
			"acme.public.users.id",
			"acme.public.users.ssn",
		})
	})

	t.Run("postgres read leaks only referenced columns", func(t *testing.T) {
		facts := EmitFacts("SELECT id FROM users", pg, pgMapping, pgNs)
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %s", facts.GetDetail())
		}
		assertLeak(t, facts, []string{"acme.public.users.id"})
	})

	t.Run("mysql write leaks only referenced columns (no whole-row dump)", func(t *testing.T) {
		facts := EmitFacts("UPDATE users SET id = 1 WHERE id = 5", mysql, mysqlMapping, mysqlNs)
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %s", facts.GetDetail())
		}
		assertLeak(t, facts, []string{"def.app.users.id"})
	})

	t.Run("postgres INSERT with an empty reference set still leaks the whole row", func(t *testing.T) {
		facts := EmitFacts("INSERT INTO users (id) VALUES (1)", pg, pgMapping, pgNs)
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %s", facts.GetDetail())
		}
		assertLeak(t, facts, []string{
			"acme.public.users.email",
			"acme.public.users.id",
			"acme.public.users.ssn",
		})
	})

	t.Run("a dotted column name emits an unresolvable key instead of vanishing", func(t *testing.T) {
		dottedCols := append(cols, columnSpec("acme", "public", "users", "ssn.secret", "VARCHAR"))
		dottedMapping, err := schemaMappingFromProto(dottedCols)
		if err != nil {
			t.Fatalf("build schema: %v", err)
		}
		facts := EmitFacts("UPDATE users SET id = 1 WHERE id = 5", pg, dottedMapping, pgNs)
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %s", facts.GetDetail())
		}
		// `acme.public.users.ssn.secret` cannot split 4-ways; it must surface as a column entry the
		// control-plane's catalog lookup misses (→ redact), never be silently dropped.
		found := false
		for _, c := range facts.GetDiagnosticLeakColumns() {
			if c.GetIdentity().GetColumn() == "acme.public.users.ssn.secret" {
				found = true
			}
		}
		if !found {
			t.Errorf("dotted column must emit a fail-closed entry: %v", facts.GetDiagnosticLeakColumns())
		}
	})
}

func assertLeak(t *testing.T, facts *pb.StatementFacts, want []string) {
	t.Helper()
	got := make([]string, 0, len(facts.GetDiagnosticLeakColumns()))
	for _, c := range facts.GetDiagnosticLeakColumns() {
		id := c.GetIdentity()
		got = append(got, c.GetCatalog()+"."+id.GetSchema()+"."+id.GetTable()+"."+id.GetColumn())
	}
	// The emitted order must already be sorted by (catalog, schema, table, column); assert it before any
	// local re-sort, since the control-plane compares the frozen list positionally.
	if !sort.StringsAreSorted(got) {
		t.Errorf("diagnostic_leak_columns must be emitted sorted: %v", got)
	}
	if !equalStrings(got, want) {
		t.Errorf("diagnostic_leak_columns = %v, want %v", got, want)
	}
}
