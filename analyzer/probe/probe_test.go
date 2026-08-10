package probe

import (
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"google.golang.org/protobuf/proto"
)

func mustParseOne(t *testing.T, sql string) exp.Expression {
	t.Helper()
	e, err := sqlglot.ParseOne(sql, "postgres")
	if err != nil {
		t.Fatalf("ParseOne(%q): %v", sql, err)
	}
	return e
}

func TestLeafSelects(t *testing.T) {
	root := mustParseOne(t, "(SELECT id FROM users UNION ALL SELECT id FROM users) UNION ALL SELECT id FROM users")
	p := &prober{}
	leaves := p.leafSelects(root)
	if len(leaves) != 3 {
		t.Fatalf("leafSelects count = %d, want 3", len(leaves))
	}
	for i, leaf := range leaves {
		if leaf.Kind() != exp.KindSelect {
			t.Fatalf("leaf %d kind = %v, want Select", i, leaf.Kind())
		}
	}
}

func TestIdentityCol(t *testing.T) {
	root := mustParseOne(t, "SELECT ssn AS r, substr(ssn, 1, 1) AS s FROM users")
	p := &prober{}
	selects := root.Selects()
	if got := p.identityCol(selects[0]); got == nil || got.Kind() != exp.KindColumn || got.Name() != "ssn" {
		t.Fatalf("identityCol(first) = %#v, want ssn column", got)
	}
	if got := p.identityCol(selects[1]); got != nil {
		t.Fatalf("identityCol(computed) = %#v, want nil", got)
	}
}

func TestIsStar(t *testing.T) {
	root := mustParseOne(t, "SELECT *, u.*, count(*) FROM users u")
	p := &prober{}
	selects := root.Selects()
	if !p.isStar(selects[0]) {
		t.Fatalf("bare star not detected")
	}
	if !p.isStar(selects[1]) {
		t.Fatalf("qualified star not detected")
	}
	if p.isStar(selects[2]) {
		t.Fatalf("count(*) projection was classified as a projection star")
	}
}

func TestIsExpressionSubquery(t *testing.T) {
	p := &prober{}
	inRoot := mustParseOne(t, "SELECT id FROM orders WHERE user_id IN (SELECT id FROM users)")
	var inner exp.Expression
	for _, sel := range inRoot.FindAll(exp.KindSelect) {
		if sel != inRoot {
			inner = sel
			break
		}
	}
	if inner == nil || !p.isExpressionSubquery(inner) {
		t.Fatalf("IN subquery was not classified as opaque expression subquery")
	}

	fromRoot := mustParseOne(t, "SELECT t.id FROM (SELECT id FROM users) AS t")
	inner = nil
	for _, sel := range fromRoot.FindAll(exp.KindSelect) {
		if sel != fromRoot {
			inner = sel
			break
		}
	}
	if inner == nil || p.isExpressionSubquery(inner) {
		t.Fatalf("FROM derived table was classified as expression subquery")
	}
}

func TestFromSourceOrder(t *testing.T) {
	root := mustParseOne(t, "SELECT * FROM users u JOIN orders o ON u.id = o.user_id")
	p := &prober{}
	got := p.fromSourceOrder(root)
	want := []string{"u", "o"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fromSourceOrder = %v, want %v", got, want)
	}
}

func TestMySQLPlaceholderResolvesAndTracesColumns(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "id", "BIGINT"),
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
	}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}

	result := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT ssn FROM users WHERE id = ?",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)},
		Namespace:    ns, Catalog: cols,
	})
	requireResolvedKeys(t, result, "def.app.users.ssn", "def.app.users.id")
}

func TestCTEColNames(t *testing.T) {
	root := mustParseOne(t, "WITH s(x) AS (SELECT ssn FROM users UNION ALL SELECT region FROM users) SELECT x FROM s")
	p := &prober{}
	cte := root.Find(exp.KindCTE)
	if cte == nil {
		t.Fatalf("CTE not found")
	}
	got := p.cteColNames(cte)
	want := []string{"x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cteColNames = %v, want %v", got, want)
	}
}
