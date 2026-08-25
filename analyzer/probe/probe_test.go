package probe

import (
	"reflect"
	"strings"
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

func TestPostgresNaturalJoinExpandsWithPhysicalLineage(t *testing.T) {
	result := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT * FROM public.left_table l NATURAL JOIN public.right_table r",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "left_table", "left_value", "TEXT"),
			columnSpec("acme", "public", "left_table", "id", "BIGINT"),
			columnSpec("acme", "public", "right_table", "id", "BIGINT"),
			columnSpec("acme", "public", "right_table", "right_value", "TEXT"),
		},
	})
	if !result.Resolved {
		t.Fatalf("NATURAL JOIN must resolve: stage=%v detail=%q", result.FailedStage, result.Detail)
	}
	wantNames := []string{"id", "left_value", "right_value"}
	if result.OutputColumns != len(wantNames) {
		t.Fatalf("output columns = %d, want %d: %+v", result.OutputColumns, len(wantNames), result.Origins)
	}
	for i, want := range wantNames {
		if result.Origins[i].Column != want {
			t.Fatalf("output %d = %q, want %q: %+v", i, result.Origins[i].Column, want, result.Origins)
		}
	}
	wantIDOrigins := []string{"acme.public.left_table.id", "acme.public.right_table.id"}
	if !reflect.DeepEqual(result.Origins[0].Origins, wantIDOrigins) {
		t.Fatalf("id origins = %v, want %v", result.Origins[0].Origins, wantIDOrigins)
	}
	for _, column := range wantIDOrigins {
		found := false
		for _, reference := range result.References[JOIN] {
			if reference == column {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("JOIN references = %v, missing %s", result.References[JOIN], column)
		}
	}
	if result.RewrittenSQL == nil {
		t.Fatal("NATURAL JOIN star must carry an executable rewrite")
	}
	rewritten, err := sqlglot.ParseOne(*result.RewrittenSQL, "postgres")
	if err != nil {
		t.Fatalf("parse rewritten SQL: %v", err)
	}
	for i, want := range wantNames {
		if got := rewritten.Selects()[i].AliasOrName(); got != want {
			t.Fatalf("rewritten output %d = %q, want %q: %q", i, got, want, *result.RewrittenSQL)
		}
	}
}

func TestPostgresNaturalJoinChainsAfterUsing(t *testing.T) {
	result := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT * FROM public.a JOIN public.b USING (id) NATURAL JOIN public.c",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "a", "id", "BIGINT"),
			columnSpec("acme", "public", "a", "a_value", "TEXT"),
			columnSpec("acme", "public", "b", "id", "BIGINT"),
			columnSpec("acme", "public", "b", "shared", "TEXT"),
			columnSpec("acme", "public", "b", "b_value", "TEXT"),
			columnSpec("acme", "public", "c", "shared", "TEXT"),
			columnSpec("acme", "public", "c", "c_value", "TEXT"),
		},
	})
	if !result.Resolved {
		t.Fatalf("chained NATURAL JOIN must resolve: stage=%v detail=%q", result.FailedStage, result.Detail)
	}
	want := []string{"shared", "id", "a_value", "b_value", "c_value"}
	if len(result.Origins) != len(want) {
		t.Fatalf("origins = %+v, want %d outputs", result.Origins, len(want))
	}
	for i, name := range want {
		if result.Origins[i].Column != name {
			t.Fatalf("output %d = %q, want %q: %+v", i, result.Origins[i].Column, name, result.Origins)
		}
	}
}

func TestPostgresNaturalJoinRespectsCommaPrecedence(t *testing.T) {
	result := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT * FROM public.a, public.b NATURAL JOIN public.c",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "a", "id", "BIGINT"),
			columnSpec("acme", "public", "a", "a_value", "TEXT"),
			columnSpec("acme", "public", "b", "shared", "TEXT"),
			columnSpec("acme", "public", "b", "b_value", "TEXT"),
			columnSpec("acme", "public", "c", "id", "BIGINT"),
			columnSpec("acme", "public", "c", "shared", "TEXT"),
			columnSpec("acme", "public", "c", "c_value", "TEXT"),
		},
	})
	if !result.Resolved {
		t.Fatalf("comma-bound NATURAL JOIN must resolve: stage=%v detail=%q", result.FailedStage, result.Detail)
	}
	want := []string{"id", "a_value", "shared", "b_value", "id", "c_value"}
	if len(result.Origins) != len(want) {
		t.Fatalf("origins = %+v, want %d outputs", result.Origins, len(want))
	}
	for i, name := range want {
		if result.Origins[i].Column != name {
			t.Fatalf("output %d = %q, want %q: %+v", i, result.Origins[i].Column, name, result.Origins)
		}
	}
}

func TestPostgresNaturalJoinWithoutCommonColumns(t *testing.T) {
	catalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "a", "a_id", "BIGINT"),
		columnSpec("acme", "public", "b", "b_id", "BIGINT"),
	}
	for _, tc := range []struct {
		name string
		sql  string
		want string
	}{
		{name: "inner", sql: "SELECT * FROM public.a NATURAL JOIN public.b", want: "TRUE"},
		{name: "left", sql: "SELECT * FROM public.a NATURAL LEFT JOIN public.b", want: "TRUE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzeProbe(t, &pb.AnalyzeRequest{
				Sql:          tc.sql,
				EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
				Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
				Catalog:      catalog,
			})
			if !result.Resolved || result.RewrittenSQL == nil {
				t.Fatalf("empty-intersection NATURAL JOIN must resolve with a rewrite: %+v", result)
			}
			if !strings.Contains(strings.ToUpper(*result.RewrittenSQL), tc.want) {
				t.Fatalf("rewrite %q does not contain %q", *result.RewrittenSQL, tc.want)
			}
		})
	}
}

func TestPostgresNaturalJoinRejectsAmbiguousCommonColumn(t *testing.T) {
	result := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT * FROM (SELECT id, id AS id FROM public.a) l NATURAL JOIN public.b",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "a", "id", "BIGINT"),
			columnSpec("acme", "public", "b", "id", "BIGINT"),
		},
	})
	if result.Resolved || result.FailedStage == nil || *result.FailedStage != "VALIDATE" || !strings.Contains(result.Detail, "ambiguous") {
		t.Fatalf("ambiguous NATURAL JOIN must fail closed in validation: %+v", result)
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
