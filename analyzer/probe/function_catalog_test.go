package probe

import (
	"slices"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func TestAnalyzeRequestAbsentFunctions(t *testing.T) {
	for _, engine := range []pb.Engine{pb.Engine_MYSQL, pb.Engine_POSTGRES} {
		t.Run(engine.String(), func(t *testing.T) {
			catalog, schema := "def", "app"
			config := &pb.EngineConfig{Engine: engine, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)}
			if engine == pb.Engine_POSTGRES {
				catalog, schema = "acme", "public"
				config = &pb.EngineConfig{Engine: engine}
			}
			for _, observed := range []bool{false, true} {
				for _, sql := range []string{"SELECT u.ssn FROM users AS u", "SELECT lower(u.ssn) FROM users AS u"} {
					req := &pb.AnalyzeRequest{
						Sql: sql, EngineConfig: config,
						Namespace: &pb.Namespace{Catalog: catalog, SearchPath: []string{schema}},
						Catalog:   snapshot([]*pb.Column{pbColumn(schema, "users", "ssn", "VARCHAR")}),
					}
					if observed {
						req.Catalog.Functions = &pb.FunctionCatalog{}
					}
					facts := analyzeProto(t, req)
					if strings.Contains(sql, "lower(") {
						if facts.GetResolved() || facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
							t.Fatalf("observed=%v sql=%q: unknown function must fail closed: %v", observed, sql, facts)
						}
					} else if !facts.GetResolved() || len(facts.GetResultReads()) != 1 || facts.GetResultReads()[0].GetColumn().GetColumn() != "ssn" {
						t.Fatalf("observed=%v: column catalog must resolve independently of functions: %v", observed, facts)
					}
					if (req.GetCatalog().GetFunctions() != nil) != observed {
						t.Fatal("analysis helper changed function catalog presence")
					}
				}
			}
		})
	}
}

func TestMySQLFunctionCatalogResolution(t *testing.T) {
	functions := &pb.FunctionCatalog{
		BuiltinFunctions:  []string{"abs", "lcase"},
		LoadableFunctions: []string{"abs", "plugin_fn"},
		UdfSchemas: []*pb.SchemaFunctions{
			{Schema: "app", Names: []string{"lookup", "abs", "plugin_fn"}},
			{Schema: "other", Names: []string{"lookup", "remote_fn", "lcase"}},
			{Schema: "def", Names: []string{"catalog_only"}},
		},
	}
	for _, tc := range []struct {
		sql, database, builtin, udf string
		resolved                    bool
	}{
		{"SELECT ABS(1)", "app", "abs", "", true},
		{"SELECT LCASE('X') AS value", "app", "lcase", "", true},
		{"SELECT lookup()", "app", "", "app.lookup", true},
		{"SELECT lookup()", "other", "", "other.lookup", true},
		{"SELECT remote_fn()", "app", "", "", false},
		{"SELECT catalog_only()", "app", "", "", false},
		{"SELECT other.remote_fn() AS value", "app", "", "other.remote_fn", true},
		{"SELECT other.LCASE('X') AS value", "app", "", "other.lcase", true},
		{"SELECT app.abs(1)", "other", "", "app.abs", true},
		{"SELECT plugin_fn()", "app", "", "plugin_fn", true},
	} {
		t.Run(tc.database+"/"+tc.sql, func(t *testing.T) {
			facts := analyzeProto(t, &pb.AnalyzeRequest{
				Sql:          tc.sql,
				EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)},
				Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{tc.database}},
				Catalog:      snapshotWith(nil, functions),
			})
			if facts.GetResolved() != tc.resolved {
				t.Fatalf("resolved=%v, want %v: %v", facts.GetResolved(), tc.resolved, facts)
			}
			if !tc.resolved {
				return
			}
			assertFunctionIdentity(t, facts, tc.builtin, tc.udf)
		})
	}
}

func TestPostgresFunctionCatalogResolution(t *testing.T) {
	functions := &pb.FunctionCatalog{
		BuiltinFunctions:      []string{"lower"},
		SystemFunctionSchemas: []*pb.SchemaFunctions{{Schema: "pg_catalog", Names: []string{"lower"}}},
		UdfSchemas:            []*pb.SchemaFunctions{{Schema: "public", Names: []string{"lower", "lookup"}}},
	}
	for _, tc := range []struct {
		sql          string
		path         []string
		builtin, udf string
		resolved     bool
	}{
		{"SELECT lower('X') AS value", []string{"analytics"}, "pg_catalog.lower", "", true},
		{"SELECT lookup() AS value", []string{"public"}, "", "public.lookup", true},
		{"SELECT lower('X') AS value", []string{"public"}, "", "", false},
		{"SELECT lower('X') AS value", []string{"public", "pg_catalog"}, "", "", false},
		{"SELECT PG_CATALOG.lower('X') AS value", []string{"public", "pg_catalog"}, "pg_catalog.lower", "", true},
		{"SELECT public.lower('X') AS value", []string{"pg_catalog", "public"}, "", "public.lower", true},
		{`SELECT "PG_CATALOG".lower('X')`, []string{"public"}, "", "", false},
	} {
		t.Run(tc.sql+strings.Join(tc.path, ","), func(t *testing.T) {
			facts := analyzeProto(t, &pb.AnalyzeRequest{
				Sql: tc.sql, EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
				Namespace: &pb.Namespace{Catalog: "acme", SearchPath: tc.path}, Catalog: snapshotWith(nil, functions),
			})
			if facts.GetResolved() != tc.resolved {
				t.Fatalf("resolved=%v, want %v: %v", facts.GetResolved(), tc.resolved, facts)
			}
			if tc.resolved {
				assertFunctionIdentity(t, facts, tc.builtin, tc.udf)
			}
		})
	}
}

func assertFunctionIdentity(t *testing.T, facts *pb.StatementFacts, builtin, udf string) {
	t.Helper()
	var wantBuiltins, wantUDFs, gotUDFs []string
	if builtin != "" {
		wantBuiltins = []string{builtin}
	}
	if udf != "" {
		wantUDFs = []string{udf}
	}
	for _, read := range facts.GetResultReads() {
		if function := read.GetFunction(); function != nil {
			gotUDFs = append(gotUDFs, function.GetName())
		}
	}
	if !slices.Equal(facts.GetFunctions(), wantBuiltins) || !slices.Equal(gotUDFs, wantUDFs) {
		t.Fatalf("functions=%v grants=%v, want functions=%v grants=%v", facts.GetFunctions(), gotUDFs, wantBuiltins, wantUDFs)
	}
}
