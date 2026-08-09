package probe

// Coverage for the protobuf FFM entry point (wire.go, docs/statement-facts-contract.md) —
// the analyzer<->JVM contract every test in this package exercises directly (no JSON anywhere in
// this module). columnSpec
// and analyzeProto below are the shared fixture-building/call helpers every other test file in this
// package reuses. These tests specifically cover the proto encode/decode path itself: the flat-catalog
// schema.Mapping build, namespace validation, and the total/fail-closed AnalyzeStatementSafe contract —
// malformed input must never escape as a panic.

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func columnSpec(catalog, schemaName, table, column, dataType string) *pb.ColumnSpec {
	return &pb.ColumnSpec{
		Catalog:  catalog,
		Identity: &pb.RelationIdentity{Schema: schemaName, Table: table, Column: column},
		DataType: dataType,
	}
}

func analyzeProto(t *testing.T, req *pb.AnalyzeRequest) *pb.StatementFacts {
	t.Helper()
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var out pb.StatementFacts
	if err := proto.Unmarshal(AnalyzeStatementSafe(reqBytes), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return &out
}

func stageString(stage *string) string {
	if stage == nil {
		return ""
	}
	return *stage
}

func analyzeProbe(t *testing.T, req *pb.AnalyzeRequest) *ProbeResult {
	t.Helper()
	sch, err := schemaMappingFromProto(req.GetCatalog())
	if err != nil {
		result := failResult("VALIDATE", err.Error())
		return &result
	}
	namespace, err := namespaceConfigFromProto(req.GetNamespace())
	if err != nil {
		result := failResult("VALIDATE", err.Error())
		return &result
	}
	result := Probe(req.GetSql(), req.GetEngineConfig(), sch, namespace)
	return &result
}

func TestAnalyzeStatementResolvesOrdinaryQuery(t *testing.T) {
	out := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT ssn FROM users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace: &pb.Namespace{
			Catalog:    "acme",
			SearchPath: []string{"public"},
		},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "users", "id", "BIGINT"),
			columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
		},
	})
	if !out.Resolved {
		t.Fatalf("expected resolved, got detail=%q stage=%v", out.Detail, out.FailedStage)
	}
	if len(out.Origins) != 1 || out.Origins[0].Column != "ssn" {
		t.Fatalf("unexpected origins: %+v", out.Origins)
	}
	if got := out.Origins[0].Origins; len(got) != 1 || got[0] != "acme.public.users.ssn" {
		t.Fatalf("unexpected origin source: %+v", got)
	}
}

func TestAnalyzeStatementMySQLRequiresLowerCaseTableNames(t *testing.T) {
	out := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT id FROM users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46"}, // no mysql_lower_case_table_names
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"acme"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "acme", "users", "id", "BIGINT"),
		},
	})
	if out.Resolved {
		t.Fatalf("expected fail-closed without mysqlLowerCaseTableNames, got resolved=true")
	}
	if stageString(out.FailedStage) != "VALIDATE" {
		t.Fatalf("expected VALIDATE stage, got %q", stageString(out.FailedStage))
	}
}

func TestAnalyzeStatementMySQLRequiresEngineVersion(t *testing.T) {
	out := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT id FROM users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(0)},
		Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
		Catalog:      []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")},
	})
	if out.Resolved || stageString(out.FailedStage) != "VALIDATE" {
		t.Fatalf("expected VALIDATE failure without engine_version, got %+v", out)
	}
}

func TestAnalyzeStatementEngineVersionReachesMySQLParser(t *testing.T) {
	out := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql: "SELECT 1 /*!50700 , ssn */ FROM users",
		EngineConfig: &pb.EngineConfig{
			Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0),
		},
		Namespace: &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("def", "acme", "users", "id", "BIGINT"),
			columnSpec("def", "acme", "users", "ssn", "VARCHAR"),
		},
	})
	if !out.Resolved {
		t.Fatalf("expected resolved executable comment, got stage=%q detail=%q", stageString(out.FailedStage), out.Detail)
	}
	found := false
	for _, origin := range out.Origins {
		for _, key := range origin.Origins {
			if key == "def.acme.users.ssn" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("engine_config.engine_version did not activate executable comment: %+v", out.Origins)
	}
}

func TestAnalyzeStatementRejectsUnspecifiedEngine(t *testing.T) {
	out := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT id FROM users",
		EngineConfig: &pb.EngineConfig{EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)}, // engine left ENGINE_UNSPECIFIED
		Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
		Catalog:      []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")},
	})
	if out.Resolved || stageString(out.FailedStage) != "VALIDATE" {
		t.Fatalf("expected ENGINE_UNSPECIFIED to fail VALIDATE, got %+v", out)
	}
}

func TestAnalyzeStatementRejectsDuplicateCatalogColumn(t *testing.T) {
	out := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT id FROM users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "users", "id", "BIGINT"),
			columnSpec("acme", "public", "users", "id", "VARCHAR"), // duplicate
		},
	})
	if out.Resolved {
		t.Fatalf("expected fail-closed on duplicate catalog column, got resolved=true")
	}
}

func TestAnalyzeStatementMissingNamespaceFailsClosed(t *testing.T) {
	out := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT 1",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		// Namespace left nil entirely.
	})
	if out.Resolved {
		t.Fatalf("expected fail-closed on missing namespace, got resolved=true")
	}
}

func TestAnalyzeStatementSafeNeverPanicsOnMalformedBytes(t *testing.T) {
	var out pb.StatementFacts
	if err := proto.Unmarshal(AnalyzeStatementSafe([]byte{0xff, 0x00, 0x01}), &out); err != nil {
		t.Fatalf("AnalyzeStatementSafe did not return valid StatementFacts: %v", err)
	}
	if out.Resolved {
		t.Fatalf("expected fail-closed on malformed request bytes, got resolved=true")
	}
}

// TestNormalizeRelation covers the dialect dispatch itself — canonical_relation_test.go covers the
// underlying MySQL fold logic in depth. Every direct Go-to-Go caller (goproxy's introspect.go and
// goproxy/db) shares this one function; no caller decides whether/how to normalize.
func TestNormalizeRelation(t *testing.T) {
	schemaName, table, column := NormalizeRelation("mysql", 1, "AppDB", "UserRows", "CustomerID")
	if schemaName != "appdb" || table != "userrows" || column != "customerid" {
		t.Fatalf("unexpected canonical relation: %s.%s.%s", schemaName, table, column)
	}

	// Postgres: an identity function — the catalog's stored spelling already IS canonical, verbatim,
	// regardless of case. Proves Go (not the caller) decides that no folding applies to this dialect.
	pgSchema, pgTable, pgColumn := NormalizeRelation("postgres", 0, "Sales", "OrderItems", "CustomerID")
	if pgSchema != "Sales" || pgTable != "OrderItems" || pgColumn != "CustomerID" {
		t.Fatalf("Postgres identity must pass through unchanged, got %s.%s.%s", pgSchema, pgTable, pgColumn)
	}
}
