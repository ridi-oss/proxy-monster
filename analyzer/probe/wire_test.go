package probe

// Coverage for the protobuf FFM entry point (wire.go, docs/statement-facts-contract.md) —
// the analyzer<->JVM contract every test in this package exercises directly (no JSON anywhere in
// this module). pbColumn, snapshot, snapshotWith,
// and analyzeProto below are the shared fixture-building/call helpers every other test file in this
// package reuses. These tests specifically cover the proto encode/decode path itself: the flat-catalog
// schema.Mapping build, namespace validation, and the total/fail-closed AnalyzeStatementSafe contract —
// malformed input must never escape as a panic.

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func pbColumn(schemaName, table, column, dataType string) *pb.Column {
	return &pb.Column{Schema: schemaName, Table: table, Column: column, DataType: dataType}
}

func snapshot(columns []*pb.Column) *pb.CatalogSnapshot {
	return &pb.CatalogSnapshot{Columns: columns}
}

func snapshotWith(columns []*pb.Column, functions *pb.FunctionCatalog) *pb.CatalogSnapshot {
	return &pb.CatalogSnapshot{Columns: columns, Functions: functions}
}

// testBuiltins is a representative PG/MySQL builtin set (pg_catalog / MySQL native) covering the
// functions the probe tests call — the resolution input the control plane introspects in production.
var testBuiltins = []string{
	"version", "now", "current_timestamp", "current_date", "current_time", "current_user", "session_user",
	"current_database", "current_schema", "current_setting", "txid_current", "pg_backend_pid", "database",
	"connection_id", "last_insert_id", "found_rows", "user", "charset", "collation", "coercibility",
	"abs", "ceil", "ceiling", "floor", "round", "trunc", "truncate", "mod", "power", "pow", "sqrt", "exp", "ln", "log", "sign",
	"lower", "upper", "lcase", "ucase", "concat", "concat_ws", "substr", "substring", "left", "right", "trim",
	"ltrim", "rtrim", "lpad", "rpad", "replace", "reverse", "repeat", "length", "char_length", "character_length",
	"ascii", "chr", "char",
	"overlay", "position", "quote_literal", "quote_ident", "md5", "sha1", "sha2", "encode", "decode", "hex", "format",
	"coalesce", "nullif", "ifnull", "nvl", "iif", "if", "greatest", "least", "cast", "age", "dateadd",
	"date_part", "extract", "datediff", "date_trunc", "to_char", "to_date", "to_timestamp",
	"count", "sum", "avg", "min", "max", "array_agg", "string_agg",
	"unnest", "generate_series", "gen_random_uuid", "uuid", "uuid_to_bin", "to_jsonb", "row_to_json",
	"pg_typeof", "typeof",
	// dangerous builtins (the control plane gates these by identity via its danger manifest)
	"set_config", "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
	"query_to_xml", "query_to_xml_and_xmlschema", "query_to_xmlschema", "table_to_xml", "database_to_xml",
	"xpath_table", "pg_get_userbyid", "pg_get_expr", "pg_tablespace_location", "pg_available_extension_versions",
	"pg_terminate_backend", "heap_page_items", "get_raw_page",
	"dblink", "dblink_exec", "dblink_open", "dblink_fetch", "dblink_send_query", "dblink_get_result",
	"lo_import", "lo_export", "load_file", "rds_kill",
	"row_number",
}

var testInfoSchemaHelpers = []string{
	"_pg_char_max_length", "_pg_char_octet_length", "_pg_datetime_precision", "_pg_expandarray",
	"_pg_index_position", "_pg_interval_type", "_pg_numeric_precision", "_pg_numeric_precision_radix",
	"_pg_numeric_scale", "_pg_truetypid", "_pg_truetypmod",
}

// testUDFs are the user-function names probe tests reference; put them in the query's user schema so
// they resolve UDF (a fail-closed Function grant) rather than Unknown.
var testUDFs = []string{"my_udf", "custom_udf", "user_fn", "leak_ssn"}

// testUDFSchemas are the qualified user-function homes probe tests reference — a qualified call
// resolves UDF only when its schema.name pair is in the catalog; anything else is Unknown (deny).
var testUDFSchemas = map[string][]string{
	"pm_leak":     {"text", "upper", "filter"},
	"app":         {"get_ssn"},
	"mydb":        {"leak"},
	"acme":        {"leak_ssn"},
	"user_schema": {"abs", "version"},
}

func testFunctionCatalog(mysql bool, searchPath []string) *pb.FunctionCatalog {
	names := func(ns []string) []string { return append([]string(nil), ns...) }
	userSchema := "public"
	if mysql {
		// MySQL: the database is the schema; unqualified stored functions resolve against it.
		if len(searchPath) > 0 {
			userSchema = searchPath[0]
		}
	}
	udfSchemas := []*pb.SchemaFunctions{{Schema: userSchema, Names: names(testUDFs)}}
	for schema, fns := range testUDFSchemas {
		if schema == userSchema {
			udfSchemas[0].Names = append(udfSchemas[0].Names, fns...)
			continue
		}
		udfSchemas = append(udfSchemas, &pb.SchemaFunctions{Schema: schema, Names: names(fns)})
	}
	ec := &pb.FunctionCatalog{
		BuiltinFunctions: names(testBuiltins),
		UdfSchemas:       udfSchemas,
	}
	if !mysql {
		// MySQL native functions are never schema-qualified; only PG carries system function schemas.
		ec.SystemFunctionSchemas = []*pb.SchemaFunctions{
			{Schema: "pg_catalog", Names: names(testBuiltins)},
			{Schema: "information_schema", Names: names(testInfoSchemaHelpers)},
		}
	}
	return ec
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
	namespace, err := namespaceConfigFromProto(req.GetNamespace())
	if err != nil {
		result := failResult("VALIDATE", err.Error())
		return &result
	}
	sch, err := schemaMappingFromProto(namespace.Catalog, req.GetCatalog().GetColumns())
	if err != nil {
		result := failResult("VALIDATE", err.Error())
		return &result
	}
	namespace.EngineCatalog = engineCatalogFromProto(req.GetCatalog().GetFunctions(), namespace.SearchPath)
	result := Probe(req.GetSql(), req.GetEngineConfig(), sch, namespace)
	return &result
}

// A column with no catalog of its own belongs to the namespace catalog; a column naming another
// catalog keeps that identity, so the two never collapse into one mapping entry.
func TestSchemaMappingColumnCatalogDefaultsToNamespace(t *testing.T) {
	sch, err := schemaMappingFromProto("acme", []*pb.Column{
		pbColumn("public", "users", "id", "BIGINT"),
		{Catalog: "acme", Schema: "public", Table: "users", Column: "ssn", DataType: "VARCHAR"},
		{Catalog: "reporting", Schema: "public", Table: "users", Column: "id", DataType: "BIGINT"},
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	if len(sch.Keys()) != 2 {
		t.Fatalf("catalogs = %v, want acme and reporting", sch.Keys())
	}
	acme := getOrNewMapping(getOrNewMapping(getOrNewMapping(sch, "acme"), "public"), "users")
	if _, ok := acme.Get("id"); !ok {
		t.Fatal("empty-catalog column must land under the namespace catalog")
	}
	if _, ok := acme.Get("ssn"); !ok {
		t.Fatal("explicit namespace-catalog column must land under the namespace catalog")
	}
	if _, err := schemaMappingFromProto("acme", []*pb.Column{
		pbColumn("public", "users", "id", "BIGINT"),
		{Catalog: "acme", Schema: "public", Table: "users", Column: "id", DataType: "BIGINT"},
	}); err == nil {
		t.Fatal("empty and explicit spellings of the same column must be a duplicate")
	}
}

func TestAnalyzeStatementResolvesOrdinaryQuery(t *testing.T) {
	out := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT ssn FROM users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace: &pb.Namespace{
			Catalog:    "acme",
			SearchPath: []string{"public"},
		},
		Catalog: snapshot([]*pb.Column{
			pbColumn("public", "users", "id", "BIGINT"),
			pbColumn("public", "users", "ssn", "VARCHAR"),
		}),
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
		Catalog: snapshot([]*pb.Column{
			pbColumn("acme", "users", "id", "BIGINT"),
		}),
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
		Catalog:      snapshot([]*pb.Column{pbColumn("acme", "users", "id", "BIGINT")}),
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
		Catalog: snapshot([]*pb.Column{
			pbColumn("acme", "users", "id", "BIGINT"),
			pbColumn("acme", "users", "ssn", "VARCHAR"),
		}),
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
		Catalog:      snapshot([]*pb.Column{pbColumn("acme", "users", "id", "BIGINT")}),
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
		Catalog: snapshot([]*pb.Column{
			pbColumn("public", "users", "id", "BIGINT"),
			pbColumn("public", "users", "id", "VARCHAR"), // duplicate
		}),
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
