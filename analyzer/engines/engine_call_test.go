package engines

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func engineCall(t *testing.T, request *pb.EngineCallRequest) *pb.EngineCallResponse {
	t.Helper()
	bytes, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := &pb.EngineCallResponse{}
	if err := proto.Unmarshal(EngineCallSafe(bytes), response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestEngineCallRejectsUnknownEngineAndCall(t *testing.T) {
	if r := engineCall(t, &pb.EngineCallRequest{Call: &pb.EngineCallRequest_CatalogName{CatalogName: "app"}}); r.GetError() == "" {
		t.Error("ENGINE_UNSPECIFIED answered")
	}
	if r := engineCall(t, &pb.EngineCallRequest{Engine: pb.Engine_MYSQL}); r.GetError() == "" {
		t.Error("a request without a call answered")
	}
	athena := &pb.EngineCallRequest{Engine: pb.Engine_ATHENA, Call: &pb.EngineCallRequest_DefaultSchemaStatement{DefaultSchemaStatement: "app"}}
	if r := engineCall(t, athena); r.GetError() == "" {
		t.Error("Athena built a default-schema statement")
	}
}

func TestEngineCallDefaultSchemaStatementQuotes(t *testing.T) {
	for _, tc := range []struct {
		engine pb.Engine
		want   string
	}{
		{pb.Engine_MYSQL, "USE `a``b`"},
		{pb.Engine_POSTGRES, "SET search_path TO \"a`b\""},
	} {
		r := engineCall(t, &pb.EngineCallRequest{Engine: tc.engine, Call: &pb.EngineCallRequest_DefaultSchemaStatement{DefaultSchemaStatement: "a`b"}})
		if r.GetText() != tc.want {
			t.Errorf("%s: %q, want %q", tc.engine, r.GetText(), tc.want)
		}
	}
}

func TestSchemaKind(t *testing.T) {
	for _, tc := range []struct {
		engine              pb.Engine
		schema              string
		fixed, system, temp bool
	}{
		{pb.Engine_MYSQL, "information_schema", true, true, false},
		{pb.Engine_MYSQL, "app", false, false, false},
		{pb.Engine_MYSQL, "pg_temp_3", false, false, false},
		{pb.Engine_POSTGRES, "pg_catalog", true, true, false},
		{pb.Engine_POSTGRES, "pg_temp_3", false, true, true},
		{pb.Engine_POSTGRES, "pg_toast", false, true, false},
		{pb.Engine_POSTGRES, "public", false, false, false},
		{pb.Engine_ATHENA, "information_schema", true, true, false},
	} {
		kind := engineCall(t, &pb.EngineCallRequest{Engine: tc.engine, Call: &pb.EngineCallRequest_SchemaKind{SchemaKind: tc.schema}}).GetSchemaKind()
		if kind.GetFixedSystem() != tc.fixed || kind.GetSystem() != tc.system || kind.GetTemp() != tc.temp {
			t.Errorf("%s %s: %v", tc.engine, tc.schema, kind)
		}
	}
}

func TestServerVersion(t *testing.T) {
	for _, tc := range []struct {
		engine  *Engine
		raw     string
		version string
		aurora  bool
	}{
		{MySQL, "8.0.mysql_aurora.3.04.0", "8.0", true},
		{MySQL, "8.0.44-0ubuntu0.22.04.1", "8.0.44", false},
		{MySQL, "", "", false},
		{Postgres, "PostgreSQL 16.4 on aarch64-unknown-linux-gnu", "16.4", false},
		{Postgres, "17.9", "17.9", false},
		{Athena, "Athena engine version 3", "3", false},
		{Athena, "PySpark engine version 3", "", false},
	} {
		v := tc.engine.Traits.serverVersion(tc.raw)
		if v.GetVersion() != tc.version || v.GetAurora() != tc.aurora {
			t.Errorf("%s %q: %v", tc.engine.WireName, tc.raw, v)
		}
	}
	if MySQL.Traits.serverVersion("").Version != nil {
		t.Error("a blank MySQL version parsed")
	}
}

func TestManifestSeries(t *testing.T) {
	if got := MySQL.Traits.manifestSeries("8.0.44"); got != "8.0" {
		t.Errorf("MySQL 8.0.44 -> %q", got)
	}
	if got := Postgres.Traits.manifestSeries("16.4"); got != "16" {
		t.Errorf("Postgres 16.4 -> %q", got)
	}
}

func TestMySQLNativesFollowTheSeries(t *testing.T) {
	if slices.Equal(mysqlNativeFunctions("8.0.44"), mysqlNativeFunctions("8.4.2")) {
		t.Fatal("8.0 and 8.4 share one list")
	}
	if !slices.Equal(mysqlNativeFunctions("garbage"), mysqlNativeFunctions("8.0.1")) {
		t.Error("an unparsable version does not fall back to 8.0")
	}
}

func TestNativeConnectionInfoValid(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"":                     true,
		"db.internal:5432":     true,
		"10.0.0.5:3306":        true,
		"[::1]:3306":           true,
		"db.internal":          false,
		"db.internal:0":        false,
		"db.internal:65536":    false,
		"user@db.internal:1":   false,
		"db.internal:1/path":   false,
		"db.internal:1?x=1":    false,
		"db.internal:1#frag":   false,
		"db.internal:1?":       false,
		"http://db.internal:1": false,
		"::1:3306":             false,
		"db:extra:3306":        false,
		"db.internal:1#":       false,
		"[fe80::1%en0]:3306":   true,
	} {
		if got := MySQL.connectionInfoValid(&pb.EngineConnectionInfo{Endpoint: endpoint}); got != want {
			t.Errorf("%q: %v, want %v", endpoint, got, want)
		}
	}
	withProperty := &pb.EngineConnectionInfo{Endpoint: "db:1", Properties: map[string]string{"region": "x"}}
	if Postgres.connectionInfoValid(withProperty) {
		t.Error("a wire engine published a property")
	}
}

func TestAthenaConnectionInfoValid(t *testing.T) {
	scope := func(region string) map[string]string {
		return map[string]string{"region": region, "workgroup": "primary", "catalog": "AwsDataCatalog", "database": "analytics"}
	}
	for name, tc := range map[string]struct {
		info *pb.EngineConnectionInfo
		want bool
	}{
		"empty":            {&pb.EngineConnectionInfo{}, true},
		"scope":            {&pb.EngineConnectionInfo{Properties: scope("ap-northeast-2")}, true},
		"https endpoint":   {&pb.EngineConnectionInfo{Endpoint: "https://athena.ap-northeast-2.amazonaws.com/", Properties: scope("ap-northeast-2")}, true},
		"bad region":       {&pb.EngineConnectionInfo{Properties: scope("Seoul")}, false},
		"blank value":      {&pb.EngineConnectionInfo{Properties: scope(" ")}, false},
		"partial scope":    {&pb.EngineConnectionInfo{Properties: map[string]string{"region": "ap-northeast-2"}}, false},
		"unknown property": {&pb.EngineConnectionInfo{Properties: map[string]string{"secret": "x"}}, false},
		"http endpoint":    {&pb.EngineConnectionInfo{Endpoint: "http://athena.example.com", Properties: scope("ap-northeast-2")}, false},
		"endpoint path":    {&pb.EngineConnectionInfo{Endpoint: "https://athena.example.com/x", Properties: scope("ap-northeast-2")}, false},
		"endpoint query":   {&pb.EngineConnectionInfo{Endpoint: "https://athena.example.com?x=1", Properties: scope("ap-northeast-2")}, false},
		"endpoint user":    {&pb.EngineConnectionInfo{Endpoint: "https://u@athena.example.com", Properties: scope("ap-northeast-2")}, false},
		"endpoint only":    {&pb.EngineConnectionInfo{Endpoint: "https://athena.example.com"}, false},
		"empty fragment":   {&pb.EngineConnectionInfo{Endpoint: "https://athena.example.com#", Properties: scope("ap-northeast-2")}, false},
	} {
		if got := Athena.connectionInfoValid(tc.info); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestAnalyzerConfig(t *testing.T) {
	targetSettings := &pb.TargetSettings{EngineVersion: "8.0.44", MysqlLowerCaseTableNames: proto.Int32(0)}
	if c := MySQL.analyzerConfig(targetSettings, &pb.SessionObservation{}); c.GetEngine() != pb.Engine_MYSQL || c.GetTarget().MysqlLowerCaseTableNames == nil {
		t.Errorf("MySQL: %v", c)
	}
	explicit := &pb.SessionObservation{Engine: &pb.SessionObservation_Athena{Athena: &pb.AthenaSqlContext{Workgroup: "team"}}}
	if c := Athena.analyzerConfig(&pb.TargetSettings{Properties: map[string]string{"workgroup": "primary"}}, explicit); c.GetSession().GetAthena().GetWorkgroup() != "team" {
		t.Errorf("the request's workgroup was replaced: %v", c)
	}
	athena := Athena.analyzerConfig(&pb.TargetSettings{Properties: map[string]string{"workgroup": "primary"}}, &pb.SessionObservation{})
	if athena.GetSession().GetAthena().GetWorkgroup() != "primary" {
		t.Errorf("Athena without a request scope runs outside the registered workgroup: %v", athena)
	}
}

func TestPostgresFunctionCatalogTiers(t *testing.T) {
	catalog := Postgres.Traits.functionCatalog(Postgres, []*pb.SchemaFunctions{
		{Schema: "pg_catalog", Names: []string{"abs", "coalesce"}},
		{Schema: "information_schema", Names: []string{"_pg_expandarray"}},
		{Schema: "public", Names: []string{"add_tax"}},
		{Schema: "pg_temp_3", Names: []string{"scratch"}},
	}, "16.4")
	if want := append([]string{"abs", "coalesce"}, postgresGrammarFunctions[1:]...); !slices.Equal(catalog.GetBuiltinFunctions(), want) {
		t.Errorf("builtins %v", catalog.GetBuiltinFunctions())
	}
	if len(catalog.GetSystemFunctionSchemas()) != 2 || len(catalog.GetUdfSchemas()) != 1 || catalog.GetUdfSchemas()[0].GetSchema() != "public" {
		t.Errorf("tiers %v", catalog)
	}
}
