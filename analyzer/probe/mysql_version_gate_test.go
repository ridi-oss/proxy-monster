package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/schema"
	"google.golang.org/protobuf/proto"
)

func usersSchema(t *testing.T) *schema.Mapping {
	t.Helper()
	m, err := schemaMappingFromProto([]*pb.ColumnSpec{
		columnSpec("def", "acme", "users", "id", "BIGINT"),
		columnSpec("def", "acme", "users", "ssn", "VARCHAR"),
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	return m
}

func TestMySQLWithoutKnownVersionFailsValidation(t *testing.T) {
	out := Probe(
		"SELECT 1 /*!50700 , ssn */ FROM users",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(0)},
		usersSchema(t),
		NamespaceConfig{Catalog: "def", SearchPath: []string{"acme"}},
	)
	if out.Resolved || out.FailedStage == nil || *out.FailedStage != "VALIDATE" {
		t.Fatalf("expected fail-closed VALIDATE without a MySQL version, got %+v", out)
	}
}

func TestMySQLWithUnparseableVersionFailsValidation(t *testing.T) {
	out := Probe(
		"SELECT id FROM users",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "not-a-version", MysqlLowerCaseTableNames: proto.Int32(0)},
		usersSchema(t),
		NamespaceConfig{Catalog: "def", SearchPath: []string{"acme"}},
	)
	if out.Resolved || out.FailedStage == nil || *out.FailedStage != "VALIDATE" {
		t.Fatalf("expected fail-closed VALIDATE for an unparseable MySQL version, got %+v", out)
	}
}

func TestMySQLWithValidVersionRequiresLowerCaseTableNames(t *testing.T) {
	out := Probe(
		"SELECT id FROM users",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46"},
		usersSchema(t),
		NamespaceConfig{Catalog: "def", SearchPath: []string{"acme"}},
	)
	if out.Resolved || out.FailedStage == nil || *out.FailedStage != "VALIDATE" {
		t.Fatalf("expected fail-closed VALIDATE without lower_case_table_names, got %+v", out)
	}
}

func TestPostgresWithoutVersionOrMySQLModeResolves(t *testing.T) {
	sch, err := schemaMappingFromProto([]*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	out := Probe(
		"SELECT id FROM users",
		&pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		sch,
		NamespaceConfig{Catalog: "acme", SearchPath: []string{"public"}},
	)
	if !out.Resolved {
		t.Fatalf("expected PostgreSQL to resolve without MySQL inputs, got stage=%v detail=%q", out.FailedStage, out.Detail)
	}
}

func TestExecutableCommentAnalyzableWithKnownVersion(t *testing.T) {
	out := Probe(
		"SELECT 1 /*!50700 , ssn */ FROM users",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)},
		usersSchema(t),
		NamespaceConfig{Catalog: "def", SearchPath: []string{"acme"}},
	)
	if !out.Resolved {
		t.Fatalf("expected resolved=true, got failedStage=%v detail=%s", out.FailedStage, out.Detail)
	}
	found := false
	for _, o := range out.Origins {
		for _, origin := range o.Origins {
			if origin == "def.acme.users.ssn" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected ssn to be traced once the executable comment is version-gated open, got origins=%v", out.Origins)
	}
}

func TestMysqlVersionID(t *testing.T) {
	cases := []struct {
		version string
		want    int
	}{
		{"8.0.46", 80046},
		{"5.6.0", 50600},
		{"8.0", 80000},
		{"17.4", 170400},
		{"", 0},
		{"not-a-version", 0},
		{"(aurora 3.04.0)", 0},
	}
	for _, tc := range cases {
		if got := mysqlVersionID(tc.version); got != tc.want {
			t.Errorf("mysqlVersionID(%q) = %d, want %d", tc.version, got, tc.want)
		}
	}
}

func TestExecutableCommentGateRespectsVersionThreshold(t *testing.T) {
	out := Probe(
		"SELECT 1 /*!50700 , ssn */ FROM users",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "5.6.0", MysqlLowerCaseTableNames: proto.Int32(0)},
		usersSchema(t),
		NamespaceConfig{Catalog: "def", SearchPath: []string{"acme"}},
	)
	if !out.Resolved {
		t.Fatalf("expected resolved=true, got failedStage=%v detail=%s", out.FailedStage, out.Detail)
	}
	for _, o := range out.Origins {
		for _, origin := range o.Origins {
			if origin == "def.acme.users.ssn" {
				t.Fatalf("ssn must stay hidden below the comment's version gate, got origins=%v", out.Origins)
			}
		}
	}
}

func TestCreateEngineRejectsUnspecifiedEngine(t *testing.T) {
	if _, err := createEngine(&pb.EngineConfig{}); err == nil {
		t.Fatal("createEngine with ENGINE_UNSPECIFIED unexpectedly succeeded")
	}
}

func TestCreateEngineRejectsNilConfig(t *testing.T) {
	if _, err := createEngine(nil); err == nil {
		t.Fatal("createEngine(nil) unexpectedly succeeded")
	}
}
