package probe

import (
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"google.golang.org/protobuf/proto"
)

func catalogColumn(catalog, schema, table, column, dataType string) *pb.Column {
	return &pb.Column{Catalog: catalog, Schema: schema, Table: table, Column: column, DataType: dataType}
}

func athenaRequest(sql string, parameters ...string) *pb.AnalyzeRequest {
	return &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_ATHENA},
		Namespace:    &pb.Namespace{Catalog: "awsdatacatalog", SearchPath: []string{"sample"}},
		Catalog: &pb.CatalogSnapshot{Columns: []*pb.Column{
			catalogColumn("awsdatacatalog", "sample", "users", "id", "BIGINT"),
			catalogColumn("awsdatacatalog", "sample", "users", "email", "VARCHAR"),
			catalogColumn("archive", "sample", "users", "id", "BIGINT"),
			catalogColumn("archive", "sample", "users", "email", "VARCHAR"),
		}},
		AthenaContext: &pb.AthenaSqlContext{Workgroup: "sample", ExecutionParameters: parameters},
	}
}

func TestAthenaSQLNormalization(t *testing.T) {
	for _, pair := range [][2]string{
		{"SELECT EMAIL FROM USERS", "select email from users"},
		{"CREATE EXTERNAL TABLE `sample` (id BIGINT) STORED AS PARQUET", "create external table `sample` (id bigint) stored as parquet;"},
		{"SHOW TABLES; SELECT email FROM users", "show tables; select email from users;"},
	} {
		left, leftOK := SqlNormalize(pair[0], "athena")
		right, rightOK := SqlNormalize(pair[1], "athena")
		if !leftOK || !rightOK || left != right {
			t.Fatalf("Athena normalization mismatch: %q %v / %q %v", left, leftOK, right, rightOK)
		}
	}
	assertNormalizesDistinct(t, "athena", "SELECT 'A'", "SELECT 'a'")
	assertNormalizesDistinct(t, "athena", "SELECT * FROM archive.sample.users", "SELECT * FROM awsdatacatalog.sample.users")
}

func TestAthenaLineage(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM users",
		`SELECT "EMAIL" FROM "USERS"`,
		"SELECT upper(email) AS normalized FROM users WHERE id = 1",
		"WITH u AS (SELECT email, id FROM users) SELECT email FROM u WHERE id = 1",
		"SELECT email FROM users UNION ALL SELECT email FROM archive.sample.users",
		"SELECT a.email, b.email FROM users a JOIN archive.sample.users b ON a.id = b.id",
		"SELECT id, row_number() OVER (ORDER BY email) AS n FROM users",
		"EXPLAIN (TYPE DISTRIBUTED) SELECT email FROM users",
		"CREATE TABLE sample.copy AS SELECT email FROM users",
	} {
		t.Run(sql, func(t *testing.T) {
			facts := analyzeProto(t, athenaRequest(sql))
			if !facts.GetResolved() {
				t.Fatalf("unresolved: %s", facts)
			}
			if len(facts.GetResultReads()) == 0 {
				t.Fatalf("missing read grants: %s", facts)
			}
		})
	}
}

func TestAthenaUnnamedDerivedFieldsStayUnresolved(t *testing.T) {
	facts := analyzeProto(t, athenaRequest("SELECT x._col0 FROM (SELECT upper(email) FROM users) x"))
	if facts.GetResolved() {
		t.Fatalf("display label became an addressable derived column: %s", facts)
	}
	facts = analyzeProto(t, athenaRequest("SELECT x.normalized FROM (SELECT upper(email) AS normalized FROM users) x"))
	if !facts.GetResolved() {
		t.Fatalf("explicit derived alias did not resolve: %s", facts)
	}
}

func TestAthenaComplexValuesConserveTopLevelColumns(t *testing.T) {
	for _, sql := range []string{
		"SELECT payload[1] FROM users",
		"SELECT payload[1].email FROM users",
		"SELECT id FROM users WHERE payload[1].email = 'sample@example.test'",
	} {
		request := athenaRequest(sql)
		request.Catalog.Columns = append(request.Catalog.Columns, catalogColumn("awsdatacatalog", "sample", "users", "payload", "ARRAY<STRUCT<email: VARCHAR>>"))
		facts := analyzeProto(t, request)
		if !facts.GetResolved() {
			if facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
				t.Fatalf("complex expression failed without exception semantics: %s", facts)
			}
			continue
		}
		covered := false
		for _, grant := range facts.GetResultReads() {
			if grant.GetColumn().GetIdentity().GetColumn() == "payload" {
				covered = true
				if grant.GetMaskedDisposition() == pb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT {
					t.Fatalf("complex extraction inherited a base-column mask: %s", facts)
				}
			}
		}
		if !covered {
			t.Fatalf("lost complex value's top-level column: %s", facts)
		}
	}
}

func TestAthenaPartitionValuesRequireUtilityGrant(t *testing.T) {
	facts := analyzeProto(t, athenaRequest("SHOW PARTITIONS sample.users"))
	if !facts.GetResolved() || len(facts.GetResultReads()) != 1 || facts.GetResultReads()[0].GetUtility().GetCommand() != "SHOW_PARTITIONS" {
		t.Fatalf("partition values escaped the data-leak gate: %s", facts)
	}
}

func TestAthenaCrossCatalogRewrite(t *testing.T) {
	request := athenaRequest("SELECT * FROM archive.sample.users")
	facts := analyzeProto(t, request)
	if !facts.GetResolved() || facts.GetAthenaSubmission() == nil {
		t.Fatalf("missing resolved submission: %s", facts)
	}
	root, err := sqlglot.ParseOne(facts.GetAthenaSubmission().GetQueryString(), "athena")
	if err != nil {
		t.Fatal(err)
	}
	tables := root.FindAll(exp.KindTable)
	if len(tables) != 1 || tables[0].CatalogName() != "archive" {
		t.Fatalf("lost executable catalog: %s", root.ToS())
	}
	if !strings.Contains(facts.String(), `catalog:"archive"`) {
		t.Fatalf("lost source catalog: %s", facts)
	}
	for _, config := range []*pb.EngineConfig{
		{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)},
		{Engine: pb.Engine_POSTGRES},
	} {
		request.EngineConfig = config
		request.AthenaContext = nil
		if got := analyzeProto(t, request); got.GetResolved() {
			t.Fatalf("cross-catalog floor lost for %s: %s", config.GetEngine(), got)
		}
	}
}

func TestAthenaParameterBinding(t *testing.T) {
	request := athenaRequest("SELECT email FROM users WHERE id = ? AND email = ?", "CAST('7' AS BIGINT)", "'sample@example.test'")
	facts := analyzeProto(t, request)
	if !facts.GetResolved() || facts.GetAthenaSubmission() == nil {
		t.Fatalf("unresolved parameters: %s", facts)
	}
	submission := facts.GetAthenaSubmission()
	if len(submission.GetExecutionParameters()) != 0 || strings.Contains(submission.GetQueryString(), "?") {
		t.Fatalf("parameters were not replaced together: %s", submission)
	}
	if !strings.Contains(submission.GetQueryString(), "sample@example.test") || !strings.Contains(submission.GetQueryString(), "BIGINT") {
		t.Fatalf("lost bound expression: %s", submission)
	}
	plain := athenaRequest(submission.GetQueryString())
	if got := analyzeProto(t, plain); !got.GetResolved() || len(got.GetResultReads()) != len(facts.GetResultReads()) {
		t.Fatalf("replacement is not analyzable with the same grants: %s", got)
	}
}

func TestAthenaParametersFollowSQLOrderAcrossScopes(t *testing.T) {
	request := athenaRequest("/* 한글 */ WITH a AS (SELECT r.email, r.id FROM users r WHERE r.email = ?) SELECT a.email FROM a WHERE EXISTS (SELECT 1 FROM users s WHERE s.id = ?) AND a.id = ?", "'한글'", "20", "30")
	facts := analyzeProto(t, request)
	if !facts.GetResolved() || facts.GetAthenaSubmission() == nil {
		t.Fatalf("scoped parameters did not resolve: %s", facts)
	}
	root, err := sqlglot.ParseOne(facts.GetAthenaSubmission().GetQueryString(), "athena")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, equality := range root.FindAll(exp.KindEQ) {
		literal := equality.Right().Find(exp.KindLiteral)
		if literal != nil {
			got[equality.Left().TableName()+"."+equality.Left().Name()] = literal.Name()
		}
	}
	for column, want := range map[string]string{"r.email": "한글", "s.id": "20", "a.id": "30"} {
		if got[column] != want {
			t.Fatalf("parameters followed AST order rather than SQL order: %v; want %s=%s", got, column, want)
		}
	}
}

func TestAthenaParameterFailures(t *testing.T) {
	for _, request := range []*pb.AnalyzeRequest{
		athenaRequest("SELECT email FROM users WHERE id = ?"),
		athenaRequest("SELECT email FROM users", "1"),
		athenaRequest("SELECT ? FROM users", "1"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "1; SELECT 2"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "1, 2"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "1 FROM users"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "(SELECT id FROM users)"),
		athenaRequest("SELECT email FROM users WHERE id = :named", "1"),
		athenaRequest("SELECT email FROM users WHERE id = @?", "1"),
		athenaRequest("SELECT email FROM users WHERE id = $?", "1"),
		athenaRequest("SELECT email FROM users WHERE id = @named"),
		athenaRequest("SELECT email FROM users WHERE id = $1"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "@named"),
		athenaRequest("SELECT email FROM users WHERE id = ?", "$?"),
	} {
		if facts := analyzeProto(t, request); facts.GetResolved() || facts.GetAthenaSubmission() != nil || facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
			t.Fatalf("unproven parameters did not reach exception: %s: %s", request, facts)
		}
	}
}

func TestAthenaExecuteSyntax(t *testing.T) {
	eng, err := newAthenaEngine(&pb.EngineConfig{Engine: pb.Engine_ATHENA})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sql   string
		name  string
		count int
	}{
		{"EXECUTE lookup_user", "lookup_user", 0},
		{`EXECUTE "Lookup_User"`, "Lookup_User", 0},
		{"EXECUTE /* name */ lookup_user USING 'a,b', ARRAY[1, 2], CONCAT('x', ',y')", "lookup_user", 3},
		{"EXECUTE lookup_user USING CAST('1' AS BIGINT), (1 + 2)", "lookup_user", 2},
		{"EXECUTE lookup_user USING 'quoted '' value', 'question ? mark'", "lookup_user", 2},
	} {
		root, err := athenaSingleStatement(tc.sql, eng)
		if err != nil {
			t.Fatalf("%s: %v", tc.sql, err)
		}
		name, parameters, err := athenaExecute(root, eng)
		if err != nil || name != tc.name || len(parameters) != tc.count {
			t.Fatalf("%s: name=%q parameters=%v error=%v", tc.sql, name, parameters, err)
		}
	}
	for _, sql := range []string{
		"EXECUTE", "EXECUTE 'lookup_user'", "EXECUTE a.b", "EXECUTE lookup_user USING",
		"EXECUTE lookup_user USING 1 FROM users", "EXECUTE lookup_user USING (SELECT email FROM users)",
		"EXECUTE lookup_user USING ?", "EXECUTE lookup_user USING email",
	} {
		root, err := athenaSingleStatement(sql, eng)
		if err != nil {
			continue
		}
		if _, _, err := athenaExecute(root, eng); err == nil {
			t.Fatalf("unproven EXECUTE syntax accepted: %s", sql)
		}
	}
}

func TestAthenaPreparedDefinition(t *testing.T) {
	request := athenaRequest("EXECUTE lookup_user USING 7")
	facts := analyzeProto(t, request)
	need := facts.GetAthenaPreparedDefinitionNeed()
	if facts.GetResolved() || need.GetName() != "lookup_user" || need.GetWorkgroup() != "sample" {
		t.Fatalf("missing prepared need: %s", facts)
	}
	request.AthenaContext.PreparedDefinitions = []*pb.AthenaPreparedDefinition{{Workgroup: "sample", Name: "lookup_user", QueryString: "SELECT email FROM users WHERE id = ?"}}
	facts = analyzeProto(t, request)
	if !facts.GetResolved() || facts.GetAthenaSubmission() == nil || facts.GetAthenaPreparedDefinitionNeed() != nil {
		t.Fatalf("prepared definition not expanded: %s", facts)
	}
	if strings.HasPrefix(facts.GetAthenaSubmission().GetQueryString(), "EXECUTE") || strings.Contains(facts.GetAthenaSubmission().GetQueryString(), "?") {
		t.Fatalf("mutable prepared reference retained: %s", facts)
	}
	request.AthenaContext.PreparedDefinitions[0].Workgroup = "other"
	if got := analyzeProto(t, request); got.GetResolved() || got.GetAthenaPreparedDefinitionNeed() == nil {
		t.Fatalf("foreign workgroup definition used: %s", got)
	}
}

func TestAthenaMissingContextAndUnknownSemantics(t *testing.T) {
	batch := analyzeProto(t, athenaRequest("SELECT 1; SELECT 2"))
	if batch.GetResolved() || batch.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		t.Fatalf("batch is not inadmissible: %s", batch)
	}
	request := athenaRequest("SELECT email FROM users")
	request.AthenaContext = nil
	if facts := analyzeProto(t, request); facts.GetResolved() || facts.GetAthenaSubmission() != nil {
		t.Fatalf("missing context resolved: %s", facts)
	}
	for _, sql := range []string{
		"EXECUTE unknown USING 1",
		"PREPARE lookup_user FROM SELECT email FROM users WHERE id = ?",
		"USING EXTERNAL FUNCTION secret(input VARCHAR) RETURNS VARCHAR LAMBDA 'sample-function' SELECT secret(email) FROM users",
		"SELECT email FROM missing_view",
	} {
		facts := analyzeProto(t, athenaRequest(sql))
		if facts.GetResolved() || facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
			t.Fatalf("unknown semantics bypassed exception: %s: %s", sql, facts)
		}
	}
}

func TestAthenaRowCapIsPushedIntoTheSubmission(t *testing.T) {
	for _, tc := range []struct{ sql, want string }{
		{"SELECT email FROM users", "LIMIT 5"},
		{"SELECT email FROM users LIMIT 500", "LIMIT 5"},
		{"SELECT email FROM users LIMIT 3", "LIMIT 3"},
		{"SELECT email FROM users UNION ALL SELECT email FROM users", "LIMIT 5"},
		{"SELECT * FROM users", "LIMIT 5"},
	} {
		request := athenaRequest(tc.sql)
		request.AthenaContext.MaxRows = 5
		facts := analyzeProto(t, request)
		if !facts.GetResolved() {
			t.Fatalf("%s: unresolved: %s", tc.sql, facts)
		}
		submitted := facts.GetAthenaSubmission().GetQueryString()
		if submitted == "" {
			submitted = tc.sql
		}
		if !strings.HasSuffix(strings.ToUpper(submitted), tc.want) || strings.Count(strings.ToUpper(submitted), "LIMIT") != 1 {
			t.Fatalf("%s -> %q, want suffix %q", tc.sql, submitted, tc.want)
		}
	}
	request := athenaRequest("SELECT email FROM users")
	if facts := analyzeProto(t, request); facts.GetAthenaSubmission() != nil {
		t.Fatalf("no cap requested but the submission was replaced: %s", facts)
	}
}
