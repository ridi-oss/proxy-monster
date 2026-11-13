package engines

import (
	"slices"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func bigqueryRequest(sql string, parameters ...*pb.BigQueryParameter) *pb.AnalyzeRequest {
	return &pb.AnalyzeRequest{
		Sql: sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_BIGQUERY, Session: &pb.SessionObservation{Engine: &pb.SessionObservation_Bigquery{Bigquery: &pb.BigQuerySqlContext{
			Project: "sample-project", DefaultDatasetId: "Sales", Parameters: parameters,
		}}}},
		Namespace: &pb.Namespace{Catalog: "sample-project", SearchPath: []string{"Sales"}},
		Catalog: &pb.CatalogSnapshot{
			Columns: []*pb.Column{
				catalogColumn("sample-project", "Sales", "Users", "id", "INT64"),
				catalogColumn("sample-project", "Sales", "Users", "email", "STRING"),
				catalogColumn("sample-project", "Sales", "Users", "profile", "STRUCT<email STRING, age INT64>"),
				catalogColumn("sample-project", "Sales", "Users", "tags", "ARRAY<STRING>"),
				catalogColumn("sample-project", "Sales", "Users", "seen", "TIME"),
				catalogColumn("sample-project", "Sales", "users", "id", "INT64"),
				catalogColumn("other-project", "Archive", "Users", "email", "STRING"),
				catalogColumn("sample-project", "Sales", "events_20260101", "id", "INT64"),
			},
			Functions: bigqueryFunctionCatalog(BigQuery, nil, ""),
		},
	}
}

func readColumns(facts *pb.StatementFacts) []string {
	var out []string
	for _, grant := range facts.GetResultReads() {
		if c := grant.GetColumn(); c != nil {
			out = append(out, c.GetCatalog()+"."+c.GetSchema()+"."+c.GetTable()+"."+c.GetColumn())
		}
	}
	return out
}

func TestBigQueryLineage(t *testing.T) {
	for sql, want := range map[string]string{
		"SELECT email FROM Users":                                             "sample-project.Sales.Users.email",
		"SELECT EMAIL FROM Sales.Users":                                       "sample-project.Sales.Users.email",
		"SELECT email FROM `sample-project.Sales.Users`":                      "sample-project.Sales.Users.email",
		"SELECT email FROM `other-project`.Archive.Users":                     "other-project.Archive.Users.email",
		"SELECT upper(u.email) AS e FROM Users u WHERE id = 1":                "sample-project.Sales.Users.email",
		"SELECT * EXCEPT (id, profile) FROM Users":                            "sample-project.Sales.Users.email",
		"WITH u AS (SELECT email FROM Users) SELECT email FROM u":             "sample-project.Sales.Users.email",
		"SELECT e FROM Users, UNNEST([email]) AS e":                           "sample-project.Sales.Users.email",
		"SELECT profile FROM Users":                                           "sample-project.Sales.Users.profile",
		"SELECT email FROM Users QUALIFY count(*) OVER (PARTITION BY id) = 1": "sample-project.Sales.Users.email",
	} {
		t.Run(sql, func(t *testing.T) {
			facts := analyzeProto(t, bigqueryRequest(sql))
			if !facts.GetResolved() {
				t.Fatalf("unresolved: %s", facts)
			}
			if got := readColumns(facts); !strings.Contains(strings.Join(got, " "), want) {
				t.Fatalf("missing read of %s: %v", want, got)
			}
		})
	}
}

// Table names are case-sensitive: Users and users are different tables.
func TestBigQueryTableNamesKeepCase(t *testing.T) {
	facts := analyzeProto(t, bigqueryRequest("SELECT id FROM users"))
	if !facts.GetResolved() || strings.Join(readColumns(facts), " ") != "sample-project.Sales.users.id" {
		t.Fatalf("users resolved as Users: %v %s", readColumns(facts), facts)
	}
	if facts := analyzeProto(t, bigqueryRequest("SELECT email FROM USERS")); facts.GetResolved() {
		t.Fatalf("USERS resolved to an existing table: %s", facts)
	}
	// Inside its own body, a CTE named like a table reads the table: Users, not its twin users.
	facts = analyzeProto(t, bigqueryRequest("WITH Users AS (SELECT * FROM Users) SELECT email FROM Users"))
	if !facts.GetResolved() || strings.Join(readColumns(facts), " ") != "sample-project.Sales.Users.email" {
		t.Fatalf("CTE body read the wrong table: %v %s", readColumns(facts), facts)
	}
}

// A field read from a STRUCT conserves its top-level column and never takes that column's output mask.
func TestBigQueryStructFieldReadsTheTopLevelColumn(t *testing.T) {
	for _, sql := range []string{
		"SELECT profile.email FROM Users",
		"SELECT u.profile.email FROM Users u",
		"SELECT id FROM Users WHERE profile.age > 30",
	} {
		t.Run(sql, func(t *testing.T) {
			facts := analyzeProto(t, bigqueryRequest(sql))
			if !facts.GetResolved() {
				t.Fatalf("unresolved: %s", facts)
			}
			covered := false
			for _, grant := range facts.GetResultReads() {
				if grant.GetColumn().GetColumn() == "profile" {
					covered = true
					if grant.GetMaskedDisposition() == pb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT {
						t.Fatalf("field extraction inherited the column mask: %s", facts)
					}
				}
			}
			if !covered {
				t.Fatalf("lost the struct's top-level column: %s", facts)
			}
		})
	}
}

func TestBigQueryParametersBindIntoTheSubmittedText(t *testing.T) {
	for _, c := range []struct {
		sql        string
		parameters []*pb.BigQueryParameter
		want       string
	}{
		{"SELECT Email AS MyEmail FROM Users WHERE id = @ID AND email <> @mail",
			[]*pb.BigQueryParameter{{Name: "id", Value: "CAST('7' AS INT64)"}, {Name: "mail", Value: "'a@example.test'"}},
			"SELECT Email AS MyEmail FROM Users WHERE id = (CAST('7' AS INT64)) AND email <> 'a@example.test'"},
		{"SELECT email FROM Users WHERE id = ? OR id = ?",
			[]*pb.BigQueryParameter{{Value: "1"}, {Value: "2"}},
			"SELECT email FROM Users WHERE id = 1 OR id = 2"},
		{"SELECT email FROM Users LIMIT @n OFFSET @o",
			[]*pb.BigQueryParameter{{Name: "n", Value: "10"}, {Name: "o", Value: "20"}},
			"SELECT email FROM Users LIMIT 10 OFFSET 20"},
	} {
		facts := analyzeProto(t, bigqueryRequest(c.sql, c.parameters...))
		if !facts.GetResolved() || facts.GetSubmission().GetBigquery() == nil || facts.GetRewrittenSql() != c.want {
			t.Errorf("%s: got %q\n%s", c.sql, facts.GetRewrittenSql(), facts)
		}
	}
}

func TestBigQueryParameterMismatchesFailClosed(t *testing.T) {
	for name, request := range map[string]*pb.AnalyzeRequest{
		"missing named":     bigqueryRequest("SELECT email FROM Users WHERE id = @id"),
		"missing position":  bigqueryRequest("SELECT email FROM Users WHERE id = ?"),
		"extra position":    bigqueryRequest("SELECT email FROM Users", &pb.BigQueryParameter{Value: "1"}),
		"mixed":             bigqueryRequest("SELECT email FROM Users WHERE id = ?", &pb.BigQueryParameter{Value: "1"}, &pb.BigQueryParameter{Name: "x", Value: "2"}),
		"duplicate":         bigqueryRequest("SELECT email FROM Users WHERE id = @x", &pb.BigQueryParameter{Name: "x", Value: "1"}, &pb.BigQueryParameter{Name: "X", Value: "2"}),
		"column as value":   bigqueryRequest("SELECT id FROM Users WHERE id = @x", &pb.BigQueryParameter{Name: "x", Value: "email"}),
		"subquery as value": bigqueryRequest("SELECT id FROM Users WHERE id = @x", &pb.BigQueryParameter{Name: "x", Value: "(SELECT 1)"}),
		"system variable":   bigqueryRequest("SELECT @@project_id", &pb.BigQueryParameter{Name: "project_id", Value: "'x'"}),
	} {
		t.Run(name, func(t *testing.T) {
			if facts := analyzeProto(t, request); facts.GetResolved() {
				t.Fatalf("resolved: %s", facts)
			}
		})
	}
}

func TestBigQueryUnprovenFormsDeny(t *testing.T) {
	for _, sql := range []string{
		"SELECT profile.* EXCEPT (age) FROM Users",
		"SELECT * FROM `sample-project.Sales.INFORMATION_SCHEMA.JOBS`",
		"SELECT * FROM `region-us`.INFORMATION_SCHEMA.JOBS",
		"SELECT @@project_id",
		"SELECT AI.GENERATE(email) FROM Users",
		"SELECT AI.EMBED(email) FROM Users",
		"SELECT AI.SIMILARITY(email, 'x') FROM Users",
		"DECLARE x INT64",
		"EXECUTE IMMEDIATE 'SELECT email FROM Users'",
		"CALL Sales.leak()",
		"SELECT * FROM APPENDS(TABLE Sales.Users)",
		"SELECT * FROM EXTERNAL_QUERY('conn', 'SELECT 1')",
		"SELECT SEARCH(Users, 'secret') FROM Sales.Users",
		"BEGIN SELECT email FROM Users; END",
		"CREATE TEMP FUNCTION f(x STRING) AS (x); SELECT f(email) FROM Users",
	} {
		t.Run(sql, func(t *testing.T) {
			if facts := analyzeProto(t, bigqueryRequest(sql)); facts.GetResolved() {
				t.Fatalf("resolved: %s", facts)
			}
		})
	}
}

func TestBigQueryEditorRowCap(t *testing.T) {
	request := bigqueryRequest("SELECT email FROM Users")
	request.EngineConfig.Session.GetBigquery().MaxRows = 100
	facts := analyzeProto(t, request)
	if !strings.Contains(facts.GetRewrittenSql(), "LIMIT 100") {
		t.Fatalf("row cap missing: %s", facts)
	}
}

func TestBigQueryCallResolution(t *testing.T) {
	request := func(sql string) *pb.AnalyzeRequest {
		r := bigqueryRequest(sql)
		r.Catalog.Functions.BuiltinFunctions = append(r.Catalog.Functions.BuiltinFunctions, "net.host")
		r.Catalog.Functions.UdfSchemas = []*pb.SchemaFunctions{{Schema: "Sales", Names: []string{"mask_email", "MaskEmail"}}}
		return r
	}
	for _, sql := range []string{
		"SELECT SAFE.upper(email) FROM Users",
		"SELECT NET.HOST(email) FROM Users",
		"SELECT Sales.mask_email(email) FROM Users",
		"SELECT `sample-project.Sales.mask_email`(email) FROM Users",
		"SELECT Sales.MaskEmail(email) FROM Users",
	} {
		facts := analyzeProto(t, request(sql))
		if !facts.GetResolved() {
			t.Errorf("%s: %s", sql, facts)
		}
		udf := map[bool]string{true: "Sales.mask_email", false: "Sales.MaskEmail"}[strings.Contains(sql, "mask_email")]
		if strings.Contains(sql, "Sales") && !slices.ContainsFunc(facts.GetResultReads(), func(g *pb.RequireResultReadGrant) bool {
			return g.GetFunction().GetName() == udf
		}) {
			t.Errorf("%s: no function grant: %s", sql, facts)
		}
	}
	for _, sql := range []string{
		"SELECT SAFE.leak(email) FROM Users",
		"SELECT sales.mask_email(email) FROM Users",
		"SELECT Sales.MASK_EMAIL(email) FROM Users",
		"SELECT Sales.maskemail(email) FROM Users",
		"SELECT `other-project.Sales.mask_email`(email) FROM Users",
	} {
		if facts := analyzeProto(t, request(sql)); facts.GetResolved() {
			t.Errorf("%s resolved: %s", sql, facts)
		}
	}
}

// _DBT_MAX_PARTITION is an ordinary column name in BigQuery, so its read is tracked.
func TestBigQueryDbtColumnIsARead(t *testing.T) {
	request := bigqueryRequest("SELECT _dbt_max_partition FROM Users")
	request.Catalog.Columns = append(request.Catalog.Columns, catalogColumn("sample-project", "Sales", "Users", "_dbt_max_partition", "STRING"))
	facts := analyzeProto(t, request)
	if !facts.GetResolved() || !strings.Contains(strings.Join(readColumns(facts), " "), "Users._dbt_max_partition") {
		t.Fatalf("read untracked: %s", facts)
	}
}

// The request's default dataset, with its own project, decides where `Users` resolves; `Sales.Users` stays
// in the job project.
func TestBigQueryDefaultDatasetInAnotherProject(t *testing.T) {
	for sql, want := range map[string]string{
		"SELECT email FROM Users":       "other-project.Archive.Users.email",
		"SELECT email FROM Sales.Users": "sample-project.Sales.Users.email",
	} {
		request := bigqueryRequest(sql)
		request.EngineConfig.Session.GetBigquery().DefaultDatasetProjectId = "other-project"
		request.EngineConfig.Session.GetBigquery().DefaultDatasetId = "Archive"
		facts := analyzeProto(t, request)
		if got := strings.Join(readColumns(facts), " "); !facts.GetResolved() || got != want {
			t.Errorf("%s: got %s\n%s", sql, got, facts)
		}
	}
}

func TestBigQueryKeywordArgumentBuiltins(t *testing.T) {
	for _, sql := range []string{
		"SELECT NULLIF(email, '') FROM Users",
		"SELECT TIME_TRUNC(seen, HOUR) FROM Users",
		"SELECT TIME_DIFF(seen, seen, MINUTE) FROM Users",
		"SELECT NORMALIZE(email, NFKC) FROM Users",
		"SELECT NORMALIZE_AND_CASEFOLD(email, NFD) FROM Users",
	} {
		if facts := analyzeProto(t, bigqueryRequest(sql)); !facts.GetResolved() {
			t.Errorf("%s denied: %s", sql, facts)
		}
	}
}

// A path over a FROM alias, from a subquery or a join, is an UNNEST of that row's array, not a table.
func TestBigQueryAliasArrayPathReadsTheColumn(t *testing.T) {
	for _, sql := range []string{
		"SELECT (SELECT STRING_AGG(x) FROM Public.tags AS x) FROM Sales.Users AS Public",
		"SELECT t FROM Sales.Users AS u LEFT JOIN u.tags AS t ON TRUE",
		"SELECT t FROM Sales.Users JOIN users.tags AS t ON TRUE",
	} {
		facts := analyzeProto(t, bigqueryRequest(sql))
		if !facts.GetResolved() || !slices.Contains(readColumns(facts), "sample-project.Sales.Users.tags") {
			t.Errorf("%s: tags read not recorded: %v %s", sql, readColumns(facts), facts)
		}
	}
}
