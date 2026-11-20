package bigquery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"google.golang.org/protobuf/proto"
)

func TestOperationRoutes(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		header         string
		name           string
		kind           httpdb.Kind
		fails          bool
	}{
		{"POST", "/bigquery/v2/projects/p/queries", "", "jobs.query", httpdb.KindSubmission, false},
		{"POST", "/bigquery/v2/projects/p/jobs?alt=json&prettyPrint=false", "", "jobs.insert", httpdb.KindSubmission, false},
		{"GET", "/bigquery/v2/projects/p/queries/j?location=US&maxResults=5&pageToken=t&timeoutMs=1&formatOptions.useInt64Timestamp=true", "", "jobs.getQueryResults", httpdb.KindResultPage, false},
		{"GET", "/bigquery/v2/projects/p/jobs/j?location=US&projection=full", "", "jobs.get", httpdb.KindMetadata, false},
		{"POST", "/bigquery/v2/projects/p/jobs/j/cancel", "", "jobs.cancel", httpdb.KindMetadata, false},
		{"GET", "/bigquery/v2/projects/p/jobs?stateFilter=done&stateFilter=running&allUsers=true", "", "jobs.list", httpdb.KindListing, false},
		{"GET", "/bigquery/v2/projects", "", "projects.list", httpdb.KindMetadata, false},
		{"GET", "/bigquery/v2/projects/p/datasets?all=true&filter=labels.a", "", "datasets.list", httpdb.KindMetadata, false},
		{"PATCH", "/bigquery/v2/projects/p/datasets/d", "", "datasets.patch", httpdb.KindMetadata, false},
		{"GET", "/bigquery/v2/projects/p/datasets/d/tables/t", "", "tables.get", httpdb.KindMetadata, false},
		{"DELETE", "/bigquery/v2/projects/p/datasets/d/routines/r", "", "routines.delete", httpdb.KindMetadata, false},
		{"GET", "/bigquery/v2/projects/p/datasets/d/tables/t%20x", "", "tables.get", httpdb.KindMetadata, false},

		{"GET", "/bigquery/v2/projects/p/datasets/d/tables/t/data", "", "", httpdb.KindRefused, false},
		{"POST", "/bigquery/v2/projects/p/datasets/d/tables/t/insertAll", "", "", httpdb.KindRefused, false},
		{"DELETE", "/bigquery/v2/projects/p/jobs/j/delete", "", "", httpdb.KindRefused, false},
		{"PUT", "/bigquery/v2/projects/p/datasets/d/routines/r", "", "", httpdb.KindRefused, false},
		{"POST", "/bigquery/v2/projects/p/datasets/d/routines", "", "", httpdb.KindRefused, false},
		{"GET", "/bigquery/v2/projects/p/datasets/d/models/m", "", "", httpdb.KindRefused, false},
		{"GET", "/bigquery/v2/projects/p/queries/j?fields=rows,pageToken", "X-Goog-FieldMask", "jobs.getQueryResults", httpdb.KindResultPage, false},
		{"POST", "/bigquery/v2/projects/p/datasets/d:undelete", "", "", 0, true},
		{"GET", "/bigquery/v2/projects/example.com:p/datasets/d", "", "datasets.get", httpdb.KindMetadata, false},

		{"GET", "/bigquery/v2/projects?access_token=x", "", "", 0, true},
		{"GET", "/bigquery/v2/projects?alt=media", "", "", 0, true},
		{"GET", "/bigquery/v2/projects/p/datasets/d?future=1", "", "", 0, true},
		{"GET", "/bigquery/v2/projects/p/jobs/j?location=US&location=EU", "", "", 0, true},
		{"GET", "/bigquery/v2/projects//datasets", "", "", 0, true},
		{"GET", "/bigquery/v2/projects/p/datasets/%2E%2E", "", "", 0, true},
		{"GET", "/bigquery/v2/projects/p/datasets/a%5Cb", "", "", 0, true},
		{"GET", "/bigquery/v2/projects", "X-HTTP-Method-Override", "", 0, true},
		{"GET", "/bigquery/v2/projects", "x-goog-user-project", "", 0, true},
	} {
		request := httptest.NewRequest(tc.method, "https://proxy.example"+tc.target, nil)
		if tc.header != "" {
			request.Header[tc.header] = []string{"v"}
		}
		operation, err := engine{}.Operation(request)
		if (err != nil) != tc.fails || errors.Is(err, httpdb.ErrUnsupportedTransport) || operation.Name != tc.name || operation.Kind != tc.kind {
			t.Errorf("%s %s: %+v %v", tc.method, tc.target, operation, err)
		}
		if request.URL.Query().Has("fields") || request.Header.Get("X-Goog-FieldMask") != "" {
			t.Errorf("%s %s: field mask kept: %s %v", tc.method, tc.target, request.URL.RawQuery, request.Header)
		}
	}
	if _, err := (engine{}).Operation(httptest.NewRequest("POST", "https://proxy.example/upload/bigquery/v2/projects/p/jobs", nil)); !errors.Is(err, httpdb.ErrUnsupportedTransport) {
		t.Errorf("upload path: %v", err)
	}
	if operation, _ := (engine{}).Operation(httptest.NewRequest("POST", "https://proxy.example"+queries, nil)); !operation.InlineResult {
		t.Error("jobs.query does not carry its first page")
	}
}

func TestReferencesNameTheJob(t *testing.T) {
	e := engine{&target{settings: settings{location: "US"}}}
	for target, want := range map[string]struct {
		id    string
		first bool
	}{
		"/bigquery/v2/projects/p/queries/j":               {"p/us/j", true},
		"/bigquery/v2/projects/p/queries/j?location=EU":   {"p/eu/j", true},
		"/bigquery/v2/projects/p/queries/j?pageToken=x":   {"p/us/j", false},
		"/bigquery/v2/projects/p/queries/j?startIndex=10": {"p/us/j", false},
		"/bigquery/v2/projects/p/jobs/j?location=asia":    {"p/asia/j", true},
	} {
		ids, first, err := e.References(httptest.NewRequest("GET", "https://proxy.example"+target, nil), nil)
		if err != nil || len(ids) != 1 || ids[0] != want.id || first != want.first {
			t.Errorf("%s: %v %v %v", target, ids, first, err)
		}
	}
}

func TestParameterLiterals(t *testing.T) {
	text := func(s string) *string { return &s }
	for _, tc := range []struct {
		kind  string
		value *string
		want  string
	}{
		{"INT64", text("7"), "7"},
		{"INT64", text("-007"), "-7"},
		{"INT64", text("9223372036854775808"), "CAST('9223372036854775808' AS INT64)"},
		{"INT64", text("0x10"), "CAST('0x10' AS INT64)"},
		{"STRING", text(`it's a \ path`), `CAST('it\'s a \\ path' AS STRING)`},
		{"STRING", text("line\nbreak\ttab\rret"), `CAST('line\nbreak\ttab\rret' AS STRING)`},
		{"STRING", text("'); DROP TABLE t; --"), `CAST('\'); DROP TABLE t; --' AS STRING)`},
		{"STRING", text("é 漢"), "CAST('é 漢' AS STRING)"},
		{"FLOAT64", text("1.5"), "CAST('1.5' AS FLOAT64)"},
		{"NUMERIC", text("1.25"), "CAST('1.25' AS NUMERIC)"},
		{"BIGNUMERIC", text("1e40"), "CAST('1e40' AS BIGNUMERIC)"},
		{"BOOL", text("true"), "CAST('true' AS BOOL)"},
		{"DATE", text("2026-11-16"), "CAST('2026-11-16' AS DATE)"},
		{"DATETIME", text("2026-11-16 10:00:00"), "CAST('2026-11-16 10:00:00' AS DATETIME)"},
		{"TIME", text("10:00:00"), "CAST('10:00:00' AS TIME)"},
		{"TIMESTAMP", text("2026-11-16 10:00:00+00"), "CAST('2026-11-16 10:00:00+00' AS TIMESTAMP)"},
		{"INTERVAL", text("1-2 3 4:5:6"), "CAST('1-2 3 4:5:6' AS INTERVAL)"},
		{"JSON", text(`{"a":"it's"}`), `PARSE_JSON('{"a":"it\'s"}')`},
		{"GEOGRAPHY", text("POINT(1 2)"), "ST_GEOGFROM('POINT(1 2)')"},
		{"BYTES", text("AP8n"), "FROM_BASE64('AP8n')"},
		{"INT64", nil, "CAST(NULL AS INT64)"},
		{"GEOGRAPHY", nil, "CAST(NULL AS GEOGRAPHY)"},
	} {
		got, err := literal(tc.kind, tc.value)
		if err != nil || got != tc.want {
			t.Errorf("%s %v: %q %v, want %q", tc.kind, tc.value, got, err, tc.want)
			continue
		}
		if tc.value == nil || tc.kind == "INT64" && !strings.HasPrefix(got, "CAST") {
			continue
		}
		parsed, err := sqlglot.ParseOne(got, "bigquery")
		if err != nil || parsed.Find(exp.KindLiteral) == nil || parsed.Find(exp.KindLiteral).Name() != *tc.value {
			t.Errorf("%s %q does not read back from %s: %v", tc.kind, *tc.value, got, err)
		}
	}
	for _, bad := range []struct{ kind, value string }{{"BYTES", "not base64!"}, {"STRING", "nul\x00"}, {"STRING", "bell\x07"}} {
		if got, err := literal(bad.kind, &bad.value); err == nil {
			t.Errorf("%s %q accepted as %s", bad.kind, bad.value, got)
		}
	}
}

// LIMIT takes only a literal, so an INT64 parameter must bind as a bare number.
func TestIntegerParameterBindsIntoLimit(t *testing.T) {
	var raw []queryParameter
	if err := json.Unmarshal([]byte(`[{"name":"n","parameterType":{"type":"INT64"},"parameterValue":{"value":"10"}},{"name":"o","parameterType":{"type":"INT64"}}]`), &raw); err != nil {
		t.Fatal(err)
	}
	parameters, err := sqlParameters("NAMED", raw)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := engines.AnalyzeStatement(&enginepb.AnalyzeRequest{
		Sql: "SELECT email FROM Users WHERE @o IS NULL LIMIT @n",
		EngineConfig: &enginepb.EngineConfig{Engine: enginepb.Engine_BIGQUERY, Session: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Bigquery{Bigquery: &enginepb.BigQuerySqlContext{
			Project: "p", DefaultDatasetId: "Sales", Httpdb: &enginepb.HttpDbSqlContext{Parameters: parameters},
		}}}},
		Namespace: &enginepb.Namespace{Catalog: "p", SearchPath: []string{"Sales"}},
		Catalog:   &enginepb.CatalogSnapshot{Columns: []*enginepb.Column{{Catalog: "p", Schema: "Sales", Table: "Users", Column: "email", DataType: "STRING"}}},
	})
	if err != nil || !facts.GetResolved() || facts.GetRewrittenSql() != "SELECT email FROM Users WHERE (CAST(NULL AS INT64)) IS NULL LIMIT 10" {
		t.Fatalf("%q %v\n%s", facts.GetRewrittenSql(), err, facts)
	}
}

func TestParameterModes(t *testing.T) {
	for _, tc := range []struct {
		mode, body string
		ok         bool
	}{
		{"NAMED", `[{"name":"a","parameterType":{"type":"INT64"},"parameterValue":{"value":"1"}}]`, true},
		{"POSITIONAL", `[{"parameterType":{"type":"STRING"},"parameterValue":{"value":"x"}},{"parameterType":{"type":"DATE"}}]`, true},
		{"", `[{"name":"a","parameterType":{"type":"INT64"}}]`, false},
		{"NAMED", `[{"parameterType":{"type":"INT64"}}]`, false},
		{"POSITIONAL", `[{"name":"a","parameterType":{"type":"INT64"}}]`, false},
		{"NAMED", `[{"name":"a","parameterType":{"type":"STRUCT","structTypes":[]}}]`, false},
		{"NAMED", `[{"name":"a","parameterType":{"type":"RANGE","rangeElementType":{"type":"DATE"}}}]`, false},
		{"NAMED", `[{"name":"a","parameterType":{"type":"INTEGER"}}]`, false},
		{"NAMED", `[{"name":"a"}]`, false},
	} {
		var parameters []queryParameter
		if err := json.Unmarshal([]byte(tc.body), &parameters); err != nil {
			t.Fatal(err)
		}
		if _, err := sqlParameters(tc.mode, parameters); (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.mode, tc.body, err)
		}
	}
}

func TestMaskPageShape(t *testing.T) {
	mask := func(ordinal int32, kind string) *pb.Verdict {
		return &pb.Verdict{Decision: pb.EnfAction_MASK, Masks: []*pb.ColumnMask{{Column: "c", Kind: kind, Ordinal: proto.Int32(ordinal)}}}
	}
	page := func(fields, rows string) []byte {
		return []byte(`{"schema":{"fields":` + fields + `},"rows":` + rows + `,"jobComplete":true}`)
	}
	scalar := `[{"name":"email","type":"STRING"},{"name":"n","type":"INTEGER"}]`
	record := `[{"name":"r","type":"RECORD","fields":[{"name":"x","type":"STRING"}]},{"name":"n","type":"INTEGER"}]`
	repeated := `[{"name":"tags","type":"STRING","mode":"REPEATED"},{"name":"n","type":"INTEGER"}]`
	width := int32(3)
	for name, tc := range map[string]struct {
		body    []byte
		verdict *pb.Verdict
		width   *int32
		bound   []byte
		want    error
	}{
		"masked record":       {page(record, `[{"f":[{"v":{"f":[{"v":"x"}]}},{"v":"1"}]}]`), mask(0, "FIXED"), nil, nil, httpdb.ErrResultShape},
		"masked null record":  {page(record, `[{"f":[{"v":null},{"v":"1"}]}]`), mask(0, "FIXED"), nil, nil, httpdb.ErrResultShape},
		"masked repeated":     {page(repeated, `[{"f":[{"v":[{"v":"x"}]},{"v":"1"}]}]`), mask(0, "NULL"), nil, nil, httpdb.ErrResultShape},
		"short row":           {page(scalar, `[{"f":[{"v":"x"}]}]`), mask(0, "FIXED"), nil, nil, httpdb.ErrResultShape},
		"width differs":       {page(scalar, `[]`), mask(0, "FIXED"), &width, nil, httpdb.ErrResultShape},
		"digest differs":      {page(scalar, `[]`), mask(0, "FIXED"), nil, make([]byte, 32), httpdb.ErrResultShape},
		"rows without schema": {[]byte(`{"rows":[{"f":[{"v":"x"}]}]}`), mask(0, "FIXED"), nil, nil, httpdb.ErrResultShape},
		"non-string cell":     {page(scalar, `[{"f":[{"v":5},{"v":"1"}]}]`), mask(0, "FIXED"), nil, nil, httpdb.ErrResultShape},
		"unbound mask":        {page(scalar, `[]`), mask(5, "FIXED"), nil, nil, relay.ErrMaskUnbound},
	} {
		if _, _, err := maskPage(tc.body, tc.verdict, tc.width, tc.bound); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	pending := []byte(`{"kind":"bigquery#getQueryResultsResponse","jobReference":{"projectId":"p","jobId":"j","location":"US"},"jobComplete":false}`)
	if out, digest, err := maskPage(pending, mask(0, "FIXED"), nil, nil); err != nil || digest != nil || string(out) != string(pending) {
		t.Errorf("pending page: %s %x %v", out, digest, err)
	}
	out, digest, err := maskPage(page(record, `[{"f":[{"v":{"f":[{"v":"x"}]}},{"v":"1"}]}]`), mask(1, "NULL"), nil, nil)
	if err != nil || len(digest) != 32 || !strings.Contains(string(out), `{"v":null}`) || !strings.Contains(string(out), `"type":"INTEGER"`) || !strings.Contains(string(out), `{"f":[{"v":"x"}]}`) {
		t.Errorf("NULL mask beside a record: %s %v", out, err)
	}
}

func TestErrorsAreGoogleShaped(t *testing.T) {
	recorder := httptest.NewRecorder()
	engine{}.WriteError(recorder, http.StatusForbidden, "bigquery.request_denied")
	want := `{"error":{"code":403,"errors":[{"domain":"global","message":"bigquery.request_denied","reason":"accessDenied"}],"message":"bigquery.request_denied","status":"PERMISSION_DENIED"}}`
	if recorder.Body.String() != want+"\n" {
		t.Errorf("error body: %s", recorder.Body)
	}
}

func TestValuesSpellRecordsAsPlainJSON(t *testing.T) {
	raw := `{"jobComplete":true,"jobReference":{"projectId":"p","jobId":"j","location":"US"},"schema":{"fields":[` +
		`{"name":"device","type":"RECORD","fields":[{"name":"model","type":"STRING"},{"name":"tags","type":"STRING","mode":"REPEATED"}]},` +
		`{"name":"visits","type":"RECORD","mode":"REPEATED","fields":[{"name":"at","type":"TIMESTAMP"}]},{"name":"id","type":"INTEGER"}]},` +
		`"rows":[{"f":[{"v":{"f":[{"v":"iPhone"},{"v":[{"v":"a"},{"v":"b"}]}]}},{"v":[{"v":{"f":[{"v":"1.7E9"}]}}]},{"v":"7"}]},` +
		`{"f":[{"v":{"f":[{"v":null},{"v":[]}]}},{"v":[]},{"v":null}]}]}`
	page, _, err := decodePage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := page.values()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{`{"model":"iPhone","tags":["a","b"]}`, `[{"at":"1.7E9"}]`, "7"}, {`{"model":null,"tags":[]}`, `[]`, "<nil>"}}
	if len(rows) != len(want) {
		t.Fatalf("rows: %d, want %d", len(rows), len(want))
	}
	for i, row := range rows {
		for j, cell := range row {
			got := "<nil>"
			if cell != nil {
				got = *cell
			}
			if got != want[i][j] {
				t.Errorf("row %d column %d = %s, want %s", i, j, got, want[i][j])
			}
		}
	}
}
