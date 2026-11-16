package bigquery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestSettings(t *testing.T) {
	valid := Flags{Project: "proj-a", Location: "asia-northeast3", Dataset: "Sales", ContextPath: ":memory:", Endpoint: "https://bigquery.googleapis.com"}
	with := func(change func(*Flags)) Flags {
		flags := valid
		change(&flags)
		return flags
	}
	for name, tc := range map[string]struct {
		flags     Flags
		advertise string
		ok        bool
	}{
		"valid":                {valid, "proxy.example:6444", true},
		"multi-region":         {with(func(f *Flags) { f.Location = "US" }), "", true},
		"domain-scoped":        {with(func(f *Flags) { f.Project = "example.com:proj-a" }), "", true},
		"emulator endpoint":    {with(func(f *Flags) { f.Endpoint = "https://localhost:9050/" }), "", true},
		"no project":           {with(func(f *Flags) { f.Project = "" }), "", false},
		"project injection":    {with(func(f *Flags) { f.Project = "proj-a`.x" }), "", false},
		"no location":          {with(func(f *Flags) { f.Location = "" }), "", false},
		"location injection":   {with(func(f *Flags) { f.Location = "us`.x" }), "", false},
		"no dataset":           {with(func(f *Flags) { f.Dataset = " " }), "", false},
		"http endpoint":        {with(func(f *Flags) { f.Endpoint = "http://bigquery.googleapis.com" }), "", false},
		"endpoint with path":   {with(func(f *Flags) { f.Endpoint = "https://bigquery.googleapis.com/bigquery/v2" }), "", false},
		"advertise not a host": {valid, "https://proxy.example:6444", false},
	} {
		cfg, err := newSettings(tc.flags, tc.advertise)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err == nil && strings.HasSuffix(cfg.endpoint, "/") {
			t.Errorf("%s: endpoint keeps its slash: %s", name, cfg.endpoint)
		}
	}
}

func TestTargetBinding(t *testing.T) {
	cfg := settings{project: "proj-a", location: "US", dataset: "sales", endpoint: "https://bigquery.googleapis.com"}
	base := targetBinding(cfg, "proxy@proj-a.iam.gserviceaccount.com")
	if !bytes.Equal(base, targetBinding(cfg, "proxy@proj-a.iam.gserviceaccount.com")) || len(base) != 32 {
		t.Fatal("binding is not stable")
	}
	cfg.contextPath, cfg.advertise = "/var/lib/contexts", "proxy.example:6444"
	if !bytes.Equal(base, targetBinding(cfg, "proxy@proj-a.iam.gserviceaccount.com")) {
		t.Error("binding depends on a setting outside the target")
	}
	for name, changed := range map[string]func(settings) (settings, string){
		"principal": func(s settings) (settings, string) { return s, "other@proj-a.iam.gserviceaccount.com" },
		"project": func(s settings) (settings, string) {
			s.project = "proj-b"
			return s, "proxy@proj-a.iam.gserviceaccount.com"
		},
		"location": func(s settings) (settings, string) {
			s.location = "EU"
			return s, "proxy@proj-a.iam.gserviceaccount.com"
		},
		"dataset": func(s settings) (settings, string) {
			s.dataset = "hr"
			return s, "proxy@proj-a.iam.gserviceaccount.com"
		},
		"endpoint": func(s settings) (settings, string) {
			s.endpoint = "https://emulator.test"
			return s, "proxy@proj-a.iam.gserviceaccount.com"
		},
	} {
		if bytes.Equal(base, targetBinding(changed(cfg))) {
			t.Errorf("binding ignores the %s", name)
		}
	}
}

func TestCredentialPrincipal(t *testing.T) {
	var tokenInfoCalls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenInfoCalls++
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.FormValue("access_token") != "upstream-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"azp":"1234","sub":"1234","email":"user@example.test","expires_in":"3599"}`)
	}))
	defer server.Close()
	token := func(context.Context) (string, error) { return "upstream-token", nil }
	for name, tc := range map[string]struct {
		json, want string
	}{
		"service account key": {`{"type":"service_account","client_email":"proxy@proj-a.iam.gserviceaccount.com"}`, "proxy@proj-a.iam.gserviceaccount.com"},
		"impersonated": {`{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/bq@proj-a.iam.gserviceaccount.com:generateAccessToken","source_credentials":{"type":"authorized_user"}}`,
			"bq@proj-a.iam.gserviceaccount.com"},
		"federated": {`{"type":"external_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wif@proj-a.iam.gserviceaccount.com:generateAccessToken"}`,
			"wif@proj-a.iam.gserviceaccount.com"},
		"user credentials": {`{"type":"authorized_user","refresh_token":"x"}`, "user@example.test"},
		"metadata server":  {"", "user@example.test"},
	} {
		got, err := credentialPrincipal(context.Background(), []byte(tc.json), token, server.Client(), server.URL)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
	if tokenInfoCalls != 2 {
		t.Errorf("tokeninfo called %d times, want only for credentials without an email", tokenInfoCalls)
	}
	if _, err := credentialPrincipal(context.Background(), []byte(`{"type":"authorized_user"}`), token, server.Client(), server.URL+"/missing?x"); err == nil {
		t.Error("an unknown principal did not fail")
	}
}

func TestFindCredentialsReadsApplicationDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	key := `{"type":"service_account","project_id":"proj-a","client_email":"proxy@proj-a.iam.gserviceaccount.com","private_key_id":"k","private_key":"unused","token_uri":"https://oauth2.example.test/token"}`
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	credentials, token, err := findCredentials()
	if err != nil || token == nil {
		t.Fatal(err)
	}
	principal, err := credentialPrincipal(context.Background(), credentials.JSON, token, nil, "")
	if err != nil || principal != "proxy@proj-a.iam.gserviceaccount.com" {
		t.Fatalf("%q %v", principal, err)
	}
}

func TestConnectionInfoPublishesScopeOnly(t *testing.T) {
	target := testTarget(t, newFakeBigQuery().handle)
	target.advertise = "proxy.example:6444"
	info := target.ConnectionInfo()
	if info.GetEndpoint() != "https://proxy.example:6444" || len(info.GetProperties()) != 3 ||
		info.GetProperties()["project"] != "proj-a" || info.GetProperties()["location"] != "US" || info.GetProperties()["dataset"] != "sales" {
		t.Fatalf("connection info: %v", info)
	}
	if !strings.HasPrefix(target.TargetInfo(), "127.0.0.1:") || !strings.HasSuffix(target.TargetInfo(), " project proj-a, location US") {
		t.Errorf("TargetInfo() = %q", target.TargetInfo())
	}
}

// fakeMetadata answers the INFORMATION_SCHEMA jobs and tables.get: the columns arrive on two pages, with a
// partition pseudo-column unless hidden ones are filtered, and the routines job runs past jobs.query.
func fakeMetadata(t *testing.T, queries *[]map[string]any) http.HandlerFunc {
	page := func(job, fields, rows, token string) string {
		out := `{"jobComplete":true,"jobReference":` + reference(job) + `,"schema":{"fields":` + fields + `},"rows":` + rows
		if token != "" {
			out += `,"pageToken":"` + token + `"`
		}
		return out + "}"
	}
	columnFields := `[{"name":"table_schema","type":"STRING"},{"name":"table_name","type":"STRING"},{"name":"column_name","type":"STRING"},{"name":"data_type","type":"STRING"},{"name":"ordinal_position","type":"INTEGER"},{"name":"is_nullable","type":"STRING"}]`
	routineFields := `[{"name":"routine_schema","type":"STRING"},{"name":"routine_name","type":"STRING"}]`
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/proj-a"); {
		case r.Method == http.MethodPost && path == "/queries":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			*queries = append(*queries, body)
			if body["location"] != "US" || body["jobCreationMode"] != "JOB_CREATION_REQUIRED" || body["useLegacySql"] != false {
				t.Errorf("metadata job not pinned: %v", body)
			}
			query, _ := body["query"].(string)
			switch {
			case strings.Contains(query, "FROM `proj-a`.`region-us`.INFORMATION_SCHEMA.COLUMNS"):
				rows := `[{"f":[{"v":"Sales"},{"v":"Users"},{"v":"Email"},{"v":"STRING"},{"v":"1"},{"v":"YES"}]},` +
					`{"f":[{"v":"Sales"},{"v":"Users"},{"v":"profile"},{"v":"STRUCT<email STRING, age INT64>"},{"v":"2"},{"v":"NO"}]}`
				if !strings.Contains(query, "is_hidden = 'NO'") {
					rows += `,{"f":[{"v":"Sales"},{"v":"Users"},{"v":"_PARTITIONTIME"},{"v":"TIMESTAMP"},{"v":null},{"v":"YES"}]}`
				}
				_, _ = io.WriteString(w, page("cols", columnFields, rows+"]", "p2"))
			case strings.Contains(query, "FROM `proj-a`.`region-us`.INFORMATION_SCHEMA.ROUTINES"):
				_, _ = io.WriteString(w, `{"jobComplete":false,"jobReference":`+reference("routines")+`}`)
			default:
				t.Errorf("unexpected query %q", query)
			}
		case r.Method == http.MethodGet && path == "/queries/cols" && r.URL.Query().Get("pageToken") == "p2":
			_, _ = io.WriteString(w, page("cols", columnFields, `[{"f":[{"v":"Sales"},{"v":"Orders"},{"v":"ID"},{"v":"ARRAY<INT64>"},{"v":"1"},{"v":"YES"}]}]`, ""))
		case r.Method == http.MethodGet && path == "/queries/routines" && r.URL.Query().Get("location") == "US":
			_, _ = io.WriteString(w, page("routines", routineFields, `[{"f":[{"v":"Sales"},{"v":"MaskEmail"}]}]`, ""))
		case r.Method == http.MethodGet && path == "/datasets/Sales/tables/Users":
			_, _ = io.WriteString(w, `{"description":"people","schema":{"fields":[{"name":"Email","type":"STRING","mode":"REQUIRED","description":"contact"},`+
				`{"name":"profile","type":"RECORD","fields":[{"name":"email","type":"STRING"},{"name":"age","type":"INTEGER"}]},`+
				`{"name":"visits","type":"RECORD","mode":"REPEATED","fields":[{"name":"at","type":"TIMESTAMP"}]},{"name":"tags","type":"STRING","mode":"REPEATED"}]}}`)
		default:
			t.Errorf("unexpected %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestIntrospectReadsTheLocation(t *testing.T) {
	var queries []map[string]any
	target := testTarget(t, fakeMetadata(t, &queries))
	catalog, err := target.Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []*enginepb.Column{
		{Catalog: "proj-a", Schema: "Sales", Table: "Users", Column: "email", DataType: "STRING", Ordinal: 1, Nullable: true},
		{Catalog: "proj-a", Schema: "Sales", Table: "Users", Column: "profile", DataType: "STRUCT<email STRING, age INT64>", Ordinal: 2},
		{Catalog: "proj-a", Schema: "Sales", Table: "Orders", Column: "id", DataType: "ARRAY<INT64>", Ordinal: 1, Nullable: true},
	}
	columns := catalog.GetCatalog().GetColumns()
	if len(columns) != len(want) {
		t.Fatalf("columns: %v", columns)
	}
	for i := range want {
		if columns[i].String() != want[i].String() {
			t.Errorf("column %d = %v, want %v", i, columns[i], want[i])
		}
	}
	routines := catalog.GetCatalog().GetRoutines()
	if len(routines) != 1 || routines[0].GetSchema() != "Sales" || len(routines[0].GetNames()) != 1 || routines[0].GetNames()[0] != "MaskEmail" {
		t.Errorf("routines: %v", routines)
	}
	if catalog.GetCurrentCatalog() != "proj-a" || len(catalog.GetDefaultSchemas()) != 1 || catalog.GetDefaultSchemas()[0] != "sales" {
		t.Errorf("namespace: %v %v", catalog.GetCurrentCatalog(), catalog.GetDefaultSchemas())
	}
	if len(queries) != 2 || queries[0]["queryParameters"] != nil {
		t.Errorf("queries: %v", queries)
	}
}

func TestInspectSchemaFiltersOneDataset(t *testing.T) {
	var queries []map[string]any
	target := testTarget(t, fakeMetadata(t, &queries))
	push, err := target.InspectSchema("Sales", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(push.GetColumns()) != 3 || len(push.GetRoutines()) != 1 || len(push.GetContentHash()) != 32 || push.GetUnchanged() {
		t.Fatalf("fragment: %v", push)
	}
	for _, query := range queries {
		parameters, _ := json.Marshal(query["queryParameters"])
		if query["parameterMode"] != "NAMED" || !strings.Contains(query["query"].(string), "= @dataset") ||
			string(parameters) != `[{"name":"dataset","parameterType":{"type":"STRING"},"parameterValue":{"value":"Sales"}}]` {
			t.Errorf("dataset filter not bound: %v", query)
		}
	}
	again, err := target.InspectSchema("Sales", push.GetContentHash())
	if err != nil || !again.GetUnchanged() || len(again.GetColumns()) != 0 {
		t.Fatalf("unchanged fragment: %v %v", again, err)
	}
}

func TestReadTableDetailSpellsGoogleSQLTypes(t *testing.T) {
	var queries []map[string]any
	target := testTarget(t, fakeMetadata(t, &queries))
	detail, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: "proj-a", Schema: "Sales", Table: "Users"})
	if err != nil {
		t.Fatal(err)
	}
	if detail.Catalog != "proj-a" || detail.Schema != "Sales" || detail.Table != "Users" || detail.Metadata.Engine != "bigquery" || *detail.Metadata.Comment != "people" {
		t.Fatalf("detail: %+v", detail)
	}
	want := []struct {
		name, dataType string
		nullable       bool
	}{
		{"email", "STRING", false},
		{"profile", "STRUCT<email STRING, age INT64>", true},
		{"visits", "ARRAY<STRUCT<at TIMESTAMP>>", false},
		{"tags", "ARRAY<STRING>", false},
	}
	if len(detail.Columns) != len(want) || *detail.Columns[0].Comment != "contact" {
		t.Fatalf("columns: %+v", detail.Columns)
	}
	for i, column := range detail.Columns {
		if column.Name != want[i].name || column.DataType != want[i].dataType || column.Nullable != want[i].nullable || column.Ordinal != i+1 {
			t.Errorf("column %d: %+v, want %+v", i, column, want[i])
		}
	}
}
