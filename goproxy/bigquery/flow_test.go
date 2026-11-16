package bigquery

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
)

const queries = "/bigquery/v2/projects/proj-a/queries"

const namedQuery = `{"query":"SELECT * FROM users WHERE n > @n","useLegacySql":false,"parameterMode":"NAMED",` +
	`"queryParameters":[{"name":"n","parameterType":{"type":"INT64"},"parameterValue":{"value":"7"}}],"requestId":"client-request"}`

func TestQueryIsRewrittenAndItsRowsMasked(t *testing.T) {
	server, client, upstream := flowServer(t, "alice", maskVerdict())
	response := serve(server, "alice", http.MethodPost, queries, namedQuery, "Accept-Encoding", "gzip")
	body := response.Body.String()
	if response.Code != http.StatusOK || strings.Contains(body, "a@example.test") || !strings.Contains(body, "####") || !strings.Contains(body, "job_1") {
		t.Fatalf("inline rows not masked: %d %s", response.Code, body)
	}
	var page struct {
		Schema struct{ Fields []struct{ Name, Type string } }
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.Schema.Fields[0].Type != "STRING" || page.Schema.Fields[1].Type != "INTEGER" {
		t.Fatalf("schema: %+v %v", page, err)
	}
	if len(client.decisions) != 1 {
		t.Fatalf("decisions: %v", client.decisions)
	}
	session := client.decisions[0].GetSession().GetBigquery()
	if parameters := session.GetHttpdb().GetParameters(); session.GetProject() != "proj-a" || len(parameters) != 1 || parameters[0].Name != "n" || parameters[0].Value != "7" || client.decisions[0].CurrentCatalog != "proj-a" {
		t.Fatalf("decision lacks the BigQuery context: %+v", client.decisions[0])
	}
	sent := upstream.last(http.MethodPost, queries)
	requestID, _ := sent.body["requestId"].(string)
	if sent.body["query"] != *maskVerdict().RewrittenSql || sent.body["queryParameters"] != nil || sent.body["parameterMode"] != nil ||
		sent.body["jobCreationMode"] != "JOB_CREATION_REQUIRED" || sent.body["location"] != "US" || len(requestID) != 36 || requestID == "client-request" {
		t.Fatalf("submission not rewritten: %v", sent.body)
	}
	if dataset, _ := sent.body["defaultDataset"].(map[string]any); dataset["projectId"] != "proj-a" || dataset["datasetId"] != "sales" {
		t.Fatalf("default dataset not pinned: %v", sent.body)
	}
	if sent.header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("upstream Accept-Encoding = %q", sent.header.Get("Accept-Encoding"))
	}

	response = serve(server, "alice", http.MethodGet, queries+"/job_1?location=US&maxResults=10", "")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), "####") {
		t.Fatalf("result page not masked: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "alice", http.MethodGet, "/bigquery/v2/projects/proj-a/jobs/job_1", "")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), relay.RedactedDiagnosticMessage) {
		t.Fatalf("job status not released with redacted diagnostics: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "alice", http.MethodGet, "/bigquery/v2/projects/proj-a/jobs?allUsers=true", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "job_1") || strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("own job list not released: %d %s", response.Code, response.Body.String())
	}

	server.Client = &flowClient{principal: "bob", verdict: maskVerdict(), completed: make(chan struct{}, 8)}
	for _, target := range []string{queries + "/job_1", "/bigquery/v2/projects/proj-a/jobs/job_1", queries + "/job_9"} {
		if response := serve(server, "bob", http.MethodGet, target, ""); response.Code != http.StatusConflict {
			t.Fatalf("bob read %s: %d %s", target, response.Code, response.Body.String())
		}
	}
	response = serve(server, "bob", http.MethodGet, "/bigquery/v2/projects/proj-a/jobs", "")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "job_1") || !strings.Contains(response.Body.String(), `"jobs":[]`) || !strings.Contains(response.Body.String(), "page-2") {
		t.Fatalf("bob saw alice's jobs or lost the page token: %d %s", response.Code, response.Body.String())
	}
}

func TestAllowedQueryReleasesRowsUnchanged(t *testing.T) {
	server, _, _ := flowServer(t, "alice", &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 5})
	if response := serve(server, "alice", http.MethodPost, queries, `{"query":"SELECT email, n FROM users","useLegacySql":false}`); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("allowed inline rows altered: %d %s", response.Code, response.Body.String())
	}
	if response := serve(server, "alice", http.MethodGet, queries+"/job_1", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("allowed page altered: %d %s", response.Code, response.Body.String())
	}
}

func TestInsertedQueryJobKeepsItsIDInTheTargetScope(t *testing.T) {
	server, _, upstream := flowServer(t, "alice", maskVerdict())
	body := `{"jobReference":{"jobId":"mine_1"},"configuration":{"query":{"query":"SELECT * FROM users WHERE n > ?","useLegacySql":false,"parameterMode":"POSITIONAL",` +
		`"queryParameters":[{"parameterType":{"type":"INT64"},"parameterValue":{"value":"7"}}],"defaultDataset":{"projectId":"proj-b","datasetId":"other"}}}}`
	if response := serve(server, "alice", http.MethodPost, "/bigquery/v2/projects/proj-a/jobs", body); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "mine_1") {
		t.Fatalf("job insert failed: %d %s", response.Code, response.Body.String())
	}
	sent := upstream.last(http.MethodPost, "/bigquery/v2/projects/proj-a/jobs")
	reference, _ := sent.body["jobReference"].(map[string]any)
	query, _ := sent.body["configuration"].(map[string]any)["query"].(map[string]any)
	dataset, _ := query["defaultDataset"].(map[string]any)
	if reference["jobId"] != "mine_1" || reference["projectId"] != "proj-a" || reference["location"] != "US" || query["query"] != *maskVerdict().RewrittenSql ||
		query["queryParameters"] != nil || dataset["projectId"] != "proj-b" || sent.body["jobCreationMode"] != nil {
		t.Fatalf("job not rewritten in scope: %v", sent.body)
	}
	if response := serve(server, "alice", http.MethodGet, queries+"/mine_1", ""); response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("inserted job's results not masked: %d %s", response.Code, response.Body.String())
	}
}

func TestRefusedRequestsNeverReachBigQuery(t *testing.T) {
	server, _, upstream := flowServer(t, "alice", maskVerdict())
	for _, tc := range []struct {
		name, method, target, body string
		headers                    []string
		want                       int
	}{
		{"legacy SQL", http.MethodPost, queries, `{"query":"SELECT 1","useLegacySql":true}`, nil, http.StatusForbidden},
		{"legacy SQL by default", http.MethodPost, queries, `{"query":"SELECT 1"}`, nil, http.StatusForbidden},
		{"array parameter", http.MethodPost, queries, `{"query":"SELECT @a","useLegacySql":false,"parameterMode":"NAMED","queryParameters":[{"name":"a","parameterType":{"type":"ARRAY","arrayType":{"type":"INT64"}},"parameterValue":{"arrayValues":[{"value":"1"}]}}]}`, nil, http.StatusBadGateway},
		{"tabledata.list", http.MethodGet, "/bigquery/v2/projects/proj-a/datasets/sales/tables/users/data", "", nil, http.StatusForbidden},
		{"tabledata.insertAll", http.MethodPost, "/bigquery/v2/projects/proj-a/datasets/sales/tables/users/insertAll", `{}`, nil, http.StatusForbidden},
		{"upload", http.MethodPost, "/upload/bigquery/v2/projects/proj-a/jobs", `{}`, nil, http.StatusBadRequest},
		{"key in the query", http.MethodGet, "/bigquery/v2/projects?key=k", "", nil, http.StatusBadRequest},
		{"method override", http.MethodPost, "/bigquery/v2/projects/proj-a/datasets", `{}`, []string{"X-HTTP-Method-Override", "DELETE"}, http.StatusBadRequest},
		{"billing project", http.MethodGet, "/bigquery/v2/projects", "", []string{"X-Goog-User-Project", "proj-b"}, http.StatusBadRequest},
		{"encoded slash", http.MethodGet, "/bigquery/v2/projects/proj-a/datasets/a%2Fb", "", nil, http.StatusBadRequest},
	} {
		response := serve(server, "alice", tc.method, tc.target, tc.body, tc.headers...)
		if response.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, response.Code, response.Body.String(), tc.want)
		}
		var google struct{ Error struct{ Code int } }
		if err := json.Unmarshal(response.Body.Bytes(), &google); err != nil || google.Error.Code != response.Code {
			t.Errorf("%s: not a Google error: %s", tc.name, response.Body.String())
		}
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.requests) != 0 {
		t.Fatalf("refused requests reached BigQuery: %+v", upstream.requests)
	}
}

func TestDeniedStatementIsAnInvalidQuery(t *testing.T) {
	server, _, upstream := flowServer(t, "alice", &pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no access to users.email", DecisionId: 3})
	response := serve(server, "alice", http.MethodPost, queries, `{"query":"SELECT email FROM users","useLegacySql":false}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"status":"INVALID_ARGUMENT"`) ||
		!strings.Contains(response.Body.String(), "proxy-monster denied this statement: no access to users.email") {
		t.Fatalf("deny not surfaced: %d %s", response.Code, response.Body.String())
	}
	if upstream.last(http.MethodPost, queries) != nil {
		t.Fatal("denied statement reached BigQuery")
	}
}

func TestRequestIDReplayKeepsTheOriginalContext(t *testing.T) {
	server, client, upstream := flowServer(t, "alice", maskVerdict())
	for range 2 {
		if response := serve(server, "alice", http.MethodPost, queries, namedQuery); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "job_1") || strings.Contains(response.Body.String(), "a@example.test") {
			t.Fatalf("retry not accepted: %d %s", response.Code, response.Body.String())
		}
	}
	client.verdict = &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 9, RewrittenSql: maskVerdict().RewrittenSql}
	if response := serve(server, "alice", http.MethodPost, queries, namedQuery); response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("replay released rows under a later decision: %d %s", response.Code, response.Body.String())
	}
	if len(upstream.jobs) != 1 {
		t.Fatalf("requestId not stable: %v", upstream.jobs)
	}
}

func TestFieldMaskIsDroppedAndTheFullPageMasked(t *testing.T) {
	server, client, upstream := flowServer(t, "alice", maskVerdict())
	if response := serve(server, "alice", http.MethodPost, queries, namedQuery); response.Code != http.StatusOK {
		t.Fatalf("query failed: %d %s", response.Code, response.Body.String())
	}
	response := serve(server, "alice", http.MethodGet, queries+"/job_1?location=US&fields=jobReference,rows", "", "X-Goog-FieldMask", "rows")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), "####") {
		t.Fatalf("result page not masked: %d %s", response.Code, response.Body.String())
	}
	sent := upstream.last(http.MethodGet, queries+"/job_1")
	if sent == nil || strings.Contains(sent.query, "fields") || sent.query != "location=US" || sent.header.Get("X-Goog-FieldMask") != "" {
		t.Fatalf("field mask forwarded: %+v", sent)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	for _, d := range client.descriptors {
		if strings.Contains(d.RawQuery, "fields") {
			t.Fatalf("descriptor carries the field mask: %q", d.RawQuery)
		}
	}
}

func TestDefaultDatasetSentIsTheAnalyzedOne(t *testing.T) {
	server, client, upstream := flowServer(t, "alice", maskVerdict())
	body := `{"query":"SELECT email FROM users","useLegacySql":false,"defaultDataset":{"datasetId":"safe","DATASETID":"other"}}`
	if response := serve(server, "alice", http.MethodPost, queries, body); response.Code != http.StatusOK {
		t.Fatalf("query failed: %d %s", response.Code, response.Body.String())
	}
	analyzed := client.decisions[0].GetSession().GetBigquery()
	sent, _ := upstream.last(http.MethodPost, queries).body["defaultDataset"].(map[string]any)
	if len(sent) != 2 || sent["projectId"] != "proj-a" || sent["datasetId"] != analyzed.GetDefaultDatasetId() || analyzed.GetDefaultDatasetId() == "" {
		t.Fatalf("sent %v, analyzed %+v", sent, analyzed)
	}
}
