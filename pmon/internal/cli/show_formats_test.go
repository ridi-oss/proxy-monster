package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestShowGenericFormatsPreserveExistingFlags(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{{"name": "mysql", "engine": "mysql", "connectionInfo": map[string]any{"properties": map[string]string{"database": "sample"}}, "advertiseAddr": dummyProxy(t)}})
	e.mustRun(t, "login", "--url", cp.URL)
	for _, format := range []string{"url", "jdbc", "go-dsn", "cli"} {
		legacy := e.mustRun(t, "show", "mysql", "--"+format)
		generic := e.mustRun(t, "show", "mysql", "--format", format)
		if legacy != generic {
			t.Errorf("--%s output %q differs from --format %s output %q", format, legacy, format, generic)
		}
	}
	legacy := e.mustRun(t, "show", "mysql", "--jdbc", "--jdbc-with-truncation-diagnostics")
	generic := e.mustRun(t, "show", "mysql", "--format", "jdbc", "--jdbc-with-truncation-diagnostics")
	if legacy != generic {
		t.Error("generic JDBC format changed truncation diagnostics behavior")
	}
	for _, format := range []string{"python", "unknown"} {
		output, err := e.run("show", "mysql", "--format", format)
		if err == nil || !strings.Contains(output, "not supported") || !strings.Contains(output, "url, jdbc, go-dsn, cli") {
			t.Errorf("unsupported format %q: %v, %s", format, err, output)
		}
	}
	if output, err := e.run("show", "mysql", "--format", "url", "--cli"); err == nil {
		t.Fatalf("mutually exclusive formats were accepted: %s", output)
	}
}

func TestShowAthenaFormatsAndFormattedAWSCLI(t *testing.T) {
	e := newEnv(t)
	var received atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "Bearer pmk_tok" || r.Header.Get("X-Amz-Target") != "AmazonAthena.StartQueryExecution" {
			t.Errorf("unexpected token or operation: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			QueryString           string
			WorkGroup             string
			QueryExecutionContext struct{ Catalog, Database string }
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.QueryString != "SELECT 1" || payload.WorkGroup != "analytics" || payload.QueryExecutionContext.Catalog != "AwsDataCatalog" || payload.QueryExecutionContext.Database != "sample" {
			t.Errorf("unexpected request body: %s, error: %v", body, err)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"QueryExecutionId":"cli-query"}`)
	}))
	defer upstream.Close()
	cp := fakeCP(t, []map[string]any{{
		"name": "warehouse", "engine": "athena", "advertiseAddr": strings.TrimPrefix(upstream.URL, "https://"),
		"advertiseWireTls":   true,
		"advertiseCertChain": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})),
		"connectionInfo": map[string]any{"endpoint": upstream.URL, "properties": map[string]string{
			"region": "us-east-1", "workgroup": "analytics", "catalog": "AwsDataCatalog", "database": "sample",
		}},
	}})
	e.mustRun(t, "login", "--url", cp.URL)
	bare := strings.TrimSpace(e.mustRun(t, "show", "warehouse"))
	if explicit := strings.TrimSpace(e.mustRun(t, "show", "warehouse", "--cli")); bare != explicit || !strings.Contains(bare, "aws athena start-query-execution") {
		t.Fatalf("Athena default is not the native CLI command: %q", bare)
	}
	for _, test := range []struct{ format, content string }{
		{"url", "http://127.0.0.1:"},
		{"jdbc", "jdbc:athena://Region=us-east-1;"},
		{"python", "boto3.client("},
		{"node", "@aws-sdk/client-athena"},
		{"aws-config", "[profile pmon-"},
	} {
		output := e.mustRun(t, "show", "warehouse", "--format", test.format)
		if !strings.Contains(output, test.content) {
			t.Errorf("format %s missing %q: %s", test.format, test.content, output)
		}
		if test.format == "jdbc" && !strings.Contains(output, ";ResultFetcher=GetQueryResults;") {
			t.Errorf("JDBC configuration leaves result reads off the proxied API: %s", output)
		}
	}
	for _, flags := range [][]string{{"--go-dsn"}, {"--format", "go-dsn"}, {"--format", "unknown"}} {
		output, err := e.run(append([]string{"show", "warehouse"}, flags...)...)
		if err == nil || !strings.Contains(output, "not supported") || !strings.Contains(output, "cli, url, jdbc, python, node, aws-config") {
			t.Errorf("unsupported Athena format %v: %v, %s", flags, err, output)
		}
	}
	t.Run("actual AWS CLI", func(t *testing.T) {
		if _, err := exec.LookPath("aws"); err != nil {
			t.Skip("AWS CLI is not installed")
		}
		// The first aws run on a fresh Windows runner spends 6-55s starting before it sends anything.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "sh", "-c", bare+" --output json --no-cli-pager")
		// Killing sh on Windows leaves aws holding the output pipes.
		command.WaitDelay = 10 * time.Second
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "AWS_") && !strings.HasPrefix(entry, "BOTO_") {
				command.Env = append(command.Env, entry)
			}
		}
		command.Env = append(command.Env,
			"AWS_CONFIG_FILE="+os.DevNull, "AWS_SHARED_CREDENTIALS_FILE="+os.DevNull,
			"AWS_EC2_METADATA_DISABLED=true", "AWS_CLI_AUTO_PROMPT=off", "AWS_MAX_ATTEMPTS=1",
		)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), `"QueryExecutionId": "cli-query"`) || received.Load() != 1 {
			t.Fatalf("formatted CLI did not complete through the spawned daemon: %v, %s, requests: %d", err, output, received.Load())
		}
	})
}

func TestShowBigQueryFormatsAndFormattedBQ(t *testing.T) {
	e := newEnv(t)
	var received atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "Bearer pmk_tok" || r.Header.Get("X-Goog-User-Project") != "" {
			t.Errorf("unexpected credentials reached the proxy: %v", r.Header)
		}
		job := `"jobReference":{"projectId":"proj","jobId":"j1","location":"US"}`
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/bigquery/v2/projects/proj/jobs":
			_, _ = io.WriteString(w, `{"kind":"bigquery#job","id":"proj:US.j1",`+job+`,"configuration":{"query":{"query":"SELECT 1","useLegacySql":false}},"statistics":{"query":{"statementType":"SELECT"}},"status":{"state":"DONE"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/queries/j1":
			_, _ = io.WriteString(w, `{"kind":"bigquery#getQueryResultsResponse",`+job+`,"jobComplete":true,"totalRows":"1","schema":{"fields":[{"name":"f0_","type":"INTEGER","mode":"NULLABLE"}]},"rows":[{"f":[{"v":"1"}]}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/jobs/j1":
			_, _ = io.WriteString(w, `{"kind":"bigquery#job","id":"proj:US.j1",`+job+`,"configuration":{"query":{"query":"SELECT 1","useLegacySql":false}},"statistics":{"query":{"statementType":"SELECT"}},"status":{"state":"DONE"}}`)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	cp := fakeCP(t, []map[string]any{{
		"name": "warehouse", "engine": "bigquery", "advertiseAddr": strings.TrimPrefix(upstream.URL, "https://"),
		"advertiseWireTls":   true,
		"advertiseCertChain": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})),
		"connectionInfo": map[string]any{"endpoint": upstream.URL, "properties": map[string]string{
			"project": "proj", "location": "US", "dataset": "sales",
		}},
	}})
	e.mustRun(t, "login", "--url", cp.URL)
	bare := strings.TrimSpace(e.mustRun(t, "show", "warehouse"))
	if !strings.HasPrefix(bare, "bq --api=") {
		t.Fatalf("BigQuery default is not the bq command: %q", bare)
	}
	if output := e.mustRun(t, "show", "warehouse", "--format", "python"); !strings.Contains(output, "bigquery.Client(") {
		t.Errorf("python format: %s", output)
	}
	endpoint := strings.TrimSpace(e.mustRun(t, "show", "warehouse", "--format", "url"))
	token := regexp.MustCompile(`--oauth_access_token='([^']+)'`).FindStringSubmatch(bare)
	if token == nil {
		t.Fatalf("no local token in %q", bare)
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint+"/bigquery/v2/projects/proj/queries/j1", nil)
	request.Header.Set("Authorization", "Bearer "+token[1])
	request.Header.Set("X-Goog-User-Project", "proj")
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK || received.Load() != 1 {
		t.Fatalf("shown token did not reach the proxy through the daemon: %v %v", err, response)
	}
	response.Body.Close()
	t.Run("actual bq", func(t *testing.T) {
		if _, err := exec.LookPath("bq"); err != nil {
			t.Skip("bq is not installed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "sh", "-c", strings.Replace(bare, "bq ", "bq --format=json ", 1))
		command.WaitDelay = 10 * time.Second
		command.Env = append(os.Environ(), "CLOUDSDK_CONFIG="+t.TempDir(), "BIGQUERYRC="+os.DevNull)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), `"f0_":"1"`) {
			t.Fatalf("formatted bq did not complete through the spawned daemon: %v, %s", err, output)
		}
	})
}
