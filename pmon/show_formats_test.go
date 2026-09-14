package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestShowGenericFormatsPreserveExistingFlags(t *testing.T) {
	e := newEnv(t)
	cp := fakeCP(t, []map[string]any{{"name": "mysql", "engine": "mysql", "dbName": "sample", "advertiseAddr": dummyProxy(t)}})
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

func TestShowAthenaFormatsAndRenderedAWSCLI(t *testing.T) {
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
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "sh", "-c", bare+" --output json --no-cli-pager")
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
			t.Fatalf("rendered CLI did not complete through the spawned daemon: %v, %s, requests: %d", err, output, received.Load())
		}
	})
}
