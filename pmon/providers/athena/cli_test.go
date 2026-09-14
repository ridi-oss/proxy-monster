package athena

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestRenderedAWSCLI(t *testing.T) {
	if _, err := exec.LookPath("aws"); err != nil {
		t.Skip("AWS CLI is not installed")
	}
	var received atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "Bearer pm-token" || r.Header.Get("X-Amz-Target") != "AmazonAthena.StartQueryExecution" {
			t.Errorf("unexpected upstream authentication or operation: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			QueryString           string
			WorkGroup             string
			QueryExecutionContext struct{ Catalog, Database string }
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.QueryString != "SELECT 1" || payload.WorkGroup != "primary" || payload.QueryExecutionContext.Catalog != "AwsDataCatalog" || payload.QueryExecutionContext.Database != "default" {
			t.Errorf("unexpected AWS CLI body: %s, error: %v", body, err)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"QueryExecutionId":"cli-query"}`)
	}))
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "pm-token", LocalPassword: "local-password"}
	local := serveBroker(t, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
	parsed, _ := url.Parse(local)
	_, portString, _ := net.SplitHostPort(parsed.Host)
	port, _ := strconv.Atoi(portString)
	target := driver.Target{
		Name: endpoint.Name, Engine: "athena", Port: port, User: credentials.Principal,
		Password: credentials.LocalPassword, ConnectionInfo: endpoint.ConnectionInfo,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "-c", (Provider{}).Render(driver.CLI, target, driver.Options{})+" --output json --no-cli-pager")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "AWS_") && !strings.HasPrefix(entry, "BOTO_") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env,
		"AWS_CONFIG_FILE="+os.DevNull, "AWS_SHARED_CREDENTIALS_FILE="+os.DevNull,
		"AWS_EC2_METADATA_DISABLED=true", "AWS_CLI_AUTO_PROMPT=off", "AWS_MAX_ATTEMPTS=1",
		"AWS_SESSION_TOKEN=stale-ambient-token", "AWS_SECURITY_TOKEN=stale-ambient-token",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("rendered AWS CLI failed: %v\n%s", err, output)
	}
	var result struct {
		QueryExecutionID string `json:"QueryExecutionId"`
	}
	if err := json.Unmarshal(output, &result); err != nil || result.QueryExecutionID != "cli-query" || received.Load() != 1 {
		t.Fatalf("unexpected AWS CLI result: %s, error: %v, requests: %d", output, err, received.Load())
	}
}
