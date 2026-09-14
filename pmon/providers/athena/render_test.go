package athena

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func renderTarget() driver.Target {
	return driver.Target{
		Name: "warehouse", Engine: "athena", Port: 32123, User: "alice", Password: "local-password",
		ConnectionInfo: &driver.ConnectionInfo{Properties: map[string]string{"region": "us-east-1", "workgroup": "analytics", "catalog": "AwsDataCatalog", "database": "sample"}},
	}
}

func TestRenderOrdinaryClients(t *testing.T) {
	provider := Provider{}
	target := renderTarget()
	credentials := localCredentials(target.User, target.Name, target.Password)
	if got := provider.Render(driver.URL, target, driver.Options{}); got != "http://127.0.0.1:32123" {
		t.Fatalf("endpoint = %q", got)
	}
	for _, test := range []struct {
		format driver.Format
		parts  []string
	}{
		{driver.CLI, []string{"aws athena start-query-execution", "AWS_ENDPOINT_URL_ATHENA='http://127.0.0.1:32123'", "--region 'us-east-1'", "--work-group 'analytics'", `--query-execution-context '{"Catalog":"AwsDataCatalog","Database":"sample"}'`, "AWS_SESSION_TOKEN=''"}},
		{driver.JDBC, []string{"jdbc:athena://Region=us-east-1;", "AthenaEndpoint=http://127.0.0.1:32123;", "Workgroup=analytics;Catalog=AwsDataCatalog;Database=sample;", "CredentialsProvider=Static;"}},
		{"python", []string{"import boto3", "boto3.client(", `endpoint_url="http://127.0.0.1:32123"`, `region_name="us-east-1"`, `WorkGroup="analytics"`, `QueryExecutionContext={"Catalog":"AwsDataCatalog","Database":"sample"}`}},
		{"node", []string{`from "@aws-sdk/client-athena"`, `endpoint: "http://127.0.0.1:32123"`, `region: "us-east-1"`, `WorkGroup: "analytics"`, `QueryExecutionContext: {"Catalog":"AwsDataCatalog","Database":"sample"}`}},
		{"aws-config", []string{"[profile pmon-", "region = us-east-1", "endpoint_url = http://127.0.0.1:32123", "aws_access_key_id = "}},
	} {
		t.Run(string(test.format), func(t *testing.T) {
			got := provider.Render(test.format, target, driver.Options{})
			for _, part := range append(test.parts, credentials.AccessKeyID, credentials.SecretAccessKey) {
				if !strings.Contains(got, part) {
					t.Errorf("missing %q in %s", part, got)
				}
			}
			if strings.Contains(got, target.Password) {
				t.Error("renderer exposed the shared loopback password instead of scoped derived credentials")
			}
		})
	}
}

func TestRenderURLNeedsOnlyLocalPort(t *testing.T) {
	if got := (Provider{}).Render(driver.URL, driver.Target{Port: 32123}, driver.Options{}); got != "http://127.0.0.1:32123" {
		t.Fatalf("local endpoint = %q", got)
	}
}

func TestRenderUnsupportedFormats(t *testing.T) {
	for _, format := range []driver.Format{driver.GoDSN, "unknown"} {
		if got := (Provider{}).Render(format, renderTarget(), driver.Options{}); got != "" {
			t.Fatalf("unsupported format %q rendered %q", format, got)
		}
	}
	// The driver's default S3 fetcher dials S3 with the local credentials, which AWS rejects.
	if got := (Provider{}).Render(driver.JDBC, renderTarget(), driver.Options{}); !strings.Contains(got, ";ResultFetcher=GetQueryResults;") {
		t.Fatalf("JDBC configuration leaves result reads off the proxied API: %s", got)
	}
}

func TestRenderProfilesChangeWithPrincipal(t *testing.T) {
	target := renderTarget()
	first := (Provider{}).Render("aws-config", target, driver.Options{})
	target.User = "bob"
	second := (Provider{}).Render("aws-config", target, driver.Options{})
	if first == second || strings.Split(first, "\n")[0] == strings.Split(second, "\n")[0] {
		t.Fatal("different principals share a saved profile")
	}
}

func TestRenderEscapesMetadata(t *testing.T) {
	target := renderTarget()
	target.ConnectionInfo.Properties["workgroup"] = "data'$(command)"
	target.ConnectionInfo.Properties["database"] = "sample\"\\\n"
	cli := (Provider{}).Render(driver.CLI, target, driver.Options{})
	if !strings.Contains(cli, `--work-group 'data'\''$(command)'`) || !strings.Contains(cli, `sample\"\\\n`) {
		t.Fatalf("shell or JSON escaping missing: %s", cli)
	}
	node := (Provider{}).Render("node", target, driver.Options{})
	if !strings.Contains(node, `sample\"\\\n`) {
		t.Fatalf("JavaScript escaping missing: %s", node)
	}
	if got := (Provider{}).Render(driver.JDBC, target, driver.Options{}); got != "" {
		t.Fatalf("unsafe JDBC metadata rendered: %s", got)
	}
	target.ConnectionInfo.Properties["region"] = "us-east-1\naws_session_token = injected"
	if got := (Provider{}).Render("aws-config", target, driver.Options{}); got != "" {
		t.Fatalf("unsafe profile region rendered: %s", got)
	}
}

func TestRenderDefaultsStayProviderOwned(t *testing.T) {
	target := renderTarget()
	target.ConnectionInfo = &driver.ConnectionInfo{Properties: map[string]string{"region": "us-east-1"}}
	target.DbName = "fallback"
	got := (Provider{}).Render(driver.CLI, target, driver.Options{})
	for _, part := range []string{"--work-group 'primary'", `"Catalog":"AwsDataCatalog"`, `"Database":"fallback"`} {
		if !strings.Contains(got, part) {
			t.Errorf("missing default %q in %s", part, got)
		}
	}
}
