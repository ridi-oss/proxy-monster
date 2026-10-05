package athena

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func formatTarget() driver.Target {
	return driver.Target{
		Name: "warehouse", Engine: "athena", Port: 32123, User: "alice", Password: "local-password",
		ConnectionInfo: &driver.ConnectionInfo{Properties: map[string]string{"region": "us-east-1", "workgroup": "analytics", "catalog": "AwsDataCatalog", "database": "sample"}},
	}
}

func TestFormatOrdinaryClients(t *testing.T) {
	provider := Provider{}
	target := formatTarget()
	credentials := localCredentials(target.User, target.Name, target.Password)
	if got := provider.FormatConnectionString(driver.URL, target, driver.Options{}); got != "http://127.0.0.1:32123" {
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
			got := provider.FormatConnectionString(test.format, target, driver.Options{})
			for _, part := range append(test.parts, credentials.AccessKeyID, credentials.SecretAccessKey) {
				if !strings.Contains(got, part) {
					t.Errorf("missing %q in %s", part, got)
				}
			}
			if strings.Contains(got, target.Password) {
				t.Error("formatter exposed the shared loopback password instead of scoped derived credentials")
			}
		})
	}
}

func TestFormatURLNeedsOnlyLocalPort(t *testing.T) {
	if got := (Provider{}).FormatConnectionString(driver.URL, driver.Target{Port: 32123}, driver.Options{}); got != "http://127.0.0.1:32123" {
		t.Fatalf("local endpoint = %q", got)
	}
}

func TestFormatUnsupportedFormats(t *testing.T) {
	for _, format := range []driver.Format{driver.GoDSN, "unknown"} {
		if got := (Provider{}).FormatConnectionString(format, formatTarget(), driver.Options{}); got != "" {
			t.Fatalf("unsupported format %q formatted %q", format, got)
		}
	}
	// The driver's default S3 fetcher dials S3 with the local credentials, which AWS rejects.
	if got := (Provider{}).FormatConnectionString(driver.JDBC, formatTarget(), driver.Options{}); !strings.Contains(got, ";ResultFetcher=GetQueryResults;") {
		t.Fatalf("JDBC configuration leaves result reads off the proxied API: %s", got)
	}
}

func TestFormatProfilesChangeWithPrincipal(t *testing.T) {
	target := formatTarget()
	first := (Provider{}).FormatConnectionString("aws-config", target, driver.Options{})
	target.User = "bob"
	second := (Provider{}).FormatConnectionString("aws-config", target, driver.Options{})
	if first == second || strings.Split(first, "\n")[0] == strings.Split(second, "\n")[0] {
		t.Fatal("different principals share a saved profile")
	}
}

func TestFormatEscapesMetadata(t *testing.T) {
	target := formatTarget()
	target.ConnectionInfo.Properties["workgroup"] = "data'$(command)"
	target.ConnectionInfo.Properties["database"] = "sample\"\\\n"
	cli := (Provider{}).FormatConnectionString(driver.CLI, target, driver.Options{})
	if !strings.Contains(cli, `--work-group 'data'\''$(command)'`) || !strings.Contains(cli, `sample\"\\\n`) {
		t.Fatalf("shell or JSON escaping missing: %s", cli)
	}
	node := (Provider{}).FormatConnectionString("node", target, driver.Options{})
	if !strings.Contains(node, `sample\"\\\n`) {
		t.Fatalf("JavaScript escaping missing: %s", node)
	}
	if got := (Provider{}).FormatConnectionString(driver.JDBC, target, driver.Options{}); got != "" {
		t.Fatalf("unsafe JDBC metadata formatted: %s", got)
	}
	target.ConnectionInfo.Properties["region"] = "us-east-1\naws_session_token = injected"
	if got := (Provider{}).FormatConnectionString("aws-config", target, driver.Options{}); got != "" {
		t.Fatalf("unsafe profile region formatted: %s", got)
	}
}

func TestFormatDefaultsStayProviderOwned(t *testing.T) {
	target := formatTarget()
	target.ConnectionInfo = &driver.ConnectionInfo{Properties: map[string]string{"region": "us-east-1"}}
	target.DbName = "fallback"
	got := (Provider{}).FormatConnectionString(driver.CLI, target, driver.Options{})
	for _, part := range []string{"--work-group 'primary'", `"Catalog":"AwsDataCatalog"`, `"Database":"fallback"`} {
		if !strings.Contains(got, part) {
			t.Errorf("missing default %q in %s", part, got)
		}
	}
}
