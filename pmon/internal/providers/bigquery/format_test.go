package bigquery

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestFormats(t *testing.T) {
	target := driver.Target{Name: "warehouse", Port: 32123, User: "alice", Password: "local-password",
		ConnectionInfo: &driver.ConnectionInfo{Properties: map[string]string{"project": "proj", "location": "US"}}}
	token := localToken("alice", "warehouse", "local-password")
	for _, tc := range []struct {
		format driver.Format
		want   []string
	}{
		{driver.URL, []string{"http://127.0.0.1:32123"}},
		{driver.CLI, []string{"bq --api='http://127.0.0.1:32123' --oauth_access_token='" + token + "' --project_id='proj' --location='US' query --nouse_legacy_sql 'SELECT 1'"}},
		{"python", []string{`project="proj"`, `location="US"`, `Credentials(token="` + token + `")`, `ClientOptions(api_endpoint="http://127.0.0.1:32123")`}},
	} {
		got := (Provider{}).FormatConnectionString(tc.format, target, driver.Options{})
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s = %q, missing %q", tc.format, got, want)
			}
		}
	}
	target.ConnectionInfo.Properties["project"] = ""
	if got := (Provider{}).FormatConnectionString(driver.CLI, target, driver.Options{}); got != "" {
		t.Errorf("CLI without a project = %q", got)
	}
}
