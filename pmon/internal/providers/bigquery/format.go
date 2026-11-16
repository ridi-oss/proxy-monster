package bigquery

import (
	"encoding/json"
	"fmt"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// FormatConnectionString produces client configuration for the local endpoint. url needs only the port; the
// others embed the local bearer token and the datasource's project, and return "" without them.
func (Provider) FormatConnectionString(format driver.Format, target driver.Target, _ driver.Options) string {
	endpoint := fmt.Sprintf("http://%s:%d", driver.Host, target.Port)
	if format == driver.URL {
		return endpoint
	}
	if target.ConnectionInfo == nil || target.User == "" || target.Name == "" || target.Password == "" {
		return ""
	}
	project, location := target.ConnectionInfo.Properties["project"], target.ConnectionInfo.Properties["location"]
	if project == "" {
		return ""
	}
	token := localToken(target.User, target.Name, target.Password)
	switch format {
	case driver.CLI:
		quote := driver.ShellQuote
		command := fmt.Sprintf("bq --api=%s --oauth_access_token=%s --project_id=%s", quote(endpoint), quote(token), quote(project))
		if location != "" {
			command += " --location=" + quote(location)
		}
		return command + " query --nouse_legacy_sql 'SELECT 1'"
	case "python":
		locationArg := ""
		if location != "" {
			locationArg = fmt.Sprintf("    location=%s,\n", jsonString(location))
		}
		return fmt.Sprintf("from google.api_core.client_options import ClientOptions\nfrom google.cloud import bigquery\nfrom google.oauth2.credentials import Credentials\n\nclient = bigquery.Client(\n    project=%s,\n%s    credentials=Credentials(token=%s),\n    client_options=ClientOptions(api_endpoint=%s),\n)\nrows = client.query_and_wait(\"SELECT 1\")",
			jsonString(project), locationArg, jsonString(token), jsonString(endpoint))
	default:
		return ""
	}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
