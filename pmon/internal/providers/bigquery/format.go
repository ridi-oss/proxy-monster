package bigquery

import (
	"encoding/json"
	"fmt"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// FormatConnectionString produces client configuration for the local endpoint. url needs only the port; the
// others embed the local bearer token and the datasource's project, and return "" without them. python reads
// query results through the Storage Read API at the same port, over cleartext HTTP/2.
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
		return fmt.Sprintf(`import grpc
from google.api_core.client_options import ClientOptions
from google.cloud import bigquery, bigquery_storage
from google.cloud.bigquery_storage_v1.services.big_query_read.transports import BigQueryReadGrpcTransport
from google.oauth2.credentials import Credentials

client = bigquery.Client(
    project=%[1]s,
%[2]s    credentials=Credentials(token=%[3]s),
    client_options=ClientOptions(api_endpoint=%[4]s),
)
bqstorage_client = bigquery_storage.BigQueryReadClient(transport=BigQueryReadGrpcTransport(channel=grpc.secure_channel(
    %[5]s,
    grpc.composite_channel_credentials(grpc.local_channel_credentials(), grpc.access_token_call_credentials(%[3]s)),
    options=[("grpc.max_receive_message_length", -1)],
)))
df = client.query("SELECT 1").to_dataframe(bqstorage_client=bqstorage_client)`,
			jsonString(project), locationArg, jsonString(token), jsonString(endpoint), jsonString(fmt.Sprintf("%s:%d", driver.Host, target.Port)))
	default:
		return ""
	}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
