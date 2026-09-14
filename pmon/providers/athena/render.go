package athena

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func (Provider) Render(format driver.Format, target driver.Target, _ driver.Options) string {
	endpoint := fmt.Sprintf("http://%s:%d", driver.Host, target.Port)
	if format == driver.URL {
		return endpoint
	}
	if target.ConnectionInfo == nil {
		return ""
	}
	region := target.ConnectionInfo.Properties["region"]
	if !regionPattern.MatchString(region) || target.User == "" || target.Name == "" || target.Password == "" {
		return ""
	}
	workgroup := target.ConnectionInfo.Properties["workgroup"]
	if workgroup == "" {
		workgroup = "primary"
	}
	catalog := target.ConnectionInfo.Properties["catalog"]
	if catalog == "" {
		catalog = "AwsDataCatalog"
	}
	database := target.ConnectionInfo.Properties["database"]
	if database == "" {
		database = target.DbName
	}
	if database == "" {
		database = "default"
	}
	credentials := localCredentials(target.User, target.Name, target.Password)
	context, _ := json.Marshal(map[string]string{"Catalog": catalog, "Database": database})
	quote := driver.ShellQuote
	switch format {
	case driver.CLI:
		return fmt.Sprintf("AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN='' AWS_SECURITY_TOKEN='' AWS_DEFAULT_REGION=%s AWS_ENDPOINT_URL_ATHENA=%s aws athena start-query-execution --endpoint-url %s --region %s --work-group %s --query-execution-context %s --query-string 'SELECT 1'",
			quote(credentials.AccessKeyID), quote(credentials.SecretAccessKey), quote(region), quote(endpoint),
			quote(endpoint), quote(region), quote(workgroup), quote(string(context)))
	case driver.JDBC:
		for _, value := range []string{region, workgroup, catalog, database} {
			if strings.ContainsAny(value, ";\r\n\x00") {
				return ""
			}
		}
		// ResultFetcher=GetQueryResults keeps result reads on the proxied API; the driver's default S3 fetcher
		// would dial S3 directly, where the local credentials are not valid.
		return fmt.Sprintf("jdbc:athena://Region=%s;AthenaEndpoint=%s;Workgroup=%s;Catalog=%s;Database=%s;CredentialsProvider=Static;User=%s;Password=%s;ResultFetcher=GetQueryResults;",
			region, endpoint, workgroup, catalog, database, credentials.AccessKeyID, credentials.SecretAccessKey)
	case "python":
		return fmt.Sprintf("import boto3\n\nathena = boto3.client(\n    \"athena\",\n    endpoint_url=%s,\n    region_name=%s,\n    aws_access_key_id=%s,\n    aws_secret_access_key=%s,\n)\nresult = athena.start_query_execution(\n    QueryString=\"SELECT 1\",\n    WorkGroup=%s,\n    QueryExecutionContext=%s,\n)",
			jsonString(endpoint), jsonString(region), jsonString(credentials.AccessKeyID), jsonString(credentials.SecretAccessKey), jsonString(workgroup), context)
	case "node":
		return fmt.Sprintf("import { AthenaClient, StartQueryExecutionCommand } from \"@aws-sdk/client-athena\";\n\nconst athena = new AthenaClient({\n  endpoint: %s,\n  region: %s,\n  credentials: { accessKeyId: %s, secretAccessKey: %s },\n});\nconst result = await athena.send(new StartQueryExecutionCommand({\n  QueryString: \"SELECT 1\",\n  WorkGroup: %s,\n  QueryExecutionContext: %s,\n}));",
			jsonString(endpoint), jsonString(region), jsonString(credentials.AccessKeyID), jsonString(credentials.SecretAccessKey), jsonString(workgroup), context)
	case "aws-config":
		return fmt.Sprintf("[profile pmon-%s]\nregion = %s\nendpoint_url = %s\naws_access_key_id = %s\naws_secret_access_key = %s\n",
			strings.ToLower(credentials.AccessKeyID), region, endpoint, credentials.AccessKeyID, credentials.SecretAccessKey)
	default:
		return ""
	}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
