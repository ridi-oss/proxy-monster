package grpcsvc

import (
	"slices"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
)

const queryExecution = "query-execution"

var athenaAPI = httpDbEngine{
	service: "athena", contextKind: queryExecution, operations: athenaOperations,
	validCall: validAthenaCall, submissionScope: validateSubmissionScope,
}

// validAthenaCall is the JSON 1.1 protocol: every call is a POST to "/" with an Athena target.
func validAthenaCall(d *pb.HttpDbRequest) error {
	if d.GetMethod() != "POST" || d.GetPath() != "/" || d.GetRawQuery() != "" || d.GetAthena() == nil {
		return errMalformed
	}
	return nil
}

// athenaName is a literal Athena name (an API field, not SQL text) in the analyzer's canonical spelling.
func athenaName(raw string) (name string, err error) {
	defer func() {
		if recover() != nil {
			name, err = "", errMalformed
		}
	}()
	s, err := engines.Athena.NewSession(nil)
	if err != nil {
		return "", errMalformed
	}
	return s.CatalogColumnNames([]*analyzerpb.Column{{Catalog: raw}})[0].Catalog().String(), nil
}

func validateSubmissionScope(d *pb.HttpDbRequest, b body) error {
	target := d.GetAthena()
	if q, ok := b["QueryString"]; !ok || !isString(q) {
		return errMalformed
	}
	if params, ok := b["ExecutionParameters"]; ok {
		list, isList := params.([]any)
		if !isList || slices.ContainsFunc(list, func(p any) bool { return !isString(p) }) {
			return errMalformed
		}
	}
	if v, ok := b["WorkGroup"]; ok && !isString(v) {
		return errMalformed
	}
	var execCtx map[string]any
	if v, ok := b["QueryExecutionContext"]; ok {
		if execCtx, ok = v.(map[string]any); !ok {
			return errMalformed
		}
	}
	var result map[string]any
	if v, ok := b["ResultConfiguration"]; ok {
		if result, ok = v.(map[string]any); !ok {
			return errMalformed
		}
	}
	exact := func(s string) (string, error) { return s, nil }
	inScope := func(m map[string]any, field, configured string, canonical func(string) (string, error)) (bool, error) {
		v, ok := m[field]
		if !ok {
			return true, nil
		}
		s, isText := v.(string)
		if !isText {
			return false, errMalformed
		}
		if blank(configured) {
			return false, nil
		}
		requested, err := canonical(s)
		if err != nil {
			return false, err
		}
		want, err := canonical(configured)
		return requested == want, err
	}
	// Workgroup names are not identifiers; catalog and database names compare in their canonical spelling.
	for _, check := range []struct {
		m                 map[string]any
		field, configured string
		canonical         func(string) (string, error)
	}{
		{b, "WorkGroup", target.GetDefaultWorkgroup(), exact},
		{execCtx, "Catalog", target.GetDefaultCatalog(), athenaName},
		{execCtx, "Database", target.GetDefaultDatabase(), athenaName},
	} {
		ok, err := inScope(check.m, check.field, check.configured, check.canonical)
		if err != nil {
			return err
		}
		if !ok {
			return denyError(nativeScopeViolation)
		}
	}
	// A client-chosen output location is an S3 write through the proxy's role, outside the configured scope.
	if _, ok := result["OutputLocation"]; ok {
		return denyError(nativeScopeViolation)
	}
	// Result reuse returns an earlier execution's rows under a new id; today's plan cannot vouch for them.
	if _, ok := b["ResultReuseConfiguration"]; ok {
		return denyError(nativeScopeViolation)
	}
	return nil
}

// catalogPath is joined with each part an Athena name in its canonical spelling.
func catalogPath(names ...string) func(body) (string, error) { return path(athenaName, names) }

func workgroupOrPrimary(b body) (string, error) { return b.optStr("WorkGroup", "primary") }

// athenaOperations is every Athena API operation by its X-Amz-Target suffix; an operation absent here is denied.
// A list without a named scope authorizes the datasource itself; its response releases only observed resources.
var athenaOperations = map[string]httpDbOperation{
	"StartQueryExecution": {sqlSubmission, none},

	"GetQueryExecution":         {executionCall, one(queryExecution, field("QueryExecutionId"))},
	"BatchGetQueryExecution":    {executionCall, many(queryExecution, func(b body) ([]string, error) { return b.strs("QueryExecutionIds") })},
	"GetQueryResults":           {executionCall, one(queryExecution, field("QueryExecutionId"))},
	"GetQueryResultsStream":     {executionCall, one(queryExecution, field("QueryExecutionId"))},
	"StopQueryExecution":        {executionCall, one(queryExecution, field("QueryExecutionId"))},
	"GetQueryRuntimeStatistics": {executionCall, one(queryExecution, field("QueryExecutionId"))},
	"ListQueryExecutions":       {historyCall, none},

	"ListDataCatalogs":                   {metadataCall, none},
	"GetDataCatalog":                     {metadataCall, one("data-catalog", catalogPath("Name"))},
	"ListDatabases":                      {metadataCall, one("data-catalog", catalogPath("CatalogName"))},
	"GetDatabase":                        {metadataCall, one("database", catalogPath("CatalogName", "DatabaseName"))},
	"ListTableMetadata":                  {metadataCall, one("database", catalogPath("CatalogName", "DatabaseName"))},
	"GetTableMetadata":                   {metadataCall, one("table", catalogPath("CatalogName", "DatabaseName", "TableName"))},
	"ListWorkGroups":                     {metadataCall, none},
	"GetWorkGroup":                       {metadataCall, one("workgroup", field("WorkGroup"))},
	"GetPreparedStatement":               {metadataCall, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"BatchGetPreparedStatement":          {metadataCall, many("prepared-statement", preparedStatementNames)},
	"ListPreparedStatements":             {metadataCall, one("workgroup", field("WorkGroup"))},
	"GetNamedQuery":                      {metadataCall, one("named-query", field("NamedQueryId"))},
	"BatchGetNamedQuery":                 {metadataCall, many("named-query", func(b body) ([]string, error) { return b.strs("NamedQueryIds") })},
	"ListNamedQueries":                   {metadataCall, one("workgroup", workgroupOrPrimary)},
	"ListEngineVersions":                 {metadataCall, none},
	"ListApplicationDPUSizes":            {metadataCall, none},
	"GetCapacityReservation":             {metadataCall, one("capacity-reservation", field("Name"))},
	"ListCapacityReservations":           {metadataCall, none},
	"GetCapacityAssignmentConfiguration": {metadataCall, one("capacity-reservation", field("CapacityReservationName"))},
	"ListTagsForResource":                {metadataCall, one("tagged-resource", field("ResourceARN"))},
	"GetResourceDashboard":               {metadataCall, one("tagged-resource", field("ResourceARN"))},

	"CreatePreparedStatement":            {invokeCall, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"UpdatePreparedStatement":            {invokeCall, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"DeletePreparedStatement":            {invokeCall, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"CreateNamedQuery":                   {invokeCall, one("workgroup", workgroupOrPrimary)},
	"UpdateNamedQuery":                   {invokeCall, one("named-query", field("NamedQueryId"))},
	"DeleteNamedQuery":                   {invokeCall, one("named-query", field("NamedQueryId"))},
	"CreateWorkGroup":                    {invokeCall, one("workgroup", field("Name"))},
	"UpdateWorkGroup":                    {invokeCall, one("workgroup", field("WorkGroup"))},
	"DeleteWorkGroup":                    {invokeCall, one("workgroup", field("WorkGroup"))},
	"CreateDataCatalog":                  {invokeCall, one("data-catalog", catalogPath("Name"))},
	"UpdateDataCatalog":                  {invokeCall, one("data-catalog", catalogPath("Name"))},
	"DeleteDataCatalog":                  {invokeCall, one("data-catalog", catalogPath("Name"))},
	"CreateCapacityReservation":          {invokeCall, one("capacity-reservation", field("Name"))},
	"UpdateCapacityReservation":          {invokeCall, one("capacity-reservation", field("Name"))},
	"CancelCapacityReservation":          {invokeCall, one("capacity-reservation", field("Name"))},
	"DeleteCapacityReservation":          {invokeCall, one("capacity-reservation", field("Name"))},
	"PutCapacityAssignmentConfiguration": {invokeCall, one("capacity-reservation", field("CapacityReservationName"))},
	"TagResource":                        {invokeCall, one("tagged-resource", field("ResourceARN"))},
	"UntagResource":                      {invokeCall, one("tagged-resource", field("ResourceARN"))},
}

// preparedStatementNames is BatchGetPreparedStatement's "<workgroup>/<name>" ids; Kotlin reads the names first.
func preparedStatementNames(b body) ([]string, error) {
	names, err := b.strs("PreparedStatementNames")
	if err != nil {
		return nil, err
	}
	wg, err := b.str("WorkGroup")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, wg+"/"+n)
	}
	return out, nil
}
