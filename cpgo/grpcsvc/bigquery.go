package grpcsvc

import (
	"maps"
	"net/url"
	"slices"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
)

const bigqueryJob = "job"

var bigqueryAPI = httpDbEngine{
	service: "bigquery", contextKind: bigqueryJob, operations: bigqueryOperations(),
	validCall: validBigQueryCall, submissionScope: bigquerySubmissionScope, bodiless: true,
}

// bigqueryRoute is one REST method: its HTTP method, its path under /bigquery/v2/, and the resource it names,
// read from the path or, for an insert, from the body's <kind>Reference.
type bigqueryRoute struct {
	method, pattern string
	category        callCategory
	kind            string
	inserts         bool
}

const (
	bqDataset = "projects/{p}/datasets/{d}"
	bqTable   = bqDataset + "/tables/{t}"
	bqRoutine = bqDataset + "/routines/{t}"
)

// bigqueryRoutes is every REST method the proxy forwards, by the name it sends; any other is denied.
var bigqueryRoutes = map[string]bigqueryRoute{
	"jobs.query":           {"POST", "projects/{p}/queries", sqlSubmission, "", false},
	"jobs.insert":          {"POST", "projects/{p}/jobs", sqlSubmission, "", false},
	"jobs.get":             {"GET", "projects/{p}/jobs/{j}", executionCall, bigqueryJob, false},
	"jobs.getQueryResults": {"GET", "projects/{p}/queries/{j}", executionCall, bigqueryJob, false},
	"jobs.cancel":          {"POST", "projects/{p}/jobs/{j}/cancel", executionCall, bigqueryJob, false},
	"jobs.list":            {"GET", "projects/{p}/jobs", historyCall, "", false},

	"projects.list":   {"GET", "projects", metadataCall, "", false},
	"datasets.list":   {"GET", "projects/{p}/datasets", metadataCall, "project", false},
	"datasets.get":    {"GET", bqDataset, metadataCall, "dataset", false},
	"tables.list":     {"GET", bqDataset + "/tables", metadataCall, "dataset", false},
	"tables.get":      {"GET", bqTable, metadataCall, "table", false},
	"routines.list":   {"GET", bqDataset + "/routines", metadataCall, "dataset", false},
	"routines.get":    {"GET", bqRoutine, metadataCall, "routine", false},
	"datasets.insert": {"POST", "projects/{p}/datasets", invokeCall, "dataset", true},
	"datasets.patch":  {"PATCH", bqDataset, invokeCall, "dataset", false},
	"datasets.update": {"PUT", bqDataset, invokeCall, "dataset", false},
	"datasets.delete": {"DELETE", bqDataset, invokeCall, "dataset", false},
	"tables.insert":   {"POST", bqDataset + "/tables", invokeCall, "table", true},
	"tables.patch":    {"PATCH", bqTable, invokeCall, "table", false},
	"tables.update":   {"PUT", bqTable, invokeCall, "table", false},
	"tables.delete":   {"DELETE", bqTable, invokeCall, "table", false},
	"routines.delete": {"DELETE", bqRoutine, invokeCall, "routine", false},
}

func bigqueryOperations() map[string]httpDbOperation {
	out := make(map[string]httpDbOperation, len(bigqueryRoutes))
	for name, route := range bigqueryRoutes {
		out[name] = httpDbOperation{route.category, func(d *pb.HttpDbRequest, b body) ([]nativeResource, error) {
			return route.resources(d, b)
		}}
	}
	return out
}

// validBigQueryCall checks that the path is the operation's route with a BigQuery target; jobs live only in
// the target project.
func validBigQueryCall(d *pb.HttpDbRequest) error {
	target := d.GetBigquery()
	if target == nil || blank(target.GetProject()) || blank(target.GetLocation()) {
		return errMalformed
	}
	route, ok := bigqueryRoutes[d.GetOperation()]
	if !ok {
		return denyError(nativeNotAuthorized)
	}
	vars, err := route.match(d)
	if err != nil {
		return err
	}
	if strings.HasPrefix(d.GetOperation(), "jobs.") && vars["p"] != target.GetProject() {
		return denyError(nativeScopeViolation)
	}
	return nil
}

// match reads the path variables; "/bigquery/v2/projects/p1/datasets/d1" is {p: p1, d: d1} for bqDataset.
func (r bigqueryRoute) match(d *pb.HttpDbRequest) (map[string]string, error) {
	rest, ok := strings.CutPrefix(d.GetPath(), "/bigquery/v2/")
	if !ok || d.GetMethod() != r.method {
		return nil, errMalformed
	}
	got, want := strings.Split(rest, "/"), strings.Split(r.pattern, "/")
	if len(got) != len(want) {
		return nil, errMalformed
	}
	vars := map[string]string{}
	for i, w := range want {
		if name, isVar := strings.CutPrefix(w, "{"); isVar {
			if blank(got[i]) || got[i] == "." || got[i] == ".." || strings.ContainsAny(got[i], `\`) {
				return nil, errMalformed
			}
			vars[strings.TrimSuffix(name, "}")] = got[i]
		} else if got[i] != w {
			return nil, errMalformed
		}
	}
	return vars, nil
}

// resources names what a route touches: a job is "<project>/<location>/<jobId>", the location from the
// request's location parameter or the target's, lowercased; a dataset is "<project>.<dataset>", and a table,
// routine or model "<project>.<dataset>.<id>".
func (r bigqueryRoute) resources(d *pb.HttpDbRequest, b body) ([]nativeResource, error) {
	vars, err := r.match(d)
	if err != nil {
		return nil, err
	}
	switch r.kind {
	case "":
		return nil, nil
	case bigqueryJob:
		id, err := bigqueryJobID(d, vars["p"], vars["j"])
		if err != nil {
			return nil, err
		}
		return []nativeResource{{kind: bigqueryJob, id: id}}, nil
	case "project":
		return []nativeResource{{kind: "project", id: vars["p"]}}, nil
	}
	if r.kind == "table" && slices.ContainsFunc(slices.Collect(maps.Keys(b)), definesSQLOrData) {
		return nil, denyError(nativeScopeViolation)
	}
	if r.inserts {
		ref, ok := b[r.kind+"Reference"].(map[string]any)
		if !ok {
			return nil, errMalformed
		}
		if p, ok := ref["projectId"]; ok && p != vars["p"] {
			return nil, errMalformed
		}
		if ds, ok := ref["datasetId"]; ok && r.kind != "dataset" && ds != vars["d"] {
			return nil, errMalformed
		}
		id, ok := ref[r.kind+"Id"].(string)
		if !ok || blank(id) {
			return nil, errMalformed
		}
		if r.kind == "dataset" {
			vars["d"] = id
		} else {
			vars["t"] = id
		}
	}
	id := vars["p"] + "." + vars["d"]
	if r.kind != "dataset" {
		id += "." + vars["t"]
	}
	return []nativeResource{{kind: r.kind, id: id}}, nil
}

// definesSQLOrData reports a Table field whose SQL or external data would be read without Decide; the API
// also accepts snake_case names.
func definesSQLOrData(field string) bool {
	switch strings.ToLower(strings.ReplaceAll(field, "_", "")) {
	case "view", "materializedview", "externaldataconfiguration", "tablereplicationinfo":
		return true
	}
	return false
}

func bigqueryJobID(d *pb.HttpDbRequest, project, job string) (string, error) {
	query, err := url.ParseQuery(d.GetRawQuery())
	if err != nil || len(query["location"]) > 1 {
		return "", errMalformed
	}
	location := d.GetBigquery().GetLocation()
	if l := query.Get("location"); l != "" {
		location = l
	}
	return project + "/" + strings.ToLower(location) + "/" + job, nil
}

var (
	queryRequestFields = []string{"kind", "query", "useLegacySql", "defaultDataset", "location", "queryParameters", "parameterMode",
		"requestId", "dryRun", "maxResults", "timeoutMs", "useQueryCache", "labels", "maximumBytesBilled", "formatOptions",
		"jobCreationMode", "jobTimeoutMs", "destinationEncryptionConfiguration", "preserveNulls"}
	jobFields              = []string{"kind", "jobReference", "configuration"}
	jobConfigurationFields = []string{"query", "labels", "dryRun", "jobTimeoutMs", "jobType"}
	queryConfigFields      = []string{"query", "useLegacySql", "defaultDataset", "queryParameters", "parameterMode", "priority",
		"useQueryCache", "maximumBytesBilled", "maximumBillingTier", "destinationEncryptionConfiguration", "preserveNulls", "continuous"}
)

// bigquerySubmissionScope admits a GoogleSQL query job in the target project and location. Anything that
// writes outside the result, reads outside SQL, or runs as legacy SQL is a scope violation, as is any field
// not known to leave the statement's meaning alone.
func bigquerySubmissionScope(d *pb.HttpDbRequest, b body) error {
	target := d.GetBigquery()
	query, location := map[string]any(b), b["location"]
	topFields, queryFields := queryRequestFields, queryRequestFields
	if d.GetOperation() == "jobs.insert" {
		topFields, queryFields, location = jobFields, queryConfigFields, nil
		if v, ok := b["jobReference"]; ok {
			ref, ok := v.(map[string]any)
			if !ok {
				return errMalformed
			}
			if p, ok := ref["projectId"]; ok && p != target.GetProject() {
				return denyError(nativeScopeViolation)
			}
			location = ref["location"]
		}
		config, ok := b["configuration"].(map[string]any)
		if !ok {
			return errMalformed
		}
		if err := onlyFields(config, jobConfigurationFields); err != nil {
			return err
		}
		if t, ok := config["jobType"]; ok && t != "QUERY" {
			return denyError(nativeScopeViolation)
		}
		if config["dryRun"] != nil && config["dryRun"] != false {
			return denyError(nativeScopeViolation)
		}
		if query, ok = config["query"].(map[string]any); !ok {
			return errMalformed
		}
	}
	if err := onlyFields(b, topFields); err != nil {
		return err
	}
	if err := onlyFields(query, queryFields); err != nil {
		return err
	}
	if q, ok := query["query"].(string); !ok || blank(q) {
		return errMalformed
	}
	if legacy, ok := query["useLegacySql"].(bool); !ok || legacy {
		return denyError(nativeScopeViolation)
	}
	if query["dryRun"] != nil && query["dryRun"] != false || query["continuous"] != nil && query["continuous"] != false {
		return denyError(nativeScopeViolation)
	}
	if location != nil {
		l, ok := location.(string)
		if !ok {
			return errMalformed
		}
		if !strings.EqualFold(l, target.GetLocation()) {
			return denyError(nativeScopeViolation)
		}
	}
	if v, ok := query["defaultDataset"]; ok {
		ref, ok := v.(map[string]any)
		if !ok || !isString(ref["datasetId"]) || (ref["projectId"] != nil && !isString(ref["projectId"])) {
			return errMalformed
		}
		if err := onlyFields(ref, []string{"projectId", "datasetId"}); err != nil {
			return err
		}
	}
	if v, ok := query["queryParameters"]; ok {
		list, isList := v.([]any)
		if !isList || slices.ContainsFunc(list, func(p any) bool { _, ok := p.(map[string]any); return !ok }) {
			return errMalformed
		}
	}
	return nil
}

func onlyFields(m map[string]any, allowed []string) error {
	for name := range m {
		if !slices.Contains(allowed, name) {
			return denyError(nativeScopeViolation)
		}
	}
	return nil
}
