package grpcsvc

import (
	"slices"
	"testing"
	"time"

	apb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"

	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
)

func bq(op, method, path, body string, phase apb.HttpDbAuthorizationPhase, mods ...func(*pb.HttpDbRequest)) *pb.HttpDbRequest {
	d := &pb.HttpDbRequest{
		Service: "bigquery", Operation: op, Method: method, Path: "/bigquery/v2/" + path, Body: []byte(body), Phase: phase,
		TargetBinding: binding, Target: &pb.HttpDbRequest_Bigquery{Bigquery: &apb.BigQueryTarget{
			Project: "proj-a", Location: "US", DefaultDataset: "sales", Endpoint: "https://bigquery.googleapis.com",
		}},
	}
	for _, m := range mods {
		m(d)
	}
	return d
}

func query(raw string) func(*pb.HttpDbRequest) { return func(d *pb.HttpDbRequest) { d.RawQuery = raw } }

// newWarehouse is a BigQuery datasource "wh" on project proj-a tagged production, alice holding reader.
func newWarehouse(t *testing.T) *lake {
	f := newFixture(t)
	f.datasource("wh", "bigquery", "proj-a", "production")
	f.grant("alice", "reader")
	return &lake{fixture: f, alice: f.token("USER", "alice"), carol: f.token("USER", "carol"), now: time.Now()}
}

func (l *lake) runWarehouse(cases []athenaCase) {
	l.t.Helper()
	for _, tc := range cases {
		l.policies(tc.policies...)
		if got := l.rpc(tc.d, l.alice, "wh", ""); !got.equal(tc.want) {
			l.t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestBigQueryRejectsMalformedDescriptors(t *testing.T) {
	l := newWarehouse(t)
	gate := []string{connectAll, invokeAll}
	get := func(op, path string, mods ...func(*pb.HttpDbRequest)) *pb.HttpDbRequest {
		return bq(op, "GET", path, "", requestPhase, mods...)
	}
	l.runWarehouse([]athenaCase{
		{"projects.list", gate, get("projects.list", "projects"), act(forward)},
		{"unknown operation", gate, get("tabledata.list", "projects/proj-a/datasets/sales/tables/users/data"), deny(nativeNotAuthorized)},
		{"routine definition", gate, bq("routines.insert", "POST", "projects/proj-a/datasets/sales/routines", `{}`, requestPhase), deny(nativeNotAuthorized)},
		{"model", gate, get("models.get", "projects/proj-a/datasets/sales/models/m"), deny(nativeNotAuthorized)},
		{"wrong service", gate, get("projects.list", "projects", func(d *pb.HttpDbRequest) { d.Service = "athena" }), deny(nativeNotAuthorized)},
		{"wrong method", gate, bq("datasets.get", "DELETE", "projects/proj-a/datasets/sales", "", requestPhase), deny(nativeInvalidDescriptor)},
		{"path of another operation", gate, get("datasets.get", "projects/proj-a/datasets/sales/tables"), deny(nativeInvalidDescriptor)},
		{"no API prefix", gate, get("projects.list", "projects", func(d *pb.HttpDbRequest) { d.Path = "/upload/bigquery/v2/projects" }), deny(nativeInvalidDescriptor)},
		{"empty segment", gate, get("datasets.get", "projects//datasets/sales"), deny(nativeInvalidDescriptor)},
		{"dot segment", gate, get("datasets.get", "projects/proj-a/datasets/.."), deny(nativeInvalidDescriptor)},
		{"no target", gate, get("projects.list", "projects", func(d *pb.HttpDbRequest) { d.Target = nil }), deny(nativeInvalidDescriptor)},
		{"athena target", gate, get("projects.list", "projects", func(d *pb.HttpDbRequest) {
			d.Target = &pb.HttpDbRequest_Athena{Athena: &apb.AthenaTarget{Region: "us-east-1"}}
		}), deny(nativeInvalidDescriptor)},
		{"two locations", gate, get("jobs.get", "projects/proj-a/jobs/j1", query("location=US&location=EU")), deny(nativeInvalidDescriptor)},
		{"non-object body", gate, bq("datasets.patch", "PATCH", "projects/proj-a/datasets/sales", "[]", requestPhase), deny(nativeInvalidDescriptor)},
	})
}

func TestBigQuerySubmissionScope(t *testing.T) {
	l := newWarehouse(t)
	gate := []string{connectAll}
	q := func(body string, mods ...func(*pb.HttpDbRequest)) *pb.HttpDbRequest {
		return bq("jobs.query", "POST", "projects/proj-a/queries", body, requestPhase, mods...)
	}
	ins := func(config string) *pb.HttpDbRequest {
		return bq("jobs.insert", "POST", "projects/proj-a/jobs", `{"jobReference":{"projectId":"proj-a","jobId":"j1","location":"US"},"configuration":`+config+`}`, requestPhase)
	}
	l.runWarehouse([]athenaCase{
		{"query", gate, q(`{"query":"select 1","useLegacySql":false,"defaultDataset":{"projectId":"proj-b","datasetId":"d"},"queryParameters":[{"parameterType":{"type":"INT64"},"parameterValue":{"value":"1"}}],"requestId":"r"}`), act(sqlAdmission)},
		{"response phase", gate, q(`{"query":"select 1","useLegacySql":false}`, func(d *pb.HttpDbRequest) { d.Phase = responsePhase }), deny(nativeNotAuthorized)},
		{"location in another case", gate, q(`{"query":"select 1","useLegacySql":false,"location":"us"}`), act(sqlAdmission)},
		{"no connect", nil, q(`{"query":"select 1","useLegacySql":false}`), deny(nativeNotAuthorized)},
		{"legacy SQL by default", gate, q(`{"query":"select 1"}`), deny(nativeScopeViolation)},
		{"legacy SQL", gate, q(`{"query":"select 1","useLegacySql":true}`), deny(nativeScopeViolation)},
		{"other project", gate, bq("jobs.query", "POST", "projects/proj-b/queries", `{"query":"select 1","useLegacySql":false}`, requestPhase), deny(nativeScopeViolation)},
		{"other location", gate, q(`{"query":"select 1","useLegacySql":false,"location":"EU"}`), deny(nativeScopeViolation)},
		{"session", gate, q(`{"query":"select 1","useLegacySql":false,"createSession":true}`), deny(nativeScopeViolation)},
		{"connection properties", gate, q(`{"query":"select 1","useLegacySql":false,"connectionProperties":[{"key":"session_id","value":"s"}]}`), deny(nativeScopeViolation)},
		{"continuous", gate, q(`{"query":"select 1","useLegacySql":false,"continuous":true}`), deny(nativeScopeViolation)},
		{"dry run", gate, q(`{"query":"select 1","useLegacySql":false,"dryRun":true}`), deny(nativeScopeViolation)},
		{"unknown field", gate, q(`{"query":"select 1","useLegacySql":false,"future":1}`), deny(nativeScopeViolation)},
		{"no query", gate, q(`{"useLegacySql":false}`), deny(nativeInvalidDescriptor)},
		{"non-object parameter", gate, q(`{"query":"select 1","useLegacySql":false,"queryParameters":[1]}`), deny(nativeInvalidDescriptor)},
		{"default dataset key in another case", gate, q(`{"query":"select 1","useLegacySql":false,"defaultDataset":{"datasetId":"safe","DATASETID":"other"}}`), deny(nativeScopeViolation)},
		{"non-string location", gate, q(`{"query":"select 1","useLegacySql":false,"location":1}`), deny(nativeInvalidDescriptor)},

		{"query job", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"priority":"BATCH"},"labels":{"a":"b"}}`), act(sqlAdmission)},
		{"job legacy SQL", gate, ins(`{"query":{"query":"select 1"}}`), deny(nativeScopeViolation)},
		{"destination table", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"destinationTable":{"projectId":"x","datasetId":"y","tableId":"z"}}}`), deny(nativeScopeViolation)},
		{"table definitions", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"tableDefinitions":{}}}`), deny(nativeScopeViolation)},
		{"UDF resources", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"userDefinedFunctionResources":[]}}`), deny(nativeScopeViolation)},
		{"script options", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"scriptOptions":{"keyResultStatement":"FIRST_SELECT"}}}`), deny(nativeScopeViolation)},
		{"job session", gate, ins(`{"query":{"query":"select 1","useLegacySql":false,"createSession":true}}`), deny(nativeScopeViolation)},
		{"load job", gate, ins(`{"load":{"sourceUris":["gs://b/o"]}}`), deny(nativeScopeViolation)},
		{"extract job", gate, ins(`{"extract":{"destinationUris":["gs://b/o"]},"query":{"query":"select 1","useLegacySql":false}}`), deny(nativeScopeViolation)},
		{"copy job type", gate, ins(`{"jobType":"COPY","query":{"query":"select 1","useLegacySql":false}}`), deny(nativeScopeViolation)},
		{"job dry run", gate, ins(`{"dryRun":true,"query":{"query":"select 1","useLegacySql":false}}`), deny(nativeScopeViolation)},
		{"job in another project", gate, bq("jobs.insert", "POST", "projects/proj-a/jobs", `{"jobReference":{"projectId":"proj-b"},"configuration":{"query":{"query":"select 1","useLegacySql":false}}}`, requestPhase), deny(nativeScopeViolation)},
		{"job in another location", gate, bq("jobs.insert", "POST", "projects/proj-a/jobs", `{"jobReference":{"location":"EU"},"configuration":{"query":{"query":"select 1","useLegacySql":false}}}`, requestPhase), deny(nativeScopeViolation)},
		{"no configuration", gate, bq("jobs.insert", "POST", "projects/proj-a/jobs", `{}`, requestPhase), deny(nativeInvalidDescriptor)},
	})
}

func TestBigQueryMetadataNeedsInvokeOnNamedResource(t *testing.T) {
	l := newWarehouse(t)
	scoped := []string{connectAll, `permit(principal, action == Action::"native.invoke", resource)
		when { resource.kind == "table" && resource.id == "proj-a.sales.users" && context has native_operation && context.native_operation == "bigquery:tables.get" };`}
	l.runWarehouse([]athenaCase{
		{"named table", scoped, bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/users", "", requestPhase), act(forward)},
		{"named table response", scoped, bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/users", "", responsePhase), act(release)},
		{"table in another case", scoped, bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/Users", "", requestPhase), deny(nativeNotAuthorized)},
		{"other table", scoped, bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/salaries", "", requestPhase), deny(nativeNotAuthorized)},
		{"connect only", []string{connectAll}, bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/users", "", requestPhase), deny(nativeNotAuthorized)},
	})
}

// The engine reads which resources a call touches; Cedar alone decides them.
func TestBigQueryAccessNamesTheResources(t *testing.T) {
	ds := reqDS("wh", "bigquery", "proj-a")
	read := func(d *pb.HttpDbRequest) access { return bigqueryAPI.access(athenaOp(d), ds, "alice", time.Now()) }
	for _, tc := range []struct {
		name string
		d    *pb.HttpDbRequest
		want []nativeResource
	}{
		{"projects", bq("projects.list", "GET", "projects", "", requestPhase), []nativeResource{{kind: "datasource", id: "wh"}}},
		{"datasets of a project", bq("datasets.list", "GET", "projects/proj-b/datasets", "", requestPhase), []nativeResource{{kind: "project", id: "proj-b"}}},
		{"dataset", bq("datasets.get", "GET", "projects/proj-a/datasets/sales", "", requestPhase), []nativeResource{{kind: "dataset", id: "proj-a.sales"}}},
		{"routine", bq("routines.delete", "DELETE", "projects/proj-a/datasets/sales/routines/f", "", requestPhase), []nativeResource{{kind: "routine", id: "proj-a.sales.f"}}},
		{"created dataset", bq("datasets.insert", "POST", "projects/proj-a/datasets", `{"datasetReference":{"projectId":"proj-a","datasetId":"new"}}`, requestPhase), []nativeResource{{kind: "dataset", id: "proj-a.new"}}},
		{"created table", bq("tables.insert", "POST", "projects/proj-a/datasets/sales/tables", `{"tableReference":{"projectId":"proj-a","datasetId":"sales","tableId":"t2"}}`, requestPhase), []nativeResource{{kind: "table", id: "proj-a.sales.t2"}}},
		{"patched table", bq("tables.patch", "PATCH", "projects/proj-a/datasets/sales/tables/t2", `{"description":"d"}`, requestPhase), []nativeResource{{kind: "table", id: "proj-a.sales.t2"}}},
	} {
		a := read(tc.d)
		if a.deny != "" || !a.native || !slices.EqualFunc(a.resources, tc.want, func(x, y nativeResource) bool { return x.kind == y.kind && x.id == y.id }) {
			t.Errorf("%s: %+v, want %+v", tc.name, a, tc.want)
		}
	}
	if a := read(bq("tables.get", "GET", "projects/proj-a/datasets/sales/tables/users", "", requestPhase)); a.operation != "bigquery:tables.get" {
		t.Errorf("operation %q", a.operation)
	}
	for name, d := range map[string]*pb.HttpDbRequest{
		"insert into another dataset": bq("tables.insert", "POST", "projects/proj-a/datasets/sales/tables", `{"tableReference":{"datasetId":"other","tableId":"t2"}}`, requestPhase),
		"insert into another project": bq("datasets.insert", "POST", "projects/proj-a/datasets", `{"datasetReference":{"projectId":"proj-b","datasetId":"new"}}`, requestPhase),
		"insert without an id":        bq("datasets.insert", "POST", "projects/proj-a/datasets", `{"datasetReference":{}}`, requestPhase),
	} {
		if a := read(d); a.deny != nativeInvalidDescriptor {
			t.Errorf("%s: %+v", name, a)
		}
	}
	for name, d := range map[string]*pb.HttpDbRequest{
		"view":                  bq("tables.insert", "POST", "projects/proj-a/datasets/sales/tables", `{"tableReference":{"tableId":"t2"},"view":{"query":"SELECT email FROM users"}}`, requestPhase),
		"materialized view":     bq("tables.patch", "PATCH", "projects/proj-a/datasets/sales/tables/t2", `{"materializedView":{"query":"SELECT 1"}}`, requestPhase),
		"snake_case view":       bq("tables.update", "PUT", "projects/proj-a/datasets/sales/tables/t2", `{"materialized_view":{"query":"SELECT 1"}}`, requestPhase),
		"external data":         bq("tables.insert", "POST", "projects/proj-a/datasets/sales/tables", `{"tableReference":{"tableId":"t2"},"externalDataConfiguration":{}}`, requestPhase),
		"replication of a view": bq("tables.patch", "PATCH", "projects/proj-a/datasets/sales/tables/t2", `{"tableReplicationInfo":{}}`, requestPhase),
	} {
		if a := read(d); a.deny != nativeScopeViolation {
			t.Errorf("%s: %+v", name, a)
		}
	}
}

func TestBigQueryJobNeedsOwnedContextInTheTargetProject(t *testing.T) {
	l := newWarehouse(t)
	gate := []string{connectAll}
	mine := l.ctx("proj-a/us/j1")
	job := func(op, method, path string, phase apb.HttpDbAuthorizationPhase, mods ...func(*pb.HttpDbRequest)) *pb.HttpDbRequest {
		return bq(op, method, path, "", phase, append(mods, cached(mine))...)
	}
	l.runWarehouse([]athenaCase{
		{"results", gate, job("jobs.getQueryResults", "GET", "projects/proj-a/queries/j1", responsePhase), act(applyContext, "proj-a/us/j1")},
		{"results at the named location", gate, job("jobs.getQueryResults", "GET", "projects/proj-a/queries/j1", responsePhase, query("location=US&maxResults=10")), act(applyContext, "proj-a/us/j1")},
		{"results at another location", gate, job("jobs.getQueryResults", "GET", "projects/proj-a/queries/j1", requestPhase, query("location=EU")), deny(nativeContextUnavailable)},
		{"status", gate, job("jobs.get", "GET", "projects/proj-a/jobs/j1", requestPhase), act(forward)},
		{"cancel", gate, job("jobs.cancel", "POST", "projects/proj-a/jobs/j1/cancel", requestPhase), act(forward)},
		{"delete", gate, job("jobs.delete", "DELETE", "projects/proj-a/jobs/j1/delete", requestPhase), deny(nativeNotAuthorized)},
		{"other job", gate, job("jobs.get", "GET", "projects/proj-a/jobs/j2", requestPhase), deny(nativeContextUnavailable)},
		{"other project", gate, job("jobs.get", "GET", "projects/proj-b/jobs/j1", requestPhase), deny(nativeScopeViolation)},
		{"other owner", gate, bq("jobs.get", "GET", "projects/proj-a/jobs/j1", "", requestPhase, cached(cachedContext("proj-a/us/j1", "bob", l.now.Add(time.Hour)))), deny(nativeContextUnavailable)},
		{"stray observation", gate, job("jobs.get", "GET", "projects/proj-a/jobs/j1", responsePhase, observe(observation(bigqueryJob, "proj-a/us/j2"))), deny(nativeContextUnavailable)},
	})
}

func TestBigQueryHistoryKeepsOnlyOwnedJobs(t *testing.T) {
	l := newWarehouse(t)
	gate := []string{connectAll}
	list := func(phase apb.HttpDbAuthorizationPhase, mods ...func(*pb.HttpDbRequest)) *pb.HttpDbRequest {
		return bq("jobs.list", "GET", "projects/proj-a/jobs", "", phase, mods...)
	}
	l.runWarehouse([]athenaCase{
		{"request", gate, list(requestPhase), act(forward)},
		{"mixed owners", gate, list(responsePhase, cached(l.ctx("proj-a/us/j1"), cachedContext("proj-a/us/j3", "bob", l.now.Add(time.Hour))),
			observe(observation(bigqueryJob, "proj-a/us/j1"), observation(bigqueryJob, "proj-a/us/j3"))), act(applyContext, "proj-a/us/j1")},
		{"another project", gate, bq("jobs.list", "GET", "projects/proj-b/jobs", "", requestPhase), deny(nativeScopeViolation)},
	})
}
