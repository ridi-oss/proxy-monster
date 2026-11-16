package bigquery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

// fakeEditorUpstream answers the editor's jobs: jobs.query returns before the job completes, and the
// result arrives on two pages of one row each, or as a DML count. A set hold blocks requests of method holdOn.
type fakeEditorUpstream struct {
	mu        sync.Mutex
	submitted map[string]any
	pages     []string
	canceled  []string
	failure   string
	dml       bool
	holdOn    string
	reading   chan struct{}
	hold      chan struct{}
}

func (f *fakeEditorUpstream) handle(w http.ResponseWriter, r *http.Request) {
	if f.hold != nil && r.Method == f.holdOn {
		f.reading <- struct{}{}
		<-f.hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer upstream-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	row := func(email, n string) string { return `[{"f":[{"v":` + email + `},{"v":"` + n + `"}]}]` }
	switch path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/proj-a"); {
	case r.Method == http.MethodPost && path == "/queries":
		_ = json.NewDecoder(r.Body).Decode(&f.submitted)
		if f.failure != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"code":400,"message":"`+f.failure+`","status":"INVALID_ARGUMENT"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"jobComplete":false,"jobReference":`+reference("job_1")+`}`)
	case r.Method == http.MethodGet && path == "/queries/job_1":
		query := r.URL.Query()
		f.pages = append(f.pages, query.Get("pageToken")+"/"+query.Get("maxResults"))
		if query.Get("location") != "US" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.dml {
			_, _ = io.WriteString(w, `{"jobComplete":true,"jobReference":`+reference("job_1")+`,"numDmlAffectedRows":"3"}`)
			return
		}
		if query.Get("pageToken") == "" {
			_, _ = io.WriteString(w, `{"jobComplete":true,"jobReference":`+reference("job_1")+`,"schema":`+schemaJSON+`,"rows":`+row(`"a@example.test"`, "1")+`,"pageToken":"t2"}`)
			return
		}
		_, _ = io.WriteString(w, `{"jobComplete":true,"jobReference":`+reference("job_1")+`,"schema":`+schemaJSON+`,"rows":`+row(`"b@example.test"`, "2")+`}`)
	case r.Method == http.MethodPost && path == "/jobs/job_1/cancel":
		f.canceled = append(f.canceled, r.URL.Query().Get("location"))
		_, _ = io.WriteString(w, `{"job":{"jobReference":`+reference("job_1")+`}}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func openEditor(t *testing.T, verdict *pb.Verdict) (spi.Connection, *flowClient, *fakeEditorUpstream) {
	t.Helper()
	upstream := &fakeEditorUpstream{}
	connection, client := openEditorOn(t, testTarget(t, upstream.handle), verdict)
	return connection, client, upstream
}

func openEditorOn(t *testing.T, target *target, verdict *pb.Verdict) (spi.Connection, *flowClient) {
	t.Helper()
	client := &flowClient{principal: "alice", verdict: verdict, completed: make(chan struct{}, 8)}
	connection, err := target.OpenConnection(context.Background(), spi.NewAuthorizer(client, "login-alice", []byte("0123456789abcdef")), nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.OnOpen(context.Background(), []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "sales", Catalog: "proj-a"}}}}); err != nil {
		t.Fatal(err)
	}
	return connection, client
}

func TestConnectionSubmitsPagesAndMasks(t *testing.T) {
	connection, client, upstream := openEditor(t, maskVerdict())
	result, err := connection.ServeStatement("SELECT * FROM users WHERE n > 0", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied || result.Decision == nil || result.Decision.Action != "MASK" {
		t.Fatalf("decision: %+v", result)
	}
	if len(result.Columns) != 2 || result.Columns[0] != "email" || result.Columns[1] != "n" {
		t.Fatalf("columns = %v", result.Columns)
	}
	if len(result.Rows) != 2 || *result.Rows[0][0] != "####" || *result.Rows[0][1] != "1" || *result.Rows[1][0] != "####" || *result.Rows[1][1] != "2" {
		t.Fatalf("rows = %v", result.Rows)
	}
	submitted := upstream.submitted
	dataset, _ := json.Marshal(submitted["defaultDataset"])
	if submitted["query"] != *maskVerdict().RewrittenSql || submitted["useLegacySql"] != false || submitted["location"] != "US" ||
		submitted["jobCreationMode"] != "JOB_CREATION_REQUIRED" || submitted["maxResults"] != float64(101) || submitted["timeoutMs"] != float64(editorSubmitWait) || string(dataset) != `{"datasetId":"sales","projectId":"proj-a"}` {
		t.Fatalf("submission = %v", submitted)
	}
	if strings.Join(upstream.pages, ",") != "/101,t2/101" {
		t.Errorf("result pages read = %v", upstream.pages)
	}
	session := client.decisions[0].GetSession().GetBigquery()
	if len(client.decisions) != 1 || session.GetProject() != "proj-a" || session.GetHttpdb().GetMaxRows() != 100 || client.decisions[0].GetSearchPath()[0] != "sales" {
		t.Fatalf("decision request: %+v", client.decisions)
	}
}

func TestConnectionAppliesTheVerdictRowCap(t *testing.T) {
	verdict := maskVerdict()
	verdict.MaxRows = 1
	connection, _, upstream := openEditor(t, verdict)
	result, err := connection.ServeStatement("SELECT * FROM users", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || !result.TruncatedByCap {
		t.Fatalf("cap of 1 over a 2-row result: rows=%d truncatedByCap=%v", len(result.Rows), result.TruncatedByCap)
	}
	if upstream.submitted["maxResults"] != float64(2) || strings.Join(upstream.pages, ",") != "/2,t2/2" {
		t.Errorf("pages not bounded by the cap: %v %v", upstream.submitted["maxResults"], upstream.pages)
	}
}

func TestConnectionRedactsUpstreamFailure(t *testing.T) {
	connection, _, upstream := openEditor(t, maskVerdict())
	upstream.failure = "Invalid value a@example.test"
	_, err := connection.ServeStatement("SELECT * FROM users", 100)
	var failure relay.TargetDbError
	if !errors.As(err, &failure) || failure.Message != upstream.failure || failure.Redacted != relay.RedactedDiagnosticMessage {
		t.Fatalf("err = %#v", err)
	}
}

func TestConnectionCancelsTheRunningJob(t *testing.T) {
	connection, _, upstream := openEditor(t, maskVerdict())
	if err := connection.Cancel(); err != nil || len(upstream.canceled) != 0 {
		t.Fatalf("idle cancel: %v %v", err, upstream.canceled)
	}
	for stage, method := range map[string]string{"submitting": http.MethodPost, "reading results": http.MethodGet} {
		upstream.mu.Lock()
		upstream.canceled = nil
		upstream.mu.Unlock()
		upstream.holdOn, upstream.reading, upstream.hold = method, make(chan struct{}, 1), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := connection.ServeStatement("SELECT * FROM users", 100)
			done <- err
		}()
		<-upstream.reading
		if err := connection.Cancel(); err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			close(upstream.hold)
		}
		if err := <-done; !errors.Is(err, httpdb.ErrCanceled) {
			t.Fatalf("%s: statement err = %v", stage, err)
		}
		if method == http.MethodGet {
			close(upstream.hold)
		}
		upstream.mu.Lock()
		canceled := upstream.canceled
		upstream.mu.Unlock()
		if len(canceled) != 1 || canceled[0] != "US" {
			t.Fatalf("%s: jobs.cancel sent %v", stage, canceled)
		}
	}
}

// recordingInspector notes how many result reads preceded each after-statement refetch.
type recordingInspector struct {
	fakeInspector
	upstream *fakeEditorUpstream
	pagesAt  *[]int
}

func (r recordingInspector) InspectSchema(schema string, hash []byte) (*pb.SchemaFragmentPush, error) {
	r.upstream.mu.Lock()
	*r.pagesAt = append(*r.pagesAt, len(r.upstream.pages))
	r.upstream.mu.Unlock()
	return r.fakeInspector.InspectSchema(schema, hash)
}

func TestConnectionRunsAfterStatementAndReportsDML(t *testing.T) {
	verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW, RewrittenSql: proto.String("UPDATE `proj-a`.sales.users SET n = 1 WHERE TRUE"),
		AfterStatement: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "sales", Catalog: "proj-a"}}}}}
	upstream := &fakeEditorUpstream{dml: true}
	target := testTarget(t, upstream.handle)
	var pagesAt []int
	target.inspector = recordingInspector{upstream: upstream, pagesAt: &pagesAt}
	connection, _ := openEditorOn(t, target, verdict)
	result, err := connection.ServeStatement("UPDATE users SET n = 1 WHERE TRUE", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsAffected != 3 || len(result.Rows) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if len(pagesAt) != 2 || pagesAt[1] != 1 {
		t.Fatalf("after-statement refetch ran after %v result reads, want OnOpen then once after the completing read", pagesAt)
	}
}

func TestConnectionRejectsAForeignDefaultDataset(t *testing.T) {
	target := testTarget(t, (&fakeEditorUpstream{}).handle)
	client := &flowClient{principal: "alice", verdict: maskVerdict(), completed: make(chan struct{}, 8)}
	if _, err := target.OpenConnection(context.Background(), spi.NewAuthorizer(client, "login-alice", []byte("0123456789abcdef")), nil, 0, "hr"); err == nil {
		t.Fatal("OpenConnection opened in a dataset other than the configured one")
	}
	opened, err := target.OpenConnection(context.Background(), spi.NewAuthorizer(client, "login-alice", []byte("0123456789abcdef")), nil, 0, "sales")
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
}
