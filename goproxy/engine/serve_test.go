package engine

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func serveInput() AuthzInput {
	return AuthzInput{SQL: "SELECT 1", ProbeNamespace: func() (NamespaceProbe, error) { return NamespaceProbe{Namespace: []string{"app"}}, nil }}
}

func TestServeStatementFailHasNoDecision(t *testing.T) {
	qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: DecisionOutcome{Err: "unreachable"}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *Decision) (bool, error) {
		t.Fatal("run called for Fail")
		return false, nil
	})
	var fail FailError
	if !errors.As(err, &fail) || fail.Message != "unreachable" || dec != nil || denied {
		t.Fatalf("ServeStatement = (%v, %v, %v), want nil, false, FailError", dec, denied, err)
	}
}

func TestServeStatementDenySkipsRun(t *testing.T) {
	want := &Decision{Action: "DENY", DenyReason: "policy"}
	qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: DecisionOutcome{Decision: want}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *Decision) (bool, error) {
		t.Fatal("run called for Deny")
		return false, nil
	})
	if err != nil || !denied || dec != want {
		t.Fatalf("ServeStatement = (%v, %v, %v), want decision, true, nil", dec, denied, err)
	}
}

func TestServeStatementRunErrorRetainsDecision(t *testing.T) {
	want := &Decision{Action: "ALLOW"}
	runErr := errors.New("target DB failed")
	qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: DecisionOutcome{Decision: want}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *Decision) (bool, error) {
		return false, runErr
	})
	if dec != want || denied || !errors.Is(err, runErr) {
		t.Fatalf("ServeStatement = (%v, %v, %v), want retained decision and run error", dec, denied, err)
	}
}

func TestServeStatementRefetchesOnlyAfterCleanCompletion(t *testing.T) {
	str := func(value string) *string { return &value }
	newRef := func(calls *int) *Refetcher {
		return &Refetcher{
			Db: mysqlDb,
			Probe: func(sql string, expected int) ([][]*string, error) {
				*calls++
				if expected == 6 {
					return [][]*string{{str("app"), str("t"), str("id"), str("int"), str("1"), str("NO")}}, nil
				}
				return [][]*string{{str("hash")}}, nil
			},
			Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 1, nil },
		}
	}
	for _, tc := range []struct {
		name  string
		clean bool
		want  int
	}{{"clean", true, 3}, {"target-DB error response", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			decision := &Decision{Action: "ALLOW", AfterStatement: []*pb.Refetch{{Schema: "app"}}}
			qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: DecisionOutcome{Decision: decision}})
			_, _, err := ServeStatement(qe, serveInput(), newRef(&calls), nil, func(string, []*pb.ColumnMask, *Decision) (bool, error) {
				return tc.clean, nil
			})
			if err != nil || calls != tc.want {
				t.Fatalf("ServeStatement err=%v probe calls=%d, want %d", err, calls, tc.want)
			}
		})
	}
}

func TestServeStatementGuardWrapsOnlyRun(t *testing.T) {
	var events []string
	in := serveInput()
	in.ProbeNamespace = func() (NamespaceProbe, error) {
		events = append(events, "authorize")
		return NamespaceProbe{Namespace: []string{"app"}}, nil
	}
	qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: okOutcome("ALLOW", nil)})
	guard := func(exec func() error) error {
		events = append(events, "guard-enter")
		err := exec()
		events = append(events, "guard-exit")
		return err
	}
	_, _, err := ServeStatement(qe, in, nil, guard, func(string, []*pb.ColumnMask, *Decision) (bool, error) {
		events = append(events, "run")
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"authorize", "guard-enter", "run", "guard-exit"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestDecisionPageRowsAndCapBinds(t *testing.T) {
	for _, test := range []struct {
		name       string
		decision   *Decision
		clientRows int
		wantRows   int
		wantBinds  bool
	}{
		{name: "nil decision leaves the client page size", clientRows: 500, wantRows: 500},
		{name: "uncapped verdict", decision: &Decision{}, clientRows: 500, wantRows: 500},
		{name: "cap below the page size binds", decision: &Decision{MaxRows: 100}, clientRows: 500, wantRows: 100, wantBinds: true},
		{name: "page size below the cap is a page end", decision: &Decision{MaxRows: 100}, clientRows: 50, wantRows: 50},
		{name: "equal cap and page size binds", decision: &Decision{MaxRows: 100}, clientRows: 100, wantRows: 100, wantBinds: true},
		{name: "unpaged caller takes the cap", decision: &Decision{MaxRows: 100}, wantRows: 100, wantBinds: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.decision.PageRows(test.clientRows); got != test.wantRows {
				t.Fatalf("PageRows = %d, want %d", got, test.wantRows)
			}
			if got := test.decision.CapBinds(test.clientRows); got != test.wantBinds {
				t.Fatalf("CapBinds = %v, want %v", got, test.wantBinds)
			}
		})
	}
}

// A connection's next Decide waits for its previous statement's completion report, so a sequential script
// cannot outrun its own volume budget.
func TestAuthorizeWaitsForPendingCompletion(t *testing.T) {
	release := make(chan struct{})
	reporter := &blockingReporter{release: release}
	decider := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	qe := NewQueryEngine(mysqlDb, decider)
	qe.AwaitCompletion(EmitCompletion(reporter, &Decision{DecisionID: 7}, RelayStats{Rows: 3}, StatusOK, time.Now()))

	decided := make(chan struct{})
	go func() {
		qe.Authorize(serveInput())
		close(decided)
	}()
	select {
	case <-decided:
		t.Fatal("Authorize ran before the completion report was delivered")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-decided:
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not resume after the completion report")
	}
	if got := reporter.reports.Load(); got != 1 {
		t.Fatalf("reports = %d, want 1", got)
	}
	// A nil decision emits nothing and must not block the next Decide.
	qe.AwaitCompletion(EmitCompletion(reporter, nil, RelayStats{}, StatusOK, time.Now()))
	qe.Authorize(serveInput())
}

type blockingReporter struct {
	release <-chan struct{}
	reports atomic.Int32
}

func (r *blockingReporter) ReportCompletion(CompletionReport) {
	<-r.release
	r.reports.Add(1)
}
