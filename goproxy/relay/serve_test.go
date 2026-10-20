package relay

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

type fakeDecider struct {
	outcome spi.DecisionOutcome
	calls   int
	lastReq spi.DecideRequest
}

func (f *fakeDecider) Decide(req spi.DecideRequest) spi.DecisionOutcome {
	f.calls++
	f.lastReq = req
	return f.outcome
}

func okOutcome(action string, masks []*pb.ColumnMask) spi.DecisionOutcome {
	return spi.DecisionOutcome{Decision: &spi.Decision{Action: action, Masks: masks}}
}

func serveInput() spi.AuthzInput {
	return spi.AuthzInput{SQL: "SELECT 1", ProbeSession: func() (spi.SessionObservation, error) { return spi.SessionObservation{Namespace: []string{"app"}}, nil }}
}

func TestServeStatementFailHasNoDecision(t *testing.T) {
	qe := spi.NewAuthorizer(&fakeDecider{outcome: spi.DecisionOutcome{Err: "unreachable"}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *spi.Decision) (bool, error) {
		t.Fatal("run called for spi.Fail")
		return false, nil
	})
	var fail FailError
	if !errors.As(err, &fail) || fail.Message != "unreachable" || dec != nil || denied {
		t.Fatalf("ServeStatement = (%v, %v, %v), want nil, false, FailError", dec, denied, err)
	}
}

func TestServeStatementDenySkipsRun(t *testing.T) {
	want := &spi.Decision{Action: "DENY", DenyReason: "policy"}
	qe := spi.NewAuthorizer(&fakeDecider{outcome: spi.DecisionOutcome{Decision: want}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *spi.Decision) (bool, error) {
		t.Fatal("run called for spi.Deny")
		return false, nil
	})
	if err != nil || !denied || dec != want {
		t.Fatalf("ServeStatement = (%v, %v, %v), want decision, true, nil", dec, denied, err)
	}
}

func TestServeStatementRunErrorRetainsDecision(t *testing.T) {
	want := &spi.Decision{Action: "ALLOW"}
	runErr := errors.New("target DB failed")
	qe := spi.NewAuthorizer(&fakeDecider{outcome: spi.DecisionOutcome{Decision: want}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask, *spi.Decision) (bool, error) {
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
			Catalog: "def",
			Db:      mysqlDb,
			Probe: func(sql string, expected int) ([][]*string, error) {
				*calls++
				if expected == 7 {
					return [][]*string{{str("app"), str("t"), str("id"), str("int"), str("1"), str("NO"), str("def")}}, nil
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
	}{{"clean", true, 4}, {"target-DB error response", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			decision := &spi.Decision{Action: "ALLOW", AfterStatement: []*pb.ProxyCommand{&pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: "def", Schema: "app"}}}}}
			qe := spi.NewAuthorizer(&fakeDecider{outcome: spi.DecisionOutcome{Decision: decision}})
			_, _, err := ServeStatement(qe, serveInput(), newRef(&calls), nil, func(string, []*pb.ColumnMask, *spi.Decision) (bool, error) {
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
	in.ProbeSession = func() (spi.SessionObservation, error) {
		events = append(events, "authorize")
		return spi.SessionObservation{Namespace: []string{"app"}}, nil
	}
	qe := spi.NewAuthorizer(&fakeDecider{outcome: okOutcome("ALLOW", nil)})
	guard := func(exec func() error) error {
		events = append(events, "guard-enter")
		err := exec()
		events = append(events, "guard-exit")
		return err
	}
	_, _, err := ServeStatement(qe, in, nil, guard, func(string, []*pb.ColumnMask, *spi.Decision) (bool, error) {
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
		decision   *spi.Decision
		clientRows int
		wantRows   int
		wantBinds  bool
	}{
		{name: "nil decision leaves the client page size", clientRows: 500, wantRows: 500},
		{name: "uncapped verdict", decision: &spi.Decision{}, clientRows: 500, wantRows: 500},
		{name: "cap below the page size binds", decision: &spi.Decision{MaxRows: 100}, clientRows: 500, wantRows: 100, wantBinds: true},
		{name: "page size below the cap is a page end", decision: &spi.Decision{MaxRows: 100}, clientRows: 50, wantRows: 50},
		{name: "equal cap and page size binds", decision: &spi.Decision{MaxRows: 100}, clientRows: 100, wantRows: 100, wantBinds: true},
		{name: "unpaged caller takes the cap", decision: &spi.Decision{MaxRows: 100}, wantRows: 100, wantBinds: true},
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

func TestDecisionCapExceededNamesTheCrossedBound(t *testing.T) {
	dec := &spi.Decision{MaxRows: 2, MaxBytes: 100}
	if got := dec.CapExceeded(spi.RelayStats{Rows: 1, Bytes: 10}, 10); got != "" {
		t.Fatalf("CapExceeded = %q, want it to fit", got)
	}
	if got := dec.CapExceeded(spi.RelayStats{Rows: 2, Bytes: 10}, 10); got != "proxy-monster: result exceeds the row cap (2 rows); request unbounded access" {
		t.Fatalf("row bound message = %q", got)
	}
	if got := dec.CapExceeded(spi.RelayStats{Rows: 1, Bytes: 95}, 10); got != "proxy-monster: result exceeds the byte cap (100 bytes); request unbounded access" {
		t.Fatalf("byte bound message = %q", got)
	}
	if got := (*spi.Decision)(nil).CapExceeded(spi.RelayStats{Rows: 9}, 9); got != "" {
		t.Fatalf("nil decision = %q, want uncapped", got)
	}
}

func TestRowBudgetAdmitsUntilItsBoundThenRefusesEveryLaterRow(t *testing.T) {
	budget := RowBudget{MaxBytes: 10}
	for _, want := range []bool{true, true, false} {
		if got := budget.Admit(0, 4); got != want {
			t.Fatalf("Admit = %v, want %v", got, want)
		}
	}
	// A row that fits the remaining 2 bytes is still refused: a budget that overflowed stays overflowed,
	// so the collected prefix is contiguous.
	if budget.Admit(0, 1) {
		t.Fatal("a budget that overflowed must refuse every later row")
	}
	if !budget.Overflowed || !budget.ByteCapped {
		t.Fatalf("budget = %+v, want overflowed by the byte bound", budget)
	}

	rows := RowBudget{MaxRows: 2}
	if !rows.Admit(1, 1_000_000) || rows.Admit(2, 1) {
		t.Fatalf("row bound = %+v, want the third row refused", rows)
	}
	if rows.ByteCapped {
		t.Fatal("a row-bound overflow is not a byte cap")
	}
	// The row bound can be the caller's own page size, so it only counts as a cap when the verdict's is
	// at or below it; the byte bound is the verdict's alone.
	if rows.CapTruncated(&spi.Decision{MaxRows: 100}, 2) {
		t.Fatal("a page end under a looser verdict cap is not a cap truncation")
	}
	if !rows.CapTruncated(&spi.Decision{MaxRows: 2}, 2) {
		t.Fatal("a verdict cap at the page size IS a cap truncation")
	}
}

// A connection's next Decide waits for its previous statement's completion report, so a sequential script
// cannot outrun its own volume budget.
func TestAuthorizeWaitsForPendingCompletion(t *testing.T) {
	release := make(chan struct{})
	reporter := &blockingReporter{release: release}
	decider := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	qe := spi.NewAuthorizer(decider)
	qe.AwaitCompletion(EmitCompletion(reporter, &spi.Decision{DecisionID: 7}, spi.RelayStats{Rows: 3}, StatusOK, time.Now()))

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
	qe.AwaitCompletion(EmitCompletion(reporter, nil, spi.RelayStats{}, StatusOK, time.Now()))
	qe.Authorize(serveInput())
}

type blockingReporter struct {
	release <-chan struct{}
	reports atomic.Int32
}

func (r *blockingReporter) ReportCompletion(spi.CompletionReport) {
	<-r.release
	r.reports.Add(1)
}
