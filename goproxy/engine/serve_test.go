package engine

import (
	"errors"
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func serveInput() AuthzInput {
	return AuthzInput{SQL: "SELECT 1", ProbeSession: func() (SessionObservation, error) { return SessionObservation{Namespace: []string{"app"}}, nil }}
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
	in.ProbeSession = func() (SessionObservation, error) {
		events = append(events, "authorize")
		return SessionObservation{Namespace: []string{"app"}}, nil
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

func TestDecisionCapExceededNamesTheCrossedBound(t *testing.T) {
	dec := &Decision{MaxRows: 2, MaxBytes: 100}
	if got := dec.CapExceeded(RelayStats{Rows: 1, Bytes: 10}, 10); got != "" {
		t.Fatalf("CapExceeded = %q, want it to fit", got)
	}
	if got := dec.CapExceeded(RelayStats{Rows: 2, Bytes: 10}, 10); got != "proxy-monster: result exceeds the row cap (2 rows); request unbounded access" {
		t.Fatalf("row bound message = %q", got)
	}
	if got := dec.CapExceeded(RelayStats{Rows: 1, Bytes: 95}, 10); got != "proxy-monster: result exceeds the byte cap (100 bytes); request unbounded access" {
		t.Fatalf("byte bound message = %q", got)
	}
	if got := (*Decision)(nil).CapExceeded(RelayStats{Rows: 9}, 9); got != "" {
		t.Fatalf("nil decision = %q, want uncapped", got)
	}
}
