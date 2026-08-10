package engine

import (
	"errors"
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func serveInput() AuthzInput {
	return AuthzInput{SQL: "SELECT 1", ProbeNamespace: func() (NamespaceProbe, error) { return NamespaceProbe{Namespace: []string{"app"}}, nil }}
}

func TestServeStatementFailHasNoDecision(t *testing.T) {
	qe := NewQueryEngine(mysqlDb, &fakeDecider{outcome: DecisionOutcome{Err: "unreachable"}})
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask) (bool, error) {
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
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask) (bool, error) {
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
	dec, denied, err := ServeStatement(qe, serveInput(), nil, nil, func(string, []*pb.ColumnMask) (bool, error) {
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
			_, _, err := ServeStatement(qe, serveInput(), newRef(&calls), nil, func(string, []*pb.ColumnMask) (bool, error) {
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
	_, _, err := ServeStatement(qe, in, nil, guard, func(string, []*pb.ColumnMask) (bool, error) {
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
