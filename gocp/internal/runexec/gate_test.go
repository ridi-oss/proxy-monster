package runexec

import (
	"context"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// taskID is a helper for the *int64 parameter.
func taskID(n int64) *int64 { return &n }

// TestTheQuerySendHappensWhileHoldingTheCancelGate is the REGRESSION TEST 🔒 INV-A7-35 ASKS FOR, and it
// is written to fail on the specific wrong port rather than on a general smell.
//
// # The bug it prevents
//
// A Go port that builds the RunQuery message under the gate and SENDS IT OUTSIDE reintroduces the
// reordering the gate exists to stop: `sent = true` is published, the gate is released, and a racing
// RunCancel then reaches the stream BEFORE the query it is meant to cancel. An idle proxy — one that has
// no statement in flight yet — DROPS a RunCancel, so the query then arrives afterwards and RUNS. A
// just-cancelled statement executes against production data, and both the task row and the audit trail
// say it was cancelled.
//
// # How this detects it
//
// The outbound channel starts FULL, so the query send BLOCKS. A preflight closure signals the moment the
// gate has been taken. Then:
//
//	correct port  — the sender is blocked ON THE SEND while still holding the gate,
//	                so CancelActiveRun blocks acquiring it and does not return.
//	broken port   — the sender released the gate before blocking,
//	                so CancelActiveRun acquires it immediately and returns.
//
// The assertion is therefore "the cancel has NOT returned while the send is in flight". That is a
// property only the correct nesting has, and it is not satisfiable by accident.
func TestTheQuerySendHappensWhileHoldingTheCancelGate(t *testing.T) {
	s := pureService()

	// Capacity 3, filled to the brim: the query send has nowhere to go until the test drains it.
	outbound := make(chan *pb.ControlRunMsg, 3)
	for i := 0; i < 3; i++ {
		outbound <- closeMsg() // filler; any message will do
	}

	run := s.register(taskID(7), outbound)
	insideGate := make(chan struct{})
	sendDone := make(chan error, 1)

	go func() {
		sendDone <- s.sendRunQuery(context.Background(), run, outbound,
			// preflight runs INSIDE the gate (RunExec.kt:233), which is what makes it a reliable
			// "the gate is now held" signal.
			func() bool { close(insideGate); return true },
			"select 1", 500)
	}()

	select {
	case <-insideGate:
	case <-time.After(2 * time.Second):
		t.Fatal("the sender never entered the cancel gate")
	}

	cancelReturned := make(chan bool, 1)
	go func() { cancelReturned <- s.CancelActiveRun(context.Background(), 7) }()

	// 🔒 THE ASSERTION. The sender is parked on a blocked send; if that send is inside the critical
	// section, nothing can acquire the gate until it completes.
	select {
	case <-cancelReturned:
		t.Fatal("CancelActiveRun acquired the cancel gate WHILE THE QUERY SEND WAS STILL IN FLIGHT.\n" +
			"🔒 INV-A7-35: the send must happen while holding the lock. A port that builds the message " +
			"under the gate and sends outside it lets a RunCancel reach the stream BEFORE its query; an " +
			"idle proxy drops that cancel and the just-cancelled query then runs anyway.")
	case <-time.After(150 * time.Millisecond):
		// Correct: the cancel is queued behind the send.
	}

	// Drain, which lets the query land — and it lands FIRST, because the cancel cannot even be built
	// until the gate is free.
	for i := 0; i < 3; i++ {
		<-outbound
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("sendRunQuery: %v", err)
	}
	if got := <-cancelReturned; !got {
		t.Error("CancelActiveRun returned false for a registered run")
	}

	first := <-outbound
	if first.GetQuery() == nil {
		t.Fatalf("the first message on the stream is %T, want the RunQuery", first.GetKind())
	}
	select {
	case second := <-outbound:
		if second.GetCancel() == nil {
			t.Errorf("the second message is %T, want the RunCancel", second.GetKind())
		}
	case <-time.After(2 * time.Second):
		t.Error("the RunCancel never reached the stream after the query")
	}
}

// TestACancelThatWinsTheGateVetoesTheSendEntirely is INV-A7-35's OTHER branch.
//
// 🔒 Nothing leaves the control plane. The run reports ErrRunCanceledBeforeStart — which every async
// body maps to a NIL failure code, so the cancel path owns the task's terminal state instead of it being
// overwritten with FAILED.
func TestACancelThatWinsTheGateVetoesTheSendEntirely(t *testing.T) {
	s := pureService()
	outbound := make(chan *pb.ControlRunMsg, 4)
	run := s.register(taskID(11), outbound)

	if !s.CancelActiveRun(context.Background(), 11) {
		t.Fatal("CancelActiveRun returned false for a registered run")
	}
	// The cancel arrived BEFORE any dispatch, so `sent` was false and NO RunCancel was emitted either:
	// there is no statement to cancel yet.
	if len(outbound) != 0 {
		t.Errorf("a pre-dispatch cancel put %d message(s) on the stream; it must emit none", len(outbound))
	}

	err := s.sendRunQuery(context.Background(), run, outbound, nil, "select 1", 500)
	if err != query.ErrRunCanceledBeforeStart {
		t.Fatalf("the vetoed send returned %v, want query.ErrRunCanceledBeforeStart", err)
	}
	if len(outbound) != 0 {
		t.Errorf("the vetoed query still reached the stream (%d message(s)) — the veto is the whole point",
			len(outbound))
	}
}

// TestAFailedPreflightVetoesTheSendLikeACancel — `preflight?.invoke() == false` is the DB status
// re-check, and it runs INSIDE the gate.
//
// It exists so a task whose row was cancelled between the execution claim and the dispatch never sends
// its statement: the editor's queued-statement case (EditorSubmitRouteDbTest's "canceling a queued
// editor task sends no cancel or query") depends on exactly this.
func TestAFailedPreflightVetoesTheSendLikeACancel(t *testing.T) {
	s := pureService()
	outbound := make(chan *pb.ControlRunMsg, 4)
	run := s.register(taskID(13), outbound)

	err := s.sendRunQuery(context.Background(), run, outbound, func() bool { return false }, "select queued", 500)
	if err != query.ErrRunCanceledBeforeStart {
		t.Fatalf("a false preflight returned %v, want query.ErrRunCanceledBeforeStart", err)
	}
	if len(outbound) != 0 {
		t.Errorf("the preflight-vetoed query reached the stream (%d message(s))", len(outbound))
	}

	// 🔒 And the run is NOT marked sent, so a later cancel does not emit a RunCancel for a statement
	// that never went out.
	if !s.CancelActiveRun(context.Background(), 13) {
		t.Fatal("CancelActiveRun returned false for a still-registered run")
	}
	if len(outbound) != 0 {
		t.Errorf("a cancel after a vetoed send emitted %d message(s); nothing was ever dispatched",
			len(outbound))
	}
}

// TestAnUntrackedRunSendsWithNoGate — `if (run == null) { outbound.send(msg); return }`. The synchronous
// `POST /api/datasources/{id}/query` passes no taskId, so it has no cancel gate at all and must not
// require one.
func TestAnUntrackedRunSendsWithNoGate(t *testing.T) {
	s := pureService()
	outbound := make(chan *pb.ControlRunMsg, 1)
	// preflight is deliberately a FALSE closure: with no ActiveRun there is no gate, so the Kotlin never
	// invokes it. A port that hoisted the preflight out of the gate would veto this send.
	if err := s.sendRunQuery(context.Background(), nil, outbound, func() bool { return false }, "select 1", 500); err != nil {
		t.Fatalf("an untracked send failed: %v", err)
	}
	msg := <-outbound
	if msg.GetQuery() == nil {
		t.Fatalf("an untracked run put %T on the stream, want the RunQuery", msg.GetKind())
	}
}

// TestCancelActiveRunReportsWhetherARunWasRegistered — the boolean is what `/cancel` uses to decide
// whether it terminalised a live run or a task that was never dispatched.
func TestCancelActiveRunReportsWhetherARunWasRegistered(t *testing.T) {
	s := pureService()
	if s.CancelActiveRun(context.Background(), 404) {
		t.Error("CancelActiveRun returned true for an unregistered task")
	}
	outbound := make(chan *pb.ControlRunMsg, 2)
	run := s.register(taskID(5), outbound)
	if !s.CancelActiveRun(context.Background(), 5) {
		t.Error("CancelActiveRun returned false for a registered task")
	}
	// 🔒 Deregistration is ConcurrentHashMap.remove(key, value): it removes ONLY when the mapped value
	// is still this run. A plain delete would drop a LATER run's registration for the same task id —
	// which is exactly what happens when a task is retried while a stale goroutine unwinds.
	later := s.register(taskID(5), outbound)
	s.deregister(taskID(5), run) // the STALE run unwinding
	if !s.CancelActiveRun(context.Background(), 5) {
		t.Error("the stale run's deregistration removed the LATER run's registration; " +
			"remove must be value-conditional")
	}
	s.deregister(taskID(5), later)
	if s.CancelActiveRun(context.Background(), 5) {
		t.Error("the run stayed registered after its own deregistration")
	}
}

// TestMaxRowsIsCoercedIntoZeroToFiveThousandWithZeroPreserved.
//
// 🔒 ZERO IS A WIRE SENTINEL, NOT A MISTAKE: it means "use the proxy's default (500)", which the proxy
// re-coerces into [1, 5000]. A port that clamped to [1, 5000] here would turn every default-max-rows
// query into a ONE-ROW query, and no test that only checks the ceiling would notice.
func TestMaxRowsIsCoercedIntoZeroToFiveThousandWithZeroPreserved(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int32
		why  string
	}{
		{0, 0, "🔒 the wire sentinel for the proxy's default (500) — must NOT become 1"},
		{-1, 0, "negative floors to the sentinel"},
		{1, 1, "the smallest explicit cap passes through"},
		{500, 500, "the ordinary case"},
		{5000, 5000, "the ceiling is inclusive"},
		{5001, 5000, "above the ceiling is capped"},
		{9000, 5000, "GrpcRunExecDbTest's value — clamped BEFORE crossing the wire"},
	} {
		if got := coerceMaxRows(tc.in); got != tc.want {
			t.Errorf("coerceMaxRows(%d) = %d, want %d — %s", tc.in, got, tc.want, tc.why)
		}
		// And the same through the message builder, since that is what actually crosses the wire.
		if got := queryMsg("select 1", tc.in).GetQuery().GetMaxRows(); got != tc.want {
			t.Errorf("RunQuery.max_rows for %d = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestASendOntoAWedgedStreamFailsRatherThanBlockingForever pins doc.go's divergence 3.
//
// A Go channel whose drainer has died FILLS instead of failing, so an unbounded send under the cancel
// gate would hold that gate forever — and CancelActiveRun would then hang with it, taking
// `POST /api/approvals/{id}/cancel` down. The budget converts that into the Kotlin's observable:
// ProxyRunError("proxy run stream closed before the query was sent").
func TestASendOntoAWedgedStreamFailsRatherThanBlockingForever(t *testing.T) {
	s := pureService()
	full := make(chan *pb.ControlRunMsg, 1)
	full <- closeMsg()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := s.sendRunQuery(ctx, s.register(taskID(3), full), full, nil, "select 1", 500)
	if err == nil {
		t.Fatal("the send onto a full stream reported success")
	}
	// The caller maps it; assert the mapping too, since that is the observable.
	mapped := s.sendFailure(context.Background(), err, "proxy run stream closed before the query was sent")
	wantProxyRunError(t, mapped, "proxy run stream closed before the query was sent")
}

// TestACancelledContextIsReportedAsCancellationNotAProxyFault is `currentCoroutineContext()
// .ensureActive()` (RunExec.kt:323): a caller that went away is not a proxy problem, and must not be
// reported as 502 `query.failed`.
func TestACancelledContextIsReportedAsCancellationNotAProxyFault(t *testing.T) {
	s := pureService()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := s.sendFailure(ctx, context.Canceled, "proxy run stream closed before the query was sent")
	if got != context.Canceled {
		t.Errorf("a cancelled caller produced %v, want context.Canceled to propagate", got)
	}
	// 🔒 ErrRunCanceledBeforeStart passes through UNTOUCHED even on a live context — it is not a
	// failure, and wrapping it would lose the arm that maps it to a nil failure code.
	if got := s.sendFailure(context.Background(), query.ErrRunCanceledBeforeStart, "unused"); got != query.ErrRunCanceledBeforeStart {
		t.Errorf("ErrRunCanceledBeforeStart became %v; it must pass through", got)
	}
}
