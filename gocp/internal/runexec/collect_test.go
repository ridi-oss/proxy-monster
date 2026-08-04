package runexec

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// pureService is a [Service] with NO core, usable only for [Service.collectResponse] and the message
// builders.
//
// ⚠️ THE NIL CORE IS THE CONSTRAINT THAT MAKES THIS SAFE, AND IT BINDS EVERY TEST IN THIS FILE: the
// only path from collectResponse into the core is [Service.response]'s audit lookup, and that runs ONLY
// when the decision carries a non-zero decision_id. So every fixture below leaves decision_id at 0. A
// test that sets one gets a nil-pointer panic rather than a wrong answer, which is the failure mode to
// prefer — and the piiTouched lookup itself is asserted for real against a live audit row in
// internal/app's DB suite (GrpcRunExecDbTest cases 2-4).
func pureService() *Service {
	return &Service{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		activeRuns:               map[int64]*activeRun{},
		openSessions:             map[string]*openEditorSession{},
		defaultExchangeTimeoutMs: 630_000,
		nowNanos:                 func() int64 { return time.Now().UnixNano() },
	}
}

// collect feeds msgs into a fresh inbound channel, CLOSES it, and runs collectResponse to completion.
//
// Closing is what makes the "stream closed before a terminal response" arm reachable: the gRPC handler
// closes `attached.Inbound` on every stream exit, so an exhausted channel IS a closed stream.
func collect(t *testing.T, msgs ...*pb.ProxyRunMsg) (query.QueryResponse, error) {
	t.Helper()
	inbound := make(chan *pb.ProxyRunMsg, len(msgs)+1)
	for _, m := range msgs {
		inbound <- m
	}
	close(inbound)
	never := make(chan time.Time)
	return pureService().collectResponse(context.Background(), never, inbound, time.Now())
}

// wantProxyRunError asserts the error is a ProxyRunError carrying exactly `message`.
//
// EXACT, not a substring: each of these strings reaches the wire as `query.failed{detail}`, so the text
// is observable API and a near-match is a change no client asked for.
func wantProxyRunError(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ProxyRunError %q, got no error at all — the rejection did not fire", message)
	}
	pre, ok := err.(*query.ProxyRunError)
	if !ok {
		t.Fatalf("expected *query.ProxyRunError %q, got %T: %v", message, err, err)
	}
	if pre.Message != message {
		t.Errorf("ProxyRunError message = %q, want %q (verbatim — it is the wire `detail`)", pre.Message, message)
	}
}

func decisionMsg(action pb.EnfAction) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Decision{Decision: &pb.RunDecision{Decision: action}}}
}

func rowsMsg(columns []string, rows ...[]*string) *pb.ProxyRunMsg {
	wire := make([]*pb.RunRow, 0, len(rows))
	for _, row := range rows {
		values := make([]*pb.RunValue, 0, len(row))
		for _, cell := range row {
			if cell == nil {
				values = append(values, &pb.RunValue{IsNull: true})
				continue
			}
			values = append(values, &pb.RunValue{Value: *cell})
		}
		wire = append(wire, &pb.RunRow{Values: values})
	}
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_ResultRows{ResultRows: &pb.RunResultRows{
		Columns: columns, Rows: wire,
	}}}
}

func doneMsg(rowsAffected int32) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Done{Done: &pb.RunDone{RowsAffected: rowsAffected}}}
}

func errorMsg(message string) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Error{Error: &pb.RunError{Message: message}}}
}

func readyMsg(sessionID string) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_SessionReady{SessionReady: &pb.RunReady{SessionId: sessionID}}}
}

func sp(s string) *string { return &s }

// deniedCollector is a [collector] primed with the state a DENY decision leaves behind.
//
// It exists because the DENY arm RETURNS — so no message after it is ever read by the loop — and the two
// arms that guard "rows/Done arrived anyway" would otherwise be unassertable. Priming the struct is the
// only way to reach them, and they are the ones standing between a misbehaving proxy and a leak.
func deniedCollector() *collector {
	return &collector{
		s:          pureService(),
		decision:   &pb.RunDecision{Decision: pb.EnfAction_DENY, DenyReason: "policy denies column rrn"},
		action:     pb.EnfAction_DENY,
		haveAction: true,
	}
}

// TestCollectResponseRejectsEveryProtocolViolation is the CONTROL PLANE'S DEFENCE AGAINST A MISBEHAVING
// PROXY, all ten cases.
//
// 🔒 07-tasks-approvals-results.md §10 records these as a coverage gap: "collectResponse's ten protocol
// rejections — none appear to be asserted at unit level. These are the CP's defence against a
// misbehaving proxy." A proxy is a separate process holding a database connection; a control plane that
// trusts its framing has no floor left if it is compromised or merely buggy.
//
// Each case is named for the message it must produce, and asserts it VERBATIM because the message is
// the `detail` on a 502 `query.failed`.
func TestCollectResponseRejectsEveryProtocolViolation(t *testing.T) {
	t.Run("a second decision", func(t *testing.T) {
		// Silently taking the second would let a proxy replace a DENY with an ALLOW.
		_, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), decisionMsg(pb.EnfAction_ALLOW))
		wantProxyRunError(t, err, ErrMsgSecondDecision)
	})

	t.Run("rows before any decision", func(t *testing.T) {
		// Rows with no verdict behind them are UNENFORCED data — nothing decided they may be returned.
		_, err := collect(t, rowsMsg([]string{"id"}, []*string{sp("1")}))
		wantProxyRunError(t, err, ErrMsgRowsBeforeDecision)
	})

	t.Run("rows after a DENY", func(t *testing.T) {
		// 🔒 UNREACHABLE by feeding the loop — the DENY arm returns before any later message is read — so
		// the collector's state is PRIMED to exactly what a broken DENY path would leave and stepped once.
		// This is the leak the early return prevents, and this arm is the belt to its braces.
		_, terminal, err := deniedCollector().step(context.Background(),
			rowsMsg([]string{"rrn"}, []*string{sp("must-not-escape")}), time.Now())
		if !terminal {
			t.Fatal("rows after a DENY must END the exchange, not be collected")
		}
		wantProxyRunError(t, err, ErrMsgRowsAfterDeny)
	})

	t.Run("a row narrower than the first chunk's header", func(t *testing.T) {
		_, err := collect(t,
			decisionMsg(pb.EnfAction_ALLOW),
			rowsMsg([]string{"id", "email"}, []*string{sp("1")}),
		)
		wantProxyRunError(t, err, ErrMsgWrongColumnCount)
	})

	t.Run("a row wider than the first chunk's header", func(t *testing.T) {
		// 🔒 The FIRST chunk's width is the contract. A later chunk that declares more columns does not
		// widen it — its own `columns` are ignored — so an extra value has nothing to bind to and would
		// shift every mask ordinal after it.
		_, err := collect(t,
			decisionMsg(pb.EnfAction_MASK),
			rowsMsg([]string{"id"}, []*string{sp("1")}),
			rowsMsg([]string{"id", "rrn"}, []*string{sp("2"), sp("900101-1234567")}),
		)
		wantProxyRunError(t, err, ErrMsgWrongColumnCount)
	})

	t.Run("done with no decision", func(t *testing.T) {
		_, err := collect(t, doneMsg(-1))
		wantProxyRunError(t, err, ErrMsgDoneBeforeDecision)
	})

	t.Run("done after a DENY", func(t *testing.T) {
		// Same shape as "rows after a DENY": unreachable by feeding the loop, primed instead.
		_, terminal, err := deniedCollector().step(context.Background(), doneMsg(-1), time.Now())
		if !terminal {
			t.Fatal("a Done after a DENY must END the exchange")
		}
		wantProxyRunError(t, err, ErrMsgDoneAfterDeny)
	})

	t.Run("a second RunReady", func(t *testing.T) {
		// The FIRST Ready is consumed by the gRPC handler to claim the session (INV-A7-32). One reaching
		// this loop means the proxy is re-announcing a stream it already owns.
		_, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), readyMsg("s1"))
		wantProxyRunError(t, err, ErrMsgSecondReady)
	})

	t.Run("an empty message", func(t *testing.T) {
		// An unset oneof. A future arm this control plane does not know lands here too, which is the
		// fail-closed answer rather than being skipped as a no-op.
		_, err := collect(t, &pb.ProxyRunMsg{})
		wantProxyRunError(t, err, ErrMsgEmptyMessage)
	})

	t.Run("the stream closes with no terminal message", func(t *testing.T) {
		// The one of the ten that fires in ordinary operation: a proxy that dies mid-statement. Partial
		// rows are DISCARDED rather than returned as if the query had finished.
		_, err := collect(t,
			decisionMsg(pb.EnfAction_ALLOW),
			rowsMsg([]string{"id"}, []*string{sp("1")}),
		)
		wantProxyRunError(t, err, ErrMsgStreamClosedEarly)
	})

	t.Run("done with a decision but no verdict", func(t *testing.T) {
		// 🔒 UNREACHABLE THROUGH THE PUBLIC PATH and kept anyway, because the Kotlin keeps it: `decision`
		// and `action` are set together, so this fires only if a future edit splits them. Primed with the
		// verdict deliberately withheld — the exact state that edit would produce.
		c := &collector{s: pureService(), decision: &pb.RunDecision{Decision: pb.EnfAction_ALLOW}}
		_, terminal, err := c.step(context.Background(), doneMsg(-1), time.Now())
		if !terminal {
			t.Fatal("a Done with no verdict must END the exchange")
		}
		wantProxyRunError(t, err, ErrMsgDoneWithoutVerdict)
	})
}

// TestARunErrorEndsTheExchangeAndNeverReturnsEarlierRows is the RunError arm.
//
// 🔒 Rows already collected are DROPPED. A backend that failed halfway through a result set has
// returned an unknown prefix of an unknown query; handing that prefix back as a success would present
// partial data as complete.
func TestARunErrorEndsTheExchangeAndNeverReturnsEarlierRows(t *testing.T) {
	response, err := collect(t,
		decisionMsg(pb.EnfAction_ALLOW),
		rowsMsg([]string{"email"}, []*string{sp("must-not-escape@example.com")}),
		errorMsg("backend disconnected"),
	)
	wantProxyRunError(t, err, "backend disconnected")
	if len(response.Rows) != 0 {
		t.Errorf("the failed exchange returned %d rows; it must return none", len(response.Rows))
	}
}

// TestABlankRunErrorGetsTheFallbackDetail — `message.ifBlank { "proxy run execution failed" }`. A blank
// detail on the wire tells an operator nothing.
func TestABlankRunErrorGetsTheFallbackDetail(t *testing.T) {
	for _, blank := range []string{"", "   ", "\t\n"} {
		_, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), errorMsg(blank))
		wantProxyRunError(t, err, ErrMsgExecutionFailed)
	}
}

// TestTheQueryTimeoutSentinelIsAttributedAsATimeoutNotAFailure pins 🔒 INV-A7-31.
//
// The proxy's PM_QUERY_TIMEOUT watchdog aborts a statement with an EXACT message. Matched, it becomes
// ErrProxyRunTimeout ⇒ 504 `query.proxy_timeout` and a FAILED task attributed to the timeout. Unmatched
// — one character off — it becomes a generic ProxyRunError ⇒ 502 `query.failed`, and the operator loses
// the only signal that says "your query ran out of time" rather than "the backend broke".
func TestTheQueryTimeoutSentinelIsAttributedAsATimeoutNotAFailure(t *testing.T) {
	if _, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), errorMsg(QueryTimeoutMessage)); err != query.ErrProxyRunTimeout {
		t.Fatalf("the exact sentinel produced %v, want query.ErrProxyRunTimeout", err)
	}
	// One character off is NOT the sentinel — the match is equality, never a prefix or a contains.
	for _, near := range []string{
		"statement aborted: PM_QUERY_TIMEOUT exceeded.",
		"statement aborted: PM_QUERY_TIMEOUT exceede",
		"Statement aborted: PM_QUERY_TIMEOUT exceeded",
		"statement aborted: PM_QUERY_TIMEOUT exceeded ",
	} {
		_, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), errorMsg(near))
		if err == query.ErrProxyRunTimeout {
			t.Errorf("%q was treated as the timeout sentinel; the match must be exact equality", near)
		}
		wantProxyRunError(t, err, near)
	}
}

// TestTheExchangeBudgetProducesATypedTimeout — `withTimeout(exchangeTimeoutMs)` fires while the proxy
// is still silent, and the caller must see ErrProxyRunTimeout (⇒ 504) rather than a stream error.
func TestTheExchangeBudgetProducesATypedTimeout(t *testing.T) {
	inbound := make(chan *pb.ProxyRunMsg) // nothing is ever sent, and it is never closed
	if _, err := pureService().collectWithin(context.Background(), inbound, time.Now(), time.Millisecond); err != query.ErrProxyRunTimeout {
		t.Fatalf("a silent proxy past the budget produced %v, want query.ErrProxyRunTimeout", err)
	}
}

// TestADenyIsTerminalAndCarriesNoData — 🔒 INV-A7-39's second half. The DENY arm returns IMMEDIATELY,
// with empty columns and rows, without waiting for a Done that will never come.
func TestADenyIsTerminalAndCarriesNoData(t *testing.T) {
	inbound := make(chan *pb.ProxyRunMsg, 1)
	inbound <- &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Decision{Decision: &pb.RunDecision{
		Decision:       pb.EnfAction_DENY,
		DenyReason:     "policy denies column rrn",
		EffectiveRoles: []string{"contractor"},
	}}}
	// Deliberately NOT closed: a DENY must return without needing the stream to end.
	never := make(chan time.Time)
	response, err := pureService().collectResponse(context.Background(), never, inbound, time.Now())
	if err != nil {
		t.Fatalf("a DENY must be a successful RESPONSE, not an error: %v", err)
	}
	if pb.EnfAction(response.Decision) != pb.EnfAction_DENY {
		t.Errorf("decision = %v, want DENY", response.Decision)
	}
	if response.DenyReason == nil || *response.DenyReason != "policy denies column rrn" {
		t.Errorf("denyReason = %v, want the proxy's reason", response.DenyReason)
	}
	if len(response.Columns) != 0 || len(response.Rows) != 0 {
		t.Errorf("a DENY returned %d columns / %d rows; both must be empty",
			len(response.Columns), len(response.Rows))
	}
	if response.RowsAffected != nil {
		t.Errorf("a DENY returned rowsAffected = %d; it must be absent", *response.RowsAffected)
	}
}

// TestAnUnknownWireVerdictFailsClosedToDeny pins 🔒 INV-A7-39 / INV-A6-3 at the transport boundary: the
// action goes through query.KnownOrDeny, so ENF_ACTION_UNSPECIFIED and any future enum number collapse
// to DENY. A port that assigned `received.Decision` straight through would let an unknown verdict fall
// OPEN — the proxy's rows would be returned under a verdict nothing granted.
func TestAnUnknownWireVerdictFailsClosedToDeny(t *testing.T) {
	for _, action := range []pb.EnfAction{pb.EnfAction_ENF_ACTION_UNSPECIFIED, pb.EnfAction(97)} {
		inbound := make(chan *pb.ProxyRunMsg, 1)
		inbound <- &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Decision{Decision: &pb.RunDecision{
			Decision: action, DenyReason: "unspecified verdict",
		}}}
		never := make(chan time.Time)
		response, err := pureService().collectResponse(context.Background(), never, inbound, time.Now())
		if err != nil {
			t.Fatalf("EnfAction(%d): %v", action, err)
		}
		if pb.EnfAction(response.Decision) != pb.EnfAction_DENY {
			t.Errorf("EnfAction(%d) mapped to %v; every unknown verdict must be DENY", action, response.Decision)
		}
		if response.DecisionID != nil {
			t.Errorf("decision_id 0 must be reported as ABSENT, got %d", *response.DecisionID)
		}
	}
}

// TestChunkedRowsAssembleWithNullsPreservedAsNil covers the assembly path: two chunks join into one row
// list, the first chunk's header is the response's columns, and a null cell is nil rather than "".
//
// 🔒 The nil/"" distinction is load-bearing: the mask functions are string transforms, and a
// NULL-redacted cell that fell back to the empty string would be indistinguishable from a masked-to-
// empty one on the way back out.
func TestChunkedRowsAssembleWithNullsPreservedAsNil(t *testing.T) {
	response, err := collect(t,
		decisionMsg(pb.EnfAction_ALLOW),
		rowsMsg([]string{"id", "email"}, []*string{sp("1"), sp("a@example.com")}),
		rowsMsg([]string{"id", "email"}, []*string{sp("2"), nil}),
		doneMsg(-1),
	)
	if err != nil {
		t.Fatalf("collectResponse: %v", err)
	}
	if got := response.Columns; len(got) != 2 || got[0] != "id" || got[1] != "email" {
		t.Errorf("columns = %v, want [id email] from the FIRST chunk", got)
	}
	if len(response.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 across the two chunks", len(response.Rows))
	}
	if response.Rows[1][1] != nil {
		t.Errorf("the null cell came back as %q; a SQL NULL must be nil, never the empty string",
			*response.Rows[1][1])
	}
	// `rowsAffected == -1 ⇒ null` — a SELECT reports -1 and the field is omitted.
	if response.RowsAffected != nil {
		t.Errorf("rowsAffected = %d for a SELECT's -1; it must be absent", *response.RowsAffected)
	}
}

// TestRowsAffectedIsPreservedForEveryValueButMinusOne — the -1 sentinel is the ONLY one that becomes
// absent. Zero is a real answer (a DELETE that matched nothing) and must not be swallowed.
func TestRowsAffectedIsPreservedForEveryValueButMinusOne(t *testing.T) {
	for _, n := range []int32{0, 1, 42, -2} {
		response, err := collect(t, decisionMsg(pb.EnfAction_ALLOW), doneMsg(n))
		if err != nil {
			t.Fatalf("rowsAffected=%d: %v", n, err)
		}
		if response.RowsAffected == nil || *response.RowsAffected != n {
			t.Errorf("rowsAffected=%d came back as %v; only -1 becomes absent", n, response.RowsAffected)
		}
	}
}

// TestAZeroWidthChunkIsAccepted — an empty `columns` list makes the expected width 0, so a zero-value
// row is legal. Reproduced rather than rejected: the Kotlin computes `(columns ?: emptyList()).size`
// with no lower bound, and a `SELECT` with no output columns is a real (if odd) statement.
func TestAZeroWidthChunkIsAccepted(t *testing.T) {
	response, err := collect(t,
		decisionMsg(pb.EnfAction_ALLOW),
		rowsMsg(nil, []*string{}),
		doneMsg(-1),
	)
	if err != nil {
		t.Fatalf("a zero-width chunk was rejected: %v", err)
	}
	if len(response.Rows) != 1 || len(response.Rows[0]) != 0 {
		t.Errorf("rows = %v, want one zero-width row", response.Rows)
	}
}
