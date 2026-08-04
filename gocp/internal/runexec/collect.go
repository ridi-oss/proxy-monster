package runexec

import (
	"context"
	"time"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// The ten protocol rejections of `collectResponse` (RunExec.kt:548-616), each a ProxyRunError.
//
// 🔒 THESE ARE THE CONTROL PLANE'S DEFENCE AGAINST A MISBEHAVING PROXY, and A7 §10 records every one of
// them as UNTESTED in the Kotlin. They are exported as named constants so a test asserts the exact
// message rather than a substring, and so the ten cases are enumerable.
//
// The messages are on the wire: a ProxyRunError becomes 502 `query.failed{detail: <message>}`.
const (
	// ErrMsgSecondDecision — a run has exactly one verdict. A second would silently replace the first,
	// which is how a DENY becomes an ALLOW.
	ErrMsgSecondDecision = "proxy sent more than one run decision"
	// ErrMsgRowsBeforeDecision — rows with no verdict behind them are unenforced data.
	ErrMsgRowsBeforeDecision = "proxy sent run rows before a decision"
	// ErrMsgRowsAfterDeny — the leak this one prevents is the whole point of the DENY early return.
	ErrMsgRowsAfterDeny = "proxy sent run rows after a deny decision"
	// ErrMsgWrongColumnCount — a row narrower or wider than the FIRST chunk's header cannot be bound to
	// column names, so mask ordinals would shift. Fail closed rather than guess.
	ErrMsgWrongColumnCount = "proxy sent a run row with the wrong column count"
	// ErrMsgDoneBeforeDecision — completion with no verdict at all.
	ErrMsgDoneBeforeDecision = "proxy completed a run query before a decision"
	// ErrMsgDoneWithoutVerdict — a decision arrived but carried no action. Unreachable through
	// [query.KnownOrDeny] (which always yields one of three), and kept because the Kotlin keeps it: the
	// two fields are set together and a port that split them would need it.
	ErrMsgDoneWithoutVerdict = "proxy completed a run query without a verdict"
	// ErrMsgDoneAfterDeny — likewise unreachable while the DENY arm returns early, and likewise kept.
	ErrMsgDoneAfterDeny = "proxy sent RunDone after a deny decision"
	// ErrMsgSecondReady — the first Ready is consumed by the gRPC handler to CLAIM the session
	// (INV-A7-32); a second one reaching this loop means the proxy is re-announcing a stream it already
	// owns.
	ErrMsgSecondReady = "proxy sent RunReady more than once"
	// ErrMsgEmptyMessage — an unset oneof. A future arm this control plane does not know also lands
	// here, which is the fail-closed answer.
	ErrMsgEmptyMessage = "proxy sent an empty run message"
	// ErrMsgStreamClosedEarly — the stream ended with neither Done nor Error. This is the one of the ten
	// that fires in ordinary operation: a proxy that crashes mid-statement.
	ErrMsgStreamClosedEarly = "proxy run stream closed before a terminal response"
	// ErrMsgExecutionFailed is the `ifBlank` fallback for a RunError with an empty message — not a
	// protocol rejection, but the same defensive family: a blank detail on the wire would tell an
	// operator nothing.
	ErrMsgExecutionFailed = "proxy run execution failed"
)

// collector is the per-exchange state of `collectResponse`'s loop — Kotlin's four locals, hoisted into
// a struct.
//
// 🔒 THE HOISTING IS WHAT MAKES THE TEN REJECTIONS TESTABLE. Three of them (rows-after-DENY,
// done-after-DENY, done-without-verdict) are UNREACHABLE by feeding messages to the loop, because the
// DENY arm returns before any later message is read and because `decision`/`action` are always set
// together. With the state in a struct, a test primes exactly the state the Kotlin would have to be
// broken to produce and calls [collector.step] once. Without it those three could only be reviewed, not
// asserted — and they are the arms guarding the leak paths.
type collector struct {
	s *Service
	// decision is the verdict message; nil until one arrives.
	decision *pb.RunDecision
	// action is tracked SEPARATELY from decision, exactly as the Kotlin tracks `action` beside
	// `decision`, which is what makes ErrMsgDoneWithoutVerdict expressible at all.
	action     pb.EnfAction
	haveAction bool
	// columns is nil until the FIRST chunk sets it. Later chunks' `columns` are IGNORED — the first
	// chunk's width is the contract for every row that follows.
	columns []string
	rows    [][]*string
}

// collectResponse is `private suspend fun collectResponse(inbound, started)` (RunExec.kt:548-616).
//
// Loops over the proxy's messages until a terminal one. `timeout` is the exchange budget the caller
// wrapped it in (`withTimeout(exchangeTimeoutMs)`), delivered as a channel so the caller owns the
// timer; a fire maps to [query.ErrProxyRunTimeout], which the routes answer 504 for.
func (s *Service) collectResponse(
	ctx context.Context, timeout <-chan time.Time, inbound chan *pb.ProxyRunMsg, started time.Time,
) (query.QueryResponse, error) {
	c := &collector{s: s}
	for {
		select {
		case msg, ok := <-inbound:
			if !ok {
				// The `for (message in inbound)` loop ran to completion: the gRPC handler closed the
				// inbound channel on stream exit without a terminal message ever arriving. Whatever rows
				// were collected are DISCARDED — an unknown prefix of a result set is not a result.
				return query.QueryResponse{}, query.NewProxyRunError(ErrMsgStreamClosedEarly, nil)
			}
			response, terminal, err := c.step(ctx, msg, started)
			if terminal {
				return response, err
			}
		case <-timeout:
			return query.QueryResponse{}, query.ErrProxyRunTimeout
		case <-ctx.Done():
			return query.QueryResponse{}, ctx.Err()
		}
	}
}

// step is the body of the Kotlin's `when { … }` — one message, in the SAME ARM ORDER (decision, rows,
// done, error, sessionReady, else).
//
// It reports terminal=true when the exchange is over, in which case the response/error pair is the
// answer. terminal=false means "keep reading", and only the rows arm ever says that.
//
// 🔒 INV-A7-39 — THE DECISION'S ACTION GOES THROUGH [query.KnownOrDeny] (A6 INV-A6-3), so an
// unspecified or future verdict from the wire collapses to DENY rather than falling open, and a DENY
// RETURNS IMMEDIATELY with empty columns and rows.
func (c *collector) step(
	ctx context.Context, msg *pb.ProxyRunMsg, started time.Time,
) (query.QueryResponse, bool, error) {
	switch {
	case msg.GetDecision() != nil:
		if c.decision != nil {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgSecondDecision, nil)
		}
		received := msg.GetDecision()
		mapped := query.KnownOrDeny(received.GetDecision()) // 🔒 INV-A7-39 / INV-A6-3
		c.decision, c.action, c.haveAction = received, mapped, true
		if mapped == pb.EnfAction_DENY {
			// A DENY is TERMINAL and carries no data: empty columns, empty rows, nil rowsAffected.
			return c.s.response(ctx, received, mapped, nil, nil, nil, started), true, nil
		}
		return query.QueryResponse{}, false, nil

	case msg.GetResultRows() != nil:
		if c.decision == nil {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgRowsBeforeDecision, nil)
		}
		if c.action == pb.EnfAction_DENY {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgRowsAfterDeny, nil)
		}
		chunk := msg.GetResultRows()
		if c.columns == nil {
			c.columns = chunk.GetColumns()
		}
		expectedWidth := len(c.columns)
		// Kotlin's `rows += chunk.rowsList.map { … }` is EAGER, so a bad row anywhere in the chunk
		// discards the whole chunk. Immaterial (the error propagates out) but reproduced by building the
		// chunk's rows before appending.
		chunkRows := make([][]*string, 0, len(chunk.GetRows()))
		for _, row := range chunk.GetRows() {
			if len(row.GetValues()) != expectedWidth {
				return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgWrongColumnCount, nil)
			}
			cells := make([]*string, 0, expectedWidth)
			for _, v := range row.GetValues() {
				if v.GetIsNull() {
					// 🔒 nil, never "" — conflating them would fall a NULL cell back to an empty string,
					// and the mask functions are string transforms that treat the two differently.
					cells = append(cells, nil)
					continue
				}
				value := v.GetValue()
				cells = append(cells, &value)
			}
			chunkRows = append(chunkRows, cells)
		}
		c.rows = append(c.rows, chunkRows...)
		return query.QueryResponse{}, false, nil

	case msg.GetDone() != nil:
		if c.decision == nil {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgDoneBeforeDecision, nil)
		}
		if !c.haveAction {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgDoneWithoutVerdict, nil)
		}
		if c.action == pb.EnfAction_DENY {
			return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgDoneAfterDeny, nil)
		}
		// `rowsAffected == -1 ⇒ null` — the wire's "not a DML statement" sentinel. A SELECT reports -1
		// and the field is then OMITTED from the JSON. Zero is a REAL answer and is preserved.
		var rowsAffected *int32
		if n := msg.GetDone().GetRowsAffected(); n != -1 {
			rowsAffected = &n
		}
		return c.s.response(ctx, c.decision, c.action, c.columns, c.rows, rowsAffected, started), true, nil

	case msg.GetError() != nil:
		// 🔒 INV-A7-31 — the PM_QUERY_TIMEOUT sentinel is matched EXACTLY, so a statement the proxy's
		// watchdog aborted is attributed as a timeout (→ query.proxy_timeout, task FAILED) and never as a
		// generic failure or a success.
		if msg.GetError().GetMessage() == QueryTimeoutMessage {
			return query.QueryResponse{}, true, query.ErrProxyRunTimeout
		}
		message := msg.GetError().GetMessage()
		if isBlank(message) {
			message = ErrMsgExecutionFailed
		}
		return query.QueryResponse{}, true, query.NewProxyRunError(message, nil)

	case msg.GetSessionReady() != nil:
		return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgSecondReady, nil)

	default:
		return query.QueryResponse{}, true, query.NewProxyRunError(ErrMsgEmptyMessage, nil)
	}
}

// response is `private fun response(...)` (RunExec.kt:618-640).
//
// `piiTouched` is looked up by RE-READING the audit row the per-statement Decide already wrote for this
// exact decisionId — the control plane does not recompute it, and a decisionId of 0 (the proto's
// "none") means there is no row to read and the list is empty.
func (s *Service) response(
	ctx context.Context, decision *pb.RunDecision, action pb.EnfAction,
	columns []string, rows [][]*string, rowsAffected *int32, started time.Time,
) query.QueryResponse {
	var decisionID *int64
	var piiTouched []string
	if id := decision.GetDecisionId(); id != 0 {
		decisionID = &id
		// A read failure is NOT fatal: the Kotlin's `core.auditStore.get(it)?.piiTouched ?: emptyList()`
		// treats an absent row as "no PII", and a Go error is the same absence. Logged, never raised —
		// failing a completed query because a metadata read hiccuped would lose the rows.
		if event, err := s.core.AuditStore.Get(ctx, id); err != nil {
			s.log.Warn("run response: audit lookup for piiTouched failed", "decision", id, "err", err)
		} else if event != nil {
			piiTouched = event.PIITouched
		}
	}
	var denyReason *string
	if r := decision.GetDenyReason(); !isBlank(r) {
		denyReason = &r
	}
	return query.QueryResponse{
		Decision:       query.WireEnfAction(action),
		DecisionID:     decisionID,
		DenyReason:     denyReason,
		MaskedColumns:  decision.GetMaskedColumns(),
		PIITouched:     piiTouched,
		EffectiveRoles: decision.GetEffectiveRoles(),
		Columns:        columns,
		Rows:           rows,
		RowsAffected:   rowsAffected,
		LatencyMs:      time.Since(started).Milliseconds(),
	}
}

// isBlank is Kotlin's `String.isBlank()` for the two `ifBlank` call sites above. internal/engine has
// the general helper; this package would import it for two uses, so it is local.
func isBlank(s string) bool {
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xA0:
		default:
			return false
		}
	}
	return true
}
