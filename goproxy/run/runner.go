// Package run drives proxy-dialed control-plane channels over dedicated target-DB sessions.
package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	defaultMaxRows, maxMaxRows, resultChunkSize = 500, 5000, 1000
	defaultQueryTimeout                         = 600 * time.Second
	runSocketTimeoutGrace                       = 30 * time.Second
	streamCloseDrainTimeout                     = 5 * time.Second
	// How often the proxy heartbeats RunProgress while the target-DB open is in flight. Must stay well
	// under the control-plane's no-progress bound (RunExec.RUN_NO_PROGRESS_TIMEOUT_MS) so ordinary jitter
	// never trips it — several missed beats still leave margin.
	progressInterval = 3 * time.Second
)

// QueryTimeoutMessage is the exact RunError message the proxy sends when a statement is aborted by the
// PM_QUERY_TIMEOUT watchdog. The control-plane matches it (RunExecService.QUERY_TIMEOUT_MESSAGE) to
// attribute the failure as a timeout (query.proxy_timeout) instead of a generic execution error — and,
// crucially, to never report a timed-out statement as a success: some target DBs (e.g. MySQL SLEEP) return
// a row when interrupted, so the watchdog's verdict, not the target DB's, decides the outcome.
const QueryTimeoutMessage = "statement aborted: PM_QUERY_TIMEOUT exceeded"

var errQueryTimeout = errors.New(QueryTimeoutMessage)

type runStream = spi.RunStream

type targetDbFactory func(ctx context.Context, token string, connectionID []byte, guard engine.ExecGuard) (spi.TargetDbSession, error)

type Runner struct {
	client       spi.RunClient
	factory      targetDbFactory
	queryTimeout time.Duration
}

func NewRunner(client spi.RunClient, dbImpl engine.Db, targetDb spi.TargetDb, provider spi.Provider, queryTimeout time.Duration) *Runner {
	if queryTimeout == 0 {
		queryTimeout = defaultQueryTimeout
	}
	readTimeout := queryTimeout + runSocketTimeoutGrace
	factory := func(ctx context.Context, token string, connectionID []byte, guard engine.ExecGuard) (spi.TargetDbSession, error) {
		return provider.NewRunSession(ctx, targetDb, dbImpl, client, token, connectionID, guard, readTimeout)
	}
	return &Runner{client: client, factory: factory, queryTimeout: queryTimeout}
}

// Run drives one proxy-dialed run stream to completion. draining is closed by shutdown: when it is and no
// statement is in flight, Run returns so the control-plane session closes and the editor re-homes to the
// replacement — mirroring how the wire server lets an idle connection go on drain. A statement already
// executing is never interrupted; the drain is only observed between statements. A nil channel never fires.
func (r *Runner) Run(open spi.RunOpen, draining <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := r.client.OpenRunStream(ctx)
	if err != nil {
		slog.Warn("run stream open failed", "session_id", open.SessionID, "error", err)
		return
	}
	var messages <-chan *pb.ControlRunMsg
	defer func() { gracefulCloseStream(ctx, stream, messages) }()
	// Tell the control-plane which run this stream serves immediately — before validating the open or the
	// (~26s) target-DB open. The session id is the stream's first frame, so the control-plane attaches at
	// once and EVERY failure below is attributable to this run rather than an unmatched stream it must wait
	// out. RunProgress heartbeats keep its no-progress bound alive through the open; RunServing (below) then
	// tells it the target DB is ready for the query.
	ready := &pb.RunReady{SessionId: open.SessionID}
	if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_SessionReady{SessionReady: ready}}) != nil {
		return
	}

	if open.MapErr != nil || len(open.ConnectionID) != 16 {
		if open.MapErr == nil {
			open.MapErr = fmt.Errorf("connection_id is %d bytes, want 16", len(open.ConnectionID))
		}
		_ = sendError(stream, "invalid run open: "+open.MapErr.Error())
		if len(open.ConnectionID) == 16 {
			r.closeConnection(open.SessionID, open.ConnectionID)
		}
		return
	}

	var sess spi.TargetDbSession
	guard := func(exec func() error) error {
		cancelDone := make(chan struct{})
		var timedOut atomic.Bool
		timer := time.AfterFunc(r.queryTimeout, func() {
			timedOut.Store(true)
			if err := sess.Cancel(); err != nil {
				slog.Warn("run query cancellation failed", "error", err)
			}
			close(cancelDone)
		})
		err := exec()
		if !timer.Stop() {
			<-cancelDone
		}
		// The watchdog fired: report a timeout regardless of what the target DB returned, so an interrupted
		// statement is never surfaced as a completed one (the receive on cancelDone above orders this read
		// after the Store). timedOut is only ever set on that path, so an ordinary finish reads false.
		if timedOut.Load() {
			return errQueryTimeout
		}
		return err
	}
	// Read the inbound before the (~26s) target-DB open — not after RunServing — so a RunClose the
	// control-plane sends during the open, or a drain, aborts it instead of finishing a target-DB handshake for
	// a run nobody is waiting for.
	messages = receiveRunMessages(ctx, stream)
	sess = r.openTargetDb(ctx, stream, messages, draining, open, guard)
	if sess == nil {
		// The open failed (RunError already sent) or was aborted by an early RunClose / drain. openTargetDb owns
		// the cleanup: a failure releases the connection before returning, while an abort reaps the cancelled
		// open and releases the connection in the background (see abort) so the drain/close returns at once.
		return
	}
	defer sess.Close()
	defer r.closeConnection(open.SessionID, open.ConnectionID)
	if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Serving{Serving: &pb.RunServing{}}}) != nil {
		return
	}

	for {
		var message *pb.ControlRunMsg
		var ok bool
		select {
		case <-draining:
			// Idle between statements while shutting down: stop so the session ends and the editor re-homes.
			return
		case message, ok = <-messages:
		}
		if !ok || message.GetClose() != nil {
			return
		}
		if message.GetCancel() != nil {
			continue
		}
		query := message.GetQuery()
		if query == nil {
			continue
		}
		// Drain takes priority over a query that raced in with it: the outer select can pick the message even
		// after draining closed (Go picks randomly when both are ready), so re-check and stop rather than begin
		// a new statement on a departing proxy.
		select {
		case <-draining:
			return
		default:
		}

		queryDone := make(chan bool, 1)
		go func() { queryDone <- r.handleQuery(sess, stream, query) }()
	queryInFlight:
		for {
			select {
			case keepRunning := <-queryDone:
				if !keepRunning {
					return
				}
				break queryInFlight
			case message, ok := <-messages:
				if !ok || message.GetClose() != nil {
					r.cancelSession(sess)
					<-queryDone
					return
				}
				switch {
				case message.GetCancel() != nil:
					r.cancelSession(sess)
				case message.GetQuery() != nil:
					slog.Warn("run query received while another query is in flight; ignoring")
				}
			}
		}
	}
}

// openTargetDb dials + authenticates the target DB and runs the on-open catalog fetch, while keeping the run stream
// alive with RunProgress heartbeats and concurrently watching the inbound and the drain. It returns the ready
// session, or nil if the open failed or was aborted; on every nil return it has already released the reserved
// connection (and, for a genuine target-DB failure, sent the RunError), so the caller only sends RunServing.
//
// The open runs in its own goroutine under a cancellable child context — the ONLY writer to that context —
// while this loop is the ONLY sender on the stream (the heartbeat), so neither the gRPC stream nor the open
// contends. An early RunClose (the browser navigated away before the target DB was ready), a closed or broken
// stream, or a drain cancels the child context and returns at once; the in-flight target DB dial / auth /
// catalog reads unwind on the cancel rather than finishing a handshake for a run nobody is waiting for, and
// the open is reaped in the background (see abort). A close or drain that lands just as the open completes
// still fails the open (the post-completion re-check) so a live session is never installed on an abandoned
// run or a departing proxy — the editor re-homes to the replacement rather than onto a stream about to die.
func (r *Runner) openTargetDb(ctx context.Context, stream runStream, messages <-chan *pb.ControlRunMsg, draining <-chan struct{}, open spi.RunOpen, guard engine.ExecGuard) spi.TargetDbSession {
	openCtx, cancelOpen := context.WithCancel(ctx)
	defer cancelOpen()

	type openResult struct {
		sess    spi.TargetDbSession
		err     error
		errWhat string
	}
	done := make(chan openResult, 1)
	go func() {
		sess, err := r.factory(openCtx, open.Token, open.ConnectionID, guard)
		if err != nil {
			done <- openResult{err: err, errWhat: "target-DB connection failed: "}
			return
		}
		if err := sess.OnOpen(openCtx, open.OnOpen); err != nil {
			done <- openResult{sess: sess, err: err, errWhat: "run catalog initialization failed: "}
			return
		}
		done <- openResult{sess: sess}
	}()

	// abort cancels the in-flight open and, in the background, reaps it and releases the reserved connection.
	// The cancel unwinds the target DB dial/auth/catalog reads at once; a catalog push RPC to the control-plane
	// is not cancellable here and runs to its own deadline, so the reap runs off the hot path rather than
	// making the drain/close wait out that deadline (and the follow-on connection-release RPC).
	abort := func() spi.TargetDbSession {
		cancelOpen()
		go func() {
			res := <-done
			if res.sess != nil {
				_ = res.sess.Close()
			}
			r.closeConnection(open.SessionID, open.ConnectionID)
		}()
		return nil
	}

	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case res := <-done:
			if res.err != nil {
				_ = sendError(stream, res.errWhat+res.err.Error())
				if res.sess != nil {
					_ = res.sess.Close()
				}
				r.closeConnection(open.SessionID, open.ConnectionID)
				return nil
			}
			// The open finished, but a close or drain that landed during it must not put a live session on an
			// abandoned run or a departing proxy: re-check both before serving. The open is complete here (no
			// push in flight), so this cleanup is synchronous.
			if abandonedDuringOpen(messages, draining) {
				_ = res.sess.Close()
				r.closeConnection(open.SessionID, open.ConnectionID)
				return nil
			}
			return res.sess
		case <-ticker.C:
			// The heartbeat carries no payload — it attests the PROXY is alive, not that the open advances,
			// so the control-plane bounds a stalled-but-heartbeating open with an absolute ceiling. A Send
			// error means the stream is gone: abort the open rather than heartbeat into a dead stream.
			if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Progress{Progress: &pb.RunProgress{}}}) != nil {
				return abort()
			}
		case message, ok := <-messages:
			if !ok || message.GetClose() != nil {
				return abort()
			}
			// A Query or Cancel before RunServing is outside the protocol during a target-DB open (the CP sends a
			// query only after it observes RunServing); log it so a CP regression is visible, and ignore it.
			slog.Warn("run received a control message before RunServing; ignoring", "session_id", open.SessionID)
		case <-draining:
			return abort()
		}
	}
}

// abandonedDuringOpen reports, without blocking, whether the run was closed or the proxy drained during the
// target-DB open — checked once the open completes, before serving, so a live session is never installed on an
// abandoned run or a departing proxy. A pending RunClose, a closed stream, or a closed drain all count. A
// pre-serving Query/Cancel cannot occur (the CP sends a query only after RunServing), so any other message is
// dropped rather than carried into the serving loop. The drain is checked first in its own select: a single
// select over both would let the message arm win by chance while the drain is also ready, and Go's fairness
// would then serve onto a departing proxy.
func abandonedDuringOpen(messages <-chan *pb.ControlRunMsg, draining <-chan struct{}) bool {
	select {
	case <-draining:
		return true
	default:
	}
	select {
	case message, ok := <-messages:
		return !ok || message.GetClose() != nil
	default:
		return false
	}
}

func receiveRunMessages(ctx context.Context, stream runStream) <-chan *pb.ControlRunMsg {
	messages := make(chan *pb.ControlRunMsg)
	go func() {
		defer close(messages)
		for {
			message, err := stream.Recv()
			if err != nil {
				return
			}
			// Select on ctx so a message arriving just as the drainer stops (Run returned,
			// gracefulCloseStream's timer fired) cannot leave this goroutine parked forever on the
			// send: Run's deferred cancel() runs after gracefulCloseStream and unblocks it here.
			select {
			case messages <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	return messages
}

func (r *Runner) cancelSession(sess spi.TargetDbSession) {
	if err := sess.Cancel(); err != nil {
		slog.Warn("run query cancellation failed", "error", err)
	}
}

func (r *Runner) closeConnection(sessionID string, connectionID []byte) {
	if err := r.client.CloseConnection(connectionID); err != nil {
		slog.Warn("run connection close failed", "session_id", sessionID, "error", err)
	}
}

func (r *Runner) handleQuery(sess spi.TargetDbSession, stream runStream, query *pb.RunQuery) bool {
	maxRows := int(query.GetMaxRows())
	if maxRows == 0 {
		maxRows = defaultMaxRows
	}
	maxRows = min(max(maxRows, 1), maxMaxRows)
	result, err := sess.ServeStatement(query.GetSql(), maxRows)
	if err != nil {
		var fail engine.FailError
		if errors.As(err, &fail) {
			return sendError(stream, "decision failed: "+fail.Message)
		}
		if result.Decision != nil && !sendDecision(stream, result.Decision) {
			return false
		}
		if errors.Is(err, errQueryTimeout) {
			// Send the exact sentinel so the CP attributes a PM_QUERY_TIMEOUT abort, not a generic failure.
			return sendError(stream, QueryTimeoutMessage)
		}
		message := "query execution failed: " + err.Error()
		if errors.Is(err, engine.ErrMaskUnbound) {
			message = "mask binding failed: " + err.Error()
		}
		return sendError(stream, message)
	}
	if result.Denied {
		return sendDecision(stream, result.Decision)
	}
	if !sendDecision(stream, result.Decision) || !sendRows(stream, result.Columns, result.Rows) {
		return false
	}
	done := &pb.RunDone{RowsAffected: int32(result.RowsAffected)}
	return stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Done{Done: done}}) == nil
}

func sendDecision(stream runStream, decision *engine.Decision) bool {
	if decision == nil {
		return false
	}
	action := engine.ParseEnfActionName(decision.Action)
	maskedColumns := make([]string, 0, len(decision.Masks))
	for _, mask := range decision.Masks {
		maskedColumns = append(maskedColumns, mask.GetColumn())
	}
	return stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Decision{
		Decision: &pb.RunDecision{
			Decision:       action,
			DecisionId:     decision.DecisionID,
			MaskedColumns:  maskedColumns,
			DenyReason:     decision.DenyReason,
			EffectiveRoles:    append([]string(nil), decision.EffectiveRoles...),
			ResultFingerprint: decision.ResultFingerprint,
		},
	}}) == nil
}

func sendRows(stream runStream, columns []string, rows [][]*string) bool {
	for start := 0; ; {
		end := min(start+resultChunkSize, len(rows))
		wireRows := make([]*pb.RunRow, end-start)
		for i, row := range rows[start:end] {
			values := make([]*pb.RunValue, len(row))
			for j, value := range row {
				values[j] = &pb.RunValue{IsNull: value == nil}
				if value != nil {
					values[j].Value = *value
				}
			}
			wireRows[i] = &pb.RunRow{Values: values}
		}
		resultRows := &pb.RunResultRows{Columns: append([]string(nil), columns...), Rows: wireRows}
		if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_ResultRows{ResultRows: resultRows}}) != nil {
			return false
		}
		if end == len(rows) {
			return true
		}
		start = end
	}
}

func sendError(stream runStream, message string) bool {
	payload := &pb.RunError{Message: message}
	_ = stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Error{Error: payload}})
	return false
}

func gracefulCloseStream(ctx context.Context, stream runStream, messages <-chan *pb.ControlRunMsg) {
	_ = stream.CloseSend()
	if messages == nil {
		messages = receiveRunMessages(ctx, stream)
	}
	timer := time.NewTimer(streamCloseDrainTimeout)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-messages:
			if !ok {
				return
			}
		case <-timer.C:
			return
		}
	}
}
