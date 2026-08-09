// Package run drives proxy-dialed control-plane channels over dedicated backend sessions.
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
	// How often the proxy heartbeats RunProgress while the backend cold-open is in flight. Must stay well
	// under the control-plane's no-progress bound (RunExec.RUN_NO_PROGRESS_TIMEOUT_MS) so ordinary jitter
	// never trips it — several missed beats still leave margin.
	progressInterval = 3 * time.Second
)

// QueryTimeoutMessage is the exact RunError message the proxy sends when a statement is aborted by the
// PM_QUERY_TIMEOUT watchdog. The control-plane matches it (RunExecService.QUERY_TIMEOUT_MESSAGE) to
// attribute the failure as a timeout (query.proxy_timeout) instead of a generic execution error — and,
// crucially, to never report a timed-out statement as a success: some backends (e.g. MySQL SLEEP) return
// a row when interrupted, so the watchdog's verdict, not the backend's, decides the outcome.
const QueryTimeoutMessage = "statement aborted: PM_QUERY_TIMEOUT exceeded"

var errQueryTimeout = errors.New(QueryTimeoutMessage)

type runStream = spi.RunStream

type backendFactory func(token string, connectionID []byte, guard engine.ExecGuard) (spi.BackendSession, error)

type Runner struct {
	client       spi.RunClient
	factory      backendFactory
	queryTimeout time.Duration
}

func NewRunner(client spi.RunClient, dbImpl engine.Db, backend spi.BackendTarget, provider spi.Provider, queryTimeout time.Duration) *Runner {
	if queryTimeout == 0 {
		queryTimeout = defaultQueryTimeout
	}
	readTimeout := queryTimeout + runSocketTimeoutGrace
	factory := func(token string, connectionID []byte, guard engine.ExecGuard) (spi.BackendSession, error) {
		return provider.NewRunSession(backend, dbImpl, client, token, connectionID, guard, readTimeout)
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
	// (cold, ~26s) backend open. The session id is the stream's first frame, so the control-plane attaches at
	// once and EVERY failure below is attributable to this run rather than an unmatched stream it must wait
	// out. RunProgress heartbeats keep its no-progress bound alive through the open; RunServing (below) then
	// tells it the backend is ready for the query.
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

	var sess spi.BackendSession
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
		// The watchdog fired: report a timeout regardless of what the backend returned, so an interrupted
		// statement is never surfaced as a completed one (the receive on cancelDone above orders this read
		// after the Store). timedOut is only ever set on that path, so an ordinary finish reads false.
		if timedOut.Load() {
			return errQueryTimeout
		}
		return err
	}
	if err := heartbeatDuring(stream, func() (openErr error) {
		sess, openErr = r.factory(open.Token, open.ConnectionID, guard)
		return
	}); err != nil {
		_ = sendError(stream, "backend connection failed: "+err.Error())
		r.closeConnection(open.SessionID, open.ConnectionID)
		return
	}
	defer sess.Close()
	defer r.closeConnection(open.SessionID, open.ConnectionID)
	if err := heartbeatDuring(stream, func() error { return sess.OnOpen(open.OnOpen) }); err != nil {
		_ = sendError(stream, "run catalog initialization failed: "+err.Error())
		return
	}
	if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Serving{Serving: &pb.RunServing{}}}) != nil {
		return
	}

	messages = receiveRunMessages(ctx, stream)
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

// heartbeatDuring runs work while emitting a RunProgress heartbeat on the stream every progressInterval, so a
// slow backend cold-open keeps the control-plane's no-progress bound alive. The heartbeat carries no payload —
// it only attests the PROXY is alive, not that the backend open advances, so the control-plane bounds a
// stalled-but-heartbeating open with an absolute ceiling, not this signal. For the span of work it is the ONLY
// sender on the stream — RunReady precedes it; RunServing/RunError follow only after it returns — and it JOINS
// its ticker before returning via defer, so even a panic in work stops the ticker before Run's deferred stream
// teardown runs (the gRPC stream is not safe for concurrent Send). A Send error from the ticker just stops the
// heartbeat; the caller's next Send surfaces the broken stream.
func heartbeatDuring(stream runStream, work func() error) error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Progress{Progress: &pb.RunProgress{}}}) != nil {
					return
				}
			}
		}
	}()
	defer func() { close(stop); <-done }()
	return work()
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

func (r *Runner) cancelSession(sess spi.BackendSession) {
	if err := sess.Cancel(); err != nil {
		slog.Warn("run query cancellation failed", "error", err)
	}
}

func (r *Runner) closeConnection(sessionID string, connectionID []byte) {
	if err := r.client.CloseConnection(connectionID); err != nil {
		slog.Warn("run connection close failed", "session_id", sessionID, "error", err)
	}
}

func (r *Runner) handleQuery(sess spi.BackendSession, stream runStream, query *pb.RunQuery) bool {
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
			EffectiveRoles: append([]string(nil), decision.EffectiveRoles...),
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
