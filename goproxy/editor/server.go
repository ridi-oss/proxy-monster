// Package editor drives proxy-dialed editor and table-detail sessions, each over its own target-DB connection.
package editor

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	defaultMaxRows, maxMaxRows, resultChunkSize = 500, 5000, 1000
	defaultQueryTimeout                         = 600 * time.Second
	socketTimeoutGrace                          = 30 * time.Second
	streamCloseDrainTimeout                     = 5 * time.Second
	// How often the proxy heartbeats EditorProgress while the target-DB open is in flight. Must stay well
	// under the control-plane's no-progress bound (EditorExec.EDITOR_NO_PROGRESS_TIMEOUT_MS) so ordinary jitter
	// never trips it — several missed beats still leave margin.
	progressInterval = 3 * time.Second
)

// QueryTimeoutMessage is the exact EditorError message the proxy sends when a statement is aborted by the
// PM_QUERY_TIMEOUT watchdog. The control-plane matches it (EditorExecService.QUERY_TIMEOUT_MESSAGE) to
// attribute the failure as a timeout (query.proxy_timeout) instead of a generic execution error — and,
// crucially, to never report a timed-out statement as a success: some target DBs (e.g. MySQL SLEEP) return
// a row when interrupted, so the watchdog's verdict, not the target DB's, decides the outcome.
const QueryTimeoutMessage = "statement aborted: PM_QUERY_TIMEOUT exceeded"

var errQueryTimeout = errors.New(QueryTimeoutMessage)

type editorStream = spi.EditorStream

// Server joins the target and the control-plane client: registration and catalog pushes, editor sessions, and
// table detail.
type Server struct {
	client        spi.ControlPlane
	target        spi.Target
	queryTimeout  time.Duration
	readTimeout   time.Duration
	registerSlots chan struct{}
	refreshBatch  atomic.Pointer[refreshBatch]
}

func NewServer(client spi.ControlPlane, target spi.Target, queryTimeout time.Duration) *Server {
	if queryTimeout == 0 {
		queryTimeout = defaultQueryTimeout
	}
	return &Server{client: client, target: target, queryTimeout: queryTimeout, readTimeout: queryTimeout + socketTimeoutGrace, registerSlots: make(chan struct{}, maxResyncConcurrency)}
}

// Serve drives one proxy-dialed editor stream to completion. draining is closed by shutdown: when it is and no
// statement is in flight, Serve returns so the control-plane session closes and the editor re-homes to the
// replacement — mirroring how the wire server lets an idle connection go on drain. A statement already
// executing is never interrupted; the drain is only observed between statements. A nil channel never fires.
func (s *Server) Serve(req *pb.OpenEditorSession, draining <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := s.client.OpenEditorStream(ctx)
	if err != nil {
		slog.Warn("editor stream open failed", "session_id", req.GetSessionId(), "error", err)
		return
	}
	var messages <-chan *pb.CpEditorMsg
	defer func() { gracefulCloseStream(ctx, stream, messages) }()
	// Tell the control-plane which session this stream serves immediately — before admitting the connection or the
	// (~26s) target-DB open. The session id is the stream's first frame, so the control-plane attaches at
	// once and EVERY failure below is attributable to this editor session rather than an unmatched stream it must wait
	// out. EditorProgress heartbeats keep its no-progress bound alive through the open; EditorServing (below) then
	// tells it the target DB is ready for the query.
	ready := &pb.EditorReady{SessionId: req.GetSessionId()}
	if stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_SessionReady{SessionReady: ready}}) != nil {
		return
	}

	authz, identity, err := spi.Authenticate(s.client, req.GetEphemeralToken(), "", pb.ConnectionDoor_CONNECTION_DOOR_EDITOR)
	if err != nil {
		_ = sendError(stream, "editor session admission failed: "+err.Error())
		return
	}
	defer authz.Close()

	var connection spi.Connection
	guard := func(exec func() error) error {
		cancelDone := make(chan struct{})
		var timedOut atomic.Bool
		timer := time.AfterFunc(s.queryTimeout, func() {
			timedOut.Store(true)
			if err := connection.Cancel(); err != nil {
				slog.Warn("editor query cancellation failed", "error", err)
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
	// Read the inbound before the (~26s) target-DB open — not after EditorServing — so an EditorClose the
	// control-plane sends during the open, or a drain, aborts it instead of finishing a target-DB handshake for
	// an editor session nobody is waiting for.
	messages = receiveEditorMessages(ctx, stream)
	var namespace *enginepb.Namespace
	connection, namespace = s.openTargetDb(ctx, stream, messages, draining, req, authz, identity.OnOpen, guard)
	if connection == nil {
		// The open failed (EditorError already sent) or was aborted by an early EditorClose / drain.
		return
	}
	defer connection.Close()
	if stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Serving{Serving: &pb.EditorServing{Namespace: namespace}}}) != nil {
		return
	}

	// A query that arrives after a statement's EditorDone went out but before its handler reported back is the
	// next statement, not a concurrent one: hold it rather than drop it.
	var pending *pb.CpEditorMsg
	for {
		var message *pb.CpEditorMsg
		var ok bool
		if pending != nil {
			message, ok, pending = pending, true, nil
		} else {
			select {
			case <-draining:
				// Idle between statements while shutting down: stop so the session ends and the editor re-homes.
				return
			case message, ok = <-messages:
			}
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
		go func() { queryDone <- s.handleQuery(connection, stream, query, guard) }()
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
					s.cancelConnection(connection)
					<-queryDone
					return
				}
				switch {
				case message.GetCancel() != nil:
					s.cancelConnection(connection)
				case message.GetQuery() != nil:
					if pending != nil {
						slog.Warn("editor query received while another query is already queued; ignoring")
						continue
					}
					pending = message
				}
			}
		}
	}
}

// openTargetDb dials + authenticates the target DB and runs the on-open catalog fetch, while keeping the editor stream
// alive with EditorProgress heartbeats and concurrently watching the inbound and the drain. It returns the ready
// session, or nil if the open failed or was aborted (for a genuine target-DB failure, after sending the
// EditorError), so the caller only sends EditorServing.
//
// The open runs in its own goroutine under a cancellable child context — the ONLY writer to that context —
// while this loop is the ONLY sender on the stream (the heartbeat), so neither the gRPC stream nor the open
// contends. An early EditorClose (the browser navigated away before the target DB was ready), a closed or broken
// stream, or a drain cancels the child context and returns at once; the in-flight target DB dial / auth /
// catalog reads unwind on the cancel rather than finishing a handshake for an editor session nobody is waiting for, and
// the open is reaped in the background (see abort). A close or drain that lands just as the open completes
// still fails the open (the post-completion re-check) so a live session is never installed on an abandoned
// editor session or a departing proxy — the editor re-homes to the replacement rather than onto a stream about to die.
func (s *Server) openTargetDb(ctx context.Context, stream editorStream, messages <-chan *pb.CpEditorMsg, draining <-chan struct{}, req *pb.OpenEditorSession, authz *spi.Authorizer, onOpen []*pb.ProxyCommand, guard spi.ExecGuard) (spi.Connection, *enginepb.Namespace) {
	openCtx, cancelOpen := context.WithCancel(ctx)
	defer cancelOpen()

	type openResult struct {
		connection spi.Connection
		namespace  *enginepb.Namespace
		err        error
		errWhat    string
	}
	done := make(chan openResult, 1)
	go func() {
		connection, err := s.target.OpenConnection(openCtx, authz, guard, s.readTimeout, req.GetDefaultSchema())
		if err != nil {
			done <- openResult{err: err, errWhat: "target-DB connection failed: "}
			return
		}
		if err := connection.OnOpen(openCtx, onOpen); err != nil {
			done <- openResult{connection: connection, err: err, errWhat: "editor session catalog initialization failed: "}
			return
		}
		// Read inside the open so the heartbeat and an early close still cover it.
		done <- openResult{connection: connection, namespace: connectionNamespace(connection, nil)}
	}()

	// abort cancels the in-flight open and reaps it in the background. The cancel unwinds the target DB
	// dial/auth/catalog reads at once; a catalog push RPC to the control-plane is not cancellable here and runs
	// to its own deadline, so the reap runs off the hot path rather than making the drain/close wait it out.
	abort := func() (spi.Connection, *enginepb.Namespace) {
		cancelOpen()
		go func() {
			if res := <-done; res.connection != nil {
				_ = res.connection.Close()
			}
		}()
		return nil, nil
	}

	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case res := <-done:
			if res.err != nil {
				_ = sendError(stream, res.errWhat+res.err.Error())
				if res.connection != nil {
					_ = res.connection.Close()
				}
				return nil, nil
			}
			// The open finished, but a close or drain that landed during it must not put a live session on an
			// abandoned editor session or a departing proxy: re-check both before serving. The open is complete here (no
			// push in flight), so this cleanup is synchronous.
			if abandonedDuringOpen(messages, draining) {
				_ = res.connection.Close()
				return nil, nil
			}
			return res.connection, res.namespace
		case <-ticker.C:
			// The heartbeat carries no payload — it attests the PROXY is alive, not that the open advances,
			// so the control-plane bounds a stalled-but-heartbeating open with an absolute ceiling. A Send
			// error means the stream is gone: abort the open rather than heartbeat into a dead stream.
			if stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Progress{Progress: &pb.EditorProgress{}}}) != nil {
				return abort()
			}
		case message, ok := <-messages:
			if !ok || message.GetClose() != nil {
				return abort()
			}
			// A Query or Cancel before EditorServing is outside the protocol during a target-DB open (the CP sends a
			// query only after it observes EditorServing); log it so a CP regression is visible, and ignore it.
			slog.Warn("editor session received a control message before EditorServing; ignoring", "session_id", req.GetSessionId())
		case <-draining:
			return abort()
		}
	}
}

// abandonedDuringOpen reports, without blocking, whether the editor session was closed or the proxy drained during the
// target-DB open — checked once the open completes, before serving, so a live session is never installed on an
// abandoned editor session or a departing proxy. A pending EditorClose, a closed stream, or a closed drain all count. A
// pre-serving Query/Cancel cannot occur (the CP sends a query only after EditorServing), so any other message is
// dropped rather than carried into the serving loop. The drain is checked first in its own select: a single
// select over both would let the message arm win by chance while the drain is also ready, and Go's fairness
// would then serve onto a departing proxy.
func abandonedDuringOpen(messages <-chan *pb.CpEditorMsg, draining <-chan struct{}) bool {
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

func receiveEditorMessages(ctx context.Context, stream editorStream) <-chan *pb.CpEditorMsg {
	messages := make(chan *pb.CpEditorMsg)
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

func (s *Server) cancelConnection(connection spi.Connection) {
	if err := connection.Cancel(); err != nil {
		slog.Warn("editor query cancellation failed", "error", err)
	}
}

func (s *Server) handleQuery(connection spi.Connection, stream editorStream, query *pb.EditorQuery, guard spi.ExecGuard) bool {
	maxRows := int(query.GetMaxRows())
	if maxRows == 0 {
		maxRows = defaultMaxRows
	}
	maxRows = min(max(maxRows, 1), maxMaxRows)
	result, err := connection.ServeStatement(query.GetSql(), maxRows)
	if err != nil {
		var fail relay.FailError
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
		var targetDbErr relay.TargetDbError
		if errors.As(err, &targetDbErr) {
			// The only failure the CP may surface as errorDetail: the target DB's own ERR for the executed
			// statement. Send BOTH forms (raw + redacted) so the CP re-gates it per viewer at view.
			return sendTargetDbError(stream, targetDbErr.Message, targetDbErr.Redacted)
		}
		message := "query execution failed: " + err.Error()
		if errors.Is(err, relay.ErrMaskUnbound) {
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
	done := &pb.EditorDone{RowsAffected: int32(result.RowsAffected), TruncatedByCap: result.TruncatedByCap, Namespace: connectionNamespace(connection, guard)}
	return stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Done{Done: done}}) == nil
}

// sessionNamespace returns nil when the read fails or outlasts guard. Authorization never uses it.
func connectionNamespace(connection spi.Connection, guard spi.ExecGuard) *enginepb.Namespace {
	var catalog string
	var searchPath []string
	read := func() (err error) {
		catalog, searchPath, err = connection.Namespace()
		return err
	}
	var err error
	if guard != nil {
		err = guard(read)
	} else {
		err = read()
	}
	if err != nil {
		slog.Warn("editor connection namespace probe failed", "error", err)
		return nil
	}
	return &enginepb.Namespace{Catalog: catalog, SearchPath: searchPath}
}

func sendDecision(stream editorStream, decision *spi.Decision) bool {
	if decision == nil {
		return false
	}
	action := relay.ParseEnfActionName(decision.Action)
	maskedColumns := make([]string, 0, len(decision.Masks))
	for _, mask := range decision.Masks {
		maskedColumns = append(maskedColumns, mask.GetColumn())
	}
	return stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Decision{
		Decision: &pb.EditorDecision{
			Decision:            action,
			DecisionId:          decision.DecisionID,
			MaskedColumns:       maskedColumns,
			DenyReason:          decision.DenyReason,
			DenyCode:            decision.DenyCode,
			EffectiveRoles:      append([]string(nil), decision.EffectiveRoles...),
			SanitizeDiagnostics: decision.SanitizeDiagnostics,
			MaxRows:             decision.MaxRows,
			MaxBytes:            decision.MaxBytes,
			ResultRequirements:  decision.ResultRequirements,
		},
	}}) == nil
}

func sendRows(stream editorStream, columns []string, rows [][]*string) bool {
	for start := 0; ; {
		end := min(start+resultChunkSize, len(rows))
		wireRows := make([]*pb.EditorRow, end-start)
		for i, row := range rows[start:end] {
			values := make([]*pb.EditorValue, len(row))
			for j, value := range row {
				values[j] = &pb.EditorValue{IsNull: value == nil}
				if value != nil {
					values[j].Value = *value
				}
			}
			wireRows[i] = &pb.EditorRow{Values: values}
		}
		resultRows := &pb.EditorResultRows{Columns: append([]string(nil), columns...), Rows: wireRows}
		if stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_ResultRows{ResultRows: resultRows}}) != nil {
			return false
		}
		if end == len(rows) {
			return true
		}
		start = end
	}
}

// sendError sends a terminal EditorError whose provenance is NOT a target-DB statement ERR — every
// proxy/decode/decision/mask-binding failure — so target_db_error stays false and the CP keeps it generic.
func sendError(stream editorStream, message string) bool {
	_ = stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Error{Error: &pb.EditorError{Message: message}}})
	return false
}

// sendTargetDbError sends the target DB's own ERR for the executed statement — the ONLY provenance the CP may
// surface as a query's error detail. Message carries the value-free redacted form (the CP's safe default);
// raw_message carries the raw text, released only to a viewer who reads unmasked. Both travel so the CP
// re-gates per viewer at view time.
func sendTargetDbError(stream editorStream, raw, redacted string) bool {
	payload := &pb.EditorError{Message: redacted, TargetDbError: true, RawMessage: raw}
	_ = stream.Send(&pb.ProxyEditorMsg{Kind: &pb.ProxyEditorMsg_Error{Error: payload}})
	return false
}

func gracefulCloseStream(ctx context.Context, stream editorStream, messages <-chan *pb.CpEditorMsg) {
	_ = stream.CloseSend()
	if messages == nil {
		messages = receiveEditorMessages(ctx, stream)
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
