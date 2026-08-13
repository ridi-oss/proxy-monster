package pgproxy

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// isCleanExecuteTerminal reports whether an extended-protocol Execute ended without a target-DB error: a
// CommandComplete (statement done), an EmptyQueryResponse (empty statement), or a PortalSuspended (a
// row-limited Execute that stopped with more rows pending) are all clean; an ErrorResponse is not.
func isCleanExecuteTerminal(terminal pgproto3.BackendMessage) bool {
	switch terminal.(type) {
	case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
		return true
	default:
		return false
	}
}

var extendedProbeSequence atomic.Uint64

// preparedStatement stores only the SQL confirmed by ParseComplete. PostgreSQL resolves and plans a
// portal under the search_path in force at Bind: plancache revalidation can re-resolve a named statement
// whose path changed after Parse (verified against PostgreSQL 16). Therefore Parse never freezes the
// authorization context and no control-plane decision is stored (docs/datasource-registration.md).
type preparedStatement struct {
	sql string
}

// boundPortal snapshots the namespace and temporary-column context immediately before its confirmed Bind.
// Every Execute re-decides the portal SQL against this snapshot, matching PostgreSQL's resolution point.
// This is the PostgreSQL analog of MySQL's Prepare-time freeze (goproxy/mysqlproxy/stmt.go). Capturing the
// context at Bind (rather than refusing a Parse-to-Bind path drift) lets the probe-always model authorize
// the true Bind context with a fail-closed guarantee. No decision is ever stored.
type boundPortal struct {
	sql       string
	namespace []string
	temps     []engine.TempColumn
	binary    bool
}

func renderExtendedVerdict(sess *session, verdict engine.Verdict) (engine.Proceed, bool, error) {
	switch verdict := verdict.(type) {
	case engine.Fail:
		sess.skipToSync = true
		err := sendError(sess.client, "ERROR", "58000", "proxy-monster: "+verdict.Message, false, 0)
		return engine.Proceed{}, false, err
	case engine.Deny:
		reason := "policy"
		if verdict.Decision != nil && verdict.Decision.DenyReason != "" {
			reason = verdict.Decision.DenyReason
		}
		sess.skipToSync = true
		err := sendError(sess.client, "ERROR", "42501", "proxy-monster denied: "+reason, false, 0)
		return engine.Proceed{}, false, err
	case engine.Proceed:
		return verdict, true, nil
	default:
		return engine.Proceed{}, false, errors.New("pgproxy: engine returned an unknown verdict")
	}
}

func refuseExtended(sess *session, code, message string) error {
	sess.skipToSync = true
	return sendError(sess.client, "ERROR", code, "proxy-monster: "+message, false, 0)
}

func (s *Server) awaitExtendedCompletion(sess *session, isTerminal func(pgproto3.BackendMessage) bool) (pgproto3.BackendMessage, error) {
	for {
		message, err := sess.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(sess, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(sess, message)
		case *pgproto3.NotificationResponse:
			sess.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.ParameterDescription:
			sess.client.Send(message)
		default:
			if !isTerminal(message) {
				return nil, failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB extended response %T", message))
			}
			if errMsg, failed := message.(*pgproto3.ErrorResponse); failed {
				forwardError(sess, errMsg)
				sess.skipToSync = true
			} else {
				sess.client.Send(message)
			}
			return message, nil
		}
	}
}

func (s *Server) handleParse(sess *session, message *pgproto3.Parse) error {
	// Parse always authorizes against the live namespace. Lockstep has drained every earlier response,
	// so pgx.Batch cannot interleave this injected simple-query probe with extended frames. Outside an
	// explicit transaction the probe can commit the batch's implicit transaction early; that is a
	// deliberate fail-safe deviation (an extra probe, never a skipped one). In an aborted transaction,
	// the probe fails and produces a fail-safe 58000 refusal before PostgreSQL's equivalent 25P02 Parse.
	sess.qe.MarkNamespaceDirty()
	sess.pendingDirty = false
	verdict := sess.qe.Authorize(sess.authzInput(message.Query, sess.token, sess.clientAddr, sess.connectionID, s.refetcher(sess, true).RunAll))
	proceed, allowed, err := renderExtendedVerdict(sess, verdict)
	if err != nil || !allowed {
		return err
	}
	if proceed.Decision == nil {
		return refuseExtended(sess, "58000", "control plane returned no decision")
	}
	// Parse has no statement effect, so its after_statement commands are deliberately not fired.

	sentSQL := message.Query
	if proceed.RewrittenSQL != nil {
		sentSQL = *proceed.RewrittenSQL
	}
	sess.targetDb.Send(&pgproto3.Parse{Name: message.Name, Query: sentSQL, ParameterOIDs: message.ParameterOIDs})
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(sess, func(message pgproto3.BackendMessage) bool {
		switch message.(type) {
		case *pgproto3.ParseComplete, *pgproto3.ErrorResponse:
			return true
		default:
			return false
		}
	})
	if err != nil {
		return err
	}
	if _, complete := terminal.(*pgproto3.ParseComplete); complete {
		sess.statements[message.Name] = preparedStatement{sql: sentSQL}
	}
	return sess.client.Flush()
}

func (s *Server) handleBind(sess *session, message *pgproto3.Bind) error {
	statement, ok := sess.statements[message.PreparedStatement]
	if !ok {
		return refuseExtended(sess, "26000", "Bind references an unknown or denied prepared statement")
	}
	binary := false
	for _, code := range message.ResultFormatCodes {
		if code == 1 {
			binary = true
			break
		}
	}

	// Capture immediately before forwarding: the lockstep single writer guarantees nothing executes on the
	// target DB between this probe and Bind, so the captured context is exactly the one PostgreSQL binds under.
	// Probing first also leaves no registry/target DB inconsistency if capture fails. An aborted transaction
	// fails here before PostgreSQL's equivalent 25P02 Bind, retaining the prior portal snapshot and target DB portal.
	namespace, temps, err := s.probeBindContext(sess)
	if err != nil {
		if errors.Is(err, errClientEncoding) || errors.Is(err, errStdConformingStrings) {
			return err
		}
		return refuseExtended(sess, "58000", "bind-time namespace unavailable")
	}

	sess.targetDb.Send(message)
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(sess, func(message pgproto3.BackendMessage) bool {
		switch message.(type) {
		case *pgproto3.BindComplete, *pgproto3.ErrorResponse:
			return true
		default:
			return false
		}
	})
	if err != nil {
		return err
	}
	if _, complete := terminal.(*pgproto3.BindComplete); complete {
		sess.portals[message.DestinationPortal] = boundPortal{
			sql:       statement.sql,
			namespace: namespace,
			temps:     temps,
			binary:    binary,
		}
	}
	return sess.client.Flush()
}

func (s *Server) handleDescribe(sess *session, message *pgproto3.Describe) error {
	sess.targetDb.Send(message)
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	_, err := s.awaitExtendedCompletion(sess, func(message pgproto3.BackendMessage) bool {
		switch message.(type) {
		case *pgproto3.RowDescription, *pgproto3.NoData, *pgproto3.ErrorResponse:
			return true
		default:
			return false
		}
	})
	if err != nil {
		return err
	}
	return sess.client.Flush()
}

func (s *Server) runExtendedProbe(sess *session, sql string, expectedColumns int) ([][]*string, error) {
	sequence := extendedProbeSequence.Add(1)
	statementName := fmt.Sprintf("__pm_probe_statement_%d__", sequence)
	portalName := fmt.Sprintf("__pm_probe_portal_%d__", sequence)

	sess.targetDb.Send(&pgproto3.Parse{Name: statementName, Query: sql})
	sess.targetDb.Send(&pgproto3.Bind{DestinationPortal: portalName, PreparedStatement: statementName})
	sess.targetDb.Send(&pgproto3.Execute{Portal: portalName})
	sess.targetDb.Send(&pgproto3.Close{ObjectType: 'P', Name: portalName})
	sess.targetDb.Send(&pgproto3.Close{ObjectType: 'S', Name: statementName})
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return nil, err
	}

	var rows [][]*string
	parseComplete := false
	bindComplete := false
	rowDescription := false
	commandComplete := false
	closeCompletes := 0
	var probeErr error
	fail := func(err error) {
		if probeErr == nil {
			probeErr = err
		}
	}

	for {
		message, err := sess.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.ParseComplete:
			if parseComplete || bindComplete || rowDescription || commandComplete || closeCompletes != 0 {
				fail(errors.New("probe returned ParseComplete out of order"))
			}
			parseComplete = true
		case *pgproto3.BindComplete:
			if !parseComplete || bindComplete || rowDescription || commandComplete || closeCompletes != 0 {
				fail(errors.New("probe returned BindComplete out of order"))
			}
			bindComplete = true
		case *pgproto3.RowDescription:
			if !bindComplete || rowDescription || commandComplete || closeCompletes != 0 {
				fail(errors.New("probe returned RowDescription out of order"))
			}
			rowDescription = true
			if len(message.Fields) != expectedColumns {
				fail(fmt.Errorf("probe returned %d columns, want %d", len(message.Fields), expectedColumns))
			}
		case *pgproto3.DataRow:
			// Execute does not require a preceding Describe, so PostgreSQL commonly emits DataRow directly
			// after BindComplete. Accept an optional RowDescription but validate every row independently.
			if !bindComplete || commandComplete || closeCompletes != 0 {
				fail(errors.New("probe returned DataRow out of order"))
			}
			if len(message.Values) != expectedColumns {
				fail(fmt.Errorf("probe row returned %d columns, want %d", len(message.Values), expectedColumns))
				continue
			}
			row := make([]*string, len(message.Values))
			for i, value := range message.Values {
				if value != nil {
					copyValue := string(value)
					row[i] = &copyValue
				}
			}
			rows = append(rows, row)
		case *pgproto3.CommandComplete:
			if !bindComplete || commandComplete || closeCompletes != 0 {
				fail(errors.New("probe returned CommandComplete out of order"))
			}
			commandComplete = true
		case *pgproto3.CloseComplete:
			if !commandComplete || closeCompletes >= 2 {
				fail(errors.New("probe returned CloseComplete out of order"))
			}
			closeCompletes++
			if closeCompletes == 2 {
				if err := sess.client.Flush(); err != nil {
					return nil, err
				}
				if probeErr != nil {
					return nil, probeErr
				}
				return rows, nil
			}
		case *pgproto3.ErrorResponse:
			// PostgreSQL discards the remaining extended messages until Sync after an error, so there are no
			// CloseComplete frames to drain. The caller refuses this Bind and enters skipToSync.
			return nil, errors.New(message.Message)
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(sess, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(sess, message)
		case *pgproto3.NotificationResponse:
			sess.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		default:
			fail(fmt.Errorf("unexpected target DB probe response %T", message))
		}
	}
}

// probeBindContext captures the namespace and temporary-column context PostgreSQL will bind the next portal under.
func (s *Server) probeBindContext(sess *session) ([]string, []engine.TempColumn, error) {
	if sess.lastTxStatus == 'E' {
		// Aborted transaction: both injected probes would fail with 25P02 and block an extended-protocol
		// ROLLBACK's Bind. Reuse the last namespace + temp overlay (symmetric with handleQuery / handleParse).
		return append([]string{}, sess.namespaceOverlay...), append([]engine.TempColumn{}, sess.tempOverlay...), nil
	}
	namespaceRows, err := s.runExtendedProbe(sess, s.db.NamespaceProbeSQL(), 1)
	if err != nil {
		return nil, nil, fmt.Errorf("target-DB namespace probe: %w", err)
	}
	namespace, err := namespaceFromRows(namespaceRows)
	if err != nil {
		return nil, nil, err
	}
	sess.namespaceOverlay = append([]string{}, namespace...)

	tempRows, err := s.runExtendedProbe(sess, s.db.TempColumnsProbeSQL(), 5)
	if err != nil {
		return nil, nil, fmt.Errorf("target DB temp-column probe: %w", err)
	}
	temps, err := tempColumnsFromRows(tempRows)
	if err != nil {
		return nil, nil, err
	}
	sess.tempOverlay = append([]engine.TempColumn{}, temps...)
	return namespace, temps, nil
}

func (s *Server) handleExecute(sess *session, message *pgproto3.Execute) error {
	portal, ok := sess.portals[message.Portal]
	if !ok {
		return refuseExtended(sess, "34000", "Execute references an unknown portal")
	}

	// Re-decide the portal SQL under the context snapshotted when PostgreSQL bound it. A live probe here can
	// diverge from the bound plan after post-Bind search_path drift and authorize a different resource.
	sess.qe.MarkNamespaceDirty()
	verdict := sess.qe.Authorize(engine.AuthzInput{
		SQL:          portal.sql,
		Token:        sess.token,
		ClientAddr:   sess.clientAddr,
		ConnectionID: sess.connectionID,
		RunCommands:  s.refetcher(sess, true).RunAll,
		ProbeNamespace: func() (engine.NamespaceProbe, error) {
			return engine.NamespaceProbe{Namespace: portal.namespace}, nil
		},
		ProbeTempColumns: func() ([]engine.TempColumn, error) {
			return portal.temps, nil
		},
	})
	sess.qe.MarkNamespaceDirty()
	proceed, allowed, err := renderExtendedVerdict(sess, verdict)
	if err != nil || !allowed {
		return err
	}
	if proceed.Decision == nil {
		return refuseExtended(sess, "58000", "control plane returned no decision")
	}

	masks := proceed.Masks
	if portal.binary {
		if proceed.Decision.Action == "MASK" && !proceed.Decision.UnmaskablePermitted {
			return refuseExtended(sess, "0A000", "binary result format is not supported for a masked statement")
		}
		masks = nil
	}
	// The fresh verdict authorizes the SQL already parsed on the target DB. A fresh rewrite cannot replace
	// that prepared statement, so RewrittenSQL is deliberately ignored at Execute.
	start := time.Now()
	sess.targetDb.Send(message)
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	var relayStats engine.RelayStats
	terminal, err := s.relayExecuteStream(sess, masks, &relayStats)
	// Post-relay, best-effort completion for this extended-protocol Execute (no-op if unaudited). A
	// CommandComplete / EmptyQueryResponse / PortalSuspended is a clean finish; an ErrorResponse or a
	// transport fault is an error carrying the partial counts relayed before it.
	engine.EmitCompletion(s.client, proceed.Decision, relayStats, engine.RelayStatus(isCleanExecuteTerminal(terminal), err), start)
	if err != nil {
		return err
	}
	if _, complete := terminal.(*pgproto3.CommandComplete); complete && len(proceed.Decision.AfterStatement) > 0 {
		if err := s.refetcher(sess, true).RunAll(proceed.Decision.AfterStatement); err != nil {
			return closeRelay(sess, err)
		}
	}
	return nil
}

func (s *Server) relayExecuteStream(sess *session, masks []*pb.ColumnMask, stats *engine.RelayStats) (pgproto3.BackendMessage, error) {
	var masker *engine.RowMasker
	bufferedFrames := 0
	for {
		message, err := sess.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.DataRow:
			if len(masks) > 0 && masker == nil {
				masker = engine.NewRowMasker(masks, len(message.Values))
				if masker == nil {
					return nil, failClosedRelay(sess, "0A000", "proxy-monster: required mask could not be bound to a result column", errMaskUnbound)
				}
			}
			// Tally the target-DB row before masking, so the volume reflects the target-DB result, not the
			// rewritten one.
			stats.Rows++
			stats.Bytes += dataRowBytes(message)
			if masker == nil {
				sess.client.Send(message)
			} else {
				sess.client.Send(maskDataRow(message, masker))
			}
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(sess, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(sess, message)
		case *pgproto3.NotificationResponse:
			sess.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.CopyInResponse, *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
			return nil, failClosedRelay(sess, "0A000", "proxy-monster: COPY is not supported", errCopyStream)
		case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
			sess.client.Send(message)
			return message, sess.client.Flush()
		case *pgproto3.ErrorResponse:
			forwardError(sess, message)
			sess.skipToSync = true
			return message, sess.client.Flush()
		default:
			return nil, failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB execute response %T", message))
		}

		bufferedFrames++
		if bufferedFrames >= clientFlushThreshold {
			if err := sess.client.Flush(); err != nil {
				return nil, err
			}
			bufferedFrames = 0
		}
	}
}

func (s *Server) handleClose(sess *session, message *pgproto3.Close) error {
	sess.targetDb.Send(message)
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(sess, func(message pgproto3.BackendMessage) bool {
		switch message.(type) {
		case *pgproto3.CloseComplete, *pgproto3.ErrorResponse:
			return true
		default:
			return false
		}
	})
	if err != nil {
		return err
	}
	if _, complete := terminal.(*pgproto3.CloseComplete); complete {
		switch message.ObjectType {
		case 'S':
			delete(sess.statements, message.Name)
		case 'P':
			delete(sess.portals, message.Name)
		}
	}
	return sess.client.Flush()
}

func (s *Server) handleFlush(sess *session) error {
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	return sess.client.Flush()
}

func (s *Server) handleSync(sess *session) error {
	sess.targetDb.Send(&pgproto3.Sync{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	for {
		message, err := sess.targetDb.Receive()
		if err != nil {
			return err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(sess, message); err != nil {
				return err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(sess, message)
		case *pgproto3.NotificationResponse:
			sess.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.ReadyForQuery:
			sess.lastTxStatus = message.TxStatus
			sess.client.Send(message)
			sess.pendingDirty = true
			sess.skipToSync = false
			if err := sess.client.Flush(); err != nil {
				return err
			}
			return nil
		default:
			return failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB sync response %T", message))
		}
	}
}
