package postgres

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
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

// preparedStatement stores only the SQL confirmed by ParseComplete. Bind can revalidate a prepared
// statement after namespace or plan invalidation, so its authorization context is captured at Bind.
type preparedStatement struct {
	sql string
}

// boundPortal snapshots the context PostgreSQL used for its confirmed Bind. Every Execute re-decides the
// portal SQL against that snapshot, and no decision is ever stored.
type boundPortal struct {
	sql      string
	snapshot spi.SessionSnapshot
	temps    []spi.TempColumn
	binary   bool
	// Volume already relayed from this portal. A suspended portal resumes on a further Execute, so the cap
	// is measured against the portal's whole output rather than restarting with each page.
	relayed spi.RelayStats
}

func (s *Server) renderExtendedVerdict(wireState *clientWireState, verdict spi.Verdict) (spi.Proceed, bool, error) {
	switch verdict := verdict.(type) {
	case spi.Fail:
		wireState.skipToSync, wireState.abortAtSync = true, true
		err := sendError(wireState.client, "ERROR", "58000", "proxy-monster: "+verdict.Message, false, 0)
		return spi.Proceed{}, false, err
	case spi.Deny:
		if verdict.Decision != nil && verdict.Decision.TargetError != nil {
			if targetErr, ok := verdict.Decision.TargetError.Message.(*pgproto3.ErrorResponse); ok {
				wireState.skipToSync = true
				forwardTargetError(wireState, targetErr)
				wireState.authz.AwaitCompletion(relay.EmitCompletion(s.client, verdict.Decision, spi.RelayStats{}, relay.StatusError, time.Now()))
				return spi.Proceed{}, false, wireState.client.Flush()
			}
		}
		reason := "policy"
		if verdict.Decision != nil && verdict.Decision.DenyReason != "" {
			reason = verdict.Decision.DenyReason
		}
		wireState.skipToSync, wireState.abortAtSync = true, true
		err := sendError(wireState.client, "ERROR", "42501", "proxy-monster denied: "+reason, false, 0)
		return spi.Proceed{}, false, err
	case spi.Proceed:
		return verdict, true, nil
	default:
		return spi.Proceed{}, false, errors.New("pgproxy: engine returned an unknown verdict")
	}
}

func refuseExtended(wireState *clientWireState, code, message string) error {
	wireState.skipToSync, wireState.abortAtSync = true, true
	return sendError(wireState.client, "ERROR", code, "proxy-monster: "+message, false, 0)
}

func (s *Server) awaitExtendedCompletion(wireState *clientWireState, isTerminal func(pgproto3.BackendMessage) bool) (pgproto3.BackendMessage, error) {
	for {
		message, err := wireState.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(wireState, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(wireState, message)
		case *pgproto3.NotificationResponse:
			wireState.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.ParameterDescription:
			wireState.client.Send(message)
		default:
			if !isTerminal(message) {
				return nil, failClosedRelay(wireState, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB extended response %T", message))
			}
			if errMsg, failed := message.(*pgproto3.ErrorResponse); failed {
				forwardError(wireState, errMsg)
				wireState.skipToSync = true
			} else {
				wireState.client.Send(message)
			}
			return message, nil
		}
	}
}

func (s *Server) handleParse(wireState *clientWireState, message *pgproto3.Parse) error {
	// Parse always authorizes against the live namespace. Lockstep has drained every earlier response,
	// so pgx.Batch cannot interleave this injected simple-query probe with extended frames. Outside an
	// explicit transaction the probe can commit the batch's implicit transaction early; that is a
	// deliberate fail-safe deviation (an extra probe, never a skipped one). In an aborted transaction,
	// the probe fails and produces a fail-safe 58000 refusal before PostgreSQL's equivalent 25P02 Parse.
	wireState.authz.MarkNamespaceDirty()
	wireState.pendingDirty = false
	in := wireState.authzInput(message.Query, wireState.extendedCommandRunner)
	in.CheckTargetError = func(sql string) (*spi.TargetError, error) {
		return s.checkTargetError(wireState, sql, message.ParameterOIDs)
	}
	verdict := wireState.authz.Authorize(in)
	proceed, allowed, err := s.renderExtendedVerdict(wireState, verdict)
	if err != nil || !allowed {
		return err
	}
	if proceed.Decision == nil {
		return refuseExtended(wireState, "58000", "control plane returned no decision")
	}
	// Parse has no statement effect, so its after_statement commands are deliberately not fired.

	sentSQL := message.Query
	if proceed.RewrittenSQL != nil {
		sentSQL = *proceed.RewrittenSQL
	}
	wireState.targetDb.Send(&pgproto3.Parse{Name: message.Name, Query: sentSQL, ParameterOIDs: message.ParameterOIDs})
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(wireState, func(message pgproto3.BackendMessage) bool {
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
		wireState.statements[message.Name] = preparedStatement{sql: sentSQL}
	}
	return wireState.client.Flush()
}

func (s *Server) handleBind(wireState *clientWireState, message *pgproto3.Bind) error {
	statement, ok := wireState.statements[message.PreparedStatement]
	if !ok {
		return refuseExtended(wireState, "26000", "Bind references an unknown or denied prepared statement")
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
	snapshot, temps, err := s.probeBindContext(wireState)
	if err != nil {
		if errors.Is(err, errClientEncoding) || errors.Is(err, errStdConformingStrings) {
			return err
		}
		return refuseExtended(wireState, "58000", "bind-time namespace unavailable")
	}

	wireState.targetDb.Send(message)
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(wireState, func(message pgproto3.BackendMessage) bool {
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
		wireState.portals[message.DestinationPortal] = boundPortal{
			sql:      statement.sql,
			snapshot: snapshot.Clone(),
			temps:    temps,
			binary:   binary,
		}
	}
	return wireState.client.Flush()
}

func (s *Server) handleDescribe(wireState *clientWireState, message *pgproto3.Describe) error {
	wireState.targetDb.Send(message)
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	_, err := s.awaitExtendedCompletion(wireState, func(message pgproto3.BackendMessage) bool {
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
	return wireState.client.Flush()
}

func (s *Server) runExtendedProbe(wireState *clientWireState, sql string, expectedColumns int) ([][]*string, error) {
	sequence := extendedProbeSequence.Add(1)
	statementName := fmt.Sprintf("__pm_probe_statement_%d__", sequence)
	portalName := fmt.Sprintf("__pm_probe_portal_%d__", sequence)

	wireState.targetDb.Send(&pgproto3.Parse{Name: statementName, Query: sql})
	wireState.targetDb.Send(&pgproto3.Bind{DestinationPortal: portalName, PreparedStatement: statementName})
	wireState.targetDb.Send(&pgproto3.Execute{Portal: portalName})
	wireState.targetDb.Send(&pgproto3.Close{ObjectType: 'P', Name: portalName})
	wireState.targetDb.Send(&pgproto3.Close{ObjectType: 'S', Name: statementName})
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
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
		message, err := wireState.targetDb.Receive()
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
				if err := wireState.client.Flush(); err != nil {
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
			if err := s.guardParameterStatus(wireState, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(wireState, message)
		case *pgproto3.NotificationResponse:
			wireState.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		default:
			fail(fmt.Errorf("unexpected target DB probe response %T", message))
		}
	}
}

// probeBindContext captures the namespace, function visibility, and temporary columns PostgreSQL will
// bind the next portal under.
func (s *Server) probeBindContext(wireState *clientWireState) (spi.SessionSnapshot, []spi.TempColumn, error) {
	if wireState.lastTxStatus == 'E' {
		// Aborted transaction: both injected probes would fail with 25P02 and block an extended-protocol
		// ROLLBACK's Bind. Reuse the last context snapshot (symmetric with handleQuery / handleParse).
		return wireState.authz.Snapshot(), append([]spi.TempColumn{}, wireState.tempOverlay...), nil
	}
	namespaceRows, err := s.runExtendedProbe(wireState, namespaceProbeSQL, 1)
	if err != nil {
		return spi.SessionSnapshot{}, nil, fmt.Errorf("target-DB namespace probe: %w", err)
	}
	snapshot, err := snapshotFromRows(namespaceRows)
	if err != nil {
		return spi.SessionSnapshot{}, nil, err
	}
	snapshot.CurrentCatalog = wireState.currentCatalog
	wireState.authz.SetSnapshot(snapshot)

	tempRows, err := s.runExtendedProbe(wireState, tempColumnsProbeSQL, 6)
	if err != nil {
		return spi.SessionSnapshot{}, nil, fmt.Errorf("target DB temp-column probe: %w", err)
	}
	temps, err := tempColumnsFromRows(tempRows)
	if err != nil {
		return spi.SessionSnapshot{}, nil, err
	}
	wireState.tempOverlay = append([]spi.TempColumn{}, temps...)
	return snapshot, temps, nil
}

func (s *Server) handleExecute(wireState *clientWireState, message *pgproto3.Execute) error {
	portal, ok := wireState.portals[message.Portal]
	if !ok {
		return refuseExtended(wireState, "34000", "Execute references an unknown portal")
	}

	// Re-decide the portal SQL under the context snapshotted when PostgreSQL bound it. A live probe here can
	// diverge from the bound plan after post-Bind search_path drift and authorize a different resource.
	wireState.authz.MarkNamespaceDirty()
	verdict := wireState.authz.Authorize(spi.AuthzInput{
		SQL:          portal.sql,
		Commands:     wireState.extendedCommandRunner,
		ProbeSession: func() (spi.SessionSnapshot, error) { return portal.snapshot.Clone(), nil },
		ProbeTempColumns: func() ([]spi.TempColumn, error) {
			return portal.temps, nil
		},
		CheckTargetError: func(sql string) (*spi.TargetError, error) { return s.checkTargetError(wireState, sql, nil) },
	})
	wireState.authz.MarkNamespaceDirty()
	proceed, allowed, err := s.renderExtendedVerdict(wireState, verdict)
	if err != nil || !allowed {
		return err
	}
	if proceed.Decision == nil {
		return refuseExtended(wireState, "58000", "control plane returned no decision")
	}

	masks := proceed.Masks
	if portal.binary {
		if proceed.Decision.Action == "MASK" && !proceed.Decision.UnmaskablePermitted {
			if !nullOnlyMasks(masks) {
				return refuseExtended(wireState, "0A000", "binary result format is not supported for a masked statement")
			}
		} else {
			masks = nil
		}
	}
	// The fresh verdict authorizes the SQL already parsed on the target DB. A fresh rewrite cannot replace
	// that prepared statement, so RewrittenSQL is deliberately ignored at Execute.
	start := time.Now()
	wireState.targetDb.Send(message)
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	var relayStats spi.RelayStats
	terminal, err := s.relayExecuteStream(wireState, masks, &relayStats, portal.relayed, proceed.Decision)
	// A re-Bind of the same name replaces this entry, which is what resets the tally for a new portal.
	portal.relayed = portal.relayed.Plus(relayStats)
	wireState.portals[message.Portal] = portal
	// Post-relay, best-effort completion for this extended-protocol Execute (no-op if unaudited). A
	// CommandComplete / EmptyQueryResponse / PortalSuspended is a clean finish; an ErrorResponse or a
	// transport fault is an error carrying the partial counts relayed before it.
	wireState.authz.AwaitCompletion(relay.EmitCompletion(s.client, proceed.Decision, relayStats, relay.RelayStatus(isCleanExecuteTerminal(terminal), err), start))
	if err != nil {
		return err
	}
	if _, complete := terminal.(*pgproto3.CommandComplete); complete && len(proceed.Decision.AfterStatement) > 0 {
		if err := wireState.extendedCommandRunner.RunAll(proceed.Decision.AfterStatement, nil); err != nil {
			return closeRelay(wireState, err)
		}
	}
	return nil
}

// A NULL marker is the same in text and binary format, so NULL-only masks apply to a binary row too.
func nullOnlyMasks(masks []*pb.ColumnMask) bool {
	if len(masks) == 0 {
		return false
	}
	for _, mask := range masks {
		if mask.GetKind() != "NULL" {
			return false
		}
	}
	return true
}

// carried is the volume earlier Executes already drew from this portal; stats stays this Execute's own
// tally so each page audits its own completion.
func (s *Server) relayExecuteStream(wireState *clientWireState, masks []*pb.ColumnMask, stats *spi.RelayStats, carried spi.RelayStats, dec *spi.Decision) (pgproto3.BackendMessage, error) {
	var masker *relay.RowMasker
	var capped *pgproto3.ErrorResponse
	bufferedFrames := 0
	for {
		message, err := wireState.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.DataRow:
			if capped != nil {
				continue
			}
			capped = resultCapError(dec, carried.Plus(*stats), dataRowBytes(message))
			if capped != nil {
				s.cancelCappedQuery(wireState)
				continue
			}
			if len(masks) > 0 && masker == nil {
				masker = relay.NewRowMasker(masks, len(message.Values))
				if masker == nil {
					return nil, failClosedRelay(wireState, "0A000", "proxy-monster: required mask could not be bound to a result column", errMaskUnbound)
				}
			}
			// Tally the target-DB row before masking, so the volume reflects the target-DB result, not the
			// rewritten one.
			stats.Rows++
			stats.Bytes += dataRowBytes(message)
			if masker == nil {
				wireState.client.Send(message)
			} else {
				wireState.client.Send(maskDataRow(message, masker))
			}
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(wireState, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(wireState, message)
		case *pgproto3.NotificationResponse:
			wireState.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.CopyInResponse, *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
			return nil, failClosedRelay(wireState, "0A000", "proxy-monster: COPY is not supported", errCopyStream)
		case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
			if capped != nil {
				wireState.client.Send(capped)
				wireState.skipToSync, wireState.abortAtSync = true, true
				return capped, wireState.client.Flush()
			}
			wireState.client.Send(message)
			return message, wireState.client.Flush()
		case *pgproto3.ErrorResponse:
			if capped != nil {
				wireState.client.Send(capped)
				wireState.skipToSync, wireState.abortAtSync = true, true
				return capped, wireState.client.Flush()
			}
			forwardError(wireState, message)
			wireState.skipToSync = true
			return message, wireState.client.Flush()
		default:
			return nil, failClosedRelay(wireState, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB execute response %T", message))
		}

		bufferedFrames++
		if bufferedFrames >= clientFlushThreshold {
			if err := wireState.client.Flush(); err != nil {
				return nil, err
			}
			bufferedFrames = 0
		}
	}
}

func (s *Server) handleClose(wireState *clientWireState, message *pgproto3.Close) error {
	wireState.targetDb.Send(message)
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	terminal, err := s.awaitExtendedCompletion(wireState, func(message pgproto3.BackendMessage) bool {
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
			delete(wireState.statements, message.Name)
		case 'P':
			delete(wireState.portals, message.Name)
		}
	}
	return wireState.client.Flush()
}

func (s *Server) handleFlush(wireState *clientWireState) error {
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	return wireState.client.Flush()
}

func (s *Server) handleSync(wireState *clientWireState) error {
	wireState.targetDb.Send(&pgproto3.Sync{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	for {
		message, err := wireState.targetDb.Receive()
		if err != nil {
			return err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(wireState, message); err != nil {
				return err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(wireState, message)
		case *pgproto3.NotificationResponse:
			wireState.client.Send(&pgproto3.NotificationResponse{PID: message.PID, Channel: message.Channel, Payload: message.Payload})
		case *pgproto3.ReadyForQuery:
			wireState.lastTxStatus = message.TxStatus
			if wireState.abortAtSync {
				wireState.abortAtSync = false
				if err := abortTransaction(wireState); err != nil {
					return closeRelay(wireState, err)
				}
			}
			wireState.client.Send(&pgproto3.ReadyForQuery{TxStatus: wireState.lastTxStatus})
			wireState.pendingDirty = true
			wireState.skipToSync = false
			if err := wireState.client.Flush(); err != nil {
				return err
			}
			return nil
		default:
			return failClosedRelay(wireState, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB sync response %T", message))
		}
	}
}
