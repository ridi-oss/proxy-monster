package postgres

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var (
	errMaskUnbound          = relay.ErrMaskUnbound
	errCopyStream           = errors.New("COPY is not supported")
	errClientEncoding       = errors.New("client_encoding changed away from UTF8")
	errStdConformingStrings = errors.New("standard_conforming_strings changed away from on")
	errUnexpectedFrame      = errors.New("unexpected PostgreSQL query response")
)

const clientFlushThreshold = 64

type streamOpts struct{ extended, soft bool }

// pgTargetDbErr carries both forms of a PostgreSQL ErrorResponse — the raw message and the diagnostic-redacted
// message — from streamResult to its caller. It is NOT relay.TargetDbError: streamResult also serves
// internal catalog probes and refetches (collectProbe), whose errors must stay proxy-internal and never be
// surfaced as a query's error detail. Only the statement site (connection.ServeStatement) promotes this to
// relay.TargetDbError, so provenance is decided there, not for every ErrorResponse streamResult sees.
type pgTargetDbErr struct {
	message  string
	redacted string
}

func (e *pgTargetDbErr) Error() string { return e.message }

// emit receives each frame as the CLIENT should see it (masks already applied) plus the byte size of the
// TARGET-DB row it came from, so a caller measuring result volume charges the target's row rather than the
// rewritten one. rowBytes is 0 for every frame that is not a DataRow.
func (c *connection) streamResult(masks []*pb.ColumnMask, opts streamOpts, emit func(message pgproto3.BackendMessage, rowBytes int64) error) (targetDbErr error, err error) {
	var masker *relay.RowMasker
	columnCount := -1
	fail := func(cause error) bool {
		if err == nil {
			err = cause
		}
		return opts.soft
	}
	rowBytes := int64(0)
	emitFrame := func(message pgproto3.BackendMessage, data bool) bool {
		if data && (targetDbErr != nil || opts.soft && err != nil) {
			return true
		}
		if emit != nil {
			if cause := emit(message, rowBytes); cause != nil {
				return fail(cause)
			}
		}
		return true
	}

	for {
		message, receiveErr := c.targetDb.Receive()
		if receiveErr != nil {
			return targetDbErr, receiveErr
		}
		out := message
		data := true
		rowBytes = 0
		switch message := message.(type) {
		case *pgproto3.RowDescription:
			columnCount = len(message.Fields)
			masker = nil
			if len(masks) > 0 {
				masker = relay.NewRowMasker(masks, columnCount)
				if masker == nil && !fail(errMaskUnbound) {
					return targetDbErr, err
				}
			}
		case *pgproto3.DataRow:
			if columnCount < 0 || len(message.Values) != columnCount {
				cause := fmt.Errorf("%w: PostgreSQL row has %d columns, want %d", errUnexpectedFrame, len(message.Values), columnCount)
				if opts.soft {
					cause = fmt.Errorf("probe row returned %d columns, want %d", len(message.Values), columnCount)
				}
				if !fail(cause) {
					return targetDbErr, err
				}
				continue
			}
			if len(masks) > 0 && masker == nil {
				if !fail(errMaskUnbound) {
					return targetDbErr, err
				}
				continue
			}
			rowBytes = dataRowBytes(message)
			if masker != nil {
				out = maskDataRow(message, masker)
			}
		case *pgproto3.CommandComplete:
			masker = nil
			columnCount = -1
		case *pgproto3.ErrorResponse:
			data = false
			// The one client-facing target-DB-error site for both relays. A PostgreSQL error can echo a
			// masked/denied value the statement never referenced (the whole-row `DETAIL`). An editor session surfaces
			// targetDbErr and re-gates it per viewer at view time, so it captures BOTH the raw message and the
			// redacted form; the wire emit below still strips per THIS decision. See docs/diagnostic-redaction.md.
			if targetDbErr == nil {
				r := sanitizeError(message)
				targetDbErr = &pgTargetDbErr{message: message.Message, redacted: r.Severity + ": " + r.Code + " " + r.Message}
			}
			if c.authz != nil && c.authz.SanitizeDiagnostics() {
				message = sanitizeError(message)
				out = message
			}
		case *pgproto3.ParameterStatus:
			data = false
			if message.Name == "search_path" && c.authz != nil {
				c.authz.MarkNamespaceDirty()
			}
			if cause := guardParameterStatusValue(message.Name, message.Value); cause != nil && !fail(cause) {
				return targetDbErr, err
			}
		case *pgproto3.NoticeResponse, *pgproto3.NotificationResponse:
			data = false
		case *pgproto3.EmptyQueryResponse:
		case *pgproto3.ParseComplete, *pgproto3.BindComplete, *pgproto3.NoData, *pgproto3.CloseComplete, *pgproto3.PortalSuspended:
			if !opts.extended {
				if !fail(fmt.Errorf("%w %T", errUnexpectedFrame, message)) {
					return targetDbErr, err
				}
				continue
			}
		case *pgproto3.CopyInResponse, *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
			if !fail(errCopyStream) {
				return targetDbErr, err
			}
			continue
		case *pgproto3.ReadyForQuery:
			c.lastTxStatus = message.TxStatus
			if !emitFrame(message, false) {
				return targetDbErr, err
			}
			return targetDbErr, err
		default:
			if !fail(fmt.Errorf("%w %T", errUnexpectedFrame, message)) {
				return targetDbErr, err
			}
			continue
		}
		if !emitFrame(out, data) {
			return targetDbErr, err
		}
	}
}

type rowsCollector struct {
	expected int
	budget   relay.RowBudget
	result   *spi.StatementResult
	failed   error
}

func (c *rowsCollector) emit(message pgproto3.BackendMessage, rowBytes int64) error {
	if c.failed != nil {
		return nil
	}
	fail := func(err error) error { c.failed = err; return err }
	switch message := message.(type) {
	case *pgproto3.RowDescription:
		if c.expected > 0 && len(message.Fields) != c.expected {
			return fail(fmt.Errorf("probe returned %d columns, want %d", len(message.Fields), c.expected))
		}
		c.result.RowsAffected = -1
		c.result.Columns = make([]string, len(message.Fields))
		for i, field := range message.Fields {
			c.result.Columns[i] = string(field.Name)
		}
	case *pgproto3.DataRow:
		if c.expected > 0 && len(message.Values) != c.expected {
			return fail(fmt.Errorf("probe row returned %d columns, want %d", len(message.Values), c.expected))
		}
		if c.budget.Admit(len(c.result.Rows), rowBytes) {
			c.result.Rows = append(c.result.Rows, decodeTextRow(message))
		}
	case *pgproto3.CommandComplete:
		if c.result.RowsAffected != -1 {
			affected := pgconn.NewCommandTag(string(message.CommandTag)).RowsAffected()
			if affected > math.MaxInt32 {
				return fail(fmt.Errorf("affected rows %d exceeds int32 range", affected))
			}
			c.result.RowsAffected = int(affected)
		}
	}
	return nil
}

// dataRowBytes is the byte size of a DataRow's column data — the sum of its value lengths (a NULL value
// contributes nothing). It is the per-row contribution to the result-volume tally.
func dataRowBytes(message *pgproto3.DataRow) int64 {
	var total int64
	for _, value := range message.Values {
		total += int64(len(value))
	}
	return total
}

func decodeTextRow(message *pgproto3.DataRow) []*string {
	values := make([]*string, len(message.Values))
	for i, value := range message.Values {
		if value != nil {
			copyValue := string(value)
			values[i] = &copyValue
		}
	}
	return values
}

func maskDataRow(message *pgproto3.DataRow, masker *relay.RowMasker) *pgproto3.DataRow {
	masked := masker.Apply(decodeTextRow(message))
	encoded := make([][]byte, len(masked))
	for i, value := range masked {
		if value != nil {
			encoded[i] = []byte(*value)
		}
	}
	return &pgproto3.DataRow{Values: encoded}
}

func executeMaxRows(maxRows int) (uint32, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	if uint64(maxRows) >= uint64(math.MaxUint32) {
		return 0, errors.New("max rows exceeds PostgreSQL Execute range")
	}
	return uint32(maxRows + 1), nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// resultCapError is the 57014 a client sees INSTEAD of the capped statement's own terminator — the same
// SQLSTATE PostgreSQL itself sends for a cancelled query. Nil while the next row still fits.
func resultCapError(dec *spi.Decision, relayed spi.RelayStats, rowBytes int64) *pgproto3.ErrorResponse {
	message := dec.CapExceeded(relayed, rowBytes)
	if message == "" {
		return nil
	}
	return &pgproto3.ErrorResponse{
		Severity: "ERROR", Code: "57014", Message: message,
		Hint: "Request unbounded access to read the full result.",
	}
}

func (s *Server) cancelCappedQuery(wireState *clientWireState) {
	if wireState.keyData.ProcessID != 0 {
		_ = sendCancelRequest(s.target.config, wireState.keyData.ProcessID, wireState.keyData.SecretKey)
	}
}

func (s *Server) handleQuery(wireState *clientWireState, sql string) error {
	batch := splitBatch(sql)
	if batch == nil {
		_, err := s.serveQuery(wireState, sql, relayQuery)
		return err
	}
	explicit := explicitTransaction(batch)
	for i, statement := range batch {
		if statement.MayControlTransaction && !(explicit && (i == 0 || i == len(batch)-1)) {
			if err := abortTransaction(wireState); err != nil {
				return closeRelay(wireState, err)
			}
			return sendError(wireState.client, "ERROR", "0A000",
				"proxy-monster: a multi-statement query may only begin with BEGIN and end with COMMIT; send other transaction control as its own query",
				true, wireState.lastTxStatus)
		}
	}
	return s.handleBatch(wireState, batch, explicit)
}

// explicitTransaction reports a batch that opens its own transaction first and commits it last, which runs as
// PostgreSQL runs it without the proxy's wrapping transaction.
func explicitTransaction(batch []engines.BatchStatement) bool {
	return batch[0].Kind == analyzerpb.StatementKind_STATEMENT_KIND_START_TRANSACTION &&
		batch[len(batch)-1].Kind == analyzerpb.StatementKind_STATEMENT_KIND_COMMIT
}

// splitBatch cuts a multi-statement simple query into its statements, or nil to serve sql as one.
func splitBatch(sql string) []engines.BatchStatement {
	if !strings.Contains(strings.TrimRight(sql, "; \t\r\n"), ";") {
		return nil
	}
	batch, ok := engines.SplitBatch(sql, &analyzerpb.EngineConfig{Engine: analyzerpb.Engine_POSTGRES})
	if !ok || len(batch) < 2 {
		return nil
	}
	return batch
}

// handleBatch decides each statement right before it runs and answers with one ReadyForQuery. From an idle
// session the batch runs in the proxy's own transaction, so a deny or error undoes it, as PostgreSQL does.
func (s *Server) handleBatch(wireState *clientWireState, batch []engines.BatchStatement, explicit bool) error {
	owned := !explicit && wireState.lastTxStatus == 'I'
	failed := false
	if owned {
		result, err := s.serveQuery(wireState, "BEGIN", relayBatchControl)
		if err != nil {
			return err
		}
		failed, owned = result.stop, !result.stop
	}
	for i, statement := range batch {
		if failed {
			break
		}
		result, err := s.serveQuery(wireState, statement.SQL, relayBatchStatement)
		if err != nil {
			return err
		}
		failed = result.stop
		// PREPARE TRANSACTION is not marked as transaction control, but it ends the transaction.
		if wireState.lastTxStatus == 'I' && !(explicit && i == len(batch)-1) {
			owned, failed = false, true
			if err := sendError(wireState.client, "ERROR", "0A000", "proxy-monster: a statement ended the multi-statement query's transaction", false, 0); err != nil {
				return err
			}
		}
	}
	if owned {
		end := "COMMIT"
		if failed || wireState.lastTxStatus == 'E' {
			end = "ROLLBACK"
		}
		if _, err := s.serveQuery(wireState, end, relayBatchControl); err != nil {
			return err
		}
		// A denied or failed COMMIT/ROLLBACK leaves the batch pending in a transaction the client never
		// opened; closing the connection makes the target roll it back.
		if wireState.lastTxStatus != 'I' {
			return closeRelay(wireState, fmt.Errorf("multi-statement query's %s left the transaction open", end))
		}
	}
	wireState.client.Send(&pgproto3.ReadyForQuery{TxStatus: wireState.lastTxStatus})
	return wireState.client.Flush()
}

type relayMode int

const (
	relayQuery relayMode = iota
	// One statement of a batch: its ReadyForQuery is held for handleBatch to send once.
	relayBatchStatement
	// The proxy's own BEGIN/COMMIT/ROLLBACK around a batch: only its errors and notices reach the client.
	relayBatchControl
)

type queryResult struct {
	// The statement was denied, failed, or hit its result cap; a batch runs nothing after it.
	stop bool
}

// serveQuery serves one statement.
func (s *Server) serveQuery(wireState *clientWireState, sql string, mode relayMode) (queryResult, error) {
	start := time.Now()
	var relayStats spi.RelayStats
	relayStatus := relay.StatusError
	var result queryResult
	in := wireState.authzInput(sql, wireState.commandRunner)
	in.CheckTargetError = func(sql string) (*spi.TargetError, error) { return s.checkTargetErrorAndSync(wireState, sql) }
	decision, denied, err := relay.ServeStatement(wireState.authz, in, wireState.commandRunner, nil,
		func(toSend string, masks []*pb.ColumnMask, dec *spi.Decision) (bool, error) {
			wireState.targetDb.Send(&pgproto3.Query{String: toSend})
			if err := wireState.targetDb.Flush(); err != nil {
				return false, err
			}
			bufferedFrames := 0
			var capped *pgproto3.ErrorResponse
			targetDbErr, streamErr := wireState.streamResult(masks, streamOpts{}, func(message pgproto3.BackendMessage, rowBytes int64) error {
				switch message.(type) {
				case *pgproto3.DataRow:
					if capped != nil {
						return nil
					}
					capped = resultCapError(dec, relayStats, rowBytes)
					if capped != nil {
						s.cancelCappedQuery(wireState)
						return nil
					}
					relayStats.Rows++
					relayStats.Bytes += rowBytes
				case *pgproto3.ReadyForQuery:
					// A capped statement fails its transaction, so its ReadyForQuery waits for the abort below.
					if capped != nil {
						wireState.client.Send(capped)
						return nil
					}
					if mode != relayQuery {
						return nil
					}
				case *pgproto3.CommandComplete:
					if capped != nil || mode == relayBatchControl {
						return nil
					}
				default:
					// Past the cap the 57014 IS the client's terminator, so every remaining frame of this
					// Query is swallowed — including a following statement's own result frames.
					if capped != nil {
						return nil
					}
				}
				wireState.client.Send(message)
				bufferedFrames++
				if bufferedFrames >= clientFlushThreshold {
					bufferedFrames = 0
					return wireState.client.Flush()
				}
				return nil
			})
			if streamErr != nil {
				return false, mapWireStreamError(wireState, streamErr)
			}
			if capped != nil {
				if err := abortTransaction(wireState); err != nil {
					return false, err
				}
				if mode == relayQuery {
					wireState.client.Send(&pgproto3.ReadyForQuery{TxStatus: wireState.lastTxStatus})
				}
			}
			wireState.pendingDirty = true
			if err := wireState.client.Flush(); err != nil {
				return false, err
			}
			relayStatus = relay.RelayStatus(targetDbErr == nil && capped == nil, nil)
			result.stop = targetDbErr != nil || capped != nil
			return !result.stop, nil
		})
	// Post-relay, best-effort completion: only a relayed (Proceed) statement reports. A DENY relayed
	// nothing, and EmitCompletion additionally no-ops for a decision with no audit id.
	if !denied {
		wireState.authz.AwaitCompletion(relay.EmitCompletion(s.client, decision, relayStats, relayStatus, start))
	}
	if err != nil {
		var fail relay.FailError
		if errors.As(err, &fail) {
			if err := abortTransaction(wireState); err != nil {
				return queryResult{stop: true}, closeRelay(wireState, err)
			}
			return queryResult{stop: true}, sendError(wireState.client, "ERROR", "58000", "proxy-monster: "+fail.Message, mode == relayQuery, wireState.lastTxStatus)
		}
		return result, closeRelay(wireState, err)
	}
	if denied && decision != nil && decision.TargetError != nil {
		if targetErr, ok := decision.TargetError.Message.(*pgproto3.ErrorResponse); ok {
			forwardTargetError(wireState, targetErr)
			if mode == relayQuery {
				wireState.client.Send(&pgproto3.ReadyForQuery{TxStatus: wireState.lastTxStatus})
			}
			wireState.authz.AwaitCompletion(relay.EmitCompletion(s.client, decision, spi.RelayStats{}, relay.StatusError, start))
			return queryResult{stop: true}, wireState.client.Flush()
		}
	}
	if denied {
		reason := "policy"
		if decision != nil && decision.DenyReason != "" {
			reason = decision.DenyReason
		}
		if err := abortTransaction(wireState); err != nil {
			return queryResult{stop: true}, closeRelay(wireState, err)
		}
		return queryResult{stop: true}, sendError(wireState.client, "ERROR", "42501", "proxy-monster denied: "+reason, mode == relayQuery, wireState.lastTxStatus)
	}
	return result, nil
}

// abortTransaction fails an open target transaction as a target-DB error would, so a refusal the target
// never saw still makes a later COMMIT roll back.
func abortTransaction(wireState *clientWireState) error {
	if wireState.lastTxStatus != 'T' {
		return nil
	}
	wireState.targetDb.Send(&pgproto3.Query{String: "DO $$BEGIN RAISE EXCEPTION 'proxy-monster refused the statement'; END$$"})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	_, err := wireState.streamResult(nil, streamOpts{}, nil)
	return err
}

func mapWireStreamError(wireState *clientWireState, err error) error {
	switch {
	case errors.Is(err, errMaskUnbound):
		return failClosedRelay(wireState, "0A000", "proxy-monster: required mask could not be bound to a result column", err)
	case errors.Is(err, errCopyStream):
		return failClosedRelay(wireState, "0A000", "proxy-monster: COPY is not supported", err)
	case errors.Is(err, errClientEncoding):
		return failClosedRelay(wireState, "0A000", "proxy-monster: client_encoding must remain UTF8", err)
	case errors.Is(err, errStdConformingStrings):
		return failClosedRelay(wireState, "0A000", "proxy-monster: standard_conforming_strings must remain on", err)
	case errors.Is(err, errUnexpectedFrame):
		return failClosedRelay(wireState, "58000", "proxy-monster: malformed target-DB response", err)
	default:
		return err
	}
}

func guardParameterStatusValue(name, value string) error {
	switch name {
	case "client_encoding":
		if !strings.EqualFold(value, "UTF8") {
			return errClientEncoding
		}
	case "standard_conforming_strings":
		if !strings.EqualFold(value, "on") {
			return errStdConformingStrings
		}
	}
	return nil
}

func (s *Server) guardParameterStatus(wireState *clientWireState, message *pgproto3.ParameterStatus) error {
	wireState.client.Send(message)
	if message.Name == "search_path" {
		wireState.authz.MarkNamespaceDirty()
	}
	if err := guardParameterStatusValue(message.Name, message.Value); err != nil {
		return mapWireStreamError(wireState, err)
	}
	return nil
}

func failClosedRelay(wireState *clientWireState, code, message string, cause error) error {
	_ = sendError(wireState.client, "ERROR", code, message, true, wireState.lastTxStatus)
	return closeRelay(wireState, cause)
}

func closeRelay(wireState *clientWireState, cause error) error {
	_ = wireState.clientConn.Close()
	_ = wireState.targetDbConn.Close()
	return cause
}
