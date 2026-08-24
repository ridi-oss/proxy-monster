package pgproxy

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

var (
	errMaskUnbound          = engine.ErrMaskUnbound
	errCopyStream           = errors.New("COPY is not supported")
	errClientEncoding       = errors.New("client_encoding changed away from UTF8")
	errStdConformingStrings = errors.New("standard_conforming_strings changed away from on")
	errUnexpectedFrame      = errors.New("unexpected PostgreSQL query response")
)

const clientFlushThreshold = 64

type streamOpts struct{ extended, soft bool }

func (c *sessionCore) streamResult(masks []*pb.ColumnMask, opts streamOpts, emit func(pgproto3.BackendMessage) error) (targetDbErr error, err error) {
	var masker *engine.RowMasker
	columnCount := -1
	fail := func(cause error) bool {
		if err == nil {
			err = cause
		}
		return opts.soft
	}
	emitFrame := func(message pgproto3.BackendMessage, data bool) bool {
		if data && (targetDbErr != nil || opts.soft && err != nil) {
			return true
		}
		if emit != nil {
			if cause := emit(message); cause != nil {
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
		switch message := message.(type) {
		case *pgproto3.RowDescription:
			columnCount = len(message.Fields)
			masker = nil
			if len(masks) > 0 {
				masker = engine.NewRowMasker(masks, columnCount)
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
			if masker != nil {
				out = maskDataRow(message, masker)
			}
		case *pgproto3.CommandComplete:
			masker = nil
			columnCount = -1
		case *pgproto3.ErrorResponse:
			data = false
			// The one client-facing target-DB-error site for both relays: on a diagnostic-redacted decision,
			// strip the value-bearing fields before the frame is emitted (native wire) AND before targetDbErr
			// is derived (run surfaces targetDbErr) — a PostgreSQL error can echo a masked/denied value the
			// statement never referenced (the whole-row `DETAIL`). See docs/diagnostic-redaction.md.
			if c.qe != nil && c.qe.SanitizeDiagnostics() {
				message = sanitizeError(message)
				out = message
			}
			if targetDbErr == nil {
				targetDbErr = errors.New(message.Message)
			}
		case *pgproto3.ParameterStatus:
			data = false
			if message.Name == "search_path" && c.qe != nil {
				c.qe.MarkNamespaceDirty()
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
	expected, maxRows int
	result            *engine.StatementResult
	failed            error
}

func (c *rowsCollector) emit(message pgproto3.BackendMessage) error {
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
		if c.maxRows <= 0 || len(c.result.Rows) < c.maxRows {
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

func maskDataRow(message *pgproto3.DataRow, masker *engine.RowMasker) *pgproto3.DataRow {
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

func isPostgresEmptyQuery(sql string) bool {
	for i := 0; i < len(sql); {
		switch sql[i] {
		case ' ', '\t', '\n', '\r', '\f', ';':
			i++
		case '-':
			if i+1 >= len(sql) || sql[i+1] != '-' {
				return false
			}
			i += 2
			for i < len(sql) && sql[i] != '\n' && sql[i] != '\r' {
				i++
			}
		case '/':
			if i+1 >= len(sql) || sql[i+1] != '*' {
				return false
			}
			i += 2
			depth := 1
			for i < len(sql) && depth > 0 {
				switch {
				case i+1 < len(sql) && sql[i] == '/' && sql[i+1] == '*':
					depth++
					i += 2
				case i+1 < len(sql) && sql[i] == '*' && sql[i+1] == '/':
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Server) handleQuery(sess *session, sql string) error {
	if isPostgresEmptyQuery(sql) {
		sess.targetDb.Send(&pgproto3.Query{})
		if err := sess.targetDb.Flush(); err != nil {
			return closeRelay(sess, err)
		}
		_, err := sess.streamResult(nil, streamOpts{}, func(message pgproto3.BackendMessage) error {
			sess.client.Send(message)
			return nil
		})
		if err != nil {
			return closeRelay(sess, mapWireStreamError(sess, err))
		}
		return sess.client.Flush()
	}

	ref := s.refetcher(sess, false)
	start := time.Now()
	var relayStats engine.RelayStats
	relayStatus := engine.StatusError
	decision, denied, err := engine.ServeStatement(sess.qe,
		sess.authzInput(sql, sess.token, sess.clientAddr, sess.connectionID, ref.RunAll), ref, nil,
		func(toSend string, masks []*pb.ColumnMask) (bool, error) {
			sess.targetDb.Send(&pgproto3.Query{String: toSend})
			if err := sess.targetDb.Flush(); err != nil {
				return false, err
			}
			bufferedFrames := 0
			targetDbErr, streamErr := sess.streamResult(masks, streamOpts{}, func(message pgproto3.BackendMessage) error {
				if row, ok := message.(*pgproto3.DataRow); ok {
					relayStats.Rows++
					relayStats.Bytes += dataRowBytes(row)
				}
				sess.client.Send(message)
				bufferedFrames++
				if bufferedFrames >= clientFlushThreshold {
					bufferedFrames = 0
					return sess.client.Flush()
				}
				return nil
			})
			if streamErr != nil {
				return false, mapWireStreamError(sess, streamErr)
			}
			sess.pendingDirty = true
			if err := sess.client.Flush(); err != nil {
				return false, err
			}
			relayStatus = engine.RelayStatus(targetDbErr == nil, nil)
			return targetDbErr == nil, nil
		})
	// Post-relay, best-effort completion: only a relayed (Proceed) statement reports. A DENY relayed
	// nothing, and EmitCompletion additionally no-ops for a decision with no audit id.
	if !denied {
		engine.EmitCompletion(s.client, decision, relayStats, relayStatus, start)
	}
	if err != nil {
		var fail engine.FailError
		if errors.As(err, &fail) {
			return sendError(sess.client, "ERROR", "58000", "proxy-monster: "+fail.Message, true, sess.lastTxStatus)
		}
		return closeRelay(sess, err)
	}
	if denied {
		reason := "policy"
		if decision != nil && decision.DenyReason != "" {
			reason = decision.DenyReason
		}
		return sendError(sess.client, "ERROR", "42501", "proxy-monster denied: "+reason, true, sess.lastTxStatus)
	}
	return nil
}

func mapWireStreamError(sess *session, err error) error {
	switch {
	case errors.Is(err, errMaskUnbound):
		return failClosedRelay(sess, "0A000", "proxy-monster: required mask could not be bound to a result column", err)
	case errors.Is(err, errCopyStream):
		return failClosedRelay(sess, "0A000", "proxy-monster: COPY is not supported", err)
	case errors.Is(err, errClientEncoding):
		return failClosedRelay(sess, "0A000", "proxy-monster: client_encoding must remain UTF8", err)
	case errors.Is(err, errStdConformingStrings):
		return failClosedRelay(sess, "0A000", "proxy-monster: standard_conforming_strings must remain on", err)
	case errors.Is(err, errUnexpectedFrame):
		return failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", err)
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

func (s *Server) guardParameterStatus(sess *session, message *pgproto3.ParameterStatus) error {
	sess.client.Send(message)
	if message.Name == "search_path" {
		sess.qe.MarkNamespaceDirty()
	}
	if err := guardParameterStatusValue(message.Name, message.Value); err != nil {
		return mapWireStreamError(sess, err)
	}
	return nil
}

func failClosedRelay(sess *session, code, message string, cause error) error {
	_ = sendError(sess.client, "ERROR", code, message, true, sess.lastTxStatus)
	return closeRelay(sess, cause)
}

func closeRelay(sess *session, cause error) error {
	_ = sess.clientConn.Close()
	_ = sess.targetDbConn.Close()
	return cause
}
