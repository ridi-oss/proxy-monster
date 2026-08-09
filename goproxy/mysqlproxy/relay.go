package mysqlproxy

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const maxPacketPayload = mysqlwire.MaxPacketPayload

type resultPhase int

const (
	resultFirst resultPhase = iota
	resultColumnDefs
	resultAwaitEOF
	resultRows
)

type resultSetError struct {
	seq byte
	err error
}

func (e *resultSetError) Error() string { return e.err.Error() }
func (e *resultSetError) Unwrap() error { return e.err }

var (
	errMaskUnbound = engine.ErrMaskUnbound
	errRowTooLong  = errors.New("result row exceeds max packet size")
)

type resultHooks struct {
	Sink        func(seq byte, payload []byte) error
	OnColumns   func(int) error
	OnColumnDef func([]byte) error
	OnRow       func([]byte) ([]byte, error)
	OnOK        func(uint64)
	OnSchema    func(string)
	OnSysVars   func([]sysVarChange) error
	// RedactErr, when non-nil, rewrites a standalone backend ERR packet before it reaches the sink — the one
	// client-facing ERR site for both the wire relay and the run collector, so redaction here covers both.
	RedactErr func([]byte) []byte
	// Stats, when non-nil, tallies result volume as rows stream: one row per logical data row and the
	// backend row-packet payload bytes (including continuation fragments of an oversized row). It measures
	// backend data volume, not the post-mask relayed size, so a masked result reports the same volume signal.
	Stats *engine.RelayStats
}

// relayResultSet consumes one complete COM_QUERY text result for both wire relay and in-memory collection.
func relayResultSet(backend io.Reader, deprecateEOF bool, h resultHooks) (bool, error) {
	phase, columnCount, columnsSeen := resultFirst, 0, 0
	fragmenting, fragmentPhase := false, resultFirst
	sink := func(seq byte, payload []byte) error {
		if h.Sink != nil {
			return h.Sink(seq, payload)
		}
		return nil
	}
	completeColumn := func() {
		columnsSeen++
		if columnsSeen == columnCount {
			if deprecateEOF {
				phase = resultRows
			} else {
				phase = resultAwaitEOF
			}
		}
	}

	for {
		seq, payload, err := mysqlwire.ReadPacket(backend)
		if err != nil {
			return false, err
		}
		if fragmenting {
			// Continuations are opaque bytes belonging to the prior logical column definition or row.
			// A row's continuation fragments carry row data, so their bytes join the volume tally (the
			// logical row itself was already counted when its first fragment entered the resultRows phase).
			if h.Stats != nil && fragmentPhase == resultRows {
				h.Stats.Bytes += int64(len(payload))
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			if len(payload) < maxPacketPayload {
				fragmenting = false
				if fragmentPhase == resultColumnDefs {
					completeColumn()
				}
			}
			continue
		}
		if len(payload) == 0 {
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			continue
		}
		if payload[0] == 0xff {
			// A genuine standalone ERR (continuations were handled above), so it is safe to rewrite: on a
			// diagnostic-redacted decision strip it to essno + SQLSTATE + the essno's canonical symbol before
			// it reaches the sink, closing the value-echoing ERR leaks (conversion/truncation, the
			// extractvalue XPATH oracle). See docs/diagnostic-redaction.md.
			if h.RedactErr != nil {
				payload = h.RedactErr(payload)
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			return false, nil
		}

		switch phase {
		case resultFirst:
			if payload[0] == 0x00 {
				clean, affected, schema, sysVars, err := normalizeBackendOK(payload)
				if err != nil {
					return false, &resultSetError{seq, fmt.Errorf("parse result OK: %w", err)}
				}
				if schema != nil && h.OnSchema != nil {
					h.OnSchema(*schema)
				}
				if len(sysVars) > 0 && h.OnSysVars != nil {
					if err := h.OnSysVars(sysVars); err != nil {
						return false, &resultSetError{seq, err}
					}
				}
				if h.OnOK != nil {
					h.OnOK(affected)
				}
				if err := sink(seq, clean); err != nil {
					return false, err
				}
				return true, nil
			}
			count, err := mysqlwire.NewReader(payload).Lenenc()
			if err != nil {
				return false, &resultSetError{seq, fmt.Errorf("parse result column count: %w", err)}
			}
			if count == 0 || count > uint64(^uint(0)>>1) {
				return false, &resultSetError{seq, fmt.Errorf("invalid result column count %d", count)}
			}
			columnCount = int(count)
			if h.OnColumns != nil {
				if err := h.OnColumns(columnCount); err != nil {
					return false, &resultSetError{seq, err}
				}
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			phase = resultColumnDefs

		case resultColumnDefs:
			if h.OnColumnDef != nil {
				if len(payload) == maxPacketPayload {
					return false, &resultSetError{seq, errors.New("fragmented MySQL column definitions are not supported")}
				}
				if err := h.OnColumnDef(payload); err != nil {
					return false, &resultSetError{seq, err}
				}
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			if len(payload) == maxPacketPayload {
				fragmenting, fragmentPhase = true, resultColumnDefs
				continue
			}
			completeColumn()

		case resultAwaitEOF:
			if !mysqlwire.IsResultTerminator(payload) {
				return false, &resultSetError{seq, errors.New("missing EOF after column definitions")}
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			phase = resultRows

		case resultRows:
			if deprecateEOF && payload[0] == 0xfe && len(payload) < maxPacketPayload {
				clean, _, schema, sysVars, err := normalizeBackendOK(payload)
				if err != nil {
					return false, &resultSetError{seq, fmt.Errorf("parse result terminator: %w", err)}
				}
				if schema != nil && h.OnSchema != nil {
					h.OnSchema(*schema)
				}
				if len(sysVars) > 0 && h.OnSysVars != nil {
					if err := h.OnSysVars(sysVars); err != nil {
						return false, &resultSetError{seq, err}
					}
				}
				if err := sink(seq, clean); err != nil {
					return false, err
				}
				return true, nil
			}
			if !deprecateEOF && mysqlwire.IsResultTerminator(payload) {
				if err := sink(seq, payload); err != nil {
					return false, err
				}
				return true, nil
			}
			// A non-terminator packet in the rows phase starts one logical data row (its continuation
			// fragments, if any, are counted in the fragmenting block above). Tally it before masking so the
			// volume reflects the backend row, not the rewritten one.
			if h.Stats != nil {
				h.Stats.Rows++
				h.Stats.Bytes += int64(len(payload))
			}
			if h.OnRow != nil {
				if len(payload) == maxPacketPayload {
					return false, &resultSetError{seq, errRowTooLong}
				}
				payload, err = h.OnRow(payload)
				if err != nil {
					return false, &resultSetError{seq, err}
				}
			}
			if err := sink(seq, payload); err != nil {
				return false, err
			}
			if len(payload) == maxPacketPayload {
				fragmenting, fragmentPhase = true, resultRows
			}
		}
	}
}

// errRedactor returns the ERR-packet redactor for the current decision — sanitizeErrPacket when the control
// plane latched diagnostic redaction for this statement, else nil (relay the ERR verbatim). It is the single
// gate every backend-ERR relay path passes through. See docs/diagnostic-redaction.md.
func errRedactor(qe *engine.QueryEngine) func([]byte) []byte {
	if qe != nil && qe.SanitizeDiagnostics() {
		return sanitizeErrPacket
	}
	return nil
}

// relayQueryResponseTracked streams one backend result to the client and applies engine-selected masks.
// It also fails closed on a session-state violation reported in the OK packet
// (schema tracking disabled, tracking list dropped, or a charset that left UTF-8): a client-issued SET that
// the control plane allowed can still defeat the proxy's observation, so the guard terminates the session
// before the offending statement's OK reaches the client. A binding, row-decoding, or session-state failure
// sends a final ERR and closes both sockets so no unmasked row can leak, no partially-relayed protocol can
// be reused, and no follow-up query can run under a defeated invariant.
func relayQueryResponseTracked(
	client, backend net.Conn,
	deprecateEOF bool,
	masks []*pb.ColumnMask,
	redactErr func([]byte) []byte,
) (bool, engine.RelayStats, error) {
	columnCount := 0
	var masker *engine.RowMasker
	var stats engine.RelayStats

	var onFirst func(int) error
	var rewrite func([]byte) ([]byte, error)
	if len(masks) > 0 {
		onFirst = func(count int) error {
			columnCount = count
			masker = engine.NewRowMasker(masks, count)
			if masker == nil {
				return errMaskUnbound
			}
			return nil
		}
		rewrite = func(payload []byte) ([]byte, error) {
			return rewriteMaskedTextRow(payload, columnCount, masker)
		}
	}

	ok, err := relayResultSet(backend, deprecateEOF, resultHooks{
		Sink:      func(seq byte, payload []byte) error { return mysqlwire.WritePacket(client, seq, payload) },
		OnColumns: onFirst,
		OnRow:     rewrite,
		// The namespace is re-probed before every statement (probe-always), so SESSION_TRACK_SCHEMA is ignored.
		OnSysVars: checkSysVarInvariants,
		RedactErr: redactErr,
		Stats:     &stats,
	})
	if err == nil {
		return ok, stats, nil
	}

	var resultErr *resultSetError
	if errors.As(err, &resultErr) {
		code := 1105
		state := "HY000"
		message := "proxy-monster: malformed backend result set"
		switch {
		case errors.Is(resultErr, errMaskUnbound):
			code = 1235
			state = "42000"
			message = "proxy-monster: required mask could not be bound to a result column"
		case errors.Is(resultErr, errRowTooLong):
			// The wire path only rewrites rows when a mask is bound, so an oversized row here is a masked one.
			message = "proxy-monster: masked row exceeds max packet size"
		case errors.Is(resultErr, errSchemaTrackingDisabled), errors.Is(resultErr, errSessionTrackingDropped):
			state = "HY000"
			message = "proxy-monster: session-state tracking must stay enabled; connection closed"
		case errors.Is(resultErr, errUnsafeCharset):
			state = "HY000"
			message = "proxy-monster: connection character set must remain utf8mb4/utf8; connection closed"
		case errors.Is(resultErr, errUnsafeSqlMode):
			state = "HY000"
			message = "proxy-monster: backend sql_mode enables a flag that is not parse-safe (only ANSI_QUOTES and known runtime/semantic flags are allowed); connection closed"
		case len(masks) > 0:
			message = "proxy-monster: malformed backend text row"
		}
		_ = mysqlwire.WritePacket(client, resultErr.seq, mysqlwire.ErrPacketState(code, state, message))
	}
	_ = client.Close()
	_ = backend.Close()
	// The partial volume tallied before the fault still travels with the error completion.
	return false, stats, err
}

func rewriteMaskedTextRow(payload []byte, columnCount int, masker *engine.RowMasker) ([]byte, error) {
	values, err := mysqlwire.ParseTextRow(payload, columnCount)
	if err != nil {
		return nil, fmt.Errorf("decode text row: %w", err)
	}
	masked := masker.Apply(values)
	if textRowPayloadSize(masked) >= maxPacketPayload {
		return nil, errRowTooLong
	}
	return mysqlwire.TextRowPayload(masked), nil
}

func textRowPayloadSize(values []*string) int {
	total := 0
	for _, value := range values {
		if value == nil {
			total++
		} else {
			n := len(*value)
			switch {
			case n < 251:
				total += 1 + n
			case n < 65536:
				total += 3 + n
			case n < 16777216:
				total += 4 + n
			default:
				total += 9 + n
			}
		}
		if total >= maxPacketPayload {
			return total
		}
	}
	return total
}
