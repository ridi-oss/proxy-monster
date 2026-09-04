package mysqlproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	serverStatusSessionStateChanged = 0x4000
	sessionTrackSystemVariables     = 0x00
	sessionTrackSchema              = 0x01
)

// sysVarChange is one system variable reported through SESSION_TRACK_SYSTEM_VARIABLES after a statement
// changed it. Both the run session and the wire relay watch these to fail closed when an enforcement
// invariant (schema tracking, the tracking list, the connection charset) leaves its safe value.
type sysVarChange struct {
	name  string
	value string
}

var (
	errSchemaTrackingDisabled = errors.New("target DB disabled session_track_schema; session state can no longer be tracked")
	errUnsafeCharset          = errors.New("target-DB session character set left utf8mb4/utf8; identifier binding can no longer be trusted")
	errSessionTrackingDropped = errors.New("target DB dropped a required member from session_track_system_variables; session-state changes can no longer be observed")
	errUnsafeSqlMode          = errors.New("target-DB session sql_mode enabled a flag that is not parse-safe (only ANSI_QUOTES and known runtime/semantic flags are allowed; anything else — NO_BACKSLASH_ESCAPES/PIPES_AS_CONCAT/… or an unrecognized flag — fails closed); analyzer↔target-DB SQL lexing can no longer be trusted")
)

// requiredTrackedSysVars are the system variables the proxy pins to SESSION_TRACK_SYSTEM_VARIABLES so a
// DIRECT change to any of them surfaces in the OK packet of the statement that made it. The list includes
// session_track_system_variables ITSELF so a change that keeps it listed but drops another member is still
// reported.
//
// This tracker is a fast fail-closed signal for direct tampering, but it is NOT sufficient on its own:
// MySQL evaluates the tracker against the list as it stands at the END of the statement, so clearing the
// list (setting session_track_system_variables to the empty string) — or setting it to any value that
// omits the variable itself — is reported as NOTHING (verified against live MySQL 8.0: no SESSION_TRACK
// block, and the OK's SESSION_STATE_CHANGED status bit stays clear). Once the list is cleared, a later
// SET session_track_schema=OFF and SET NAMES latin1 are equally silent. The proxy therefore ALSO re-probes
// the namespace and charset before every statement (probe-always; see target DB.go mysqlSessionProbeSQL),
// which observes the true current database and charset regardless of tracker state.
var requiredTrackedSysVars = []string{
	"session_track_system_variables",
	"session_track_schema",
	"character_set_client",
	"character_set_connection",
	"character_set_results",
	"sql_mode",
}

func trackedSysVarList() string { return strings.Join(requiredTrackedSysVars, ",") }

// checkSysVarInvariants returns a terminal error if a reported system-variable change moved an enforcement
// invariant to an unsafe value: schema tracking turned off, the tracking list dropped a required member, a
// session charset left UTF-8, or sql_mode enabled a lexer-changing flag the analyzer cannot model
// (NO_BACKSLASH_ESCAPES / PIPES_AS_CONCAT / …, which desync the analyzer's lexing from the target DB's). It is
// shared by the run session and the wire relay so a client cannot silently defeat the proxy's observation
// on either path. A change that enables ONLY ANSI_QUOTES is NOT a violation here: the analyzer models it and
// the pre-statement probe forwards it, so the following statement is decided under the right mode rather than
// failing the session closed.
func checkSysVarInvariants(changes []sysVarChange) error {
	for _, change := range changes {
		switch strings.ToLower(change.name) {
		case "session_track_schema":
			// MySQL may render the boolean as "ON" or "1"; anything else (including "OFF"/"0") is unsafe.
			if !strings.EqualFold(change.value, "ON") && change.value != "1" {
				return errSchemaTrackingDisabled
			}
		case "session_track_system_variables":
			if err := requireTrackedMembers(change.value); err != nil {
				return err
			}
		case "character_set_client", "character_set_connection", "character_set_results":
			if !isSafeMySQLCharset(change.value) {
				return errUnsafeCharset
			}
		case "sql_mode":
			if _, err := classifyMySQLSqlMode(change.value); err != nil {
				return err
			}
		}
	}
	return nil
}

// requireTrackedMembers fails closed if a new SESSION_TRACK_SYSTEM_VARIABLES value drops any variable the
// proxy depends on observing.
func requireTrackedMembers(list string) error {
	present := make(map[string]bool)
	for _, member := range strings.Split(list, ",") {
		present[strings.ToLower(strings.TrimSpace(member))] = true
	}
	for _, required := range requiredTrackedSysVars {
		if !present[required] {
			return errSessionTrackingDropped
		}
	}
	return nil
}

// isSafeMySQLCharset reports whether a session character set keeps the query bytes bound to the same
// identifiers the control plane resolves. utf8mb4 and utf8/utf8mb3 decode ASCII and BMP identifiers
// identically to the UTF-8 the control plane parses; any other charset (e.g. latin1) rebinds them.
func isSafeMySQLCharset(value string) bool {
	switch strings.ToLower(value) {
	case "utf8mb4", "utf8", "utf8mb3":
		return true
	default:
		return false
	}
}

// mysqlParseSafeSqlModes are the MySQL 8.0 and MariaDB sql_mode flags known NOT to affect how a statement is TOKENIZED
// or PARSED — they change runtime/execution semantics only (strictness, zero-date handling, GROUP BY
// validation, type mapping, CHAR padding, …), so the analyzer parses the same text the same way whether or
// not they are set. Everything the analyzer's lexer/grammar is sensitive to is handled explicitly by
// classifyMySQLSqlMode (ANSI_QUOTES is observed+forwarded; NO_BACKSLASH_ESCAPES / PIPES_AS_CONCAT /
// HIGH_NOT_PRECEDENCE / IGNORE_SPACE are parse-affecting and unmodeled). This set is the ALLOWLIST: a flag
// that is neither ANSI_QUOTES nor a member here fails the session closed — fail-closed conservation, so a
// flag we do not recognize (a future MySQL version, an Aurora/fork extension) cannot silently desync the
// analyzer's lexer from the target DB's. A denylist would fail OPEN on such an unknown flag. The compound
// modes (ANSI, TRADITIONAL, …) are absent because MySQL stores @@session.sql_mode EXPANDED — only the
// component flags ever reach this classifier.
var mysqlParseSafeSqlModes = map[string]bool{
	"ALLOW_INVALID_DATES":        true,
	"ERROR_FOR_DIVISION_BY_ZERO": true,
	"NO_AUTO_CREATE_USER":        true,
	"NO_AUTO_VALUE_ON_ZERO":      true,
	"NO_DIR_IN_CREATE":           true,
	"NO_ENGINE_SUBSTITUTION":     true,
	"NO_UNSIGNED_SUBTRACTION":    true,
	"NO_ZERO_DATE":               true,
	"NO_ZERO_IN_DATE":            true,
	"ONLY_FULL_GROUP_BY":         true,
	"PAD_CHAR_TO_FULL_LENGTH":    true,
	"REAL_AS_FLOAT":              true,
	"STRICT_ALL_TABLES":          true,
	"STRICT_TRANS_TABLES":        true,
	"TIME_TRUNCATE_FRACTIONAL":   true,
}

// classifyMySQLSqlMode inspects a session sql_mode and decides, fail-closed, how the proxy must treat it.
// ANSI_QUOTES makes `"…"` a quoted identifier instead of a string literal; the analyzer models this (its
// mysql_ansi_quotes EngineConfig), so the proxy OBSERVES it and returns ansiQuotes=true to forward to the
// control plane — a masked column quoted with `"` is then still masked. A flag known to be parse-safe
// (mysqlParseSafeSqlModes) is ignored. ANY OTHER flag — a known parse-affecting one the analyzer cannot
// model (NO_BACKSLASH_ESCAPES / PIPES_AS_CONCAT / HIGH_NOT_PRECEDENCE / IGNORE_SPACE) OR one this build does
// not recognize — fails the session closed (errUnsafeSqlMode), because it could desync the analyzer's lexer
// from the target DB's and leak a masked column. sql_mode is a comma-separated flag list; an unsafe member
// takes precedence over an observed ANSI_QUOTES (e.g. "ANSI_QUOTES,NO_BACKSLASH_ESCAPES" fails closed).
// Mirrors the PG standard_conforming_strings guard (pgproxy/target DB.go).
func classifyMySQLSqlMode(value string) (ansiQuotes bool, err error) {
	for _, raw := range strings.Split(value, ",") {
		mode := strings.ToUpper(strings.TrimSpace(raw))
		switch {
		case mode == "":
			// An empty token (sql_mode="" or a trailing/duplicate comma) carries no flag.
		case mode == "ANSI_QUOTES":
			ansiQuotes = true
		case mysqlParseSafeSqlModes[mode]:
			// A known runtime/semantic flag — does not affect how the statement parses.
		default:
			return false, errUnsafeSqlMode
		}
	}
	return ansiQuotes, nil
}

// normalizeTargetDbOK removes CLIENT_SESSION_TRACK-only framing before an OK packet is sent to a frontend
// that did not negotiate it, and returns affected rows plus its authoritative session-state signals: a
// schema-change value (SESSION_TRACK_SCHEMA) and any tracked system-variable changes
// (SESSION_TRACK_SYSTEM_VARIABLES). Tracking these signals avoids interposing SELECT DATABASE() between
// client statements, which would corrupt MySQL's statement-scoped diagnostics such as ROW_COUNT(),
// FOUND_ROWS(), and SHOW WARNINGS.
func normalizeTargetDbOK(payload []byte) ([]byte, uint64, *string, []sysVarChange, error) {
	if len(payload) == 0 || (payload[0] != 0x00 && payload[0] != 0xfe) {
		return nil, 0, nil, nil, fmt.Errorf("mysqlproxy: expected target-DB OK packet")
	}

	pos := 1
	affected, err := readLenencUint(payload, &pos)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("parse OK affected rows: %w", err)
	}
	if _, err := readLenencUint(payload, &pos); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("parse OK last insert id: %w", err)
	}
	if len(payload)-pos < 4 {
		return nil, 0, nil, nil, io.ErrUnexpectedEOF
	}
	statusPos := pos
	status := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 4 // status + warnings

	clean := append([]byte(nil), payload[:pos]...)
	cleanStatus := status &^ serverStatusSessionStateChanged
	binary.LittleEndian.PutUint16(clean[statusPos:statusPos+2], cleanStatus)

	// Some compatible servers omit the optional info field when it is empty. There can be no session-state
	// payload in that shape, so the fixed fields are already valid for a non-tracking frontend.
	if pos == len(payload) {
		if status&serverStatusSessionStateChanged != 0 {
			return nil, 0, nil, nil, fmt.Errorf("mysqlproxy: target-DB OK advertises session state without a state payload")
		}
		return clean, affected, nil, nil, nil
	}

	info, err := readLenencBytes(payload, &pos)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("parse OK info: %w", err)
	}
	// Without CLIENT_SESSION_TRACK the info field is string<EOF>, not string<lenenc>.
	clean = append(clean, info...)

	var schema *string
	var sysVars []sysVarChange
	if status&serverStatusSessionStateChanged != 0 {
		state, err := readLenencBytes(payload, &pos)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("parse OK session state: %w", err)
		}
		schema, sysVars, err = parseSessionState(state)
		if err != nil {
			return nil, 0, nil, nil, err
		}
	}
	if pos != len(payload) {
		return nil, 0, nil, nil, fmt.Errorf("mysqlproxy: trailing bytes after target-DB OK packet")
	}
	return clean, affected, schema, sysVars, nil
}

func parseSessionState(state []byte) (*string, []sysVarChange, error) {
	pos := 0
	var schema *string
	var sysVars []sysVarChange
	for pos < len(state) {
		stateType := state[pos]
		pos++
		block, err := readLenencBytes(state, &pos)
		if err != nil {
			return nil, nil, fmt.Errorf("parse session-state block: %w", err)
		}
		switch stateType {
		case sessionTrackSchema:
			blockPos := 0
			name, err := readLenencBytes(block, &blockPos)
			if err != nil || blockPos != len(block) {
				return nil, nil, fmt.Errorf("mysqlproxy: malformed SESSION_TRACK_SCHEMA block")
			}
			value := string(name)
			schema = &value
		case sessionTrackSystemVariables:
			// Each changed variable is its own top-level entry: string<lenenc> name, string<lenenc> value.
			blockPos := 0
			name, err := readLenencBytes(block, &blockPos)
			if err != nil {
				return nil, nil, fmt.Errorf("mysqlproxy: malformed SESSION_TRACK_SYSTEM_VARIABLES name")
			}
			value, err := readLenencBytes(block, &blockPos)
			if err != nil {
				return nil, nil, fmt.Errorf("mysqlproxy: malformed SESSION_TRACK_SYSTEM_VARIABLES value")
			}
			if blockPos != len(block) {
				return nil, nil, fmt.Errorf("mysqlproxy: trailing bytes in SESSION_TRACK_SYSTEM_VARIABLES block")
			}
			sysVars = append(sysVars, sysVarChange{name: string(name), value: string(value)})
		}
	}
	return schema, sysVars, nil
}

func readLenencBytes(payload []byte, pos *int) ([]byte, error) {
	n, err := readLenencUint(payload, pos)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(payload)-*pos) {
		return nil, io.ErrUnexpectedEOF
	}
	value := payload[*pos : *pos+int(n)]
	*pos += int(n)
	return value, nil
}

func readLenencUint(payload []byte, pos *int) (uint64, error) {
	if *pos >= len(payload) {
		return 0, io.ErrUnexpectedEOF
	}
	first := payload[*pos]
	(*pos)++
	switch first {
	case 0xfc:
		if len(payload)-*pos < 2 {
			return 0, io.ErrUnexpectedEOF
		}
		value := uint64(binary.LittleEndian.Uint16(payload[*pos : *pos+2]))
		*pos += 2
		return value, nil
	case 0xfd:
		if len(payload)-*pos < 3 {
			return 0, io.ErrUnexpectedEOF
		}
		value := uint64(payload[*pos]) | uint64(payload[*pos+1])<<8 | uint64(payload[*pos+2])<<16
		*pos += 3
		return value, nil
	case 0xfe:
		if len(payload)-*pos < 8 {
			return 0, io.ErrUnexpectedEOF
		}
		value := binary.LittleEndian.Uint64(payload[*pos : *pos+8])
		*pos += 8
		return value, nil
	case 0xfb, 0xff:
		return 0, fmt.Errorf("mysqlproxy: invalid length-encoded prefix 0x%02x", first)
	default:
		return uint64(first), nil
	}
}
