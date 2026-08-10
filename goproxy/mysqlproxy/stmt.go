package mysqlproxy

import (
	"errors"
	"fmt"
	"io"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const malformedStmtPrepareMessage = "proxy-monster: malformed prepared-statement response"

// preparedStmt binds the SQL actually prepared on the target DB to the namespace AND the ANSI_QUOTES
// observation frozen at PREPARE. MySQL parses `"…"` as an
// identifier-or-string at PREPARE time under the then-current sql_mode, fixing it for every EXECUTE, so the
// prepare-time ansiQuotes is what each EXECUTE re-authorizes under. Every EXECUTE is re-authorized against
// exactly this triple so authorization and execution cannot diverge.
type preparedStmt struct {
	sql        string
	namespace  []string
	ansiQuotes bool
}

// relayStmtPrepareResponse relays one complete COM_STMT_PREPARE response and returns the target-DB-assigned
// statement ID. Parameter and column definitions are opaque logical packets; a full-size physical packet
// therefore consumes the following continuation without advancing the definition count.
func relayStmtPrepareResponse(client io.Writer, targetDb io.Reader, deprecateEOF bool, redactErr func([]byte) []byte) (stmtID uint32, prepared bool, err error) {
	seq, payload, err := mysqlwire.ReadPacket(targetDb)
	if err != nil {
		return 0, false, err
	}
	if len(payload) == 0 {
		return 0, false, errors.New("mysqlproxy: empty prepared-statement response")
	}
	if payload[0] == 0xff {
		// A prepare-time target-DB ERR is a mandated redaction site (fail-closed): strip it on a redacted
		// decision before it reaches the client. See docs/diagnostic-redaction.md.
		if redactErr != nil {
			payload = redactErr(payload)
		}
		if err := mysqlwire.WritePacket(client, seq, payload); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}

	ok, err := mysqlwire.ParseStmtPrepareOK(payload)
	if err != nil {
		return 0, false, writeMalformedStmtPrepare(client, seq, err)
	}
	if err := mysqlwire.WritePacket(client, seq, payload); err != nil {
		return 0, false, err
	}

	relayDefinitions := func(count int) error {
		for range count {
			for {
				seq, payload, err := mysqlwire.ReadPacket(targetDb)
				if err != nil {
					return err
				}
				if err := mysqlwire.WritePacket(client, seq, payload); err != nil {
					return err
				}
				if len(payload) < maxPacketPayload {
					break
				}
			}
		}
		return nil
	}
	relayLegacyEOF := func() error {
		seq, payload, err := mysqlwire.ReadPacket(targetDb)
		if err != nil {
			return err
		}
		if !mysqlwire.IsResultTerminator(payload) {
			return writeMalformedStmtPrepare(client, seq, errors.New("mysqlproxy: missing EOF after prepared-statement definitions"))
		}
		return mysqlwire.WritePacket(client, seq, payload)
	}

	if err := relayDefinitions(ok.NumParams); err != nil {
		return 0, false, err
	}
	if !deprecateEOF && ok.NumParams > 0 {
		if err := relayLegacyEOF(); err != nil {
			return 0, false, err
		}
	}
	if err := relayDefinitions(ok.NumColumns); err != nil {
		return 0, false, err
	}
	if !deprecateEOF && ok.NumColumns > 0 {
		if err := relayLegacyEOF(); err != nil {
			return 0, false, err
		}
	}
	return ok.StmtID, true, nil
}

func writeMalformedStmtPrepare(client io.Writer, seq byte, cause error) error {
	writeErr := mysqlwire.WritePacket(client, seq, mysqlwire.ErrPacketState(
		1105,
		"HY000",
		malformedStmtPrepareMessage,
	))
	malformedErr := fmt.Errorf("mysqlproxy: malformed prepared-statement response: %w", cause)
	if writeErr != nil {
		return errors.Join(malformedErr, writeErr)
	}
	return malformedErr
}

func writeUnknownPreparedStatement(client io.Writer, seq byte, id uint32) error {
	return mysqlwire.WritePacket(client, seq, mysqlwire.ErrPacketState(
		1243,
		"HY000",
		fmt.Sprintf("proxy-monster: unknown prepared statement %d", id),
	))
}
