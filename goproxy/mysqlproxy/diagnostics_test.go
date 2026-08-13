package mysqlproxy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

func TestSanitizeErrPacketKeepsEssnoAndSqlStateOnly(t *testing.T) {
	// A conversion warning promoted to an error that echoes the stored value (the MySQL 1292 leak).
	in := mysqlwire.ErrPacketState(1292, "01000", "Truncated incorrect INTEGER value: '010-1234-5678'")
	out := sanitizeErrPacket(in)

	if len(out) < 9 || out[0] != 0xff {
		t.Fatalf("output is not an ERR packet: %x", out)
	}
	if essno := binary.LittleEndian.Uint16(out[1:3]); essno != 1292 {
		t.Errorf("essno = %d, want 1292", essno)
	}
	if out[3] != '#' || string(out[4:9]) != "01000" {
		t.Errorf("SQLSTATE not preserved: marker=%q state=%q", out[3], string(out[4:9]))
	}
	if msg := mysqlwire.ErrString(out); msg != "ER_TRUNCATED_WRONG_VALUE" {
		t.Errorf("message = %q, want the essno symbol", msg)
	}
	if bytes.Contains(out, []byte("010-1234-5678")) {
		t.Error("stored value survived redaction")
	}
}

func TestSanitizeErrPacketDefaultsSqlStateWhenAbsent(t *testing.T) {
	// A pre-4.1-shaped ERR (no '#'+SQLSTATE): 0xff, essno LE (0x0514 = 1300), then message.
	in := append([]byte{0xff, 0x14, 0x05}, []byte("Invalid utf8mb4 character string: 'FF706D'")...)
	out := sanitizeErrPacket(in)

	if binary.LittleEndian.Uint16(out[1:3]) != 0x0514 {
		t.Errorf("essno not preserved: %x", out[1:3])
	}
	if mysqlwire.ErrString(out) != "ER_INVALID_CHARACTER_STRING" {
		t.Errorf("message = %q, want the essno symbol", mysqlwire.ErrString(out))
	}
	if bytes.Contains(out, []byte("FF706D")) {
		t.Error("chunk-oracle bytes survived redaction")
	}
}

// End-to-end: a target-DB ERR relayed through relayResultSet with the RedactErr hook installed reaches the
// client sanitized — essno + SQLSTATE preserved, message and any echoed value gone.
func TestRelayResultSetRedactsTargetDbError(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", "Table 'db.secret_010_1234_5678' doesn't exist"))

	var relayed []byte
	ok, err := relayResultSet(&targetDb, true, resultHooks{
		Sink: func(_ byte, payload []byte) error {
			relayed = append([]byte(nil), payload...)
			return nil
		},
		RedactErr: sanitizeErrPacket,
	})
	if err != nil {
		t.Fatalf("relayResultSet: %v", err)
	}
	if ok {
		t.Fatal("relayResultSet reported success for a target-DB ERR")
	}
	if binary.LittleEndian.Uint16(relayed[1:3]) != 1146 {
		t.Errorf("essno not preserved through relay: %x", relayed[1:3])
	}
	if mysqlwire.ErrString(relayed) != "ER_NO_SUCH_TABLE" {
		t.Errorf("relayed message = %q, want the essno symbol", mysqlwire.ErrString(relayed))
	}
	if bytes.Contains(relayed, []byte("secret_010_1234_5678")) {
		t.Error("table name survived redaction through the relay")
	}
}

// Without the RedactErr hook the ERR is relayed verbatim (the system:development / non-latched path), so the
// redaction is genuinely gated, not unconditional.
func TestRelayResultSetForwardsTargetDbErrorVerbatimWhenNotRedacting(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", "Table 'db.t' doesn't exist"))

	var relayed []byte
	if _, err := relayResultSet(&targetDb, true, resultHooks{
		Sink: func(_ byte, payload []byte) error {
			relayed = append([]byte(nil), payload...)
			return nil
		},
	}); err != nil {
		t.Fatalf("relayResultSet: %v", err)
	}
	if mysqlwire.ErrString(relayed) != "Table 'db.t' doesn't exist" {
		t.Errorf("relayed message = %q, want verbatim target-DB message", mysqlwire.ErrString(relayed))
	}
}

// A prepare-time target-DB ERR is one of the three mandated MySQL ERR-forward sites: with the redactor it
// must reach the client stripped, closing the fail-closed gap even though PREPARE does not evaluate rows.
func TestRelayStmtPrepareResponseRedactsTargetDbError(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", "Table 'db.secret_010_1234_5678' doesn't exist"))

	var client bytes.Buffer
	if _, prepared, err := relayStmtPrepareResponse(&client, &targetDb, true, sanitizeErrPacket); err != nil || prepared {
		t.Fatalf("relayStmtPrepareResponse: prepared=%v err=%v", prepared, err)
	}
	_, payload, err := mysqlwire.ReadPacket(&client)
	if err != nil {
		t.Fatalf("read relayed prepare ERR: %v", err)
	}
	if mysqlwire.ErrString(payload) != "ER_NO_SUCH_TABLE" {
		t.Errorf("relayed prepare ERR message = %q, want the essno symbol", mysqlwire.ErrString(payload))
	}
	if bytes.Contains(payload, []byte("secret_010_1234_5678")) {
		t.Error("stored token survived redaction on the prepare path")
	}
}

func TestMysqlDiagnosticMessage(t *testing.T) {
	if got := mysqlDiagnosticMessage(1146); got != "ER_NO_SUCH_TABLE" {
		t.Errorf("mysqlDiagnosticMessage(1146) = %q, want ER_NO_SUCH_TABLE", got)
	}
	if got := mysqlDiagnosticMessage(1062); got != "ER_DUP_ENTRY" {
		t.Errorf("mysqlDiagnosticMessage(1062) = %q, want ER_DUP_ENTRY", got)
	}
	if got := mysqlDiagnosticMessage(1050); got != "ER_TABLE_EXISTS_ERROR" {
		t.Errorf("mysqlDiagnosticMessage(1050) = %q, want ER_TABLE_EXISTS_ERROR (added by the full-catalog expansion)", got)
	}
	if got := mysqlDiagnosticMessage(999999); got != engine.RedactedDiagnosticMessage {
		t.Errorf("mysqlDiagnosticMessage(unknown) = %q, want the generic fallback", got)
	}
}
