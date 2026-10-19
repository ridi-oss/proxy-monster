package mysql

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
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

// A target-DB ERR relayed through relayResultSet with the RedactErr hook installed reaches the client
// sanitized — essno + SQLSTATE preserved, message and the echoed value gone.
func TestRelayResultSetRedactsTargetDbError(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1062, "23000", "Duplicate entry 'alice@example.com' for key 'users.email'"))

	relayed := relayErr(t, &targetDb)
	if binary.LittleEndian.Uint16(relayed[1:3]) != 1062 {
		t.Errorf("essno not preserved through relay: %x", relayed[1:3])
	}
	if mysqlwire.ErrString(relayed) != "ER_DUP_ENTRY" {
		t.Errorf("relayed message = %q, want the essno symbol", mysqlwire.ErrString(relayed))
	}
	if bytes.Contains(relayed, []byte("alice@example.com")) {
		t.Error("stored value survived redaction through the relay")
	}
}

func TestRelayResultSetKeepsSchemaOnlyError(t *testing.T) {
	var targetDb bytes.Buffer
	const msg = "Table 'acme.orders_archive' doesn't exist"
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", msg))

	relayed := relayErr(t, &targetDb)
	if got := mysqlwire.ErrString(relayed); got != msg {
		t.Errorf("relayed message = %q, want %q", got, msg)
	}
	if string(relayed[4:9]) != "42S02" {
		t.Errorf("SQLSTATE not preserved: %q", string(relayed[4:9]))
	}
}

func relayErr(t *testing.T, targetDb *bytes.Buffer) []byte {
	t.Helper()
	var relayed []byte
	ok, _, err := relayResultSet(targetDb, true, resultHooks{
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
	return relayed
}

// Without the RedactErr hook the ERR is relayed verbatim (the system:development / non-latched path), so the
// redaction is genuinely gated, not unconditional.
func TestRelayResultSetForwardsTargetDbErrorVerbatimWhenNotRedacting(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", "Table 'db.t' doesn't exist"))

	var relayed []byte
	if _, _, err := relayResultSet(&targetDb, true, resultHooks{
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
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1064, "42000",
		"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '010-1234-5678' at line 1"))

	var client bytes.Buffer
	if _, prepared, err := relayStmtPrepareResponse(&client, &targetDb, true, sanitizeErrPacket); err != nil || prepared {
		t.Fatalf("relayStmtPrepareResponse: prepared=%v err=%v", prepared, err)
	}
	_, payload, err := mysqlwire.ReadPacket(&client)
	if err != nil {
		t.Fatalf("read relayed prepare ERR: %v", err)
	}
	if mysqlwire.ErrString(payload) != "ER_PARSE_ERROR" {
		t.Errorf("relayed prepare ERR message = %q, want the essno symbol", mysqlwire.ErrString(payload))
	}
	if bytes.Contains(payload, []byte("010-1234-5678")) {
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

// Messages as MySQL 8.0 and 8.4 send them.
func TestRedactedErrMessageKeepsSchemaNames(t *testing.T) {
	cases := []struct {
		essno int
		msg   string
	}{
		{1146, "Table 'acme.orders' doesn't exist"},
		{1054, "Unknown column 'shipped_at' in 'field list'"},
		{1054, "Unknown column 'o.shipped_at' in 'where clause'"},
		{1049, "Unknown database 'acme_staging'"},
		{1050, "Table 'orders' already exists"},
		{1051, "Unknown table 'acme.orders_tmp'"},
		{1007, "Can't create database 'acme'; database exists"},
		{1008, "Can't drop database 'acme_old'; database doesn't exist"},
		{1052, "Column 'id' in field list is ambiguous"},
		{1048, "Column 'email' cannot be null"},
		{1364, "Field 'created_at' doesn't have a default value"},
		{3819, "Check constraint 'amount_positive' is violated."},
		{1452, "Cannot add or update a child row: a foreign key constraint fails (`acme`.`order_items`, CONSTRAINT `order_items_order_fk` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`))"},
		{1451, "Cannot delete or update a parent row: a foreign key constraint fails (`acme`.`order_items`, CONSTRAINT `order_items_order_fk` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`))"},
		{1451, "Cannot delete or update a parent row: a foreign key constraint fails"},
		{1061, "Duplicate key name 'orders_email_idx'"},
		{1091, "Can't DROP 'orders_email_idx'; check that column/key exists"},
		{1305, "PROCEDURE acme.refresh_totals does not exist"},
		{1305, "FUNCTION acme.mask_email does not exist"},
		{1055, "Expression #1 of SELECT list is not in GROUP BY clause and contains nonaggregated column 'acme.orders.status' which is not functionally dependent on columns in GROUP BY clause; this is incompatible with sql_mode=only_full_group_by"},
		{1140, "In aggregated query without GROUP BY, expression #1 of SELECT list contains nonaggregated column 'acme.orders.status'; this is incompatible with sql_mode=only_full_group_by"},
		{1267, "Illegal mix of collations (utf8mb4_0900_ai_ci,IMPLICIT) and (latin1_swedish_ci,EXPLICIT) for operation '='"},
		{1072, "Key column 'shipped_at' doesn't exist in table"},
		{3821, "Check constraint 'amount_positive' is not found in the table."},
		{1369, "CHECK OPTION failed 'acme.active_orders'"},
		{1066, "Not unique table/alias: 'o'"},
		{1071, "Specified key was too long; max key length is 3072 bytes"},
		{1859, "Duplicate entry for key 'orders_email_idx'"},
	}
	for _, c := range cases {
		if got := redactedErrMessage(c.essno, c.msg); got != c.msg {
			t.Errorf("redactedErrMessage(%d, %q) = %q, want the message kept", c.essno, c.msg, got)
		}
	}
}

func TestRedactedErrMessageStripsValues(t *testing.T) {
	cases := []struct {
		essno int
		msg   string
	}{
		{1062, "Duplicate entry 'alice@example.com' for key 'users.email'"},
		{1586, "Duplicate entry 'alice@example.com' for key 'users.email'"},
		{1292, "Truncated incorrect INTEGER value: '010-1234-5678'"},
		{1366, "Incorrect integer value: '010-1234-5678' for column 'age' at row 1"},
		{1064, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '010-1234-5678' at line 1"},
		{1300, "Invalid utf8mb4 character string: 'FF706D'"},
		{1105, "XPATH syntax error: '~010-1234-5678'"},
		{1265, "Data truncated for column 'phone' at row 3"},
		{1406, "Data too long for column 'phone' at row 3"},
		{1231, "Variable 'character_set_client' can't be set to the value of '010-1234-5678'"},
		{1115, "Unknown character set: '010-1234-5678'"},
		{1142, "SELECT command denied to user 'alice'@'10.0.0.1' for table 'orders'"},
		// An allowlisted essno whose text does not match its template: a SIGNAL text, a non-English
		// lc_messages, a message cut at MYSQL_ERRMSG_SIZE.
		{1146, "010-1234-5678"},
		{1054, "Unknown column '010-1234-5678'"},
		{1146, "Table 'acme.orders' n'existe pas"},
		{1146, "Table 'acme.orders' doesn't ex"},
	}
	for _, c := range cases {
		got := redactedErrMessage(c.essno, c.msg)
		if got != mysqlDiagnosticMessage(c.essno) {
			t.Errorf("redactedErrMessage(%d, %q) = %q, want the essno symbol", c.essno, c.msg, got)
		}
	}
}

func TestMysqlSchemaMessagesExcludeValueCarriers(t *testing.T) {
	for _, essno := range []int{1062, 1586, 1292, 1366, 1064, 1300, 1105, 1265, 1406, 1264, 1231, 1411, 1115, 1273, 1286, 1060, 1166, 3511} {
		if _, ok := mysqlSchemaMessages[essno]; ok {
			t.Errorf("essno %d can carry a value or literal and must not be allowlisted", essno)
		}
	}
}

func TestEveryMysqlSchemaTemplateKeepsAFilledMessage(t *testing.T) {
	spec := regexp.MustCompile(`%-?(?:\.[0-9]+)?(?:s|l{0,2}[du])`)
	for essno, templates := range mysqlSchemaMessages {
		for _, tmpl := range templates {
			msg := spec.ReplaceAllStringFunc(tmpl, func(s string) string {
				if strings.HasSuffix(s, "s") {
					return "acme_orders"
				}
				return "64"
			})
			if got := redactedErrMessage(essno, msg); got != msg {
				t.Errorf("essno %d: %q was stripped to %q", essno, msg, got)
			}
			if loc := spec.FindAllStringIndex(tmpl, -1); len(loc) > 0 && loc[len(loc)-1][1] == len(tmpl) {
				continue
			}
			if regexp.MustCompile(mysqlTemplatePattern(tmpl)).MatchString(msg + " 010-1234-5678") {
				t.Errorf("essno %d: template %q matches a message with trailing text", essno, tmpl)
			}
		}
	}
}

func TestRedactedErrStringKeepsSchemaOnlyMessage(t *testing.T) {
	kept := mysqlwire.ErrPacketState(1146, "42S02", "Table 'acme.orders' doesn't exist")
	if got, want := redactedErrString(kept), "ERROR 1146 (42S02): Table 'acme.orders' doesn't exist"; got != want {
		t.Errorf("redactedErrString = %q, want %q", got, want)
	}
	stripped := mysqlwire.ErrPacketState(1062, "23000", "Duplicate entry 'alice@example.com' for key 'users.email'")
	if got, want := redactedErrString(stripped), "ERROR 1062 (23000): ER_DUP_ENTRY"; got != want {
		t.Errorf("redactedErrString = %q, want %q", got, want)
	}
}
