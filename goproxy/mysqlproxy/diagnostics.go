package mysqlproxy

import (
	"encoding/binary"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// A MySQL ERR packet (docs/diagnostic-redaction.md) echoes the raw stored value that masking is
// meant to hide — a conversion/truncation warning promoted to an error, a duplicate-key value, an
// invalid-character oracle. On a diagnostic-redacted connection the proxy keeps only the machine-readable
// essno + SQLSTATE and replaces the message with the essno's canonical symbol (see mysqlDiagnosticMessage),
// a fixed value-free identity looked up from the code — never reconstructed from the backend's text.
//
// A CLIENT_PROTOCOL_41 ERR payload (every backend here negotiates 4.1) is:
//
//	[0]    0xff header
//	[1:3]  essno, little-endian
//	[3]    '#' SQLSTATE marker
//	[4:9]  5-byte SQLSTATE
//	[9:]   human message (rest-of-packet string)
//
// The caller applies this only to a real ERR packet (payload[0]==0xff) it is about to forward to the
// client, never to result rows or column definitions (whose bytes can also start with 0xff).
func sanitizeErrPacket(payload []byte) []byte {
	if len(payload) < 3 || payload[0] != 0xff {
		return payload
	}
	essno := int(binary.LittleEndian.Uint16(payload[1:3]))
	sqlState := "HY000"
	if len(payload) >= 9 && payload[3] == '#' {
		sqlState = string(payload[4:9])
	}
	return mysqlwire.ErrPacketState(essno, sqlState, mysqlDiagnosticMessage(essno))
}
