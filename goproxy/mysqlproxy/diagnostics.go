package mysqlproxy

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// A MySQL ERR packet (docs/diagnostic-redaction.md) echoes the raw stored value that masking is
// meant to hide — a conversion/truncation warning promoted to an error, a duplicate-key value, an
// invalid-character oracle. On a diagnostic-redacted connection the proxy keeps only the machine-readable
// essno + SQLSTATE and replaces the message with redactedErrMessage.
//
// A CLIENT_PROTOCOL_41 ERR payload (every target DB here negotiates 4.1) is:
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
	essno, sqlState := errPacketCode(payload)
	return mysqlwire.ErrPacketState(essno, sqlState, redactedErrMessage(essno, mysqlwire.ErrString(payload)))
}

// redactedErrString renders the "ERROR <essno> (<SQLSTATE>): <message>" form of a sanitized ERR packet — the
// diagnostic-redacted string a run stores for a masked view.
func redactedErrString(payload []byte) string {
	if len(payload) < 3 || payload[0] != 0xff {
		return ""
	}
	essno, sqlState := errPacketCode(payload)
	return fmt.Sprintf("ERROR %d (%s): %s", essno, sqlState, redactedErrMessage(essno, mysqlwire.ErrString(payload)))
}

func errPacketCode(payload []byte) (int, string) {
	essno := int(binary.LittleEndian.Uint16(payload[1:3]))
	sqlState := "HY000"
	if len(payload) >= 9 && payload[3] == '#' {
		sqlState = string(payload[4:9])
	}
	return essno, sqlState
}

// redactedErrMessage keeps the target DB's message when it matches its essno's schema-only template
// (mysqlSchemaMessages), and otherwise replaces it with the essno symbol — looked up from the code, never
// reconstructed from the echoed text.
func redactedErrMessage(essno int, msg string) string {
	for _, re := range mysqlSchemaPatterns[essno] {
		if re.MatchString(msg) {
			return msg
		}
	}
	return mysqlDiagnosticMessage(essno)
}

var mysqlSchemaPatterns = compileMysqlSchemaMessages()

var mysqlSpecifier = regexp.MustCompile(`%-?(?:\.[0-9]+)?(?:s|l{0,2}[du])`)

func compileMysqlSchemaMessages() map[int][]*regexp.Regexp {
	out := make(map[int][]*regexp.Regexp, len(mysqlSchemaMessages))
	for essno, templates := range mysqlSchemaMessages {
		for _, t := range templates {
			out[essno] = append(out[essno], regexp.MustCompile(mysqlTemplatePattern(t)))
		}
	}
	return out
}

// mysqlTemplatePattern turns a printf-style template into an anchored pattern: %s matches any text, a
// numeric specifier only digits.
func mysqlTemplatePattern(template string) string {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	last := 0
	for _, loc := range mysqlSpecifier.FindAllStringIndex(template, -1) {
		b.WriteString(regexp.QuoteMeta(template[last:loc[0]]))
		if template[loc[1]-1] == 's' {
			b.WriteString(`.*`)
		} else {
			b.WriteString(`[0-9]+`)
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(template[last:]))
	b.WriteString(`\z`)
	return b.String()
}
