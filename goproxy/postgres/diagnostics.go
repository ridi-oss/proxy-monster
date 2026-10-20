package postgres

import (
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// A PostgreSQL ErrorResponse / NoticeResponse echoes the raw stored value that masking is meant to hide —
// the DETAIL field alone dumps the whole offending row, including columns the statement never named and
// columns the principal is denied. On a diagnostic-redacted connection (the control plane's per-decision
// flag, fresh each Decide) the proxy must not relay those messages verbatim. Every target-DB error/notice
// forward on a client-facing path goes through the two helpers below so the strip is applied in exactly
// one place per frame type. See docs/diagnostic-redaction.md.

// sanitizeError strips a target DB ErrorResponse to what cannot carry a masked/denied value that a restricted
// principal could not otherwise reach:
//
//   - Message (the free-form primary text) is replaced with the SQLSTATE's canonical condition name — a
//     fixed value-free identity looked up from the code (see pgDiagnosticMessage), never reconstructed from
//     the target DB's echoed text. The exception is a message that matches its SQLSTATE's schema-only template
//     (pgSchemaMessages) on an error raised by the statement itself, which is kept verbatim.
//   - Detail is dropped: `DETAIL: Failing row contains (…)` prints columns the statement never named.
//   - Where is dropped: an input function reports the text it failed on there (`JSON data, line 1: …`).
//   - InternalQuery and InternalPosition are dropped, and their presence also strips Message: they mark an
//     error in SQL text built at run time (query_to_xml, ts_stat), where a value can fill any template.
//   - UnknownFields is dropped: field codes the proxy can't classify fail closed.
//
// Everything else is KEPT — the SQLSTATE + severity, the structural object names
// (Schema/Table/Column/DataType/coNstraint), Hint, the statement position, and the server source location.
// For an ordinary error those hold object names, fixed text, or are empty; the way to put an arbitrary value
// there is `RAISE … USING`, which needs PL/pgSQL and is denied for a restricted principal. A pre-existing
// trigger or vouched function that RAISEs a value into one of them is the accepted defense-in-depth residual
// — see docs/diagnostic-redaction.md.
func sanitizeError(msg *pgproto3.ErrorResponse) *pgproto3.ErrorResponse {
	out := *msg
	if msg.InternalQuery != "" || !isSchemaOnlyMessage(msg.Code, msg.Message) {
		out.Message = pgDiagnosticMessage(msg.Code)
	}
	out.Detail = ""
	out.Where = ""
	out.InternalQuery = ""
	out.InternalPosition = 0
	out.UnknownFields = nil
	return &out
}

// forwardError sends a target DB ErrorResponse to the client, sanitized when the current decision has
// diagnostic redaction set, otherwise verbatim.
func forwardError(sess *session, msg *pgproto3.ErrorResponse) {
	if sess.authz.SanitizeDiagnostics() {
		sess.client.Send(sanitizeError(msg))
		return
	}
	sess.client.Send(msg)
}

// forwardNotice sends a target DB NoticeResponse to the client — forwarded even on a redacted connection. A
// notice carries no value a restricted principal could not otherwise reach: server-generated notices are
// advisory (object names, DDL, transaction state — never a row value), and the only way to put a value in
// one is `RAISE NOTICE`, which needs PL/pgSQL and is denied for a restricted principal. A pre-existing
// trigger / vouched function that RAISEs a NOTICE is the accepted residual — the same one the kept
// ErrorResponse structural fields carry (see sanitizeError / docs/diagnostic-redaction.md). The copy
// defends against pgproto3 reusing the target DB receive buffer until the next client flush.
func forwardNotice(sess *session, msg *pgproto3.NoticeResponse) {
	copyMessage := *msg
	sess.client.Send(&copyMessage)
}

func isSchemaOnlyMessage(sqlState, message string) bool {
	for _, re := range pgSchemaPatterns[sqlState] {
		if re.MatchString(message) {
			return true
		}
	}
	return false
}

var pgSchemaPatterns = compilePgSchemaMessages()

var pgPlaceholder = regexp.MustCompile(`"%s"|%[it]`)

var pgPlaceholderPatterns = map[string]string{
	`"%s"`: `"[^"]*"`,
	`%i`:   `[A-Za-z_][A-Za-z0-9_$]*`,
	`%t`:   `[A-Za-z0-9_ .\[\]"]+`,
}

func compilePgSchemaMessages() map[string][]*regexp.Regexp {
	out := make(map[string][]*regexp.Regexp, len(pgSchemaMessages))
	for sqlState, templates := range pgSchemaMessages {
		for _, t := range templates {
			var b strings.Builder
			b.WriteString(`\A`)
			last := 0
			for _, loc := range pgPlaceholder.FindAllStringIndex(t, -1) {
				b.WriteString(regexp.QuoteMeta(t[last:loc[0]]))
				b.WriteString(pgPlaceholderPatterns[t[loc[0]:loc[1]]])
				last = loc[1]
			}
			b.WriteString(regexp.QuoteMeta(t[last:]))
			b.WriteString(`\z`)
			out[sqlState] = append(out[sqlState], regexp.MustCompile(b.String()))
		}
	}
	return out
}
