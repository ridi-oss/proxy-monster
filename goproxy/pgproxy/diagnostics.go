package pgproxy

import (
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
//     the target DB's echoed text. It is the one field an ordinary error (a type conversion) fills with a
//     value, and its content can't be bounded.
//   - Detail is dropped: `DETAIL: Failing row contains (…)` prints columns the statement never named — the
//     one reachable way an ordinary error exposes a masked *sibling* value.
//   - UnknownFields is dropped: field codes the proxy can't classify fail closed.
//
// Everything else is KEPT — the SQLSTATE + severity, the structural object names
// (Schema/Table/Column/DataType/coNstraint), the PL/pgSQL context (Where, InternalQuery), the query
// positions, and the server source location. For an ordinary error those hold object names or are empty,
// not row values; the ONLY way to put an arbitrary value there is `RAISE … USING`, which needs PL/pgSQL and
// is denied for a restricted principal. A pre-existing trigger or vouched function that RAISEs a value into
// one of them is the accepted defense-in-depth residual — see docs/diagnostic-redaction.md.
func sanitizeError(msg *pgproto3.ErrorResponse) *pgproto3.ErrorResponse {
	out := *msg
	out.Message = pgDiagnosticMessage(msg.Code)
	out.Detail = ""
	out.UnknownFields = nil
	return &out
}

// forwardError sends a target DB ErrorResponse to the client, sanitized when the current decision has
// diagnostic redaction set, otherwise verbatim.
func forwardError(sess *session, msg *pgproto3.ErrorResponse) {
	if sess.qe.SanitizeDiagnostics() {
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
