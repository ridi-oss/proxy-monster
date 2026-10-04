package config

// A7's run-transport timing constants and the two TTL derivations built on them
// (07-tasks-approvals-results.md §7's timing table; RunExec.kt:25-46, 194-198, 647-653).
//
// # Why they live in internal/config and not in internal/runexec
//
// 99-reconciliation-report.md closes A1 Q5 with "in Go it needs a shared package, not a per-area
// copy". This IS that package, and the choice is forced rather than stylistic: [DialTimeoutMS] has
// two consumers — RunExecService itself and A5's
// TableDetailExec — and internal/config is the only one of them that is an import LEAF. Hosting them
// in internal/runexec instead would need internal/config to import it, and internal/runexec imports
// internal/core → internal/datasource → internal/config: a cycle. So A7 consumes these from here.
//
// The earlier TODO on DialTimeoutMS ("when A7 lands, move it there and leave this as an alias") is
// resolved the other way round, deliberately, for that reason.

const (
	// RunTokenTTLFloorSeconds is `RUN_TOKEN_TTL_FLOOR_SECONDS = 900L` (RunExec.kt:28) — the floor for a
	// one-shot run token.
	//
	// The floor ALONE must outlast a full-length dial plus a full-length exchange, so a short
	// PM_QUERY_TIMEOUT cannot leave a cold session's token expiring mid-statement.
	RunTokenTTLFloorSeconds int64 = 900

	// EditorSessionTTLFloorSeconds is `EDITOR_SESSION_TTL_SECONDS = 8 * 3600L` (RunExec.kt:32) — the
	// absolute TTL of a PERSISTENT editor-session token.
	//
	// It is generous because the session outlives many queries (sliding refresh-on-activity is a
	// follow-up) and it is not a standing credential: the token is per-session and revoked on close,
	// and the session is bounded by the idle sweep and the explicit DELETE.
	EditorSessionTTLFloorSeconds int64 = 8 * 3600

	// TokenTTLGraceSeconds is `TOKEN_TTL_GRACE_SECONDS = 300L` (RunExec.kt:39) — the headroom a run
	// token's TTL adds over PM_QUERY_TIMEOUT.
	//
	// It covers the dial ([DialTimeoutMS]), the CP exchange grace ([QueryExchangeGraceMS]) and the
	// proxy's mid-run revalidation buffer, so the token never expires while the statement it authorizes
	// is still in flight. It must stay above DialTimeoutMS with room to spare — a token that dies
	// during a slow cold dial takes the session with it.
	TokenTTLGraceSeconds int64 = 300

	// ExchangeTimeoutMS is `EXCHANGE_TIMEOUT_MS = 630_000L` (RunExec.kt:46) — a FALLBACK ONLY.
	//
	// ⚠️ Every production path passes [Config.QueryExchangeTimeoutMS], which tracks PM_QUERY_TIMEOUT
	// plus a grace so the proxy's own watchdog always fires first. This value exists for callers that
	// supply no config, and matches the default query timeout on the same principle (600s + 30s).
	ExchangeTimeoutMS int64 = 630_000
)

// DialTimeoutMS is `internal const val DIAL_TIMEOUT_MS = 120_000L` at RunExec.kt:42.
//
// The value is MEASURED, not chosen. The dial is not just a connect: the proxy also satisfies the
// connection's opening catalog commands before it reports ready, and on a cold session against a large
// remote backend that is several schema scans. 07-tasks-approvals-results.md's timing table records
// "measured cold opens took ~26s; 10s failed them outright".
const DialTimeoutMS int64 = 120_000

// RunTokenTTLSeconds is `RunExecService.runTokenTtlSeconds(queryTimeoutSeconds)` (RunExec.kt:648-649):
//
//	max(RUN_TOKEN_TTL_FLOOR_SECONDS, q + TOKEN_TTL_GRACE_SECONDS)
//
// 🔒 INV-A7-30 — the run token must outlive the whole exchange it backs (dial + window +
// revalidation), else a genuine long query fails UNAUTHENTICATED when the proxy revalidates the token
// mid-run. This is the TOP rung of the timeout ladder.
//
// 🔴 THAT INVARIANT IS CONDITIONAL, NOT UNCONDITIONAL — index finding F26. This result is clamped by
// token.Store.Issue → token.ClampTTLSeconds → 24h, while PM_QUERY_TIMEOUT is bounded only by
// [MaxQueryTimeoutSeconds]. It therefore holds only for q ≤ 86,220 s (23h57m) with the full grace; the
// margin erodes above that, hits zero at exactly 24h, and goes NEGATIVE beyond — the token then expires
// mid-statement, which is precisely the failure the grace exists to prevent. The defect is REPRODUCED,
// not fixed (00-INDEX.md's PORT POLICY); TestF26TimeoutLadderIsNotTotal here and
// TestClampTTLSecondsLadderIsNotTotal in internal/token are the pins that make a later fix visible.
func RunTokenTTLSeconds(queryTimeoutSeconds int64) int64 {
	return max(RunTokenTTLFloorSeconds, queryTimeoutSeconds+TokenTTLGraceSeconds)
}

// EditorSessionTTLSeconds is `RunExecService.editorSessionTtlSeconds(queryTimeoutSeconds)`
// (RunExec.kt:652-653): `max(EDITOR_SESSION_TTL_SECONDS, q + TOKEN_TTL_GRACE_SECONDS)` — a persistent
// editor-session token keeps its generous absolute TTL but is never allowed to expire before a single
// query on it could finish. F26 applies here identically.
func EditorSessionTTLSeconds(queryTimeoutSeconds int64) int64 {
	return max(EditorSessionTTLFloorSeconds, queryTimeoutSeconds+TokenTTLGraceSeconds)
}
