// Package session is A4's session half: `PrincipalSessionStore` (the `principal_session` table, V6)
// plus the HMAC-authenticated cookie codec the five signed cookies ride on.
//
// Area doc: plans/proxy-monster-go-port/04-auth-session-tokens.md §3.2–§3.4 (`DaemonSession.kt`,
// `PrincipalSessionStorage.kt`) and 01-bootstrap.md §"Cookies".
//
// # One table, two kinds — and the `kind` predicate is a security boundary
//
// `kind='DAEMON'` backs `pmon` CLI logins; `kind='WEB'` backs console logins. A daemon row has
// `idle_expires_at IS NULL` and a `renewal_token_hash`; a web row has neither, and has a `device_id`
// and a `session_key`.
//
// 🔒 INV-A4-13 — every daemon lookup is scoped `kind='DAEMON'` and every web lifecycle method is
// scoped `kind='WEB'`. Only [Store.StaleSessions] and [Store.MarkCheck] deliberately span both.
// Dropping the predicate from [Store.ResolveWeb] makes a daemon row resolvable as a browser session
// with a NULL device binding — i.e. INV-A4-19's wildcard hole. Dropping it from [Store.WithinWindow]
// keeps a closed daemon renewal window alive off a still-open web row.
//
// # Three deadlines, and only one of them may move
//
//   - ABSOLUTE (`absolute_expires_at`, from `webSessionAbsoluteSeconds`) — the security bound. 🔒
//     INV-A4-22: it is not in [Store.TouchWeb]'s SET list and nothing else may put it there.
//   - IDLE (`idle_expires_at`, from `webSessionIdleSeconds`) — a convenience, extended ONLY by
//     [Store.TouchWeb].
//   - SLIDE (`webSessionSlideSeconds`) — the floor on how often idle may be extended, enforced 🔒
//     INV-A4-21 inside [Store.TouchWeb]'s WHERE clause, never in Go. config rule V1 already requires
//     slide < idle (internal/config/config.go).
//
// # The clock domain is part of the contract
//
// 🔒 INV-A4-16 / INV-A4-32 — Postgres freezes `now()`/`transaction_timestamp()` at the enclosing
// TRANSACTION's first statement. In [Store.MintWeb] that first statement is the per-principal
// advisory lock, which can block for the full idle window behind a concurrent login; a `now()`-based
// `idle_expires_at` would then be minted already in the past and 401 the session it just created.
// Both [Store.MintWeb] and [Store.withinWindowOn] therefore use `clock_timestamp()`. A Go port must
// also never compare a scanned time.Time against time.Now() for a window check — INV-A4-27 puts the
// comparison in the DATABASE clock domain, the same clock that STAMPED the column.
//
// ⚠️ F30 (04-auth-session-tokens.md:1660) records that [Store.WebSessionIsLive] and [Store.EndWeb]
// use `now()` where their neighbours use `clock_timestamp()`, and that `webSessionIsLive` tolerates a
// NULL idle deadline that [Store.ResolveWeb] rejects. Neither divergence is currently reachable
// differently. REPRODUCE — both are carried across verbatim.
//
// # The end seam
//
// 🔒 INV-A4-18 / INV-A4-23 / INV-A4-30 — every path that ends a web row (displacement in
// [Store.MintWeb], [Store.EndWeb], [Store.EndWebBySessionKey], [Store.EndAllWebForPrincipal]) routes
// through ONE callback, [Options.OnWebSessionEnded], invoked on the SAME connection as the end-write.
// A1 wires `queryResultStore.deleteEditorResultsForPrincipal` +
// `runExecService.closeSessionsForPrincipal` into it. Composing on the caller's connection is what
// makes a deprovision teardown atomic: a later statement that aborts the teardown rolls the result
// deletion back too, instead of a separate committed delete orphaning a session the rollback keeps
// alive. The callback fires ONLY on a real transition (rows > 0), never on a no-op end.
//
// # 🔴 Cookie compatibility — the DEFER is now DECIDED, and it logs everyone out once
//
// 01-bootstrap.md:222-226 left open whether the port's cookie encoding must be byte-compatible with
// Ktor's SessionTransportTransformerMessageAuthentication, and 00-INDEX.md:38 lists it under DEFER.
// [CookieCodec] implements a CLEAN HMAC-SHA256 scheme instead.
//
// CONSEQUENCE, STATED PLAINLY: **existing browser sessions do not survive cutover.** Every console
// user is signed out at the moment the Go control plane starts serving and re-authenticates through
// SSO. Nothing else breaks — `pm_did` is unsigned and unchanged so device bindings survive,
// `pm_session` is only a pointer to a server-side row, and the OAuth state/nonce/device-verify
// cookies live 5-10 minutes so at most one in-flight login per user is interrupted. The reasoning,
// including why a "compatible" implementation would be an unverified guess on this machine, is on
// [CookieCodec].
//
// # What is NOT here
//
// The route halves of A4 — `/auth/device/*`, `/auth/session/renew`, `/auth/oidc/*`, the five
// `App.kt`-hosted session routes — and `DeviceLoginStore`, `sweepSessionLiveness` and the OIDC
// discovery/validator pair. This package is the store and the cookie encoding they compose over.
//
//	TODO(A4): DeviceLoginStore (device_login, V6), sweepSessionLiveness, sessionRenewRoutes,
//	          deviceSessionRoutes, oidcRoutes.
//	TODO(A1): wire Options.OnWebSessionEnded and the cookie mux; see [Options] and [CookieCodec].
package session
