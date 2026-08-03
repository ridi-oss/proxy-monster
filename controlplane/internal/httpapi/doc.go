// Package httpapi is the HTTP plumbing every route group composes over: the middleware equivalents
// of App.kt's Ktor plugins, the four authorization gates, and the per-request helpers
// (`userSession()`, `idParam()`, the ApiError responders).
//
// Area docs: plans/proxy-monster-go-port/01-bootstrap.md §2 (the plugin stack, the five cookies),
// 02-authz.md §6 "Route gates" (requireAdmin / requireAuthz), 03-identity-scim.md §"Scim.kt"
// (requireScimAuth), 05-datasources-catalog.md §"Route-file gates and helpers" (requireApi, idParam).
//
// # Why a package of its own
//
// The Kotlin scatters these: `requireAdmin`/`requireAuthz` live in `authz/Authz.kt`, `requireApi` and
// `idParam` in `Datasources.kt`, `requireScimAuth` in `Scim.kt`, the plugins and
// `respondSessionUnauthorized` in `App.kt`, and `userSession()` in `Auth.kt`. They are all extension
// functions on one `ApplicationCall`, so placement costs nothing there. Go has no such receiver, and
// every one of the ~15 route groups needs all of them, so they cannot live in internal/app — that
// would make every route group import the composition root that imports it.
//
// 05-datasources-catalog.md:625 already blesses the move for `requireApi`: "A Go port should hoist it
// somewhere neutral — a FILE-PLACEMENT decision, not a behaviour one: the gate itself is REPRODUCE,
// byte-for-byte." The same reasoning covers the other three and the plugins.
//
// # The plugin stack, in App.kt's order (App.kt:452-542)
//
// Ktor installs ContentNegotiation → CallLogging → StatusPages → Sessions → Authentication. Only two
// of those are wrappers in Go; the rest become explicit calls, because Ktor's are implicit behaviour
// on a call object that Go does not have:
//
//	ContentNegotiation  → [RespondJSON] / [Receive]. Not middleware: there is no negotiation to do
//	                      (one converter, one media type) and Go has no place to hang it. The
//	                      appJson CONFIG survives as types.MarshalWire — INV-A1-4.
//	CallLogging(INFO)   → [CallLogging], a wrapper. Outermost, so it observes the status StatusPages
//	                      produced rather than the one the handler failed to write.
//	StatusPages         → [StatusPages], a wrapper. `exception<Throwable>` becomes `recover()`.
//	Sessions (5 cookies)→ [Sessions] plus [Sessions.Install]. The codec is internal/session's; this
//	                      package adds the per-request resolution and the tracker-id indirection.
//	Authentication      → [Sessions.RequireWebSession], a PER-ROUTE wrapper — which is what Ktor's
//	                      `authenticate(WEB_SESSION_AUTH) { … }` is too.
//
// 🔒 The StatusPages branch is a wire contract, not a nicety. An unhandled error answers
// 500 ApiError("common.fallback") EXCEPT on `/oauth/**` and `/.well-known/oauth-authorization-server`,
// which answer 500 OAuthError("server_error") — an OAuth client parses `{"error":…}` and has no schema
// for `{"code":…}`.
//
// ⚠️ F41 (99-reconciliation-report.md:245, = A3 F30) — the catch-all ALSO fires on `/api/scim/v2/**`,
// so an uncaught exception breaks the documented SCIM error-body exemption (INV-A1-13 / INV-A3-2)
// exactly where an IdP is least able to parse it. PORT POLICY says REPRODUCE, and this is a security
// surface, so it is REPRODUCE + PIN: [StatusPages] has NO SCIM branch and
// TestStatusPagesAnswersApiErrorOnScimPaths asserts the ApiError body. A later fix must change that
// test deliberately.
//
// # The four gates, and the one that is not like the others
//
//	[Gates.RequireAPI]       — "is there a session at all"                    (Datasources.kt:699)
//	[Gates.RequireAdmin]     — requireAuthz over AuthzResource.System         (Authz.kt:881)
//	[Gates.RequireAuthz]     — the general per-(action, resource) Cedar gate  (Authz.kt:896)
//	[Gates.RequireScimAuth]  — bearer + TLS, NO Cedar and NO session          (Scim.kt:150)
//
// 🔒 INV-A2-16 — the authDebug dev bypass NEVER SKIPS CEDAR; IT PREVENTS CEDAR FROM BEING REACHED.
// `Authz` itself has no bypass anywhere. The order is authDebug ⇒ allow · no session ⇒ 401
// common.unauthenticated · else the real Cedar decision, Deny ⇒ 403 common.forbidden{detail}. This
// is the choke point that closes the "admin routes require admin.*, not merely any session" hole the
// moment PM_AUTH_DEBUG goes off.
//
// 🔒 F33 / INV-A3-38 — requireScimAuth has NO PM_AUTH_DEBUG BYPASS, while `AGENTS.md` and
// `docs/authz-model.md:363` both claim "PM_AUTH_DEBUG short-circuits all four". THE CODE IS RIGHT AND
// THE DOCS ARE WRONG: `ScimAuthTest.kt:106,111`'s `testScimConfig` sets `authDebug = true` and every
// one of its six cases still expects 501/403/401. A port that implements the documentation makes a
// dev-mode control plane accept unauthenticated directory writes over plaintext. PINNED by
// TestRequireScimAuthHasNoAuthDebugBypass and by every case in scim_gate_test.go running with
// AuthDebug: true.
//
// # What is NOT here
//
//   - A12's `httpRequesterIp` / `httpAuthzContext`. [Gates.Context] is the seam it plugs into and its
//     default is an EMPTY AuthzContext — fail-closed (INV-A2-8: an absent optional attribute makes a
//     policy conditioning on it simply not fire), but a real divergence from the Kotlin for any policy
//     gated on `requester_ip`. See [Gates.Context]. `isTrustedEdge` IS here (trustededge.go), ported
//     because requireScimAuth's TLS gate needs it; A12 must reuse it rather than write a second copy.
//   - The routes themselves. Route groups own their own handlers and register through [RouteGroup].
//
// Still owed:
//
//	TODO(A12): replace [Gates.Context]'s default with the real httpAuthzContext — 12-request-context.md.
//	TODO(A1):  /auth/config, /auth/debug, /auth/me, /auth/session/*, /auth/logout,
//	           /api/me/permissions, the SSE task stream, the two background timer loops.
package httpapi
