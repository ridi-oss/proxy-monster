package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A1's auth + session routes — the ones App.kt declares DIRECTLY in `module()` (App.kt:581-783),
// as opposed to the fifteen it delegates to route-group functions.
//
//	GET  /auth/config             none          AuthConfigResponse
//	POST /auth/debug              authDebug     UserSession                (else 404 common.not_found)
//	GET  /api/me/permissions      requireApi    MePermissions
//	GET  /auth/me                 WEB_SESSION   UserSession, no-store
//	GET  /auth/session/status     WEB_SESSION   SessionStatus, no-store
//	POST /auth/session/heartbeat  WEB_SESSION   SessionStatus, no-store    (the ONLY idle-extending call)
//	POST /auth/logout             none          LogoutResponse
//
// They live in internal/app because App.kt is where they live: they are the composition root's own
// routes, they read `config` and four different core members, and three of them are the only
// consumers of the WEB_SESSION_AUTH wrapper. Everything reusable underneath them — the gates, the
// challenge, the cookie plumbing, the responders — is internal/httpapi's and is REUSED here, never
// re-implemented.
//
// Still owed by A1:
//
//	TODO(A1): the SSE /api/tasks/events stream (INV-A1-10/-11/-12 — writes and the read loop MUST
//	          stay on one goroutine) and the two background timer loops (🔒 INV-A1-5: in loop 1
//	          purgeExpiredEditorChildren() runs BEFORE purgeExpired()). Both need A7's
//	          RunExecService / QueryResultStore, which are unported.
// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------
// App-local DTOs — 01-bootstrap.md §3 "App-local DTOs"
//
// They stay HERE rather than in internal/types, which owns only the three cross-area types. Every
// one carries INV-A1-4's two rules: an optional field is *T + omitempty (absent, never null) and a
// slice is never nil on the way out.
//
// Exactly ONE of them has an optional field — [LogoutRequest]'s `sessionId: Long? = null`, and it is
// a REQUEST body, so the rule binds the console rather than this package. Every RESPONSE field here
// is non-nullable in Kotlin (SessionStatus' five, MePermissions' three, AuthConfigResponse's three,
// SessionUxConfig's five, LogoutResponse's one), so for them the contract reduces to "declaration
// order is the wire order" — which is itself worth pinning, because reordering a struct field is an
// ordinary-looking edit that changes the bytes.
// internal/conformance/wire_json_app_test.go pins the bytes for all of them.
// ---------------------------------------------------------------------------------------------

// MePermissions is `GET /api/me/permissions`' body (App.kt:186-190) — the console's COARSE
// navigation hints.
//
// 🔒 They are hints and nothing else. App.kt:304: "UI navigation and client-side guards are
// convenience only; every API authorizes independently." A route that trusted this instead of
// calling its own gate would be authorizing off a value the client could not be prevented from
// lying about anyway.
type MePermissions struct {
	IsAdmin         bool `json:"isAdmin"`
	CanReadAllAudit bool `json:"canReadAllAudit"`
	CanApprove      bool `json:"canApprove"`
}

// SessionStatus is `/auth/session/status`' and `/auth/session/heartbeat`'s body (App.kt:193-199).
//
// 🔒 All three timestamps come from the SAME ROW READ, and `now` is the DATABASE's clock, not the
// process's (session.WebRow.Now is `clock_timestamp()` selected on the same query). The console
// computes its countdown as `idleExpiresAt - now`, so a process clock skewed from the database's
// would make the warning fire early or never — and the deadline it is counting down to was stamped
// by the database. WebSessionRoutesDbTest.kt:400-402 asserts `now` sits inside a database-clock
// window taken around the call.
//
// The strings are `Instant.toString()`, not RFC3339Nano — see internal/instant for why the
// difference is wire-visible.
type SessionStatus struct {
	Now               string `json:"now"`
	IdleExpiresAt     string `json:"idleExpiresAt"`
	AbsoluteExpiresAt string `json:"absoluteExpiresAt"`
	Principal         string `json:"principal"`
	SessionID         int64  `json:"sessionId"`
}

// LogoutRequest is `POST /auth/logout`'s OPTIONAL body (App.kt:205).
//
// `sessionId: Long? = null` — nullable with a null default, so a body of `{}` and no body at all
// mean the same thing: an unconditional logout. See [authRoutes.logout] for INV-A1-9.
type LogoutRequest struct {
	SessionID *int64 `json:"sessionId,omitempty"`
}

// LogoutResponse is `POST /auth/logout`'s body (App.kt:208).
type LogoutResponse struct {
	Ended bool `json:"ended"`
}

// AuthConfigResponse is `GET /auth/config`'s body (App.kt:211-215) — PUBLIC, because the login shell
// needs to know whether to show an SSO button before it can authenticate anything.
//
// Nothing secret is in it: whether OIDC is configured, whether the dev bypass is on, and five
// client-side timings. `authDebug` being visible is deliberate — the console renders the debug login
// form from it, and an attacker learns nothing from a flag whose "on" state is already a full
// authentication bypass they could simply use.
type AuthConfigResponse struct {
	OidcEnabled bool            `json:"oidcEnabled"`
	AuthDebug   bool            `json:"authDebug"`
	Session     SessionUxConfig `json:"session"`
}

// SessionUxConfig is the session-timing block of [AuthConfigResponse] (App.kt:218-224).
//
// ⚠️ The three `*Ms` fields are `seconds * 1000` — the server does the conversion so the client
// never has to know which unit the operator configured. The absolute cap is NOT in ms: it is split
// into an amount and a unit by [normalizeDuration] so the console can render "2 hours" rather than
// "7200000 ms", and 01-bootstrap.md:38 records that the two warn leads may EXCEED their windows,
// with the client clamping rather than the config rejecting.
type SessionUxConfig struct {
	HeartbeatMs        int64  `json:"heartbeatMs"`
	IdleWarnLeadMs     int64  `json:"idleWarnLeadMs"`
	AbsoluteWarnLeadMs int64  `json:"absoluteWarnLeadMs"`
	AbsoluteCapAmount  int64  `json:"absoluteCapAmount"`
	AbsoluteCapUnit    string `json:"absoluteCapUnit"`
}

// normalizedDuration is `internal data class NormalizedDuration(amount, unit)` (App.kt:226).
type normalizedDuration struct {
	amount int64
	unit   string
}

// normalizeDuration is `internal fun normalizeDuration(seconds)` (App.kt:228-232): the largest unit
// that divides the value exactly.
//
// ⚠️ Note what it does NOT do: it never falls back through units. 5400s (1h30m) is 90 MINUTES, not
// "1 hour 30 minutes" and not 1.5 hours — `5400 % 3600 != 0`, so the hours arm is skipped entirely
// and the minutes arm takes it. WebSessionRoutesDbTest.kt:124-136 is the case that pins it.
//
// ⚠️ ZERO takes the FIRST arm (`0 % 3600 == 0`), so it renders as "0 hours". Unreachable in practice
// — `parseDuration` rejects a non-positive duration at config time — and reproduced rather than
// special-cased, because the special case would be new behaviour with no oracle.
func normalizeDuration(seconds int64) normalizedDuration {
	switch {
	case seconds%3600 == 0:
		return normalizedDuration{amount: seconds / 3600, unit: "hours"}
	case seconds%60 == 0:
		return normalizedDuration{amount: seconds / 60, unit: "minutes"}
	default:
		return normalizedDuration{amount: seconds, unit: "seconds"}
	}
}

// toSessionStatus is `private fun WebSessionRow.toSessionStatus()` (App.kt:234-240).
func toSessionStatus(row *session.WebRow) SessionStatus {
	return SessionStatus{
		Now:               instant.Format(row.Now),
		IdleExpiresAt:     instant.Format(row.IdleExpiresAt),
		AbsoluteExpiresAt: instant.Format(row.AbsoluteExpiresAt),
		Principal:         row.Principal,
		SessionID:         row.ID,
	}
}

// ---------------------------------------------------------------------------------------------
// computeMePermissions — App.kt:255-290
// ---------------------------------------------------------------------------------------------

// computeMePermissions is `internal fun computeMePermissions(principal, authz, context)`.
//
// FOUR INDEPENDENT CEDAR DECISIONS, and the independence is the design:
//
//	isAdmin         = admin.datasources ∨ admin.policies ∨ admin.identity   (all on System)
//	canReadAllAudit = audit.read on AuditLog
//	canApprove      = isAdmin
//
// 🔒 The three admin domains are deliberately OR'd rather than AND'd, quoting App.kt:256-257: "one
// permitted admin domain is enough to expose the shared admin area, while audit collection access
// remains a separate capability." A datasource admin sees the admin shell; they still cannot read
// the audit collection, because that is a fourth, separate decision. MePermissionsRouteTest cases 3
// and 4 are the two halves of that.
//
// ⚠️ `canApprove = isAdmin` is a KNOWN APPROXIMATION, carried verbatim with its reason (App.kt:287):
// "`task.approve` is request-scoped, so there is no honest coarse System check yet." It is not a
// bug and must not be "fixed" into a task.approve decision — there is no resource to make one
// against here. The real approval gate is per-request in A7.
//
// It takes the narrow [httpapi.Authorizer] rather than *authz.Authz for the reason that interface
// exists: this function answers "may this principal do this", never "what may this query see", and
// a type that could reach authorizeColumns would be a coarse capability check able to make a query
// decision.
func computeMePermissions(principal string, az httpapi.Authorizer, ctx authz.AuthzContext) MePermissions {
	allowed := func(action authz.AuthzAction, resource authz.AuthzResource) bool {
		return az.Authorize(principal, action, resource, ctx).Allowed
	}
	// All three are evaluated, never short-circuited: Kotlin assigns each to its own `val` before
	// OR-ing them, so all three decisions are made on every request. Go's `||` would skip the second
	// and third once the first allowed — invisible today, and a silent divergence the moment
	// authorize gains an audit or metric side effect.
	canAdminDatasources := allowed(authz.ActionAdminDatasources, authz.ResourceSystem{})
	canAdminPolicies := allowed(authz.ActionAdminPolicies, authz.ResourceSystem{})
	canAdminIdentity := allowed(authz.ActionAdminIdentity, authz.ResourceSystem{})
	isAdmin := canAdminDatasources || canAdminPolicies || canAdminIdentity

	canReadAllAudit := allowed(authz.ActionAuditRead, authz.ResourceAuditLog{})

	return MePermissions{
		IsAdmin:         isAdmin,
		CanReadAllAudit: canReadAllAudit,
		CanApprove:      isAdmin,
	}
}

// ---------------------------------------------------------------------------------------------
// The route group
// ---------------------------------------------------------------------------------------------

// roleReader is the slice of A3's `RoleResolver` these routes use — ONE method.
//
// 🔒 INV-A1-8 — `/auth/me` calls Resolve on EVERY REQUEST and never reads a role off the session, so
// a role gained or lost after login (a group change, an expired JIT grant, a deactivation) is
// visible on the next read. The console shows this set while explaining a decision, so a stale one
// misdescribes every later denial.
//
// It is deliberately NOT `DirectRoles`: the union of direct + JIT + group is what authorization
// uses, so reporting only the direct set would show a principal fewer roles than their queries
// actually run under.
type roleReader interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// evaluatesInCedar is `authz::evaluatesInCedar` as a function value — the second stage of
// 🔒 INV-A1-7's check. It is a func rather than an interface method so a test can drive
// httpapi.IsStorableIPLiteral's two stages without an engine, exactly as the Kotlin's parameter does.
type evaluatesInCedar func(ip string) bool

// authRoutes is App.kt's directly-declared auth surface as a [httpapi.RouteGroup].
type authRoutes struct {
	config config.Config
	// gates is the SHARED *Gates — the same instance every other route group holds, which is what
	// makes A12's one-line Context fix reach this route group's Cedar context too.
	gates *httpapi.Gates
	// sessions is the SHARED *Sessions: the cookie plumbing, the per-request identity cache and the
	// WEB_SESSION_AUTH wrapper.
	sessions *httpapi.Sessions
	// store is `principalSessionStore` — needed directly for touchWeb and mintWeb, which are not on
	// the narrow request-time interfaces.
	store *session.Store
	// authz is the SHARED Cedar graph (INV-A1-1), narrowed to the one method /api/me/permissions uses.
	authz httpapi.Authorizer
	// evaluatesInCedar is the SAME graph's IP probe. Separate field because [httpapi.Authorizer] is
	// deliberately one method wide.
	evaluatesInCedar evaluatesInCedar
	roles            roleReader
	management       *policy.PolicyManagement
	db               store.DB
	log              *slog.Logger
}

// Register mounts the seven routes. Method-aware patterns, no trailing slashes — see
// [httpapi.Router] for the three D6 divergences that constrains.
func (rt *authRoutes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/config", rt.authConfig)
	mux.HandleFunc("POST /auth/debug", rt.debugLogin)
	mux.HandleFunc("GET /api/me/permissions", rt.mePermissions)
	// `authenticate(WEB_SESSION_AUTH) { … }` (App.kt:736-766) — a PER-ROUTE wrapper in Ktor too, and
	// a different gate from requireApi: no authDebug bypass, and a SessionStatusError body instead of
	// an ApiError.
	mux.Handle("GET /auth/me", rt.sessions.RequireWebSession(http.HandlerFunc(rt.me)))
	mux.Handle("GET /auth/session/status", rt.sessions.RequireWebSession(http.HandlerFunc(rt.sessionStatus)))
	mux.Handle("POST /auth/session/heartbeat", rt.sessions.RequireWebSession(http.HandlerFunc(rt.heartbeat)))
	mux.HandleFunc("POST /auth/logout", rt.logout)
}

// authConfig is `GET /auth/config` (App.kt:581-596) — public, no gate of any kind.
func (rt *authRoutes) authConfig(w http.ResponseWriter, r *http.Request) {
	absoluteCap := normalizeDuration(rt.config.WebSessionAbsoluteSeconds)
	rt.respond(w, http.StatusOK, AuthConfigResponse{
		OidcEnabled: rt.config.OIDC != nil,
		AuthDebug:   rt.config.AuthDebug,
		Session: SessionUxConfig{
			HeartbeatMs:        rt.config.WebSessionHeartbeatSeconds * 1000,
			IdleWarnLeadMs:     rt.config.WebSessionIdleWarnLeadSeconds * 1000,
			AbsoluteWarnLeadMs: rt.config.WebSessionAbsoluteWarnLeadSeconds * 1000,
			AbsoluteCapAmount:  absoluteCap.amount,
			AbsoluteCapUnit:    absoluteCap.unit,
		},
	})
}

// debugLogin is `POST /auth/debug` (App.kt:686-732) — the dev-only login shortcut. OIDC is the
// production path.
//
// The order of its eight steps is contractual, and two orderings in particular are:
//
//  1. `if (!config.authDebug) call.notFound("endpoint")` — 404, NOT 403 and not 401. With the bypass
//     off the endpoint does not exist; answering 401 would advertise a dev login surface to an
//     unauthenticated caller on a production deployment.
//  2. `call.receive<DebugLogin>()`. A malformed body or an absent `principal` throws in the Kotlin
//     and reaches StatusPages ⇒ 500 common.fallback. [httpapi.RespondFallback] is the same body.
//  3. roles: trim, drop blank, DISTINCT. Deduplication matters because the claim becomes real
//     `principal_role` rows and the table has a uniqueness constraint.
//  4. requesterIp: trim, then blank ⇒ nil. "Blank/absent leaves the observed peer authoritative."
//  5. 🔒 INV-A1-7 — a malformed address is 400 `auth.invalid_requester_ip`, never silently dropped.
//     BEFORE the device cookie and before the transaction, so a refused login leaves NOTHING behind:
//     no session, no rewritten roles, not even a `pm_did`. DebugRequesterIpDbTest.kt:190 asserts the
//     session half of that.
//  6. ensureDeviceCookie — the `pm_did` correlator the session row binds to.
//  7. 🔒 INV-A1-6 — replaceDirectRoles AND mintWeb IN ONE TRANSACTION under ONE per-principal
//     advisory lock (mintWeb re-takes the same lock, which is re-entrant). Committing separately
//     would let a failed mint leave the roles rewritten under a login that never succeeded, and would
//     let two concurrent logins interleave so the surviving session claims {A} while the database
//     says {B}. WebSessionRoutesDbTest.kt:191-203 pins both halves of the rollback.
//  8. set the cookie, then respond `UserSession(principal, roles, debugRequesterIp)`.
//
// ⚠️ Step 8's `roles` is the CLAIM, not a re-resolution — so the response can differ from what
// /auth/me answers a moment later (the claim omits group- and grant-derived roles). REPRODUCED; the
// console reads /auth/me for the authoritative set.
func (rt *authRoutes) debugLogin(w http.ResponseWriter, r *http.Request) {
	if !rt.config.AuthDebug {
		rt.respondError(w, types.NotFound("endpoint"))
		return
	}

	var login session.DebugLogin
	if err := httpapi.Receive(r, &login); err != nil {
		// Ktor: the receive throws and StatusPages answers. Same body, same status.
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}

	// `login.roles.map { it.trim() }.filter { it.isNotBlank() }.distinct()` — order-preserving.
	roles := make([]string, 0, len(login.Roles))
	seen := make(map[string]struct{}, len(login.Roles))
	for _, raw := range login.Roles {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		roles = append(roles, name)
	}

	// `login.requesterIp?.trim()?.takeIf { it.isNotEmpty() }`.
	var debugRequesterIP *string
	if login.RequesterIP != nil {
		if trimmed := strings.TrimSpace(*login.RequesterIP); trimmed != "" {
			debugRequesterIP = &trimmed
		}
	}
	if debugRequesterIP != nil && !httpapi.IsStorableIPLiteral(*debugRequesterIP, rt.evaluatesInCedar) {
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusBadRequest,
			Body:   types.ApiError{Code: "auth.invalid_requester_ip"},
		})
		return
	}

	// `config.mcpIssuer.startsWith("https://")` — the SAME derivation the five signed cookies use
	// (session.NewCookieCodec computes it from the same string). `pm_did` sits outside the signed
	// block, so the attribute is passed by hand here exactly as Auth.kt:707 does.
	deviceID, err := session.EnsureDeviceCookie(w, r, strings.HasPrefix(rt.config.MCPIssuer(), "https://"))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}

	sessionID, err := store.InTx(r.Context(), rt.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		if _, err := rt.management.ReplaceDirectRolesOn(ctx, tx, login.Principal, roles); err != nil {
			return 0, err
		}
		return rt.store.MintWeb(ctx, tx, session.MintWebInput{
			Principal:        login.Principal,
			RefreshToken:     nil,
			AbsoluteSeconds:  rt.config.WebSessionAbsoluteSeconds,
			IdleSeconds:      rt.config.WebSessionIdleSeconds,
			DeviceID:         &deviceID,
			DebugRequesterIP: debugRequesterIP,
		})
	})
	if err != nil {
		// `catch (e: ManagementException) { call.respondManagementError(e) }` — and ONLY that. Any
		// other failure propagates to StatusPages, which is what the else arm is.
		var me *policy.ManagementError
		if errors.As(err, &me) {
			if werr := httpapi.RespondManagementError(w, me.Err); werr != nil {
				rt.logger().Error("failed to write management error", "code", me.Err.Code, "err", werr)
			}
			return
		}
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}

	if err := rt.sessions.SetWebSession(r.Context(), w, sessionID); err != nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	rt.respond(w, http.StatusOK, session.UserSession{
		Principal:   login.Principal,
		Roles:       roles,
		RequesterIP: debugRequesterIP,
	})
}

// mePermissions is `Route.mePermissionsRoute(config, authz)` (App.kt:292-307).
//
// 🔒 Under authDebug the answer is a CONSTANT `{true, true, true}` and Cedar is never consulted —
// the same INV-A2-16 shape as the gates: the bypass prevents Cedar from being reached, it does not
// teach Cedar to allow. requireApi has already returned true without reading a session, so there is
// no principal to compute against either.
func (rt *authRoutes) mePermissions(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	if rt.config.AuthDebug {
		rt.respond(w, http.StatusOK, MePermissions{IsAdmin: true, CanReadAllAudit: true, CanApprove: true})
		return
	}
	// `requireNotNull(call.userSession()) { "requireApi admitted a non-debug request without a
	// UserSession" }` — an assertion, not a control path: requireApi has already 401'd a request with
	// no session. A nil here would be a bug in the gate, so it takes the same route a Kotlin
	// IllegalArgumentException would: StatusPages, 500 common.fallback.
	sess, err := rt.sessions.UserSession(r)
	if err != nil || sess == nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	rt.respond(w, http.StatusOK, computeMePermissions(sess.Principal, rt.authz, rt.gates.AuthzContext(r)))
}

// me is `GET /auth/me` (App.kt:737-747), behind WEB_SESSION_AUTH.
//
// 🔒 INV-A1-8, both halves:
//   - roles are resolved PER REQUEST from the database, never carried on the session;
//   - `debugRequesterIp` is reported ONLY while authDebug is on, "so the console never shows a
//     simulated address the decision path is in fact ignoring".
//
// `Cache-Control: no-store` — a cached identity is a signed-out tab still rendering a principal.
func (rt *authRoutes) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	row, err := rt.sessions.WebSession(r)
	if err != nil || row == nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	roles, err := rt.roles.Resolve(r.Context(), row.Principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	// `.sorted()` — natural String order. The console renders the list verbatim, so an unstable order
	// is a UI that reshuffles between reads.
	//
	// ⚠️ Kotlin's natural String order compares UTF-16 CODE UNITS; sort.Strings compares UTF-8 BYTES.
	// The two agree on every code point below U+E000 — which is every role name the system can
	// actually hold, since `app_role.name` is operator-authored and the seeded set is ASCII
	// `system:*`. They disagree only between a supplementary character (≥ U+10000, a surrogate PAIR
	// in UTF-16, so ordered by its LEADING surrogate U+D800-U+DBFF) and a BMP character in
	// U+E000-U+FFFF: Kotlin sorts the emoji first, Go sorts it last. Recorded rather than worked
	// around — a code-unit comparator would be new code with no oracle, for an ordering difference in
	// a display list nobody can currently produce.
	sort.Strings(roles)

	var simulatedIP *string
	if rt.config.AuthDebug {
		simulatedIP = row.DebugRequesterIP
	}
	rt.respond(w, http.StatusOK, session.UserSession{
		Principal:   row.Principal,
		Roles:       roles,
		RequesterIP: simulatedIP,
	})
}

// sessionStatus is `GET /auth/session/status` (App.kt:749-753).
//
// 🔒 INV-A4-20 — OBSERVING A SESSION MUST NOT EXTEND IT. This reads the row through the SAME
// per-request resolution every other route uses (`resolveWeb`, which never touches idle); only
// [authRoutes.heartbeat] extends. A status poll that slid the deadline would make the idle window
// unreachable for any tab left open on a status page.
func (rt *authRoutes) sessionStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	row, err := rt.sessions.WebSession(r)
	if err != nil || row == nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	rt.respond(w, http.StatusOK, toSessionStatus(row))
}

// heartbeat is `POST /auth/session/heartbeat` (App.kt:755-765) — 🔒 THE ONLY IDLE-EXTENDING CALL IN
// THE SYSTEM.
//
// The gate has already resolved the session, so reaching here means it was live a moment ago.
// TouchWeb can still answer nil, and the two reasons are exactly the ones that matter:
//
//   - the row was ended or expired BETWEEN the gate's resolve and this write (displacement by a
//     login in another tab, the liveness sweep, an absolute deadline crossed);
//   - 🔒 the device binding does not match — TouchWeb re-checks `pm_did`, so a stolen cookie cannot
//     keep a session alive by heartbeating it from another browser.
//
// 🔒 The nil arm SETS FAILED_WEB_SESSION TO row.id BY HAND before answering. Nothing else can: the
// per-request resolution SUCCEEDED, so the marker the challenge reads is unset, and without this
// line every heartbeat failure would report `"none"` — "you were never signed in" — instead of
// `"displaced"` or `"bind_mismatch"`. That is the whole ended-reason UX on the one route most
// likely to observe the transition first.
func (rt *authRoutes) heartbeat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	row, err := rt.sessions.WebSession(r)
	if err != nil || row == nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	touched, err := rt.store.TouchWeb(r.Context(), row.ID, session.DeviceCookieID(r))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.logger(), err)
		return
	}
	if touched == nil {
		httpapi.SetFailedWebSession(r, row.ID)
		rt.sessions.RespondSessionUnauthorized(w, r)
		return
	}
	rt.respond(w, http.StatusOK, toSessionStatus(touched))
}

// logout is `POST /auth/logout` (App.kt:768-783) — NO GATE. Signing out must work from a session
// that is already dead, so requiring a live one would strand exactly the tabs that need it.
//
// 🔒 INV-A1-9 — CONDITIONAL LOGOUT. When the body names a `sessionId` AND the cookie currently
// resolves to a DIFFERENT one, answer `200 {ended:false}` and do nothing at all — no end-write, and
// (asserted at WebSessionRoutesDbTest.kt:294) NO Set-Cookie either. The caller is an automatic
// logout acting on a session it observed some time ago; a re-login may already have replaced the
// tracker with a fresh row, and ending THAT row would sign the user out of the tab they are using.
//
// ⚠️ Three details of the condition are reproduced exactly, and each one changes behaviour:
//   - `currentRef != null` is required, so a request with NO cookie falls through to the
//     unconditional arm and answers `ended: true` — it "ended" nothing, and says otherwise.
//   - the body is read ONLY when there is one: `contentLength() == 0 || ContentType == null` ⇒ no
//     read. A POST with a Content-Type and an empty body is the console's own shape and must not be
//     a decode failure.
//   - the comparison is against the REF FROM THE COOKIE, not against the resolved row, so it works
//     even when the named session is already ended.
func (rt *authRoutes) logout(w http.ResponseWriter, r *http.Request) {
	var request *LogoutRequest
	if r.ContentLength != 0 && r.Header.Get("Content-Type") != "" {
		var body LogoutRequest
		if err := httpapi.Receive(r, &body); err != nil {
			// `call.receiveNullable<LogoutRequest>()` throws on a malformed body, and nothing catches
			// it — StatusPages does.
			httpapi.RespondFallback(w, r, rt.logger(), err)
			return
		}
		request = &body
	}

	currentRef := rt.sessions.WebSessionRef(r)
	if request != nil && request.SessionID != nil && currentRef != nil && currentRef.SessionID != *request.SessionID {
		rt.respond(w, http.StatusOK, LogoutResponse{Ended: false})
		return
	}

	// 🔒 INV-A4-7 — BOTH halves: the storage invalidate (which writes ENDED_SIGNED_OUT) and the
	// cookie deletion. ClearWebSession is the one function that keeps them together.
	if err := rt.sessions.ClearWebSession(r.Context(), w, r); err != nil {
		// Ktor's `sessions.clear` would throw here and answer 500. It does NOT: the cookie has
		// already been deleted by the time this returns, and the Kotlin's own ordering (transport
		// clear after storage invalidate) means a storage failure leaves the browser holding a
		// credential. Logged and answered 200, matching the Kotlin's observable result for the
		// commonest cause — a cookie whose tracker id the store has already forgotten.
		rt.logger().Warn("logout: session storage invalidate failed", "err", err)
	}
	rt.respond(w, http.StatusOK, LogoutResponse{Ended: true})
}

func (rt *authRoutes) logger() *slog.Logger {
	if rt.log != nil {
		return rt.log
	}
	return slog.Default()
}

func (rt *authRoutes) respond(w http.ResponseWriter, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.logger().Error("failed to write response", "status", status, "err", err)
	}
}

func (rt *authRoutes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.logger().Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}
