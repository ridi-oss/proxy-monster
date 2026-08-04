package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Authorizer is the one method of `Authz` the route gates use: `authorize(principal, action,
// resource, context)` (Authz.kt:283). *authz.Authz satisfies it.
//
// 🔒 The interface is DELIBERATELY this narrow. Authz's other entry points — authorizeColumns,
// authorizeTables, resolveContextTags, the two-pass datasource path — are the QUERY surface, and a
// route gate that could reach them would be a route gate able to make a query decision. Keeping the
// gates to one method is a compile-time statement that they answer "may this principal do this", never
// "what may this query see".
type Authorizer interface {
	Authorize(principal string, action authz.AuthzAction, resource authz.AuthzResource, context authz.AuthzContext) authz.AuthzDecision
}

// AuthorizeFunc adapts a plain function to [Authorizer].
type AuthorizeFunc func(principal string, action authz.AuthzAction, resource authz.AuthzResource, context authz.AuthzContext) authz.AuthzDecision

// Authorize implements Authorizer.
func (f AuthorizeFunc) Authorize(principal string, action authz.AuthzAction, resource authz.AuthzResource, context authz.AuthzContext) authz.AuthzDecision {
	return f(principal, action, resource, context)
}

// Gates holds the four route gates' shared dependencies. In the Kotlin they are extension functions
// on `ApplicationCall` taking `config` (and `authz`) per call; here they are methods, so a route group
// stores one *Gates instead of threading two arguments through every handler.
//
// 🔒 AGENTS.md: "a route states its requirement by which gate helper it calls." That property is the
// reason all four keep the `Require*` naming and the bool return: a reader grepping a route file for
// `Require` sees its gate, and a route that calls none is visibly ungated.
type Gates struct {
	Config config.Config
	// Authz is the SHARED Cedar graph (INV-A1-1). Nil is legal only when nothing reaches
	// [Gates.RequireAuthz] — i.e. under authDebug, or in a requireApi-only test.
	//
	// It is the narrow [Authorizer] rather than *authz.Authz so a gate suite can assert on WHAT was
	// asked of Cedar (and whether it was asked at all — INV-A2-16's actual claim) without standing up
	// an engine. *authz.Authz satisfies it directly; internal/app passes core.Authz.
	Authz Authorizer
	// Sessions answers "is there a session" for all three session-based gates.
	Sessions *Sessions
	// Context OVERRIDES the request-scoped Cedar context. Nil — the production shape — means A12's
	// real [Gates.HTTPAuthzContext] is used, so `requester_ip` reaches every gate decision.
	//
	// It exists as an override only so a gate suite can inject a context directly and assert on WHAT
	// was asked of Cedar without standing up an edge; production must leave it nil. INV-A2-16's point
	// is that the derivation lives HERE, at one seam, rather than at ~35 admin call sites.
	Context func(r *http.Request) authz.AuthzContext
	// Log defaults to slog.Default().
	Log *slog.Logger
}

func (g *Gates) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

// authzContext is `call.httpAuthzContext(config)` — the real A12 derivation unless a suite has
// injected an override. See [Gates.Context].
func (g *Gates) authzContext(r *http.Request) authz.AuthzContext {
	if g.Context == nil {
		return g.HTTPAuthzContext(r)
	}
	return g.Context(r)
}

// AuthzContext is [Gates.authzContext] for a route that must build a Cedar decision of its own
// rather than delegate to a gate — `GET /api/me/permissions` is the only one today (App.kt:301
// passes `call.httpAuthzContext(config)` straight into computeMePermissions).
//
// 🔒 It is an ACCESSOR OVER THE SAME SEAM, not a second derivation. The route and the gates must
// agree on what `requester_ip` is for one request: if they diverged, /api/me/permissions could report
// `isAdmin: true` for a context the admin routes then deny under, and the console would render an
// admin area every one of whose calls 403s. Threading [Gates.Context] through here is what makes
// A12's single TODO fix both at once.
func (g *Gates) AuthzContext(r *http.Request) authz.AuthzContext { return g.authzContext(r) }

// ---------------------------------------------------------------------------------------------
// requireApi — Datasources.kt:699
// ---------------------------------------------------------------------------------------------

// RequireAPI is `suspend fun ApplicationCall.requireApi(config): Boolean`:
//
//	if (!config.authDebug && userSession() == null) { respond(401, ApiError("common.unauthenticated")); false } else true
//
// THE generic authenticated-session gate — used by App.kt, QueryHistory.kt, Policies.kt, Query.kt,
// Access.kt, AuditRoutes.kt and Approvals.kt, even though it is declared in Datasources.kt. It answers
// "is there a session", NEVER "is this allowed" — that is [Gates.RequireAuthz]'s job.
//
// Note the short-circuit: under authDebug the session is never even READ, so a route behind this gate
// gets no principal in debug mode and falls back to `"debug-user"` at its own call site.
//
// Returns false having ALREADY written the response, so a handler's first line reads
// `if !g.RequireAPI(w, r) { return }` — the direct analogue of Kotlin's
// `if (!call.requireApi(config)) return@get`.
func (g *Gates) RequireAPI(w http.ResponseWriter, r *http.Request) bool {
	if g.Config.AuthDebug {
		return true
	}
	sess, err := g.Sessions.UserSession(r)
	if err != nil {
		RespondFallback(w, r, g.log(), err)
		return false
	}
	if sess == nil {
		g.respond(w, types.Unauthenticated())
		return false
	}
	return true
}

// API wraps a handler in [Gates.RequireAPI], for route groups that gate every route the same way.
func (g *Gates) API(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RequireAPI(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------------------------
// requireAdmin / requireAuthz — Authz.kt:881 and :896
// ---------------------------------------------------------------------------------------------

// RequireAdmin is `suspend fun ApplicationCall.requireAdmin(config, authz, action, resource =
// AuthzResource.System)` — the `System`-resource alias over [Gates.RequireAuthz], and nothing more.
//
// Kotlin expresses the System default as a default argument; Go has none, so the alias is spelled out.
// Callers that need a non-System resource call RequireAuthz directly, which is exactly what the Kotlin
// does too ("named for the routes that aren't admin surfaces").
func (g *Gates) RequireAdmin(w http.ResponseWriter, r *http.Request, action authz.AuthzAction) bool {
	return g.RequireAuthz(w, r, action, authz.ResourceSystem{})
}

// Admin wraps a handler in [Gates.RequireAdmin].
func (g *Gates) Admin(action authz.AuthzAction, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RequireAdmin(w, r, action) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthz is `suspend fun ApplicationCall.requireAuthz(config, authz, action, resource)` — the
// general per-(action, resource) route gate.
//
//  1. config.authDebug            ⇒ true
//  2. userSession() == null       ⇒ 401 ApiError("common.unauthenticated"), false
//  3. authz.authorize(principal, action, resource, httpAuthzContext(config)):
//     Allow ⇒ true
//     Deny  ⇒ 403 ApiError("common.forbidden", {detail: reason}), false
//
// 🔒 INV-A2-16 — THE DEV BYPASS NEVER SKIPS CEDAR; IT PREVENTS CEDAR FROM BEING REACHED. `Authz`
// itself has no bypass anywhere: step 1 returns before `authorize` is ever called, and once
// PM_AUTH_DEBUG is off every admin route runs the real decision. That distinction is what makes this
// the choke point closing the "admin routes require admin.*, not merely any session" hole — a port
// that instead taught Authz to allow-everything under authDebug would leave the hole open on every
// other Cedar call site (the query path, the MCP tools, the gRPC decide) and would be untestable,
// because the bypass would no longer be observable at the gate.
//
// 🔒 Step 1 also precedes the session READ, which is load-bearing for the call sites that build the
// resource from the caller's own principal (`Token(owner)`): under authDebug there is no session to
// build one from, and the Kotlin's ordering means they never have to.
func (g *Gates) RequireAuthz(w http.ResponseWriter, r *http.Request, action authz.AuthzAction, resource authz.AuthzResource) bool {
	if g.Config.AuthDebug {
		return true
	}
	sess, err := g.Sessions.UserSession(r)
	if err != nil {
		RespondFallback(w, r, g.log(), err)
		return false
	}
	if sess == nil {
		g.respond(w, types.Unauthenticated())
		return false
	}
	decision := g.Authz.Authorize(sess.Principal, action, resource, g.authzContext(r))
	if decision.Allowed {
		return true
	}
	// `mapOf("detail" to decision.reason)` — Cedar's own reason string, always present on this path.
	g.respond(w, types.Forbidden(&decision.Reason))
	return false
}

// Authz wraps a handler in [Gates.RequireAuthz].
func (g *Gates) Authorize(action authz.AuthzAction, resource authz.AuthzResource, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RequireAuthz(w, r, action, resource) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------------------------
// requireScimAuth — Scim.kt:150
// ---------------------------------------------------------------------------------------------

// SCIM gate detail strings, verbatim from Scim.kt:153-162. They are English prose on the wire and
// that is correct here — INV-A1-13's one exemption, see [ScimError].
const (
	scimNotConfiguredDetail = "SCIM provisioning is not configured"
	scimRequiresTLSDetail   = "SCIM requires TLS"
	scimInvalidBearerDetail = "invalid bearer token"
)

// RequireScimAuth is `suspend fun ApplicationCall.requireScimAuth(config): Boolean`.
//
//  1. config.scimToken == null ⇒ 501 ScimError("501", "SCIM provisioning is not configured")
//  2. !isScimTls(config)       ⇒ 403 ScimError("403", "SCIM requires TLS")
//  3. bearer missing or wrong  ⇒ 401 ScimError("401", "invalid bearer token")
//  4. else true
//
// 🔒 F33 / INV-A3-38 — THERE IS NO PM_AUTH_DEBUG BYPASS HERE, unlike the other three gates, and that
// is deliberate even though `AGENTS.md` and `docs/authz-model.md:363` both say "PM_AUTH_DEBUG
// short-circuits all four". THE CODE IS RIGHT AND THE DOCS ARE WRONG: `ScimAuthTest.kt:106,111`'s
// `testScimConfig` sets `authDebug = true` and all six of its cases still expect 501/403/401. A port
// that implements the documentation makes a dev-mode control plane accept unauthenticated directory
// writes over plaintext. Do not add the bypass; scim_gate_test.go runs every case with AuthDebug=true
// so that adding one breaks the suite.
//
// 🔒 INV-A3-36 — an unconfigured token means NO PROVISIONING SURFACE AT ALL, not an open one. 501 is
// the fail-closed answer (docs/auth-model.md:140-143: "a deployment that never sets the token has no
// provisioning surface at all — JIT-on-login covers the directory on its own").
//
// 🔒 INV-A3-37 — THE TLS CHECK PRECEDES THE BEARER CHECK. Over plaintext the request is rejected
// BEFORE the secret is compared, so a correct bearer sent in the clear still 403s and no comparison
// is ever performed on a wire-visible secret. Reordering these two is a real regression, not a style
// change.
//
// ⚠️ `removePrefix("Bearer ")` is CASE-SENSITIVE and does not strip a lowercase `bearer `, while
// RFC 7235 declares the scheme case-insensitive — so a client sending `bearer <tok>` gets 401.
// REPRODUCE: strings.TrimPrefix with the same exact-case prefix. (Contrast A5's
// `bearerWirePrincipal`, which IS case-insensitive — the inconsistency is real and is reproduced on
// both sides.)
func (g *Gates) RequireScimAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := g.Config.ScimToken
	if expected == nil {
		g.respondScim(w, http.StatusNotImplemented, "501", scimNotConfiguredDetail)
		return false
	}
	if !g.isScimTLS(r) {
		g.respondScim(w, http.StatusForbidden, "403", scimRequiresTLSDetail)
		return false
	}
	header, ok := scimBearer(r)
	if !ok || !constantTimeEquals(header, *expected) {
		g.respondScim(w, http.StatusUnauthorized, "401", scimInvalidBearerDetail)
		return false
	}
	return true
}

// Scim wraps a handler in [Gates.RequireScimAuth].
func (g *Gates) Scim(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RequireScimAuth(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// scimBearer is `request.headers[Authorization]?.removePrefix("Bearer ")?.trim()`.
//
// The Kotlin's null-vs-value distinction survives: an ABSENT header is `null` (false here) and goes
// straight to 401. A header that does NOT start with `Bearer ` is left UNCHANGED by removePrefix and
// then compared — so `Basic abc` is compared against the token and fails, rather than being detected
// as the wrong scheme. Reproduced, including the trim, which is what makes `Bearer  tok` work.
func scimBearer(r *http.Request) (string, bool) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		// Ktor returns null for an absent header AND for one present with an empty value; both take
		// the same 401 branch, so the collapse is behaviour-preserving.
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(raw, "Bearer ")), true
}

// isScimTLS is `private fun ApplicationCall.isScimTls(config)` — the four arguments, from the
// request, in the Kotlin's order.
func (g *Gates) isScimTLS(r *http.Request) bool {
	peer, peerPresent := RequestPeer(r)
	return ResolveScimTLS(
		RequestScheme(r),
		peer, peerPresent,
		LastHeader(r, "X-Forwarded-Proto"),
		g.Config.TrustedProxies,
	)
}

// constantTimeEquals is `private fun constantTimeEquals(a, b) = MessageDigest.isEqual(...)`.
//
// 🔒 It compares SHA-256 DIGESTS, not the raw bytes, and the reason is a real divergence the spec
// calls out (03-identity-scim.md §"Go shape"): Java's MessageDigest.isEqual folds a length difference
// into its accumulator, whereas crypto/subtle.ConstantTimeCompare RETURNS 0 IMMEDIATELY on a length
// mismatch — a length oracle the Kotlin does not have. Hashing both sides to a fixed 32 bytes first
// removes the oracle and keeps the comparison itself constant-time via hmac.Equal.
//
// Do NOT "simplify" this to `==` or to subtle.ConstantTimeCompare on the raw strings. A standing
// SCIM secret with no rotation is a far juicier timing target than a short-lived token.
func constantTimeEquals(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return hmac.Equal(ha[:], hb[:])
}

// ---------------------------------------------------------------------------------------------

func (g *Gates) respond(w http.ResponseWriter, e types.ErrorResponse) {
	if err := RespondAPIError(w, e); err != nil {
		g.log().Error("failed to write gate response", "code", e.Body.Code, "err", err)
	}
}

func (g *Gates) respondScim(w http.ResponseWriter, status int, scimStatus, detail string) {
	if err := RespondScimError(w, status, NewScimError(scimStatus, detail)); err != nil {
		g.log().Error("failed to write SCIM gate response", "status", scimStatus, "err", err)
	}
}
