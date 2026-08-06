package token

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// MintSessionTokenInput is `POST /api/wire-tokens`' body — `data class
// MintSessionTokenInput(val ttlSeconds: Long? = null)` (Tokens.kt:67).
//
// ⚠️ TTLSeconds is *int64, not int64. Kotlin's null means "use the route's default" (12 h here, 1 h
// on `/api/tokens`), and Go's zero value would instead ask for a 0-second TTL — which
// [ClampTTLSeconds] would floor to 60 s, silently turning "I didn't say" into "one minute".
type MintSessionTokenInput struct {
	TTLSeconds *int64 `json:"ttlSeconds,omitempty"`
}

// CreateTokenInput is `POST /api/tokens`' body — `data class CreateTokenInput(val name: String? =
// null, val ttlSeconds: Long? = null)` (Tokens.kt:70).
//
// Name is a POINTER for the same reason: the route runs `?.ifBlank { null }` over it, and "absent"
// and "blank" both have to reach the store as SQL NULL while remaining distinguishable from a real
// empty-string name at the decode boundary.
type CreateTokenInput struct {
	Name       *string `json:"name,omitempty"`
	TTLSeconds *int64  `json:"ttlSeconds,omitempty"`
}

// CodeDeprovisioned is the 403 both mint routes answer when [MintForActivePrincipalLocked] returns
// nil — `ApiError("auth.principal_deprovisioned")` (Tokens.kt:287, :313).
//
// ⚠️ internal/device declares the SAME literal for the device-poll mint. Two copies, matching the
// Kotlin's two: DeviceAuth.kt:391 and Tokens.kt:287/:313 each spell it out. Not shared, because
// sharing it is a refactor and the port reproduces.
const CodeDeprovisioned = "auth.principal_deprovisioned"

// NotFoundToken is `notFound("token")` — the param on BOTH of DELETE's 404s: the row that does not
// exist, and the row whose revoke matched nothing. Identical bodies, so a caller cannot tell an
// unknown id from someone else's already-revoked token.
const NotFoundToken = "token"

// DebugPrincipal is `principalOf(call) = call.userSession()?.principal ?: "debug-user"`
// (Tokens.kt:267). The same literal internal/access and internal/datasource declare — three
// file-private copies in the Kotlin, reproduced as three.
const DebugPrincipal = "debug-user"

// Routes is `fun Route.tokenRoutes(config, store, userGroupStore, authz)` (Tokens.kt:270-325) — the
// four managed-credential endpoints.
//
//	POST   /api/wire-tokens     requireAuthz(token.mint,   Token(self, SESSION))  ⇒ **200**
//	GET    /api/tokens          requireAuthz(token.list,   Token(target, kind=nil)) ⇒ 200
//	POST   /api/tokens          requireAuthz(token.mint,   Token(self, USER))     ⇒ **201**
//	DELETE /api/tokens/{id}     requireAuthz(token.revoke, Token(owner, kind))    ⇒ **204**
//
// ⚠️ THE TWO MINT ROUTES ANSWER DIFFERENT SUCCESS STATUSES FOR THE SAME ACT. 200 for wire-tokens,
// 201 for tokens. An inconsistency, and a WIRE one that `web/` and `pmon` already depend on
// (04-auth-session-tokens.md §3.8) — REPRODUCE, do not align.
//
// 🔒 INV-A4-58 — CREDENTIAL ISSUANCE IS A CEDAR DECISION *AND* A LOCKED DEACTIVATION CHECK. Both
// mint routes do both, in that order, and neither is sufficient alone: Cedar answers "may this
// principal mint this KIND of token", the locked check answers "does this principal still exist",
// and only the second is immune to a SCIM teardown landing mid-request.
//
// 🔒 THE GATE RUNS BEFORE THE BODY IS READ, on both mint routes (Tokens.kt:276 then :277; :303 then
// :304). An unauthorized caller with a garbage body must get the gate's 401/403, never a 400/500
// about its JSON — parsing first inverts the disclosure order and tells an unauthenticated stranger
// something about how their input was interpreted.
//
// 🔒 THE TWO TTL DEFAULTS DIFFER AND NEITHER ROUTE CLAMPS. wire-tokens defaults to
// [SessionTTLSeconds] (12 h), tokens to [DefaultUserTTLSeconds] (1 h); the clamp lives inside
// [Store.Issue] so it applies exactly once on all six issuance paths. See [ClampTTLSeconds].
type Routes struct {
	// gates carries Config, Sessions and requireAuthz. No route here calls requireApi — every one of
	// the four is a Cedar decision, which subsumes the session check.
	gates *httpapi.Gates
	store *Store
	// deact is A3's UserGroupStore, narrowed to the one read [MintForActivePrincipalLocked] performs.
	// The Kotlin threads `userGroupStore` as a route parameter for exactly this and nothing else.
	deact Deactivation
	log   *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRoutes(gates *httpapi.Gates, store *Store, deact Deactivation, log *slog.Logger) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, store: store, deact: deact, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the four patterns.
//
// ⚠️ `/api/wire-tokens` and `/api/tokens` are SEPARATE top-level paths, not a prefix pair — nothing
// here ends in `/`, so ServeMux's subtree-match-plus-redirect behaviour (httpapi.Router divergence 1)
// is never triggered.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/wire-tokens", rt.mintWire)
	mux.HandleFunc("GET /api/tokens", rt.list)
	mux.HandleFunc("POST /api/tokens", rt.mintUser)
	mux.HandleFunc("DELETE /api/tokens/{id}", rt.revoke)
}

// mintWire is `POST /api/wire-tokens` — **200** [Issued]. The daemon's (`pm login`) short-lived
// SESSION credential.
//
// The Cedar resource carries the CONCRETE kind (SESSION), which is what lets a policy bar a role from
// long-lived PATs while still permitting sessions (A2 INV-A2-3). Compare [Routes.list], which passes
// nil.
func (rt *Routes) mintWire(w http.ResponseWriter, r *http.Request) {
	principal, ok := rt.principalOf(w, r)
	if !ok {
		return
	}
	if !rt.gates.RequireAuthz(w, r, authz.ActionTokenMint, authz.ResourceToken{
		Owner: principal, Kind: types.Ptr(authz.TokenKindSession),
	}) {
		return
	}

	var input MintSessionTokenInput
	if err := httpapi.Receive(r, &input); err != nil {
		// A BARE `call.receive<MintSessionTokenInput>()` (Tokens.kt:277): a malformed body escapes to
		// StatusPages. 500 common.fallback here, where Ktor's ContentNegotiation answers a
		// framework 400 — the port-wide D6 divergence recorded on CedarPolicyRoutes.receiveInput.
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	ttl := SessionTTLSeconds
	if input.TTLSeconds != nil {
		ttl = *input.TTLSeconds
	}

	roles, ok := rt.rolesOf(w, r)
	if !ok {
		return
	}
	issued, err := MintForActivePrincipalLocked(r.Context(), rt.store.DB(), rt.deact, principal,
		func(ctx context.Context, c store.Queryer) (Issued, error) {
			return rt.store.Issue(ctx, c, KindSession, principal, roles, nil, ttl)
		})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if issued == nil {
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusForbidden, Body: types.ApiError{Code: CodeDeprovisioned},
		})
		return
	}
	rt.respond(w, r, http.StatusOK, *issued)
}

// list is `GET /api/tokens?principal=` — 200 `[Info]`.
//
// 🔒 INV-A4-6 — THE CEDAR RESOURCE IS BUILT WITH `kind = nil`, i.e. the attribute is ABSENT, because
// listing is kind-agnostic. Per A2 INV-A2-3 absence is what lets a policy forbid minting long-lived
// PATs while still permitting a principal to LIST their sessions. Emitting `kind: ""` or a
// placeholder would silently make those policies stop matching.
//
// ⚠️ `?principal=` defaults to the caller and is NOT filtered afterwards — unlike A6's grant list,
// which forward-filters every row. Here the whole request is one Cedar decision against the TARGET
// principal, so the oversight seed (`system:token-admin`, V8__seed.sql:128) is what admits a
// cross-principal listing and an ordinary caller is denied outright with 403 rather than shown `[]`.
// Two different shapes for "may you see someone else's rows", and both are reproduced as they are.
//
// This returns METADATA only. A token's secret exists on the wire exactly once, at mint.
func (rt *Routes) list(w http.ResponseWriter, r *http.Request) {
	target, ok := rt.principalOf(w, r)
	if !ok {
		return
	}
	// `call.request.queryParameters["principal"] ?: principalOf(call)` — ABSENT falls back, but
	// PRESENT-AND-EMPTY does not: `?principal=` lists the empty principal's (no) tokens. Go's
	// Query().Get() collapses those two, so presence is tested explicitly.
	if q := r.URL.Query(); q.Has("principal") {
		target = q.Get("principal")
	}

	if !rt.gates.RequireAuthz(w, r, authz.ActionTokenList, authz.ResourceToken{
		Owner: target, Kind: nil,
	}) {
		return
	}
	tokens, err := rt.store.List(r.Context(), target)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, tokens)
}

// mintUser is `POST /api/tokens` — **201** [Issued]. The named, expiring "connect password" a human
// generates from the console or `pm`.
//
// ⚠️ `input.name?.ifBlank { null }` normalises a blank name to NULL, so `{"name":"   "}` stores NULL
// rather than three spaces — and the response then OMITS `name` entirely (INV-A1-4's
// explicitNulls=false), rather than sending `"name": null`.
func (rt *Routes) mintUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := rt.principalOf(w, r)
	if !ok {
		return
	}
	if !rt.gates.RequireAuthz(w, r, authz.ActionTokenMint, authz.ResourceToken{
		Owner: principal, Kind: types.Ptr(authz.TokenKindUser),
	}) {
		return
	}

	var input CreateTokenInput
	if err := httpapi.Receive(r, &input); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	ttl := DefaultUserTTLSeconds
	if input.TTLSeconds != nil {
		ttl = *input.TTLSeconds
	}
	name := blankToNil(input.Name)

	roles, ok := rt.rolesOf(w, r)
	if !ok {
		return
	}
	issued, err := MintForActivePrincipalLocked(r.Context(), rt.store.DB(), rt.deact, principal,
		func(ctx context.Context, c store.Queryer) (Issued, error) {
			return rt.store.Issue(ctx, c, KindUser, principal, roles, name, ttl)
		})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if issued == nil {
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusForbidden, Body: types.ApiError{Code: CodeDeprovisioned},
		})
		return
	}
	rt.respond(w, r, http.StatusCreated, *issued)
}

// revoke is `DELETE /api/tokens/{id}` — **204**, no body.
//
// 🔒 INV-A4-5 — THE ROW IS LOADED BEFORE THE GATE, so Cedar decides against the token's REAL owner
// and kind rather than against whatever the caller claims. A missing id is a 404 "before any
// authorization is revealed" (Tokens.kt:320-323). [Store.Revoke]'s `AND principal = ?` is then a
// belt-and-braces second check, no longer the gate.
//
// ⚠️ 🔒 F27 (= A4-F21) — REPRODUCED AND PINNED, NOT FIXED. THIS IS THE ROUTE THE FINDING IS ABOUT.
// [Store.Get] has NO kind filter while [Store.List] restricts to ('SESSION','USER'), so the id may
// name an `MCP_ACCESS`, `MCP_REFRESH`, `EDITOR` or `APPROVER_EXEC` row the caller could never have
// listed. For the two MCP kinds [KindFromWire] then returns ok=false, and the Cedar resource is built
// with `kind` ABSENT — which per A2 INV-A2-3 is the PERMISSIVE direction for a kind-scoped forbid.
// `Tokens.kt:26-30` says the null makes "callers fail closed"; at THIS call site it does the exact
// opposite.
//
// Reachability is live: the shipped `system:token-admin` seed permits `token.revoke` on any
// principal's tokens (V8__seed.sql:128-129) and the neighbouring hard forbid covers `token.mint`
// only. Ownership still bounds the damage — the revoke's `principal = ?` predicate makes it a
// cross-KIND hole, not a cross-USER one.
//
// 🔴 Do not add the kind filter here or in [Store.Get]. It would change an observable status code
// (404 for 204) on a security path, and that is a decision to take deliberately, before or after
// cutover, never inside the port. TestDeleteTokenBuildsAnAbsentKindForAnMcpRow is the pin.
func (rt *Routes) revoke(w http.ResponseWriter, r *http.Request) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	info, err := rt.store.Get(r.Context(), *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if info == nil {
		rt.respondError(w, types.NotFound(NotFoundToken))
		return
	}
	if !rt.gates.RequireAuthz(w, r, authz.ActionTokenRevoke, authz.ResourceToken{
		Owner: info.Principal, Kind: cedarKind(info.Kind),
	}) {
		return
	}
	revoked, err := rt.store.Revoke(r.Context(), *id, info.Principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !revoked {
		rt.respondError(w, types.NotFound(NotFoundToken))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------

// cedarKind is `TokenKind.fromWire(token.kind)` fed straight into `AuthzResource.Token(kind = …)`.
//
// 🔒 THE nil RETURN IS THE F27 HOLE AND IT IS DELIBERATE HERE. An unrecognized wire value — every
// MCP kind — yields nil, which A2 marshals as an ABSENT `kind` attribute. Making this fall back to
// some placeholder kind would "fix" the finding invisibly; making it 400 would change the status of
// a reachable request. Both are decisions outside the port.
//
// ⚠️ [authz.TokenKind] and [Kind] are two string types over the same four constants — A2 declares
// its own copy (resource.go:34-40, "Ported from Tokens.kt:31-36, which A4 owns") so internal/authz
// need not import this package. The conversion is spelled out rather than papered over with a type
// alias, so the duplication stays visible.
func cedarKind(wire string) *authz.TokenKind {
	kind, ok := KindFromWire(wire)
	if !ok {
		return nil
	}
	return types.Ptr(authz.TokenKind(kind))
}

// blankToNil is Kotlin's `?.ifBlank { null }` — nil in, nil out; all-whitespace in, nil out.
//
// `isBlank()` is "empty or every character is whitespace" by Character.isWhitespace, which for the
// ASCII range agrees with unicode.IsSpace. strings.TrimSpace trims the same Unicode space set, so a
// trimmed-empty string is exactly the blank case. Note the ORIGINAL is returned when it is not
// blank — `ifBlank` does not trim.
func blankToNil(v *string) *string {
	if v == nil || strings.TrimSpace(*v) == "" {
		return nil
	}
	return v
}

// principalOf is `private fun principalOf(call) = call.userSession()?.principal ?: "debug-user"`
// (Tokens.kt:267).
//
// 🔒 It is evaluated BEFORE requireAuthz on both mint routes, which is why the gate can build
// `Token(owner = self)` at all. Under authDebug requireAuthz short-circuits before reading a session,
// so the "debug-user" fallback is what the mint then runs as.
func (rt *Routes) principalOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	if rt.gates.Sessions == nil {
		return DebugPrincipal, true
	}
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return "", false
	}
	if sess == nil {
		return DebugPrincipal, true
	}
	return sess.Principal, true
}

// rolesOf is `private fun rolesOf(call) = call.userSession()?.roles ?: emptyList()` (Tokens.kt:268)
// — the roles SNAPSHOT frozen onto the minted row.
//
// ⚠️ 🔒 IT IS ALWAYS EMPTY, EVEN FOR A REAL SESSION. `UserSession` is built as
// `UserSession(it.principal)` with roles defaulted to `emptyList()` (Auth.kt:111), so no session ever
// carries roles. Every SESSION and USER token therefore ships with `roles = []`, and effective roles
// are re-resolved server-side at decide time — which is what makes a revoked role fail closed on the
// next query instead of living out the token's TTL. 04-auth-session-tokens.md §6 Q4 asks whether the
// empty list is intentional or a leftover; REPRODUCE either way, because a port that "helpfully"
// resolved roles here would freeze an elevation into a 24-hour credential.
func (rt *Routes) rolesOf(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	if rt.gates.Sessions == nil {
		return []string{}, true
	}
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return nil, false
	}
	if sess == nil || sess.Roles == nil {
		return []string{}, true
	}
	return sess.Roles, true
}

func (rt *Routes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *Routes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}
