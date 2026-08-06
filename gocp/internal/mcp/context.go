package mcp

import (
	"context"
	"net/http"
	"slices"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
)

// ---------------------------------------------------------------------------------------------
// A11 §2 gate 4 — `McpRequestContext` and the seams the pipeline resolves it through.
// ---------------------------------------------------------------------------------------------

// RequestContext is `data class McpRequestContext(principal, clientId, scopes, requesterIp)` — what
// gate 4 stashes in `call.attributes` and every tool handler reads.
//
// 🔒 It carries NO ROLES. INV-A11-8 resolves roles LIVE on every tool call, so a role revoked after
// the access token was minted takes effect on the very next call. Caching them here would be the one
// change that quietly breaks that.
type RequestContext struct {
	Principal string
	ClientID  string
	// Scopes is Kotlin's `Set<String>`. A slice, because it holds at most the four MCPA scopes and is
	// only ever asked "does it contain this one" — a map would be plumbing for a linear scan over four
	// elements. Duplicates are harmless for membership, which is all `toSet()` bought.
	Scopes []string
	// RequesterIP is `call.httpRequesterIp(config)` — nil when unknown.
	RequesterIP *string
}

// hasScope is `capability.requiredScope in context.scopes`.
func (c RequestContext) hasScope(scope string) bool { return slices.Contains(c.Scopes, scope) }

// AccessIdentity is `data class McpAccessIdentity(principal, clientId, resource, scopes, consentId)`
// (auth/McpOAuth.kt:46) — what resolving a bearer against the token table yields.
//
// It is declared HERE rather than imported because `McpTokenStore` lives in the Kotlin `auth/` module,
// which 14-auth.md owns and which is not ported yet. See [TokenResolver].
type AccessIdentity struct {
	Principal string
	ClientID  string
	Resource  string
	Scopes    []string
	ConsentID int64
}

// toContext is `private fun McpAccessIdentity.toContext(requesterIp)`.
//
// ⚠️ `resource` and `consentId` are DROPPED. The resource was already matched by `resolveAccess`'s
// `WHERE t.resource = ?` (the audience binding, INV-A11-18), and nothing downstream of gate 3 needs
// the consent row. Carrying them would invite a second, weaker audience check further in.
func (i AccessIdentity) toContext(requesterIP *string) RequestContext {
	return RequestContext{Principal: i.Principal, ClientID: i.ClientID, Scopes: i.Scopes, RequesterIP: requesterIP}
}

// TokenResolver is the ONE method of `McpTokenStore` gate 3 uses:
// `fun resolveAccess(token, expectedResource): McpAccessIdentity?` (auth/McpOAuth.kt:55).
//
// 🔴 A NARROW INTERFACE BECAUSE THE STORE IS A SIBLING'S. `McpTokenStore` is in the Kotlin `auth/`
// module alongside `OAuthAuthorizationStore`, counted in 14-auth.md, and internal/core's own doc
// carries `TODO(A11): McpTokenStore, the 17th member, has no Go counterpart yet`. Writing a second
// implementation of that query here would put the token-family security core — one-time PKCE-bound
// codes, audience binding, refresh rotation — in the wrong area.
//
// What the implementation MUST preserve, because gate 3 assumes it and cannot check it:
//   - the token is matched by its SHA-256 HEX HASH, never in plaintext;
//   - `kind = 'MCP_ACCESS'`, `revoked_at IS NULL`, `expires_at > now()`;
//   - `resource = expectedResource` — 🔒 INV-A11-18's audience binding, so a token minted for one
//     resource cannot be replayed against another;
//   - the joined `oauth_consent` row is itself unrevoked and matches on all four of
//     (principal, client_id, resource, scope).
//
// A nil identity with a nil error is the Kotlin's `null`: no such live token.
//
//	TODO(A14): implement in the OAuth store increment and wire it in internal/app.
type TokenResolver interface {
	ResolveAccess(ctx context.Context, token, expectedResource string) (*AccessIdentity, error)
}

// Deactivations is `core.userGroupStore.isDeactivated(principal)` — gate 3's second half.
//
// 🔒 A deactivated principal is rejected AT THE SAME GATE AS A BAD TOKEN, with the identical
// `common.invalid_token` body. Deprovisioning revokes credentials (A3), but a token minted a
// millisecond earlier would otherwise stay live for its whole TTL; this closes that window on every
// request rather than relying on the revoke having raced ahead.
//
// *identity.UserGroupStore satisfies it.
type Deactivations interface {
	IsDeactivated(ctx context.Context, principal string) (bool, error)
}

// Roles is `core.roleResolver.resolve(principal)` — 🔒 INV-A11-8's live per-call resolution.
// *identity.RoleResolver satisfies it.
type Roles interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// Cedar is the ONE method of `Authz` this area uses: `authorizeAs(principal, roles, action, resource,
// context)`.
//
// ⚠️ It is `authorizeAs`, NOT `authorizeWithContext`, and that is A11 §3's flagged consequence: NO
// `context.tags` are derived for an MCP call, because tag derivation needs a Datasource in scope
// (INV-A2-14) and every MCP capability's resource is `System`. 🔒 MCP IS A TAG-FREE CHANNEL — a
// tag-conditioned policy never fires here. §11 Q1 asks whether the two classification tools should
// derive tags against their datasource; until that is answered the narrow interface is also the
// statement that this area cannot accidentally start doing so.
//
// *authz.Authz satisfies it.
type Cedar interface {
	AuthorizeAs(principal string, roles []string, action authz.AuthzAction, resource authz.AuthzResource, ctx authz.AuthzContext) authz.AuthzDecision
}

// ---------------------------------------------------------------------------------------------
// Request-scoped state
// ---------------------------------------------------------------------------------------------

type contextKey int

const (
	// requestContextKey is Ktor's `AttributeKey<McpRequestContext>("mcp-request-context")`. Gate 4
	// puts it there and `newServer` reads it, which is the whole reason a fresh Server can be built
	// per request without threading the identity through the SDK.
	requestContextKey contextKey = iota
	// responseControlKey carries the HTTP status/header override — see [responseControl].
	responseControlKey
	// localeKey carries `requestLocale(call)`.
	localeKey
)

// withRequestContext is `call.attributes.put(MCP_CONTEXT, …)`.
func withRequestContext(r *http.Request, rc RequestContext) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestContextKey, rc))
}

// requestContextOf is `call.attributes[MCP_CONTEXT]`, which THROWS in Ktor when the key is absent.
//
// The absence is unreachable: gate 4 runs before the SDK handler on the same request, and no other
// path reaches a tool. The bool return replaces the throw so that if the pipeline is ever rewired
// wrongly the failure is a refused request rather than a nil-principal tool call running as "".
func requestContextOf(ctx context.Context) (RequestContext, bool) {
	rc, ok := ctx.Value(requestContextKey).(RequestContext)
	return rc, ok
}

// withResponseControl / responseControlOf carry the HTTP status+header override a tool handler needs
// in order to reproduce `localizedError`'s `call.response.status(403)`. Ktor hands the handler the
// live ApplicationCall; the Go SDK hands it only a context, so the override travels on the context.
func withResponseControl(ctx context.Context, ctl *responseControl) context.Context {
	return context.WithValue(ctx, responseControlKey, ctl)
}

func responseControlOf(ctx context.Context) (*responseControl, bool) {
	ctl, ok := ctx.Value(responseControlKey).(*responseControl)
	if !ok || ctl == nil {
		// A detached control keeps every caller nil-free. Writes to it are simply never applied,
		// which is the right behaviour for a code path that reached a tool without an HTTP response
		// to set a status on.
		return &responseControl{header: nil}, false
	}
	return ctl, true
}

// withLocale / localeOf carry `requestLocale(call)`, resolved ONCE at gate 4 rather than per tool.
// Ktor resolves it once in `createMcpServer` for the same reason: 38 tool descriptions come out of the
// bundle per request and re-parsing Accept-Language for each would be the same answer 38 times.
func withLocale(ctx context.Context, locale Locale) context.Context {
	return context.WithValue(ctx, localeKey, locale)
}

func localeOf(ctx context.Context) Locale {
	if l, ok := ctx.Value(localeKey).(Locale); ok {
		return l
	}
	return LocaleEnglish
}
