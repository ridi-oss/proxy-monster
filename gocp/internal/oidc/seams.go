package oidc

import (
	"context"
	"net/http"
)

// The narrow interfaces this package needs from areas it does NOT own. Each one is exactly the
// method set `oidcRoutes(...)` takes as a parameter in the Kotlin — no wider — so the eventual
// production types satisfy them without an adapter and no area's implementation leaks in here.
//
//	TODO(A3): UserGroupStore.provisionFromOidc — Users.kt:350 constructs
//	          `OidcDirectoryProvisioner(dataSource)` PER CALL and delegates straight to it, so A3's
//	          method should be a two-line wrapper over [DirectoryProvisioner.Provision] and must not
//	          re-derive the reconciliation.
//	TODO(A4): PrincipalSessionStore.mintWeb + the pm_session cookie write + ensureDeviceCookie
//	          (Auth.kt:76-91). [WebSessions] is the whole surface the OIDC callback touches.

// UserGroupProvisioner is A3's `UserGroupStore.provisionFromOidc(principal, email, groups, mapping)`
// (Users.kt:350).
//
// 🔒 INV-A4-63 / INV-A14-37 — the implementation must RECONCILE membership to the mapped claim set
// (added AND removed), not merge into it. Dropping a user from the IdP admin group revokes their
// `system:admin` on their next login; that is the documented, accepted cost.
type UserGroupProvisioner interface {
	ProvisionFromOidc(ctx context.Context, principal string, email *string, idpGroups []string, mapping GroupMapping) error
}

// RoleResolver is A3's `RoleResolver.resolve(principal)`.
//
// 🔒 INV-A4-60 — the callback gates on `resolve(principal).isEmpty()` BEFORE minting anything, so a
// principal with no effective roles reaches the no-access screen with no `principal_session` row
// created. Ordering matters: minting first and checking second would leave a live cookie for an
// unauthorized user.
type RoleResolver interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// WebSessions is the slice of A4's `PrincipalSessionStore` + `Auth.kt` cookie helpers that the OIDC
// callback uses, and nothing else.
//
// Unlike internal/device's [device.DaemonSessions], this is NOT satisfied by *session.Store directly,
// and deliberately so: two of its three methods are composites the composition root owns, not store
// reads. The adapter A1 writes is three lines each:
//
//	MintWeb          → session.Store.MintWeb(ctx, nil, session.MintWebInput{Principal, RefreshToken,
//	                   AbsoluteSeconds, IdleSeconds, DeviceID: &deviceID})
//	SetSessionCookie → codec.Set(w, session.SessionSpec(cfg.WebSessionAbsoluteSeconds),
//	                   session.WebSessionRef{SessionID: id}) AND session.Store.LinkWebSessionKey —
//	                   🔒 BOTH halves. Ktor's storage does the link implicitly; a Go port that writes
//	                   only the cookie leaves `session_key` NULL, and /auth/logout's
//	                   EndWebBySessionKey then ends nothing (INV-A4-7, INV-A4-25).
//	EnsureDeviceCookie → session.EnsureDeviceCookie(w, r, secure)
//
//	TODO(A1): supply that adapter from the composition root.
type WebSessions interface {
	// MintWeb is `mintWeb(principal, refreshToken, absoluteSeconds, idleSeconds, deviceId)`
	// (04-auth-session-tokens.md §3.4). Newest-wins: it DISPLACES the principal's other live web
	// sessions.
	MintWeb(ctx context.Context, principal string, refreshToken *string, absoluteSeconds, idleSeconds int64, deviceID string) (int64, error)

	// SetSessionCookie is `call.sessions.set(WebSessionRef(sessionId))` — writing the signed
	// `pm_session` cookie AND (in the Kotlin) linking the Ktor tracker id to the row through
	// PrincipalSessionStorage. Both halves belong to A4; the callback only asks for them to happen.
	SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error

	// EnsureDeviceCookie is `ApplicationCall.ensureDeviceCookie(secure)` (Auth.kt:76-91): read
	// `pm_did` or mint a fresh random correlator, returning the value either way.
	//
	// 🔒 INV-A4-8 — `pm_did` is UNSIGNED and that is fine, because it is never trusted alone: it is
	// only ever compared for equality with the `device_id` stored on the session row. `secure` is
	// derived by the CALLER as `config.mcpIssuer.startsWith("https://")`, the same derivation the
	// five signed cookies use.
	EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error)
}
