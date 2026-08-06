package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// ---------------------------------------------------------------------------------------------
// The Sessions plugin — 01-bootstrap.md §"Cookies", 04-auth-session-tokens.md §3.1-§3.2
// ---------------------------------------------------------------------------------------------

// WebSessionResolver is the slice of `PrincipalSessionStore` request-time identity needs. It is the
// `PRINCIPAL_SESSION_STORE` application attribute (App.kt:399), narrowed to two methods.
//
// Narrow on purpose: `*session.Store` satisfies it, and so does a fake, which is what lets the gate
// and challenge suites run without a container while internal/session's own DB suites prove the SQL.
type WebSessionResolver interface {
	// ResolveWeb is liveness + device binding, and it NEVER extends idle.
	ResolveWeb(ctx context.Context, id int64, deviceID *string) (*session.WebRow, error)
	// WebEndedReason backs the challenge's four-value `reason`.
	WebEndedReason(ctx context.Context, id int64) (*string, error)
}

// SessionStorage is the explicit three-function replacement for Ktor's `SessionStorage`
// (04-auth-session-tokens.md §3.2 "Go shape": "there is no Ktor SessionStorage in Go. The port needs
// an explicit three-function seam — link, lookup, invalidate — invoked from the cookie middleware at
// the same three moments (cookie write, cookie read, cookie clear)").
//
// 🔒 INV-A4-12 — `Read` DELIBERATELY RETURNS REFS FOR ENDED AND EXPIRED ROWS. If it filtered them out,
// [Sessions.WebSession] would never learn the sessionId, the failed-session marker would stay unset,
// and every terminated session would report `"none"` instead of `"displaced"` / `"bind_mismatch"` —
// the whole ended-reason UX. session.Store.WebIDBySessionKey carries that invariant in SQL.
type SessionStorage interface {
	// Write links a freshly minted tracker key to a session row.
	Write(ctx context.Context, key string, ref session.WebSessionRef) error
	// Read returns the ref a key points at, or session.ErrUnknownWebSessionKey.
	Read(ctx context.Context, key string) (session.WebSessionRef, error)
	// Invalidate ends the row a key points at, with ENDED_SIGNED_OUT.
	Invalidate(ctx context.Context, key string) error
}

// StoreSessionStorage is `PrincipalSessionStorage(store, serializer)` over the real store.
type StoreSessionStorage struct{ Store *session.Store }

// Write is `write(id, value)` → `store.linkWebSessionKey(ref.sessionId, id)`.
func (s StoreSessionStorage) Write(ctx context.Context, key string, ref session.WebSessionRef) error {
	return s.Store.LinkWebSessionKey(ctx, ref.SessionID, key)
}

// Read is `read(id)` → `store.webIdBySessionKey(id)`, with the sentinel standing in for Ktor's
// `NoSuchElementException("Unknown web session key")`.
func (s StoreSessionStorage) Read(ctx context.Context, key string) (session.WebSessionRef, error) {
	id, err := s.Store.WebIDBySessionKey(ctx, key)
	if err != nil {
		return session.WebSessionRef{}, err
	}
	return session.WebSessionRef{SessionID: id}, nil
}

// Invalidate is `invalidate(id)` → `store.endWebBySessionKey(id, ENDED_SIGNED_OUT)`.
//
// 🔒 INV-A4-7 — THIS is where logout ends the row. App.kt:781 only clears the cookie; a port that
// drops this call leaves a "signed out" row resolvable from a replayed cookie.
func (s StoreSessionStorage) Invalidate(ctx context.Context, key string) error {
	_, err := s.Store.EndWebBySessionKey(ctx, key, session.EndedSignedOut)
	return err
}

// Sessions is the `install(Sessions) { … }` block (App.kt:466-534) plus the
// `install(Authentication) { session<WebSessionRef>(WEB_SESSION_AUTH) }` block (App.kt:536-542).
//
// The four PAYLOAD cookies (`pm_oauth_state`, `pm_oauth_nonce`, `pm_device_verify`, and A11's MCP
// pending cookie) need nothing beyond internal/session's [session.CookieCodec], which callers already
// use directly. What needs a type is `pm_session`, because Ktor's
// `cookie<WebSessionRef>(SESSION_COOKIE, webSessionStorage)` form is a TRACKER: the browser holds an
// opaque MAC'd id and the ref lives server-side (99-library-decisions.md D7).
type Sessions struct {
	// Codec is internal/session's HMAC codec — the ONE encoding for all six control-plane cookies.
	Codec *session.CookieCodec
	// Storage is the tracker-id ↔ row seam. Nil is legal and means "no storage wired", which
	// resolves every cookie to no session (see [Sessions.WebSession]).
	Storage SessionStorage
	// Resolver is the PRINCIPAL_SESSION_STORE attribute. Nil reproduces `attributes.getOrNull(...)`
	// returning null — a test app that never wired one.
	Resolver WebSessionResolver
	// AbsoluteSeconds is `config.webSessionAbsoluteSeconds`, the `pm_session` cookie's maxAge — the
	// ONE cookie whose lifetime comes from config.
	AbsoluteSeconds int64
	// Log defaults to slog.Default().
	Log *slog.Logger
}

func (s *Sessions) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// spec is the `pm_session` CookieSpec at the configured absolute window.
func (s *Sessions) spec() session.CookieSpec { return session.SessionSpec(s.AbsoluteSeconds) }

// ---------------------------------------------------------------------------------------------
// Per-request resolution — `Auth.kt`'s RESOLVED_IDENTITY / FAILED_WEB_SESSION call attributes
// ---------------------------------------------------------------------------------------------

// resolvedIdentity is `private data class ResolvedIdentity(val row: WebSessionRow?)` plus the
// `FAILED_WEB_SESSION` attribute, in one per-request holder.
//
// 04-auth-session-tokens.md §3.1 "Go shape" is explicit about why the wrapper exists: "RESOLVED_IDENTITY
// must be able to hold 'resolved to nothing' distinctly from 'not yet resolved' — a bare *Row in
// context cannot, so carry a wrapper (that is exactly what ResolvedIdentity(row: WebSessionRow?) is
// for)." `done` is that distinction.
type resolvedIdentity struct {
	done bool
	row  *session.WebRow
	// failed is `FAILED_WEB_SESSION`: the session id a cookie NAMED but that did not resolve. It is
	// the only input the challenge has for telling "displaced" from "expired" from "never had one".
	failed *int64
}

type identityKey struct{}

// Install is the Sessions plugin's per-request half: it seats the resolution holder so that a
// request resolves its identity AT MOST ONCE.
//
// 🔒 INV-A4-11 — "resolution is cached exactly once per request, and that is why webSessionIsLive
// exists." Caching prevents N store round trips and, more importantly, N device-mismatch END-WRITES
// per request: [session.Store.ResolveWeb] ENDS a row on a binding mismatch, so resolving twice would
// mean the second call sees a row it just killed. The cost is that a long request can act on an
// identity the liveness sweep has since ended, which is why anything that GRANTS A NEW CREDENTIAL
// off that identity re-checks session.Store.WebSessionIsLive immediately before committing.
func (s *Sessions) Install(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), identityKey{}, &resolvedIdentity{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func identityOf(r *http.Request) *resolvedIdentity {
	ri, _ := r.Context().Value(identityKey{}).(*resolvedIdentity)
	return ri
}

// WebSession is `fun ApplicationCall.webSession(): WebSessionRow?` (Auth.kt:97-108) — the one
// authoritative "who is this request" for the browser surface. It resolves liveness AND device
// binding, and it NEVER extends idle.
//
// 🔒 INV-A4-10 — EVERY COOKIE-READ FAILURE MODE COLLAPSES TO "UNAUTHENTICATED", never to a 500 and
// never to a partially-trusted identity. Kotlin's `runCatching { sessions.get<WebSessionRef>() }
// .getOrNull()` swallows three distinct failures and all three are reproduced below:
//
//	(a) the storage lookup failing for an unknown tracker id (Ktor: NoSuchElementException; here:
//	    session.ErrUnknownWebSessionKey),
//	(b) deserialization failing on a PRE-CUTOVER `{principal, roles}` payload that is HMAC-VALID
//	    under the current key — WebSessionRoutesDbTest case 8, "a valid HMAC over a wrong-shape
//	    payload must be treated as unauthenticated, never a 500",
//	(c) a missing store (a test app that never wired one).
//
// Losing this turns a stale browser cookie into a 500 on every request.
//
// The error return is NOT one of those three. It is reserved for a resolver failure — the database
// being down mid-resolution — which in the Kotlin is an exception propagating out of `webSession()`
// to StatusPages and answering 500 `common.fallback`. Returning it lets the caller produce that same
// body without a panic; see [Gates.RequireAPI].
func (s *Sessions) WebSession(r *http.Request) (*session.WebRow, error) {
	ri := identityOf(r)
	if ri != nil && ri.done {
		return ri.row, nil
	}

	ref := s.readWebSessionRef(r)

	var resolved *session.WebRow
	if s.Resolver != nil && ref != nil {
		row, err := s.Resolver.ResolveWeb(r.Context(), ref.SessionID, session.DeviceCookieID(r))
		if err != nil {
			return nil, err
		}
		resolved = row
	}

	if ri != nil {
		// `if (ref != null && resolved == null) attributes.put(FAILED_WEB_SESSION, ref.sessionId)` —
		// note it fires when the store attribute was ABSENT too, not only on a rejected row.
		if ref != nil && resolved == nil {
			id := ref.SessionID
			ri.failed = &id
		}
		ri.row = resolved
		ri.done = true
	}
	return resolved, nil
}

// UserSession is `fun ApplicationCall.userSession(): UserSession?` (Auth.kt:111).
//
// `webSession()?.let { UserSession(it.principal) }` — ROLES ARE DELIBERATELY EMPTY HERE. Callers that
// need roles resolve them from A3's RoleResolver. That is why `Tokens.kt:268`'s `rolesOf(call)` always
// returns an empty list for a real session, and why minted tokens carry an empty role snapshot while
// effective roles are re-resolved at decide time. ⚠️ Not obviously intentional — 04-auth-session-tokens.md
// §6 Q4 asks whether it is deliberate or a leftover from the cookie-carried-roles era. REPRODUCE
// either way: leaving Roles nil marshals as `[]` through session.UserSession.MarshalJSON, which is
// what `emptyList()` + encodeDefaults=true produces.
func (s *Sessions) UserSession(r *http.Request) (*session.UserSession, error) {
	row, err := s.WebSession(r)
	if err != nil || row == nil {
		return nil, err
	}
	return &session.UserSession{Principal: row.Principal}, nil
}

// readWebSessionRef is Ktor's `sessions.get<WebSessionRef>()` behind `runCatching`: cookie → MAC →
// tracker id → storage → ref. EVERY failure yields nil; see INV-A4-10 on [Sessions.WebSession].
func (s *Sessions) readWebSessionRef(r *http.Request) *session.WebSessionRef {
	if s.Codec == nil || s.Storage == nil {
		return nil
	}
	ck, err := r.Cookie(session.SessionCookie)
	if err != nil {
		return nil
	}
	raw, err := s.Codec.DecodeRaw(ck.Value)
	if err != nil {
		// A forged or stale-key cookie. Worth a line — "the browser sent something forged" is a
		// different event from "the browser sent nothing" — but never an error page.
		s.log().Debug("web session cookie failed authentication", "err", err)
		return nil
	}
	ref, err := s.Storage.Read(r.Context(), string(raw))
	if err != nil {
		if !errors.Is(err, session.ErrUnknownWebSessionKey) {
			s.log().Warn("web session storage read failed", "err", err)
		}
		return nil
	}
	return &ref
}

// FailedWebSession is the `FAILED_WEB_SESSION` call attribute: the session id this request's cookie
// NAMED but that did not resolve. Nil means the request named none at all.
func FailedWebSession(r *http.Request) *int64 {
	ri := identityOf(r)
	if ri == nil {
		return nil
	}
	return ri.failed
}

// SetFailedWebSession is `call.attributes.put(FAILED_WEB_SESSION, id)` — the WRITE half of that
// attribute, for the one handler that must set it by hand.
//
// 🔒 That handler is `POST /auth/session/heartbeat` (App.kt:760). Its situation is the inverse of
// every other failure: the per-request resolution SUCCEEDED, so [Sessions.WebSession] set nothing,
// and then `touchWeb` returned null because the row was ended or the device binding failed BETWEEN
// the two. Without this write [Sessions.RespondSessionUnauthorized] would find no marker and answer
// `"none"` — "you were never signed in" — on the one route most likely to observe a displacement
// first. It is not a generic setter: no other caller has a reason to claim a session failed.
//
// A no-op when the request never went through [Sessions.Install] (there is nowhere to record it),
// which degrades to `"none"` — the same answer the Kotlin gives when the attribute is absent.
func SetFailedWebSession(r *http.Request, id int64) {
	ri := identityOf(r)
	if ri == nil {
		return
	}
	ri.failed = &id
}

// WebSessionRef is `runCatching { call.sessions.get<WebSessionRef>() }.getOrNull()` — the ref the
// cookie NAMES, without resolving it against the database.
//
// 🔒 It is a different question from [Sessions.WebSession] and `POST /auth/logout` (App.kt:774) asks
// exactly this one: INV-A1-9's conditional logout compares the client's claimed session id against
// THE COOKIE, not against a live row, so it still works when the named session is already ended —
// which is the commonest case, since an automatic logout fires precisely when something went wrong.
// Resolving instead would make a conditional logout on a dead-but-different session fall through to
// the unconditional arm and sign the user out of the tab they are actually using.
//
// Every failure mode is nil, for the reasons on [Sessions.WebSession] (INV-A4-10).
func (s *Sessions) WebSessionRef(r *http.Request) *session.WebSessionRef {
	return s.readWebSessionRef(r)
}

// ---------------------------------------------------------------------------------------------
// Cookie write / clear
// ---------------------------------------------------------------------------------------------

// SetWebSession mints a tracker key, links it to sessionID, and writes the `pm_session` cookie —
// Ktor's `call.sessions.set(WebSessionRef(id))`, which runs the storage `write` and then the
// transport.
//
// Order is load-bearing: the link is committed BEFORE the Set-Cookie is written, so a browser can
// never hold a key the database does not know. The reverse order produces a cookie that resolves to
// nothing on the very next request — i.e. a login that silently did not happen.
func (s *Sessions) SetWebSession(ctx context.Context, w http.ResponseWriter, sessionID int64) error {
	key, err := newTrackerKey()
	if err != nil {
		return err
	}
	if err := s.Storage.Write(ctx, key, session.WebSessionRef{SessionID: sessionID}); err != nil {
		return err
	}
	http.SetCookie(w, s.Codec.NewCookie(s.spec(), s.Codec.EncodeRaw([]byte(key))))
	return nil
}

// ClearWebSession is `call.sessions.clear<WebSessionRef>()`: the storage `invalidate` AND the cookie
// deletion.
//
// 🔒 INV-A4-7 — BOTH HALVES. App.kt:781's `sessions.clear(SESSION_COOKIE)` looks like it only drops a
// cookie; the end-write happens inside `PrincipalSessionStorage.invalidate`, which Ktor calls for it.
// With no such framework hook in Go this function is the only place both can be kept together, and a
// caller that writes the deletion by hand ends up with a "signed out" row that a replayed cookie
// still resolves.
//
// The cookie is cleared even when the invalidate fails: leaving the browser holding a credential
// because the database was briefly unreachable is the worse of the two failures.
func (s *Sessions) ClearWebSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var err error
	if ck, cerr := r.Cookie(session.SessionCookie); cerr == nil && s.Codec != nil && s.Storage != nil {
		if raw, derr := s.Codec.DecodeRaw(ck.Value); derr == nil {
			err = s.Storage.Invalidate(ctx, string(raw))
		}
	}
	s.Codec.Clear(w, s.spec())
	return err
}

// newTrackerKey is Ktor's `generateSessionId()` — `generateNonce()`, 16 CSPRNG bytes as 32 lowercase
// hex characters.
//
// The width is copied rather than chosen: the value is a bearer credential for a live session (it is
// the whole content of `pm_session`), so it must be unguessable, and `principal_session.session_key`
// is TEXT with a partial unique index (V6__sessions.sql:46,71), which constrains nothing about it.
func newTrackerKey() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// ---------------------------------------------------------------------------------------------
// The Authentication plugin — `session<WebSessionRef>(WEB_SESSION_AUTH)` (App.kt:536-542)
// ---------------------------------------------------------------------------------------------

// RequireWebSession is `authenticate(WEB_SESSION_AUTH) { … }`: `validate { webSession() }` plus
// `challenge { respondSessionUnauthorized(call, principalSessionStore) }`.
//
// It is a PER-ROUTE wrapper, not a global one, exactly as in the Kotlin — only `/auth/me`,
// `/auth/session/status` and `/auth/session/heartbeat` sit behind it. Note it is a DIFFERENT gate
// from [Gates.RequireAPI]: this one has no authDebug bypass and answers a SessionStatusError, while
// requireApi bypasses under authDebug and answers an ApiError.
func (s *Sessions) RequireWebSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		row, err := s.WebSession(r)
		if err != nil {
			RespondFallback(w, r, s.log(), err)
			return
		}
		if row == nil {
			s.RespondSessionUnauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RespondSessionUnauthorized is `private suspend fun respondSessionUnauthorized(call, store)`
// (App.kt:242-253).
//
//	sessionId == null                    -> "none"
//	endedReason == ENDED_DISPLACED       -> "displaced"
//	endedReason == ENDED_DEVICE_BIND_MISMATCH -> "bind_mismatch"
//	else                                 -> "expired"
//
// ⚠️ The `else` arm is why this does not simply delegate the whole mapping to session.WireReason.
// That helper maps a NIL ended-reason to `"none"`, which is right for its documented input ("no
// failed-session attribute at all") and WRONG here for the commonest failure of all: a row that
// merely ran past its deadline has `ended_reason IS NULL`, so WebEndedReason returns nil while the
// session id is very much present, and the Kotlin answers `"expired"`. The two nil cases are
// distinguished by WHICH nil it is, so the sessionId check has to come first. Pinned by
// TestChallengeReasonForLiveRowWithNoEndedReasonIsExpired.
//
// `Cache-Control: no-store` on every response — a cached 401 would keep a re-authenticated tab
// looking signed out.
func (s *Sessions) RespondSessionUnauthorized(w http.ResponseWriter, r *http.Request) {
	reason := session.WireReasonNone
	if sessionID := FailedWebSession(r); sessionID != nil {
		reason = session.WireReasonExpired
		if s.Resolver != nil {
			ended, err := s.Resolver.WebEndedReason(r.Context(), *sessionID)
			if err != nil {
				s.log().Warn("web ended reason lookup failed", "sessionId", *sessionID, "err", err)
			} else if ended != nil {
				reason = session.WireReason(ended)
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := RespondJSON(w, http.StatusUnauthorized, SessionStatusError{Reason: reason}); err != nil {
		s.log().Error("failed to write session challenge", "err", err)
	}
}
