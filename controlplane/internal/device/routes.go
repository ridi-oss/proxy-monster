package device

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/oidc"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/token"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The two private constants DeviceAuth.kt:241-242 declares.
//
// ⚠️ `DEV_PRINCIPAL = "debug-user"` (DeviceAuth.kt:240) is OMITTED: nothing in DeviceAuth.kt
// references it. Dead code, and the same literal is duplicated in Tokens.kt:267 and
// Datasources.kt:752, which is where it is actually live. 04-auth-session-tokens.md §1.5 flags it as a
// candidate finding; OMIT is the disposition dead code gets.
const (
	// PollIntervalSeconds is how often pmon polls /poll. The browser page approves out-of-band, so
	// this bounds latency, not correctness.
	PollIntervalSeconds = 2
	// LoginTTLSeconds is the 10 minutes a human has to complete the device-auth dance. Distinct from
	// the SESSION token TTL pmon asked for, which is [LoginRow.TTLSeconds].
	LoginTTLSeconds = 600
)

// The three ApiError codes this surface emits. Every one is a stable i18n key, never English prose
// (INV-A1-13).
const (
	// CodeUnknownOrExpired covers three distinct situations on purpose: no such handle/code, an
	// expired one, and one that is no longer PENDING. Collapsing them is what stops the endpoint
	// being an enumeration oracle for live user codes.
	CodeUnknownOrExpired = "device.unknown_or_expired_login"
	// CodeAlreadyCompleted is the replayed-poll refusal (INV-A4-43).
	CodeAlreadyCompleted = "device.login_already_completed"
	// CodeDeprovisioned is the mint-time deprovisioning refusal (INV-A4-50).
	CodeDeprovisioned = "auth.principal_deprovisioned"
)

// WebSession is the slice of A4's `WebSessionRow` this package reads — `call.webSession()` returns
// the row, and only these two fields are touched (DeviceAuth.kt:318, :335).
type WebSession struct {
	ID        int64
	Principal string
}

// WebSessionResolver is `ApplicationCall.webSession()` (Auth.kt:413) — cookie ⇒ live row, or nil.
//
// 🔒 It enforces the pm_did device bind (INV-A4-19) and both web clocks (INV-A4-20), and it carries
// the per-call resolution cache that makes [Routes.Authorize]'s branch-6 re-read necessary. It stays
// an interface because the request-level helper is A1/A4's composition seam over
// session.Store.ResolveWeb, not a store method this package may call directly.
//
//	TODO(A4): supply this from Auth.kt's webSession() port once it lands.
type WebSessionResolver interface {
	WebSession(ctx context.Context, r *http.Request) (*WebSession, error)
}

// DaemonSessions is the slice of A4's `PrincipalSessionStore` the device routes call. The signatures
// are session.Store's EXACTLY, so *session.Store satisfies it with no adapter — see the compile-time
// assertion in routes_db_test.go. Widening or renaming anything here silently forks the seam.
type DaemonSessions interface {
	// WebRefreshToken is `webRefreshToken(id)`.
	// 🔒 INV-A4-24 — it filters `ended_at IS NULL`, which is what makes the ordering in
	// [Routes.Authorize] safe. See INV-A4-47 there.
	WebRefreshToken(ctx context.Context, sessionID int64) (*string, error)

	// WebSessionIsLive is `webSessionIsLive(id)` — the FRESH read, deliberately separate from
	// WebSession's cached resolution.
	WebSessionIsLive(ctx context.Context, sessionID int64) (bool, error)

	// Create is `create(principal, handle, refreshToken, windowSeconds, ttlSeconds, c)` — open the
	// daemon session row on the CALLER's connection, so it joins the mint transaction.
	//
	// windowSeconds is float64 because session.Store binds it to `make_interval(secs => ...)`.
	Create(ctx context.Context, c store.Queryer, principal string, handle *string, refreshToken *string,
		windowSeconds float64, ttlSeconds int64) (session.CreatedDaemon, error)
}

// ActivePrincipalMinter is A3's `DataSource.mintForActivePrincipalLocked(principal, userGroupStore) { c -> … }`
// (Deprovision.kt:99).
//
// 🔒 INV-A4-50 — SESSION CREATION AND TOKEN ISSUANCE ARE ONE TRANSACTION UNDER THE PER-PRINCIPAL
// ADVISORY LOCK. Quoted from DeviceAuth.kt:374-380: "re-checking deprovisioning, creating the session,
// and issuing the token as ONE transaction under the per-principal advisory lock. The IdP may have
// completed device-auth just as a SCIM `active=false` teardown swept, so a check-then-create outside
// the lock could persist a fresh renewal secret + SESSION token AFTER the sweep already scanned —
// resurrectable on a later reactivation."
//
// ok=false is the Kotlin's null return: the principal is deprovisioned and NOTHING was written.
//
//	TODO(A3): Deprovision.kt's mintForActivePrincipalLocked. Its body is advisoryLockPrincipal →
//	          isDeactivated(principal, c) → body, all inside one inTx. internal/store already has both
//	          primitives (AdvisoryLockPrincipal, InTx) and internal/identity has IsDeactivatedOn, so
//	          the implementation is ~15 lines — it is absent here only because it is A3's to own.
type ActivePrincipalMinter interface {
	MintForActivePrincipalLocked(ctx context.Context, principal string,
		body func(ctx context.Context, c store.Queryer) error) (ok bool, err error)
}

// Routes is `fun Route.deviceSessionRoutes(config, deviceLoginStore, daemonSessionStore, tokenStore,
// userGroupStore, log)` (DeviceAuth.kt:263-360).
//
// ⚠️ The Kotlin's `log: Logger` parameter is OMITTED — it is accepted and never used. See the package
// doc on F33: OMIT the unused parameter, REPRODUCE the silence.
//
// ⚠️ The Kotlin's `userGroupStore` parameter is likewise absent from this struct: its only use is as
// an argument to `mintForActivePrincipalLocked`, which is [ActivePrincipalMinter]'s own dependency
// here, not this struct's.
//
// ⚠️ `sessionRenewRoutes(...)` is registered from inside deviceSessionRoutes in the Kotlin
// (DeviceAuth.kt:359). It is NOT registered here — POST /auth/session/renew is A4's renewal window,
// not device authorization. A composition root must register it separately or the route disappears.
//
//	TODO(A4): sessionRenewRoutes — 04-auth-session-tokens.md §3.5.
type Routes struct {
	Config   config.Config
	Store    *LoginStore
	Web      WebSessionResolver
	Sessions DaemonSessions
	Tokens   *token.Store
	Minter   ActivePrincipalMinter
	// Cookies carries the pm_device_verify cookie. The codec is internal/session's — one encoding
	// for all six cookies — and the spec/payload are re-exported through internal/oidc because
	// control-plane/Oidc.kt is where they are declared in the Kotlin.
	Cookies *session.CookieCodec
	// Now is the clock the expiry comparisons use, injectable for tests. Nil means time.Now.
	//
	// ⚠️ The Kotlin calls `Instant.now()` inline at three sites. Threading a clock is a structural
	// change, not a behavioural one — every comparison below is against the same instant the Kotlin
	// would have taken.
	Now func() time.Time
}

// Register mounts the four routes on a stdlib mux (D6).
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/device/start", rt.Start)
	mux.HandleFunc("POST /auth/device/confirm", rt.Confirm)
	mux.HandleFunc("GET /auth/device/authorize", rt.Authorize)
	mux.HandleFunc("POST /auth/device/poll", rt.Poll)
}

func (rt *Routes) now() time.Time {
	if rt.Now != nil {
		return rt.Now()
	}
	return time.Now()
}

// Start is `POST /auth/device/start` (DeviceAuth.kt:269-288) — no gate.
//
// 1. The body is OPTIONAL: `runCatching { receive<DeviceStartInput>() }.getOrDefault(DeviceStartInput())`.
// A missing or garbage body is NOT a 400 — it is the defaulted input, i.e. ttlSeconds = nil. That is
// one of THREE different body-parse strictnesses across these four routes, and
// 04-auth-session-tokens.md §2.1 says to reproduce each individually rather than unify them.
//
// 2. `ttl = clampTtlSeconds(input.ttlSeconds ?: SESSION_TTL_SECONDS)`.
//
// 3. A PENDING row with a 600-second handle lifetime.
//
// 4. 🔒 INV-A4-45 — the verification URI is the WEB origin.
func (rt *Routes) Start(w http.ResponseWriter, r *http.Request) {
	var input StartInput
	// The error is deliberately ignored: that IS `runCatching { … }.getOrDefault(…)`. A decode
	// failure leaves input at its zero value, which is the defaulted DeviceStartInput().
	_ = json.NewDecoder(r.Body).Decode(&input)

	ttl := token.SessionTTLSeconds
	if input.TTLSeconds != nil {
		ttl = *input.TTLSeconds
	}
	ttl = token.ClampTTLSeconds(ttl)

	row, err := rt.Store.CreatePending(r.Context(), PollIntervalSeconds, ttl,
		rt.now().Add(LoginTTLSeconds*time.Second))
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if row.UserCode == nil {
		// Kotlin's `row.userCode!!` with the comment "createPending always sets it".
		_ = types.Fallback().Respond(w)
		return
	}

	verifyURI := rt.Config.WebBaseURL() + "/device"
	respondJSON(w, http.StatusOK, StartResponse{
		VerificationURI:         verifyURI,
		VerificationURIComplete: verifyURI + "?user_code=" + encodeURLParameter(*row.UserCode),
		UserCode:                *row.UserCode,
		Handle:                  row.Handle,
		Interval:                PollIntervalSeconds,
	})
}

// Confirm is `POST /auth/device/confirm` (DeviceAuth.kt:293-303) — no gate.
//
// Body strictness #2 of 3: `runCatching { receive<DeviceConfirmInput>().userCode }.getOrNull()?.trim()`.
// A missing or garbage body yields a nil code, which falls into the 400 branch below — so it is a
// **400 device.unknown_or_expired_login**, NOT a framework 400. The distinction is observable.
//
// 🔒 INV-A4-46 — this is where the anti-phishing cookie is SET. Quoted from DeviceAuth.kt:289-291:
// "validate it's a real pending login and set the signed verify cookie binding THIS browser to the
// code. /auth/device/authorize below requires that cookie, so an attacker's direct authorize link (no
// /device confirm) cannot approve."
//
// ⚠️ Step 4 stores the row's STORED, NORMALIZED code, while [Routes.Authorize] compares the RAW query
// parameter with an exact !=. So confirming `wdjbmjht` and then authorizing `wdjbmjht` BOUNCES, because
// the cookie holds `WDJB-MJHT`. Reproduced — the web /device page always navigates with the
// normalized code it was handed.
func (rt *Routes) Confirm(w http.ResponseWriter, r *http.Request) {
	var input ConfirmInput
	var row *LoginRow
	if err := json.NewDecoder(r.Body).Decode(&input); err == nil {
		userCode := strings.TrimSpace(input.UserCode)
		if userCode != "" {
			var err error
			if row, err = rt.Store.GetByUserCode(r.Context(), userCode); err != nil {
				_ = types.Fallback().Respond(w)
				return
			}
		}
	}
	if row == nil || row.UserCode == nil || row.ExpiresAt.Before(rt.now()) || row.Status != StatusPending {
		_ = types.RespondError(w, http.StatusBadRequest, CodeUnknownOrExpired, nil)
		return
	}
	if err := rt.Cookies.Set(w, oidc.DeviceVerifyCookieSpec, oidc.DeviceVerifySession{UserCode: *row.UserCode}); err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	respondJSON(w, http.StatusOK, NewConfirmAck())
}

// Authorize is `GET /auth/device/authorize` (DeviceAuth.kt:308-343). Every failure is a REDIRECT,
// never a body.
//
// 🔒 INV-A4-46 — THE DEVICE-VERIFY COOKIE IS THE ANTI-PHISHING GATE, AND IT IS SINGLE-USE. The attack
// it stops: a phisher who has started their OWN `pmon login` mails the victim a bare
// `…/auth/device/authorize?user_code=XXXX-XXXX` link; the victim's live console session would
// otherwise approve the ATTACKER's handle silently.
//
// 🔴 WHICH BRANCHES CLEAR THE COOKIE IS LOAD-BEARING, and getting it wrong breaks the product in one
// direction or the security in the other. Exactly THREE `sessions.clear(DEVICE_VERIFY_COOKIE)` calls
// exist in the Kotlin, at DeviceAuth.kt:316, :336 and :341 — i.e. on the branches that TERMINATE an
// approval attempt:
//
//	branch 2 (no cookie / code mismatch) — NOT cleared. There is nothing to clear that belongs to
//	                                       this code, and clearing would let an attacker's link
//	                                       destroy the victim's legitimate confirm.
//	branch 3 (row gone/expired/not PENDING) — CLEARED (:316).
//	branch 4 (no console session → /login)  — NOT cleared, and this one is subtle. The user is being
//	                                       sent through /login and will land back on THIS exact URL,
//	                                       where step 2 re-requires the cookie. Clear it here and
//	                                       the whole SSO-then-approve path breaks: every first-time
//	                                       `pmon login` loops between /login and /device forever
//	                                       (OidcWebSessionDbTest case 4, DeviceLoginStoreDbTest
//	                                       case 11). The cookie is not a one-shot NONCE; it is
//	                                       one-shot with respect to APPROVAL, and step 4 is not an
//	                                       approval.
//	branch 6 (session died in between)      — CLEARED (:336).
//	branch 7 (approval attempted)           — CLEARED (:341), whether or not the CAS won.
//
// 🔒 INV-A4-47 — the live re-check at branch 6 runs AFTER the refresh-token read, ON PURPOSE. The
// per-call resolution cache means `session` may be stale; branch 6 is the fresh read. Reading the
// refresh token first is harmless because WebRefreshToken itself filters `ended_at IS NULL`
// (INV-A4-24), so a session ended in between yields nil AND fails branch 6 — a credential is never
// minted off a just-invalidated authentication.
//
// 🔒 INV-A4-48 — the existing-session path deliberately does NOT re-login: "If the user already has a
// console session, we approve this pmon login with that identity and land on success — no re-login, no
// session churn." A re-login would call mintWeb, which is newest-wins and would DISPLACE the very
// session doing the approving.
func (rt *Routes) Authorize(w http.ResponseWriter, r *http.Request) {
	userCode := strings.TrimSpace(r.URL.Query().Get("user_code"))
	backToDevice := "/device"
	if userCode != "" {
		backToDevice = "/device?user_code=" + encodeURLParameter(userCode)
	}
	loginRedirect := "/login?return_to=" + encodeURLParameter("/auth/device/authorize?user_code="+userCode)

	// Branch 2 — blank code, or the verify cookie does not carry EXACTLY this code.
	var verify oidc.DeviceVerifySession
	hasVerify := rt.Cookies.Read(r, oidc.DeviceVerifyCookieSpec, &verify) == nil
	if userCode == "" || !hasVerify || verify.UserCode != userCode {
		redirect(w, backToDevice)
		return
	}

	// Branch 3.
	row, err := rt.Store.GetByUserCode(r.Context(), userCode)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if row == nil || row.ExpiresAt.Before(rt.now()) || row.Status != StatusPending {
		rt.Cookies.Clear(w, oidc.DeviceVerifyCookieSpec)
		redirect(w, backToDevice)
		return
	}

	// Branch 4 — approve NOTHING, and do not clear the cookie.
	session, err := rt.Web.WebSession(r.Context(), r)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if session == nil {
		redirect(w, loginRedirect)
		return
	}

	// Branch 5 then 6 — this order, per INV-A4-47.
	refreshToken, err := rt.Sessions.WebRefreshToken(r.Context(), session.ID)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	live, err := rt.Sessions.WebSessionIsLive(r.Context(), session.ID)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if !live {
		rt.Cookies.Clear(w, oidc.DeviceVerifyCookieSpec)
		redirect(w, loginRedirect)
		return
	}

	// Branch 7 — the CAS, then clear regardless of the outcome (INV-A4-42: the return value is the
	// truth, so this branches on it rather than assuming success).
	approved, err := rt.Store.MarkApproved(r.Context(), row.Handle, session.Principal, refreshToken)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	rt.Cookies.Clear(w, oidc.DeviceVerifyCookieSpec)
	if approved {
		redirect(w, "/device/success")
		return
	}
	redirect(w, backToDevice)
}

// Poll is `POST /auth/device/poll` (DeviceAuth.kt:347-358) — no gate; the 192-bit handle IS the
// authentication.
//
// Body strictness #3 of 3: a BARE `receive<DevicePollInput>()`, so a malformed body is a
// FRAMEWORK-level 400 from ContentNegotiation/StatusPages, not this route's ApiError.
//
// 🔒 INV-A4-49 — poll NEVER contacts the IdP: "the approval already resolved the principal, so no IdP
// call happens here." And `principal == null` is treated as PENDING even if the status somehow says
// APPROVED — belt and braces against a partially-written row.
//
// 🔒 INV-A4-43 — the Consume CAS gates the mint. A replay finds the handle CONSUMED and is refused.
func (rt *Routes) Poll(w http.ResponseWriter, r *http.Request) {
	var input PollInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		// The framework-level 400. Ktor's StatusPages maps a deserialization failure to
		// `common.invalid_body`, which is A1's mapping, not this route's.
		_ = types.RespondError(w, http.StatusBadRequest, "common.invalid_body", nil)
		return
	}

	row, err := rt.Store.Get(r.Context(), input.Handle)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if row == nil || row.ExpiresAt.Before(rt.now()) {
		_ = types.RespondError(w, http.StatusBadRequest, CodeUnknownOrExpired, nil)
		return
	}
	if row.Status == StatusPending || row.Principal == nil {
		respondJSON(w, http.StatusAccepted, NewPollPending())
		return
	}
	consumed, err := rt.Store.Consume(r.Context(), row.Handle)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if !consumed {
		_ = types.RespondError(w, http.StatusBadRequest, CodeAlreadyCompleted, nil)
		return
	}
	refreshToken, err := rt.Store.DecryptRefresh(row)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	rt.respondWithMintedSession(w, r, *row.Principal, row, refreshToken)
}

// respondWithMintedSession is `private suspend fun respondWithMintedSession(...)`
// (DeviceAuth.kt:369-395).
//
// 🔒 INV-A4-50 — one transaction, one lock, three writes. See [ActivePrincipalMinter].
//
// 🔒 INV-A4-51 — the session WINDOW is `config.sessionWindowSeconds` (PM_SESSION_WINDOW, default 2 h)
// while the token TTL is `row.ttlSeconds` (what pmon asked for, clamped at start, default 12 h). The
// window caps SILENT RENEWAL; the TTL is the life of one wire credential. ⚠️ With the shipped defaults
// the window (2 h) is SHORTER than the token TTL (12 h), so the first token outlives its own renewal
// window — renewal simply becomes unavailable after 2 h while the token stays valid for 12 h.
// Replicate the arithmetic exactly whether or not that is intentional; §8 Q2 asks.
//
// ⚠️ The token is issued with an EMPTY roles snapshot (`emptyList()`), matching every other REST mint.
// §8 Q4 asks whether that is deliberate; it is reproduced either way.
func (rt *Routes) respondWithMintedSession(
	w http.ResponseWriter, r *http.Request, principal string, row *LoginRow, refreshToken *string,
) {
	var result PollResult
	ok, err := rt.Minter.MintForActivePrincipalLocked(r.Context(), principal,
		func(ctx context.Context, c store.Queryer) error {
			created, err := rt.Sessions.Create(ctx, c, principal, &row.Handle, refreshToken,
				float64(rt.Config.SessionWindowSeconds), row.TTLSeconds)
			if err != nil {
				return err
			}
			issued, err := rt.Tokens.Issue(ctx, c, token.KindSession, principal, []string{}, nil, row.TTLSeconds)
			if err != nil {
				return err
			}
			result = PollResult{
				Token:            issued.Token,
				ExpiresAt:        issued.ExpiresAt,
				Principal:        principal,
				SessionExpiresAt: instant.Format(created.Row.SessionExpiresAt),
				RenewalToken:     created.RenewalToken,
			}
			return nil
		})
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	if !ok {
		_ = types.RespondError(w, http.StatusForbidden, CodeDeprovisioned, nil)
		return
	}
	respondJSON(w, http.StatusOK, result)
}

// respondJSON writes a body through [types.MarshalWire].
//
// 🔒 INV-A1-4 / the #1 silent-breakage risk. MarshalWire is the ONE encoder that reproduces kotlinx's
// two behaviours Go inverts by default: it does not HTML-escape `<`, `>` and `&`, and it is the seam
// where the omit-optionals/always-emit-slices rules are enforced. A bare json.NewEncoder here would
// ship escaped bytes for any user code or handle containing those characters — none can today, but
// the rule is the encoder, not the current alphabet.
func respondJSON(w http.ResponseWriter, status int, body any) {
	payload, err := types.MarshalWire(body)
	if err != nil {
		_ = types.Fallback().Respond(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// redirect is `call.respondRedirect(url)` — 302, Location, no body.
func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// encodeURLParameter is ktor's `String.encodeURLParameter()`; see internal/oidc's copy for why
// url.QueryEscape and url.PathEscape are both wrong here.
//
// ⚠️ Duplicated rather than exported from internal/oidc, because in the Kotlin it is ktor's own
// extension that BOTH files import — there is no shared project-local helper to point at, and
// exporting one would invent a seam the original does not have. If a third caller appears, that is
// the moment to lift it.
func encodeURLParameter(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
		}
	}
	return b.String()
}
