package session

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The three ApiError codes `POST /auth/session/renew` emits. All three are 401, and the SPLIT
// between them is deliberate diagnostics, not authorization: the daemon shows a different message for
// "you never sent a credential" than for "your login window has closed", and only the second means
// `pmon login` again.
const (
	// CodeMissingRenewalToken — no `Authorization` header, or one that is not `Bearer …`.
	CodeMissingRenewalToken = "auth.missing_renewal_token"
	// CodeSessionWindowExpired — the secret resolved to a row, but the LOCKED re-check refused it.
	// It covers four distinct refusals on purpose (row vanished, window closed, principal
	// deprovisioned, liveness INACTIVE) — see [RenewRoutes.renew].
	CodeSessionWindowExpired = "auth.session_window_expired"
)

// RenewSessionResponse is `data class RenewSessionResponse(val token: String, val expiresAt: String)`
// (DaemonSession.kt:27).
//
// ⚠️ It is NOT `IssuedToken`. The daemon gets the secret and the expiry and nothing else — no id, no
// kind, no name — so the renewal reply cannot be mistaken for a mint receipt and nothing downstream
// can start keying off a token id it was never meant to see.
//
// `expiresAt` is a Java `Instant.toString()` rendering (internal/instant), carried through from
// whatever [RenewRoutes.Mint] produced.
type RenewSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

// Minted is the narrow result [RenewRoutes.Mint] hands back — A4's `IssuedToken`, reduced to the two
// fields the response carries.
//
// 🔒 IT IS A LOCAL TYPE RATHER THAN internal/token's `Issued`, AND THAT IS THE SAME CHOICE
// [RenewLocked] ALREADY MADE. RenewLocked is a free generic function precisely so this package need
// not import the token store ("keeping it generic is also what stops this package from depending on
// the token store"). Importing it here for one struct would undo that at the file next door.
type Minted struct {
	Token     string
	ExpiresAt string
}

// RenewRoutes is `internal fun Route.sessionRenewRoutes(daemonSessionStore, tokenStore,
// userGroupStore)` (DaemonSession.kt:634-665) — ONE route.
//
// # Where it is registered, and why that is a trap
//
// ⚠️ The Kotlin registers this from INSIDE `deviceSessionRoutes` (DeviceAuth.kt:359). internal/device
// deliberately does NOT do that (routes.go's "⚠️ `sessionRenewRoutes(...)` is registered from inside
// deviceSessionRoutes in the Kotlin … It is NOT registered here"), so a composition root must mount
// this group separately or `POST /auth/session/renew` silently disappears — no compile error, no
// failing test, just a daemon fleet that stops renewing twelve hours later.
//
// # The authentication model
//
// 🔒 INV-A4-26 — THE BEARER SECRET IS THE ONLY IDENTITY, AND THE ROW IS FOUND BY ITS HASH AND BY
// NOTHING ELSE. There is no request body read anywhere on this path. The named regression
// (RenewalWindowTest case 2) is the unauthenticated-renewal flaw: a body carrying `{"principal":…}`
// let anyone who knew an email address mint that person a fresh wire token. A port that added a
// convenience `?principal=` or accepted a body hint would reopen it exactly.
//
// # What is NOT here
//
// 🔒 INV-A4-34 — RENEWAL READS CACHED LIVENESS AND NEVER CALLS THE IdP. The timer sweep
// (`sweepSessionLiveness`) is the sole revalidator. Two reasons, both operational: renew sits on
// `pmon`'s critical path and must not inherit IdP latency, and an IdP outage must not become a
// fleet-wide logout.
type RenewRoutes struct {
	// Store is `daemonSessionStore` — the hash lookup plus [RenewLocked].
	Store *Store

	// IsDeactivated is A3's `userGroupStore.isDeactivated(principal, c)`, threaded as a func for the
	// same reason [RenewLocked] takes it as one: it must run ON THE LOCKED CONNECTION, so it cannot
	// be a store method that opens its own.
	//
	// The signature is [RenewLocked]'s verbatim — c LAST, matching the Kotlin's `(principal, c)`.
	IsDeactivated func(ctx context.Context, principal string, c store.Queryer) (bool, error)

	// Mint is `tokenStore.issue(SESSION, fresh.principal, emptyList(), name = null, ttlSeconds =
	// fresh.ttlSeconds, c)` (DaemonSession.kt:656).
	//
	// 🔒 FOUR THINGS ABOUT IT ARE CONTRACT, and a wiring that gets any of them wrong compiles:
	//
	//  1. the kind is SESSION — a renewed credential must pass `validate`, so it cannot be one of the
	//     two ephemeral kinds (INV-A4-56);
	//  2. the roles snapshot is EMPTY — same as every other mint (INV-A4-2), effective roles are
	//     re-resolved at decide time;
	//  3. the TTL comes from `fresh.TTLSeconds`, the FRESH row read under the lock, never from the
	//     pre-lock row the route resolved by hash (INV-A4-31);
	//  4. it runs on `c`, the locked transaction, so a concurrent teardown taking the same
	//     per-principal advisory lock cannot slip between the checks and the INSERT.
	Mint func(ctx context.Context, fresh DaemonRow, c store.Queryer) (Minted, error)

	// Log defaults to slog.Default().
	Log *slog.Logger
}

// NewRenewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRenewRoutes(
	st *Store,
	isDeactivated func(ctx context.Context, principal string, c store.Queryer) (bool, error),
	mint func(ctx context.Context, fresh DaemonRow, c store.Queryer) (Minted, error),
	log *slog.Logger,
) *RenewRoutes {
	if log == nil {
		log = slog.Default()
	}
	return &RenewRoutes{Store: st, IsDeactivated: isDeactivated, Mint: mint, Log: log}
}

// Register mounts the single pattern.
//
// It satisfies httpapi.RouteGroup structurally; the interface is not named here because
// internal/httpapi imports THIS package, so referencing it would be an import cycle. internal/device
// has the same shape for the same reason.
func (rt *RenewRoutes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/session/renew", rt.renew)
}

func (rt *RenewRoutes) log() *slog.Logger {
	if rt.Log != nil {
		return rt.Log
	}
	return slog.Default()
}

// renew is `POST /auth/session/renew` — 200 [RenewSessionResponse], or one of three 401s.
//
//  1. no `Authorization`, or it does not start with `Bearer ` ⇒ 401 auth.missing_renewal_token
//  2. `getByRenewalTokenHash(sha256Hex(secret))` finds nothing ⇒ 401 common.unauthenticated
//  3. [RenewLocked] returns nil ⇒ 401 auth.session_window_expired
//  4. otherwise 200 with the fresh token and its expiry
//
// ⚠️ Step 1's prefix test is CASE-SENSITIVE (`removePrefix("Bearer ")`), so `bearer pmr_…` falls into
// the missing-token branch even though RFC 7235 declares the scheme case-insensitive. The same
// exact-case quirk lives in the SCIM gate and is reproduced there too; A5's `bearerWirePrincipal` is
// case-INsensitive, and that inconsistency is real and reproduced on all three.
//
// ⚠️ Ktor's `headers["Authorization"]` is null for an ABSENT header; Go's Header.Get is "" for both
// absent and present-empty. Both take branch 1 either way, so the collapse is behaviour-preserving.
//
// 🔒 STEP 3 COLLAPSES FOUR DISTINCT REFUSALS INTO ONE CODE, and that is the fail-closed design rather
// than lost information: the row vanished, the absolute window closed, the principal was
// deprovisioned, or liveness went INACTIVE. [RenewLocked] returns a bare nil for all four so this
// route CANNOT accidentally tell a bearer-holder which one applied — and so the four re-checks stay
// re-checks rather than becoming a status API. INV-A4-31: every one of them re-runs UNDER the lock
// against a FRESH read; the row resolved at step 2 is only an identifier carrier and none of its
// field values are trusted.
//
// 🔒 STEP 2's 401 IS `common.unauthenticated`, NOT `auth.missing_renewal_token`. A wrong secret and
// an absent one are DIFFERENT codes — reproduced verbatim (DaemonSession.kt:642 vs :648). Neither
// leaks anything (both are 401 with no principal in them), and `pmon` distinguishes "you sent
// nothing" from "what you sent is not a credential I know".
func (rt *RenewRoutes) renew(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusUnauthorized, Body: types.ApiError{Code: CodeMissingRenewalToken},
		})
		return
	}
	// `authHeader.removePrefix("Bearer ").trim()`. The trim is what makes `Bearer  pmr_…` work.
	secret := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

	row, err := rt.Store.GetByRenewalTokenHash(r.Context(), SHA256Hex(secret))
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if row == nil {
		rt.respondError(w, types.Unauthenticated())
		return
	}

	issued, err := RenewLocked(r.Context(), rt.Store, *row, rt.IsDeactivated, rt.Mint)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if issued == nil {
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusUnauthorized, Body: types.ApiError{Code: CodeSessionWindowExpired},
		})
		return
	}
	rt.respond(w, r, http.StatusOK, RenewSessionResponse{Token: issued.Token, ExpiresAt: issued.ExpiresAt})
}

// ---------------------------------------------------------------------------------------------

// respond writes through types.MarshalWire rather than encoding/json, because kotlinx does not
// HTML-escape and INV-A1-4 requires `[]`-for-empty and omit-for-absent. internal/httpapi.RespondJSON
// does exactly this, and is unreachable from here — httpapi imports this package. internal/device
// carries the same three-line local copy for the same reason.
func (rt *RenewRoutes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	payload, err := types.MarshalWire(body)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		rt.log().Error("failed to write renew response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *RenewRoutes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := e.Respond(w); err != nil {
		rt.log().Error("failed to write renew error response", "code", e.Body.Code, "err", err)
	}
}

// fallback is App.kt's StatusPages `exception<Throwable>` arm: 500 `common.fallback`, and the detail
// stays in the log rather than on the wire (INV-A1-13). httpapi.RespondFallback is the shared one and
// is unreachable from this package for the same import-cycle reason as [RenewRoutes.respond].
func (rt *RenewRoutes) fallback(w http.ResponseWriter, r *http.Request, cause error) {
	rt.log().Error("unhandled error", "path", r.URL.Path, "err", cause)
	if err := types.Fallback().Respond(w); err != nil {
		rt.log().Error("failed to write fallback response", "err", err)
	}
}
