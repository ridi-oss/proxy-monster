package oidc

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// The IdP liveness sweep — `sweepSessionLiveness` / `revalidateSession` (DaemonSession.kt:667-756).
//
// 🔒 THIS IS THE SOLE REVALIDATOR of a web or daemon session against the IdP, and its absence is a
// security hole rather than a missing feature: without it a principal deprovisioned at the IdP —
// removed from the admin group, refresh token revoked, account disabled — keeps a live proxy-monster
// session until it expires on its own clock. Everything else in A4 enforces windows; this is the only
// thing that observes the outside world.
//
// The three-way outcome is the whole design (INV-A4-39). Only a DEFINITIVE IdP rejection may revoke;
// a transient failure must preserve last-known-good AND leave `last_idp_check_at` unstamped so the
// next tick retries immediately instead of waiting a full interval. A sweep that treated a 503 as a
// rejection would log every user out of a healthy deployment the moment the IdP hiccuped.
// ---------------------------------------------------------------------------------------------

// LivenessSessions is the slice of A4's `PrincipalSessionStore` this sweep touches, and nothing else
// — the same narrow-seam convention the rest of seams.go follows. *session.Store satisfies it
// directly; the nil Queryer arguments are its "use the pool" form.
type LivenessSessions interface {
	// StaleSessions is every live WEB or DAEMON row whose cached check is older than the interval.
	StaleSessions(ctx context.Context, recheckIntervalSeconds int64) ([]session.LivenessCandidate, error)
	// DecryptRefresh returns nil (no error) for a row that stored no refresh token.
	DecryptRefresh(enc []byte) (*string, error)
	// UpdateRefresh persists a rotated refresh token.
	UpdateRefresh(ctx context.Context, id int64, refreshToken string) error
	// MarkCheck stamps `last_idp_check_at` and the liveness status.
	MarkCheck(ctx context.Context, c store.Queryer, id int64, status string) error
	// EndWeb retires one web row with a reason.
	EndWeb(ctx context.Context, c store.Queryer, id int64, reason string) (bool, error)
	// EndAllWebForPrincipal retires EVERY live web row for a principal.
	EndAllWebForPrincipal(ctx context.Context, c store.Queryer, principal, reason string) (int64, error)
	// CloseDaemonWindow closes a daemon row's renewal window without touching its credentials.
	CloseDaemonWindow(ctx context.Context, id int64) (int64, error)
}

// LivenessDeps is the argument bundle of Kotlin's eight-parameter `sweepSessionLiveness`. A struct
// rather than a parameter list because six of the eight are nilable seams and a positional call of
// that shape is unreadable at the composition root.
type LivenessDeps struct {
	// RecheckIntervalSeconds is `config.idpRecheckIntervalSeconds`. Config guarantees it is positive.
	RecheckIntervalSeconds int64
	// OIDC is `config.oidc`. Nil disables the sweep entirely.
	OIDC *OIDCSettings
	// Discovery is nil when the IdP document has never resolved; also disables the sweep.
	Discovery *Discovery
	// Validator may be nil, which makes every id_token fail to validate — fail-closed, and the arm
	// below returns WITHOUT stamping a check.
	Validator *IDTokenValidator
	HTTP      *http.Client
	Sessions  LivenessSessions
	Groups    UserGroupProvisioner
	Roles     RoleResolver
	Log       *slog.Logger
}

// OIDCSettings is the subset of `config.oidc` the sweep needs. Declared here rather than importing
// internal/config so this package keeps depending only on seams it names.
type OIDCSettings struct {
	ClientID     string
	ClientSecret string
	GroupMapping GroupMapping
}

// SweepSessionLiveness is `suspend fun sweepSessionLiveness(...)` (DaemonSession.kt:675-691).
//
// One timer-driven pass over every stale live session. Each row's fate is decided by its OWN refresh
// token, and 🔒 EACH ROW IS ISOLATED: the Kotlin's `runCatching { … }.onFailure { log.warn }` means
// one row that panics or errors must not abort the pass, or a single poisoned session would freeze
// revalidation for the entire deployment. That per-row recover is reproduced literally.
//
// The IdP round-trip always completes before any DB write for that row; nothing here holds a lock
// across the network call.
func SweepSessionLiveness(ctx context.Context, d LivenessDeps) {
	if d.OIDC == nil || d.Discovery == nil {
		return
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	rows, err := d.Sessions.StaleSessions(ctx, d.RecheckIntervalSeconds)
	if err != nil {
		// Kotlin's `for (row in sessionStore.staleSessions(...))` would throw out of the whole sweep
		// and be caught by App.kt's own runCatching around the call. Same net effect: log and stop.
		log.Warn("IdP liveness sweep could not read stale sessions", "err", err)
		return
	}
	for _, row := range rows {
		revalidateOne(ctx, d, row, log)
	}
}

// revalidateOne is one iteration of the sweep's loop, including the Kotlin's per-row runCatching. The
// recover covers a panic from any seam; an error return is logged the same way.
func revalidateOne(ctx context.Context, d LivenessDeps, row session.LivenessCandidate, log *slog.Logger) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("IdP liveness sweep failed",
				"principal", row.Principal, "session", row.ID, "panic", r)
		}
	}()
	if err := revalidateSession(ctx, d, row, log); err != nil {
		log.Warn("IdP liveness sweep failed",
			"principal", row.Principal, "session", row.ID, "err", err)
	}
}

// revalidateSession is `private suspend fun revalidateSession(...)` (DaemonSession.kt:698-756).
//
// 🔒 FOUR ORDERINGS ARE LOAD-BEARING and are called out individually below. Three of them are the ones
// refresh.go's TODO(A4) named as "must not be lost".
func revalidateSession(ctx context.Context, d LivenessDeps, row session.LivenessCandidate, log *slog.Logger) error {
	refreshToken, err := d.Sessions.DecryptRefresh(row.RefreshTokenEnc)
	if err != nil {
		return err
	}
	// 🔒 ORDERING 1 — a row with NO stored refresh token is left completely alone: no status change and
	// NO `markCheck`. It is not evidence of anything, so stamping it would silently convert "never
	// checked" into "checked and ACTIVE" and suppress the next tick's attempt.
	if refreshToken == nil {
		log.Debug("no refresh token to revalidate liveness",
			"principal", row.Principal, "session", row.ID)
		return nil
	}

	doc, err := d.Discovery.Document(ctx)
	if err != nil {
		return err
	}

	outcome := RefreshGrant(ctx, d.HTTP, doc.TokenEndpoint, d.OIDC.ClientID, d.OIDC.ClientSecret, *refreshToken)
	switch outcome.Kind {
	case RefreshActive:
		return activeArm(ctx, d, row, outcome, log)

	case RefreshInactive:
		// 🔒 THE ONLY REVOKING ARM. A definitive IdP rejection retires ONLY this row — the Kotlin is
		// explicit that "a rejected refresh token retires only its own session".
		log.Warn("IdP rejected refresh token",
			"principal", row.Principal, "session", row.ID, "reason", outcome.Reason)
		switch row.Kind {
		case "WEB":
			_, err := d.Sessions.EndWeb(ctx, nil, row.ID, session.EndedIdpRejected)
			return err
		case "DAEMON":
			// The daemon's renewal WINDOW closes; its credentials are deliberately left intact, and
			// each daemon query re-resolves roles and fail-closes on its own.
			_, err := d.Sessions.CloseDaemonWindow(ctx, row.ID)
			return err
		default:
			log.Warn("ignoring unknown principal session kind", "kind", row.Kind, "session", row.ID)
			return nil
		}

	default: // RefreshTransient
		// 🔒 NOTHING HAPPENS, and that is the whole point (INV-A4-39). No status change, and crucially
		// no `markCheck` — leaving `last_idp_check_at` stale means the NEXT tick retries this row
		// rather than treating an IdP outage as a fresh clean bill of health for a full interval.
		log.Warn("IdP liveness check transiently failed",
			"principal", row.Principal, "session", row.ID, "reason", outcome.Reason)
		return nil
	}
}

// activeArm is the `is RefreshOutcome.Active ->` branch. Split out because its four steps each have an
// ordering constraint and reading them against the Kotlin side by side matters more than brevity.
func activeArm(
	ctx context.Context, d LivenessDeps, row session.LivenessCandidate, outcome RefreshOutcome, log *slog.Logger,
) error {
	// 🔒 ORDERING 2 — THE ROTATED TOKEN IS PERSISTED FIRST, before the id_token is even validated. A
	// rotating IdP invalidates the OLD refresh token the instant it issues the new one, so any path
	// that returns early after this point without having stored the rotation would leave the row
	// holding a token the IdP has already retired — and every subsequent sweep would then read that
	// dead token, get `invalid_grant`, and revoke a perfectly live session. Persist-then-validate is
	// what makes the early returns below safe.
	if outcome.RotatedRefreshToken != nil {
		if err := d.Sessions.UpdateRefresh(ctx, row.ID, *outcome.RotatedRefreshToken); err != nil {
			return err
		}
	}

	// A nil Validator makes this nil, exactly as Kotlin's `validator?.validate(...)` does.
	var claims *ValidatedIDToken
	if outcome.IDToken != nil && d.Validator != nil {
		claims = d.Validator.Validate(ctx, *outcome.IDToken, nil)
	}
	if claims == nil {
		// No check is stamped: an unverifiable response is not evidence the account is live.
		log.Warn("IdP liveness check returned no valid id_token",
			"principal", row.Principal, "session", row.ID)
		return nil
	}

	// `claims.email ?: claims.subject`.
	refreshedPrincipal := claims.Subject
	if claims.Email != nil {
		refreshedPrincipal = *claims.Email
	}
	// 🔒 ORDERING 3 — THE IDENTITY COMPARISON PRECEDES PROVISIONING. If the refresh grant came back
	// describing a DIFFERENT principal, provisioning first would write that other identity's IdP groups
	// onto this row's principal — an account takeover through a group sync. Bail before touching
	// membership, and again without stamping a check.
	if refreshedPrincipal != row.Principal {
		log.Warn("IdP liveness identity mismatch",
			"principal", row.Principal, "session", row.ID, "got", refreshedPrincipal)
		return nil
	}

	if err := d.Groups.ProvisionFromOidc(ctx, row.Principal, claims.Email, claims.Groups, d.OIDC.GroupMapping); err != nil {
		return err
	}

	roles, err := d.Roles.Resolve(ctx, row.Principal)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		// 🔒 PRINCIPAL-GLOBAL, NOT ROW-LOCAL, and deliberately asymmetric with the Inactive arm above.
		// Reconciliation dropped this principal to zero effective roles, which is a fact about the
		// PRINCIPAL rather than about one refresh token, so every live web session for them ends
		// regardless of which kind produced this candidate. Daemon rows stay open on purpose: each
		// daemon query re-resolves roles and fail-closes on its own.
		if _, err := d.Sessions.EndAllWebForPrincipal(ctx, nil, row.Principal, session.EndedGroupRevoked); err != nil {
			return err
		}
	}

	// 🔒 ORDERING 4 — `markCheck` IS LAST, and only on a fully successful revalidation. Every early
	// return above skips it, so `last_idp_check_at` advances only when the IdP actually confirmed this
	// identity. Stamping earlier would mean a half-failed check bought the session a full interval of
	// immunity from the next sweep.
	return d.Sessions.MarkCheck(ctx, nil, row.ID, session.LivenessActive)
}
