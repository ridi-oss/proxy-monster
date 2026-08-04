package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// `Deprovision.kt` — the shared teardown primitives (03-identity-scim.md §"Deprovision.kt").
//
// `advisoryLockPrincipal` and `inTx` already live in internal/store (every area consumes them, and
// store/doc.go says so). What lands HERE is the pair the Kotlin declares in this file and nowhere
// else: `revokeActiveCredentials` and its composable core `revokeActiveCredentialsTx`.
//
// `mintForActivePrincipalLocked` is currently hosted in internal/token with a
// `TODO(A3): relocate … when Deprovision.kt lands` (token.go:19). It is NOT moved here in this
// change: A4 owns every one of its call sites, moving it would edit a sibling package's public API
// mid-flight, and the symbol is behaviourally complete where it is. Recorded, not silently left.
//
//	TODO(A3/A4): relocate token.MintForActivePrincipalLocked into this file, together with A4's call
//	             sites, as one deliberate move.
// ---------------------------------------------------------------------------------------------

// EndedDeactivated is `ENDED_DEACTIVATED = "DEACTIVATED"` (DaemonSession.kt:56, A4) — the
// `ended_reason` a deprovision writes onto every web session it closes.
//
// It is an ALIAS of A4's constant rather than a second literal. Two literals would compile, agree
// today, and drift the moment one side is renamed — and the value is read back by
// session.WireReason to decide what the console is told, so a drift would silently change what a
// deprovisioned browser sees.
const EndedDeactivated = session.EndedDeactivated

// TokenRevoker is A4's `TokenStore.revokeAllForPrincipal(principal, c)` — wire tokens.
type TokenRevoker interface {
	RevokeAllForPrincipal(ctx context.Context, c store.Queryer, principal string) (int64, error)
}

// GrantRevoker is A6's `AccessStore.revokeAllForPrincipal(principal, c)` — JIT access grants.
type GrantRevoker interface {
	RevokeAllForPrincipalOn(ctx context.Context, c store.Queryer, principal string) (int64, error)
}

// SessionRevoker is A4's `PrincipalSessionStore` half — daemon renewal windows and web sessions.
type SessionRevoker interface {
	DeactivateAllForPrincipal(ctx context.Context, c store.Queryer, principal string) (int64, error)
	EndAllWebForPrincipal(ctx context.Context, c store.Queryer, principal, reason string) (int64, error)
}

// CredentialTeardown is the ONE method the six principal-mutating writes need. Every write in
// usergroupwrites.go and scimstore.go takes it as an explicit parameter, exactly as the Kotlin
// threads `tokenStore, accessStore, daemonSessionStore` through every one of them — the parameter is
// the reminder that a directory write without a teardown is the bug INV-A3-6 exists to prevent.
//
// It is deliberately the same method set as management.Credentials, so [Credentials] satisfies both
// without either package importing the other's interface.
type CredentialTeardown interface {
	RevokeActiveCredentialsOn(ctx context.Context, c store.Queryer, principal string) (int64, error)
}

// Credentials is the concrete teardown over the three real stores.
//
// The Kotlin passes the three stores individually to every call site and pulls the DataSource out of
// `tokenStore` "purely as a connection source; every store passed here uses the same pooled
// DataSource" — an assumption 03-identity-scim.md:352 says a Go port must preserve or make explicit.
// MADE EXPLICIT: db is its own field, so the "they all share one pool" assumption is a wiring fact
// the composition root states rather than something inferred from one of the three stores.
type Credentials struct {
	db       store.Beginner
	tokens   TokenRevoker
	grants   GrantRevoker
	sessions SessionRevoker
}

// NewCredentials wires the teardown. The three stores are narrow interfaces so this package does not
// import internal/token, internal/access or internal/session for three method references.
func NewCredentials(db store.Beginner, tokens TokenRevoker, grants GrantRevoker, sessions SessionRevoker) *Credentials {
	return &Credentials{db: db, tokens: tokens, grants: grants, sessions: sessions}
}

var _ CredentialTeardown = (*Credentials)(nil)

// RevokeActiveCredentials is
// `fun revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore): Int`
// (Deprovision.kt:57).
//
// Kills EVERY currently-active credential for principal, immediately, in ONE committed transaction;
// returns the total revoked, for logging. The Kotlin is one line — `tokenStore.dataSource.inTx { c ->
// revokeActiveCredentialsTx(...) }` — and so is this.
func (c *Credentials) RevokeActiveCredentials(ctx context.Context, principal string) (int64, error) {
	return store.InTx(ctx, c.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		return c.RevokeActiveCredentialsOn(ctx, tx, principal)
	})
}

// RevokeActiveCredentialsOn is
// `fun revokeActiveCredentialsTx(principal, c, tokenStore, accessStore, daemonSessionStore): Int`
// (Deprovision.kt:70) — the composable core, on a caller-supplied handle, so a directory mutation and
// its credential teardown commit TOGETHER.
//
// 🔒 INV-A3-3 — the advisory lock is taken HERE, by this function, "so direct callers cannot forget
// the serialization boundary". It is idempotent and re-entrant when the caller already holds it
// (every principal-mutating write does, via lockCurrentPrincipal or releaseTombstone), so composing
// callers cannot self-deadlock.
//
// 🔒 INV-A3-5 — ALL FOUR CREDENTIAL CLASSES, OR NONE, and in this order. The Kotlin names the reason
// for each: closing daemon windows "makes deprovisioning durable: even a later reactivation cannot
// reuse an old renewal secret", and ending web rows "invalidates existing browser cookies
// immediately". A port that revokes tokens and grants but leaves the daemon window open re-creates a
// resurrection bug — reactivating the principal later would revive a live renewal secret.
//
// 🔒 INV-A3-6 — the revoke commits in the SAME transaction as the directory write, never as a
// follow-up: "a separate follow-up a crash could skip, leaving a principal
// inactive-but-still-credentialed (a later reactivation would then resurrect the live token/renewal
// secret)". That is why every mutating store method takes a [CredentialTeardown] rather than the
// routes calling revoke afterwards.
//
// The return value is the exact sum, and it is asserted: DeprovisionDbTest case 4 pins 6.
func (c *Credentials) RevokeActiveCredentialsOn(
	ctx context.Context, q store.Queryer, principal string,
) (int64, error) {
	if err := store.AdvisoryLockPrincipal(ctx, q, principal); err != nil {
		return 0, err
	}
	tokens, err := c.tokens.RevokeAllForPrincipal(ctx, q, principal)
	if err != nil {
		return 0, err
	}
	grants, err := c.grants.RevokeAllForPrincipalOn(ctx, q, principal)
	if err != nil {
		return 0, err
	}
	windows, err := c.sessions.DeactivateAllForPrincipal(ctx, q, principal)
	if err != nil {
		return 0, err
	}
	web, err := c.sessions.EndAllWebForPrincipal(ctx, q, principal, EndedDeactivated)
	if err != nil {
		return 0, err
	}
	return tokens + grants + windows + web, nil
}

// revoke is the call every write in this package makes. It exists only to keep the nil check in one
// place: the Kotlin's parameters are non-null, but a Go caller (a store-level test that is not about
// teardown, or a partially-wired composition root) can pass nil, and a nil-panic inside a transaction
// is a worse failure than the no-op the Kotlin cannot express.
//
// ⚠️ A nil teardown means a directory write commits with NO credential revoke — INV-A3-6's failure
// mode exactly. Production wiring must never pass nil; internal/app passes the real [Credentials].
func revoke(ctx context.Context, creds CredentialTeardown, c store.Queryer, principal string) error {
	if creds == nil {
		return nil
	}
	_, err := creds.RevokeActiveCredentialsOn(ctx, c, principal)
	return err
}
