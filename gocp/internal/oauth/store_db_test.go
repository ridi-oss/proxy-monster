package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// McpOAuthStoreDbTest.kt — all SIX cases, ported, plus the pins 14-auth.md §9 marks REPRODUCE + PIN
// and the Kotlin suite never wrote (F32/INV-A14-16 and F33).
//
// ORACLE: McpOAuthStoreDbTest.kt:45-185 for the six, and 14-auth.md §5 for everything else. Each
// ported case keeps the Kotlin's assertion messages verbatim where it had them, so a failure here
// reads the same as a failure there.
//
// The store is REAL over a migrated Postgres. Nothing here is faked: every claim these cases make is
// about what a SQL predicate did, and a fake store would prove only that a method was called.
// ---------------------------------------------------------------------------------------------

// The Kotlin companion object (`:208-215`).
const (
	storeClientID    = "https://client.example/mcp.json"
	storeRedirectURI = "http://127.0.0.1:43110/callback"
	storeResource    = "https://proxy.example/mcp"
)

var (
	storeScopes    = []string{"mcp:read", "mcp:policies:write"}
	storeVerifier  = strings.Repeat("a", 43)
	storeChallenge = PKCES256(storeVerifier)
)

type storeFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *store.Db
	store  *AuthorizationStore
	tokens *MCPTokenStore
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &storeFixture{
		t: t, ctx: t.Context(), db: db,
		store:  NewAuthorizationStore(db.Pool),
		tokens: NewMCPTokenStore(db.Pool),
	}
}

// consume is the Kotlin helper `consume(code, resource, verifier)` (`:198-202`).
func (f *storeFixture) consume(code string, opts ...func(*ConsumeAuthorizationCodeInput)) *TokenPair {
	f.t.Helper()
	in := ConsumeAuthorizationCodeInput{
		Code: code, ClientID: storeClientID, RedirectURI: storeRedirectURI, Resource: storeResource,
		CodeVerifier: storeVerifier, AccessTTLSeconds: 600, RefreshTTLSeconds: 3_600,
	}
	for _, o := range opts {
		o(&in)
	}
	pair, err := f.store.ConsumeAuthorizationCode(f.ctx, in)
	if err != nil {
		f.t.Fatalf("ConsumeAuthorizationCode: %v", err)
	}
	return pair
}

// refresh is the Kotlin helper `refresh(token)` (`:204`).
func (f *storeFixture) refresh(token string) *TokenPair {
	f.t.Helper()
	pair, err := f.store.RotateRefresh(f.ctx, RefreshTokenInput{
		RefreshToken: token, ClientID: storeClientID, Resource: storeResource,
		AccessTTLSeconds: 600, RefreshTTLSeconds: 3_600,
	})
	if err != nil {
		f.t.Fatalf("RotateRefresh: %v", err)
	}
	return pair
}

// issue is the Kotlin helper `issue(principal, consentId)` (`:187-196`).
func (f *storeFixture) issue(principal string, consentID ...int64) *TokenPair {
	f.t.Helper()
	var id int64
	if len(consentID) > 0 {
		id = consentID[0]
	} else {
		id = f.rememberConsent(principal).ID
	}
	code := f.createCode(principal, id)
	pair := f.consume(code)
	if pair == nil {
		f.t.Fatal("issue: the exchange must succeed")
	}
	return pair
}

func (f *storeFixture) rememberConsent(principal string) *Consent {
	f.t.Helper()
	c, err := f.store.RememberConsent(f.ctx, principal, storeClientID, storeResource, storeScopes)
	if err != nil {
		f.t.Fatalf("RememberConsent: %v", err)
	}
	return c
}

func (f *storeFixture) createCode(principal string, consentID int64) string {
	f.t.Helper()
	code, err := f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
		ClientID: storeClientID, Principal: principal, RedirectURI: storeRedirectURI,
		Resource: storeResource, Scopes: storeScopes, CodeChallenge: storeChallenge, ConsentID: consentID,
	})
	if err != nil {
		f.t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	return code
}

func (f *storeFixture) resolveAccess(token string, resource ...string) *AccessIdentity {
	f.t.Helper()
	want := storeResource
	if len(resource) > 0 {
		want = resource[0]
	}
	id, err := f.tokens.ResolveAccess(f.ctx, token, want)
	if err != nil {
		f.t.Fatalf("ResolveAccess: %v", err)
	}
	return id
}

// ---- Case 1 -------------------------------------------------------------------------------------

// `authorization code is one-time PKCE-bound and access tokens are audience-bound` (`:45-78`).
//
// 🔒 INV-A14-9 (audience binding is a WHERE clause), INV-A14-15 (single use is the conditional
// UPDATE), INV-A14-6 (the plaintext is never stored) and INV-A14-25 (roles = '[]') in one case,
// exactly as the Kotlin has them.
// KT: McpOAuthStoreDbTest.kt#authorization code is one-time PKCE-bound and access tokens are audience-bound
func TestAuthorizationCodeIsOneTimePKCEBoundAndAccessTokensAreAudienceBound(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "oauth-audience@example.com"
	consent := f.rememberConsent(principal)
	code := f.createCode(principal, consent.ID)

	// `:56` — INV-A11-18 at the store: a resource mismatch is a null pair, not an error.
	if pair := f.consume(code, func(in *ConsumeAuthorizationCodeInput) {
		in.Resource = storeResource + "/wrong"
	}); pair != nil {
		t.Fatal("a resource mismatch must not exchange")
	}
	// `:57` — a structurally VALID but WRONG verifier, so this pins the hash comparison. (14-auth.md
	// §9's correction: it does NOT reach isValidPkceVerifier's reject path.)
	if pair := f.consume(code, func(in *ConsumeAuthorizationCodeInput) {
		in.CodeVerifier = strings.Repeat("b", 43)
	}); pair != nil {
		t.Fatal("a wrong verifier must not exchange")
	}
	pair := f.consume(code)
	if pair == nil {
		t.Fatal("the correct exchange must succeed")
	}
	// 🔒 The two failed attempts above did NOT burn the code — the burn happens only after every
	// check passes. This ordering is what makes a mistyped verifier recoverable.
	if again := f.consume(code); again != nil {
		t.Fatal("an authorization code must be single-use")
	}

	identity := f.resolveAccess(pair.AccessToken)
	if identity == nil {
		t.Fatal("the freshly minted access token must resolve")
	}
	if identity.Principal != principal {
		t.Errorf("principal = %q, want %q", identity.Principal, principal)
	}
	if identity.ClientID != storeClientID {
		t.Errorf("clientId = %q, want %q", identity.ClientID, storeClientID)
	}
	if got := CanonicalScopes(identity.Scopes); got != CanonicalScopes(storeScopes) {
		t.Errorf("scopes = %q, want %q", identity.Scopes, storeScopes)
	}
	if identity.ConsentID != consent.ID {
		t.Errorf("consentId = %d, want %d", identity.ConsentID, consent.ID)
	}
	// 🔒 INV-A14-9, `:66` — the SAME token against a DIFFERENT resource resolves to nothing.
	if f.resolveAccess(pair.AccessToken, storeResource+"/wrong") != nil {
		t.Error("an access token must not resolve against another resource")
	}

	// 🔒 INV-A14-6 / INV-A14-25, `:68-77`.
	var tokenHash, roles string
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT token_hash, roles::text FROM proxy_token WHERE kind='MCP_ACCESS' AND principal=$1`,
		principal).Scan(&tokenHash, &roles)
	if err != nil {
		t.Fatalf("read the stored token row: %v", err)
	}
	if strings.Contains(tokenHash, pair.AccessToken) {
		t.Error("the plaintext token must never be stored")
	}
	if tokenHash != SHA256Hex(pair.AccessToken) {
		t.Error("the stored hash must be sha256Hex of the plaintext")
	}
	if roles != "[]" {
		t.Errorf("roles = %q, want [] — an MCP token carries no role snapshot", roles)
	}
}

// ---- Case 2 -------------------------------------------------------------------------------------

// `refresh rotates once and replay revokes the complete token family` (`:80-90`).
//
// 🔒 INV-A14-17 — the security core of the area. The last assertion is the one that makes it a
// FAMILY revocation rather than a single-token one: after the replay, the SUCCESSOR refresh token is
// dead too.
// KT: McpOAuthStoreDbTest.kt#refresh rotates once and replay revokes the complete token family
func TestRefreshRotatesOnceAndReplayRevokesTheCompleteTokenFamily(t *testing.T) {
	f := newStoreFixture(t)
	first := f.issue("oauth-rotation@example.com")
	second := f.refresh(first.RefreshToken)
	if second == nil {
		t.Fatal("the first rotation must succeed")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("a rotation must mint a NEW refresh token")
	}
	if f.resolveAccess(second.AccessToken) == nil {
		t.Fatal("the rotated access token must resolve")
	}

	if f.refresh(first.RefreshToken) != nil {
		t.Fatal("a rotated refresh token is replay, not a second rotation")
	}
	if f.resolveAccess(first.AccessToken) != nil {
		t.Error("the replayed family's original access token must be revoked")
	}
	if f.resolveAccess(second.AccessToken) != nil {
		t.Error("the replayed family's successor access token must be revoked")
	}
	if f.refresh(second.RefreshToken) != nil {
		t.Error("replay must revoke the new refresh token too")
	}
}

// ---- Case 3 -------------------------------------------------------------------------------------

// `revoked consent blocks code exchange and revokes access plus refresh` (`:92-109`).
//
// 🔒 INV-A14-21 — all three effects at once, plus the idempotence of a second revoke.
// KT: McpOAuthStoreDbTest.kt#revoked consent blocks code exchange and revokes access plus refresh
func TestRevokedConsentBlocksCodeExchangeAndRevokesAccessPlusRefresh(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "oauth-consent@example.com"
	consent := f.rememberConsent(principal)
	code := f.createCode(principal, consent.ID)
	active := f.issue(principal, consent.ID)

	revoked, err := f.store.RevokeConsent(f.ctx, consent.ID, principal)
	if err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !revoked {
		t.Fatal("the first revoke must report true")
	}
	again, err := f.store.RevokeConsent(f.ctx, consent.ID, principal)
	if err != nil {
		t.Fatalf("RevokeConsent (second): %v", err)
	}
	if again {
		t.Error("a second revoke is idempotent and must report false")
	}

	if f.consume(code) != nil {
		t.Error("an outstanding code must be unredeemable once its consent is revoked")
	}
	if f.resolveAccess(active.AccessToken) != nil {
		t.Error("the cascade must kill the live access token")
	}
	if f.refresh(active.RefreshToken) != nil {
		t.Error("the cascade must kill the refresh token")
	}
}

// 🔒 INV-A14-19 — the ownership check is a SQL predicate, so IDOR is impossible even if a route
// forgets. NEW: the Kotlin case above only ever revokes as the owner.
func TestRevokeConsentRefusesAnotherPrincipalsConsentID(t *testing.T) {
	f := newStoreFixture(t)
	owner := f.rememberConsent("consent-owner@example.com")

	revoked, err := f.store.RevokeConsent(f.ctx, owner.ID, "attacker@example.com")
	if err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if revoked {
		t.Fatal("another principal's consent id must revoke nothing")
	}
	// And the row is untouched, so the owner can still use it.
	found, err := f.store.FindActiveConsent(f.ctx, "consent-owner@example.com", storeClientID, storeResource, storeScopes)
	if err != nil {
		t.Fatalf("FindActiveConsent: %v", err)
	}
	if found == nil || found.ID != owner.ID {
		t.Error("the owner's consent must still be active after a foreign revoke attempt")
	}
}

// ---- Case 4 -------------------------------------------------------------------------------------

// `RFC 7009 access revocation is local while refresh revocation closes the family` (`:111-122`).
//
// 🔒 INV-A14-24 — the asymmetry IS the behaviour. Revoking an access token must NOT log the client
// out; revoking a refresh token must end the whole grant.
// KT: McpOAuthStoreDbTest.kt#RFC 7009 access revocation is local while refresh revocation closes the family
func TestRFC7009AccessRevocationIsLocalWhileRefreshRevocationClosesTheFamily(t *testing.T) {
	f := newStoreFixture(t)
	accessOnly := f.issue("oauth-revoke-access@example.com")

	if err := f.store.Revoke(f.ctx, accessOnly.AccessToken); err != nil {
		t.Fatalf("Revoke(access): %v", err)
	}
	if f.resolveAccess(accessOnly.AccessToken) != nil {
		t.Error("a revoked access token must not resolve")
	}
	afterAccessRevoke := f.refresh(accessOnly.RefreshToken)
	if afterAccessRevoke == nil {
		t.Fatal("revoking an ACCESS token must leave the refresh grant alive")
	}
	if f.resolveAccess(afterAccessRevoke.AccessToken) == nil {
		t.Fatal("the re-minted access token must resolve")
	}

	if err := f.store.Revoke(f.ctx, afterAccessRevoke.RefreshToken); err != nil {
		t.Fatalf("Revoke(refresh): %v", err)
	}
	if f.resolveAccess(afterAccessRevoke.AccessToken) != nil {
		t.Error("revoking the REFRESH token must close its whole family, access included")
	}
	if f.refresh(afterAccessRevoke.RefreshToken) != nil {
		t.Error("a revoked refresh token must not rotate")
	}
}

// 🔒 INV-A14-22 / INV-A14-23 — the containment boundary and the silent success. NEW: the Kotlin never
// hands `revoke` a non-MCP token, and `/oauth/revoke` is UNAUTHENTICATED, so this is the test that
// stops a future `else` branch from turning that endpoint into a way to destroy a daemon SESSION.
func TestRevokeRefusesANonMCPKindAndIsSilentForAnUnknownToken(t *testing.T) {
	f := newStoreFixture(t)

	// An unknown token: no row, no error, no oracle.
	if err := f.store.Revoke(f.ctx, "pma_this-token-never-existed"); err != nil {
		t.Fatalf("an unknown token must be a silent success, got %v", err)
	}

	// A SESSION token — A4's kind, in the same table. Inserted directly, because internal/token is a
	// sibling package and this test is about what THIS store refuses to touch.
	const sessionToken = "pms_a-daemon-session-token"
	_, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at)
		     VALUES ($1, 'SESSION', 'daemon@example.com', '[]'::jsonb, now() + interval '1 hour')`,
		SHA256Hex(sessionToken))
	if err != nil {
		t.Fatalf("seed a SESSION token: %v", err)
	}
	if err := f.store.Revoke(f.ctx, sessionToken); err != nil {
		t.Fatalf("Revoke(SESSION): %v", err)
	}
	var revokedAt *time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at FROM proxy_token WHERE token_hash = $1`, SHA256Hex(sessionToken),
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read the SESSION row: %v", err)
	}
	if revokedAt != nil {
		t.Error("INV-A14-22: /oauth/revoke must not be able to destroy a daemon SESSION token")
	}
}

// ---- Case 5 -------------------------------------------------------------------------------------

// `authorization codes cannot borrow a mismatched or revoked consent` (`:124-144`).
//
// 🔒 INV-A14-15a — both halves: the OWNERSHIP check (a caller cannot bind a code to someone else's
// consent id) and the LIVENESS check, each surfacing as the Kotlin's IllegalArgumentException.
// KT: McpOAuthStoreDbTest.kt#authorization codes cannot borrow a mismatched or revoked consent
func TestAuthorizationCodesCannotBorrowAMismatchedOrRevokedConsent(t *testing.T) {
	f := newStoreFixture(t)
	const owner = "consent-owner@example.com"
	consent := f.rememberConsent(owner)

	_, err := f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
		ClientID: storeClientID, Principal: "different-principal@example.com",
		RedirectURI: storeRedirectURI, Resource: storeResource, Scopes: storeScopes,
		CodeChallenge: storeChallenge, ConsentID: consent.ID,
	})
	if err == nil {
		t.Fatal("a mismatched principal must be refused")
	}
	if err != ErrConsentMismatch { //nolint:errorlint // the store returns the sentinel unwrapped
		t.Errorf("want ErrConsentMismatch, got %v", err)
	}

	revoked, err := f.store.RevokeConsent(f.ctx, consent.ID, owner)
	if err != nil || !revoked {
		t.Fatalf("RevokeConsent: %v (revoked=%v)", err, revoked)
	}
	_, err = f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
		ClientID: storeClientID, Principal: owner, RedirectURI: storeRedirectURI,
		Resource: storeResource, Scopes: storeScopes, CodeChallenge: storeChallenge, ConsentID: consent.ID,
	})
	if err == nil {
		t.Fatal("a revoked consent must be refused")
	}
}

// 🔒 INV-A14-14 — PKCE is mandatory AT THE STORE, not only at the route. NEW: the Kotlin suite never
// hands the store a bad challenge, so nothing pinned the store's own layer.
func TestCreateAuthorizationCodeRejectsABadPKCEChallengeBeforeTouchingTheDatabase(t *testing.T) {
	f := newStoreFixture(t)
	consent := f.rememberConsent("pkce-store@example.com")

	_, err := f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
		ClientID: storeClientID, Principal: "pkce-store@example.com", RedirectURI: storeRedirectURI,
		Resource: storeResource, Scopes: storeScopes,
		CodeChallenge: strings.Repeat("a", 42), // 42, not 43
		ConsentID:     consent.ID,
	})
	if err != ErrInvalidPKCEChallenge { //nolint:errorlint // sentinel, returned unwrapped
		t.Fatalf("want ErrInvalidPKCEChallenge, got %v", err)
	}
	// And nothing was written — the guard is the FIRST statement, before the prune and the insert.
	var codes int
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM oauth_authorization_code`).Scan(&codes); err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if codes != 0 {
		t.Errorf("a rejected challenge must write nothing, found %d rows", codes)
	}
}

// ---- Case 6 -------------------------------------------------------------------------------------

// `issuing a code prunes expired and already-used authorization codes` (`:146-185`).
//
// The prune is the table's ONLY sweeper — A1's background purge loop does not cover it — so issuance
// traffic is what keeps it bounded. Both branches of `expires_at <= now() OR used_at IS NOT NULL` are
// seeded, because a port that dropped the `OR` half would still pass a test that only seeded expiry.
// KT: McpOAuthStoreDbTest.kt#issuing a code prunes expired and already-used authorization codes
func TestIssuingACodePrunesExpiredAndAlreadyUsedAuthorizationCodes(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "oauth-pruning@example.com"
	consent := f.rememberConsent(principal)
	canonical := CanonicalScopes(storeScopes)

	_, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO oauth_authorization_code
		     (code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge,
		      consent_id, expires_at, used_at)
		   VALUES ('expired-code', $1, $2, $3, $4, $5, $6, $7, now() - interval '1 minute', NULL),
		          ('used-code',    $1, $2, $3, $4, $5, $6, $7, now() + interval '1 minute', now())`,
		storeClientID, principal, storeRedirectURI, storeResource, canonical, storeChallenge, consent.ID)
	if err != nil {
		t.Fatalf("seed the prunable codes: %v", err)
	}

	f.createCode(principal, consent.ID)

	var remaining int
	err = f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM oauth_authorization_code WHERE code_hash IN ('expired-code', 'used-code')`,
	).Scan(&remaining)
	if err != nil {
		t.Fatalf("count the prunable codes: %v", err)
	}
	if remaining != 0 {
		t.Errorf("both prunable codes must be gone, %d remain", remaining)
	}
	// …and the fresh one survived, so the sweeper is not simply deleting everything.
	var live int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM oauth_authorization_code WHERE used_at IS NULL AND expires_at > now()`,
	).Scan(&live); err != nil {
		t.Fatalf("count live codes: %v", err)
	}
	if live != 1 {
		t.Errorf("the freshly issued code must survive its own prune, found %d live", live)
	}
}

// ---- The pins the Kotlin suite does not have ----------------------------------------------------

// ⚠️ 🔒 F33 (index F23) — REPRODUCE + PIN. In `rotateRefresh` the client/resource mismatch check
// PRECEDES the rotated-replay check, so replaying a stolen ROTATED token with a WRONG `client_id`
// returns a plain nil and does NOT revoke the family: the breach-detection alarm is side-steppable.
//
// The test is a differential, which is the only way to state the finding: the SAME replayed token
// revokes the family when presented with the right client_id and does NOT when presented with the
// wrong one. A single-armed test would pass against a fixed implementation too.
//
// If this test ever fails because the family IS revoked, the ordering was changed — which is the
// right fix, and it must be a deliberate, separately reviewed one.
func TestF33AReplayWithTheWrongClientIDSkipsFamilyRevocation(t *testing.T) {
	f := newStoreFixture(t)

	// Arm A: replay with the WRONG client_id.
	wrongClient := f.issue("f33-wrong-client@example.com")
	successorA := f.refresh(wrongClient.RefreshToken)
	if successorA == nil {
		t.Fatal("setup: the rotation must succeed")
	}
	replayed, err := f.store.RotateRefresh(f.ctx, RefreshTokenInput{
		RefreshToken:     wrongClient.RefreshToken, // already rotated ⇒ replay
		ClientID:         "https://attacker.example/other.json",
		Resource:         storeResource,
		AccessTTLSeconds: 600, RefreshTTLSeconds: 3_600,
	})
	if err != nil {
		t.Fatalf("RotateRefresh: %v", err)
	}
	if replayed != nil {
		t.Fatal("a replay must never mint a pair, whatever client_id it carries")
	}
	// 🔒 THE FINDING: the family survived. The legitimate holder's successor still works, and no
	// alarm fired.
	if f.resolveAccess(successorA.AccessToken) == nil {
		t.Error("F33: the family was revoked — the ordering changed, so re-review this deliberately")
	}
	if f.refresh(successorA.RefreshToken) == nil {
		t.Error("F33: the successor refresh died — the ordering changed, so re-review this deliberately")
	}

	// Arm B: the SAME replay with the RIGHT client_id DOES revoke the family. This is the control
	// that proves arm A is about the ORDERING and not about replay detection being broken outright.
	rightClient := f.issue("f33-right-client@example.com")
	successorB := f.refresh(rightClient.RefreshToken)
	if successorB == nil {
		t.Fatal("setup: the rotation must succeed")
	}
	if f.refresh(rightClient.RefreshToken) != nil {
		t.Fatal("a replay must not mint a pair")
	}
	if f.resolveAccess(successorB.AccessToken) != nil {
		t.Error("with the right client_id the whole family must die — INV-A14-17")
	}
}

// ⚠️ 🔒 F32 / INV-A14-16 (index F28) — REPRODUCE + PIN. TWO CLOCKS DECIDE EXPIRY ON ONE COLUMN:
// `ResolveAccess` reads Postgres `now()` and `insertToken` computes `expires_at` in SQL, but
// `RotateRefresh` compares against the APPLICATION clock. Under skew, an EXPIRED refresh token
// rotates successfully, or a LIVE one is refused.
//
// The pin is deterministic rather than timing-based: [AuthorizationStore.Now] is moved, and the
// database clock is left alone. Both directions are asserted, because each is a different production
// failure — one grants past expiry, the other refuses before it.
func TestF32TheRefreshGrantUsesTheApplicationClockNotThePostgresOne(t *testing.T) {
	f := newStoreFixture(t)

	t.Run("an app clock AHEAD of the database refuses a token the database still considers live", func(t *testing.T) {
		pair := f.issue("f32-ahead@example.com")
		// The access token proves the row is live BY THE DATABASE CLOCK.
		if f.resolveAccess(pair.AccessToken) == nil {
			t.Fatal("setup: the pair must be live")
		}
		f.store.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
		defer func() { f.store.Now = nil }()

		if f.refresh(pair.RefreshToken) != nil {
			t.Error("F32: the refresh grant read the DATABASE clock — the two-clock divergence is gone")
		}
		// …and the database still thinks the row is live, which is the whole point.
		var live bool
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT expires_at > now() FROM proxy_token WHERE token_hash = $1`,
			SHA256Hex(pair.RefreshToken)).Scan(&live); err != nil {
			t.Fatalf("read expires_at: %v", err)
		}
		if !live {
			t.Fatal("premise broken: the row really did expire, so the skew was not what refused it")
		}
	})

	t.Run("an app clock BEHIND the database rotates a token the database considers expired", func(t *testing.T) {
		const principal = "f32-behind@example.com"
		pair := f.issue(principal)
		// Age the row out by the DATABASE clock, leaving the application clock where it is.
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE proxy_token SET expires_at = now() - interval '1 hour' WHERE token_hash = $1`,
			SHA256Hex(pair.RefreshToken)); err != nil {
			t.Fatalf("age the refresh row: %v", err)
		}
		// A database-clock reader now refuses it…
		var live bool
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT expires_at > now() FROM proxy_token WHERE token_hash = $1`,
			SHA256Hex(pair.RefreshToken)).Scan(&live); err != nil {
			t.Fatalf("read expires_at: %v", err)
		}
		if live {
			t.Fatal("setup: the row should be expired by the database clock")
		}
		// …but with the application clock rolled back behind it, the rotation SUCCEEDS.
		f.store.Now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
		defer func() { f.store.Now = nil }()

		if rotated := f.refresh(pair.RefreshToken); rotated == nil {
			t.Error("F32: an expired refresh token was refused — the grant now reads the database clock")
		}
	})
}

// 🔒 INV-A14-10 — the JOIN re-verifies the FULL consent tuple. A token whose denormalized copy has
// DRIFTED from its consent must fail closed, which is the only thing that makes the five-column join
// more than redundancy.
//
// NEW: nothing in the Kotlin suite drifts a row, so the invariant was asserted nowhere.
func TestADriftedTokenTupleFailsClosedAgainstItsConsent(t *testing.T) {
	f := newStoreFixture(t)
	pair := f.issue("drift@example.com")
	if f.resolveAccess(pair.AccessToken) == nil {
		t.Fatal("setup: the token must resolve")
	}

	// Drift ONE of the five join columns on the token side. The FK is untouched, so a port that
	// joined only on `c.id = t.consent_id` would still authorize this.
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE proxy_token SET scope = 'mcp:read' WHERE token_hash = $1`,
		SHA256Hex(pair.AccessToken)); err != nil {
		t.Fatalf("drift the scope: %v", err)
	}
	if f.resolveAccess(pair.AccessToken) != nil {
		t.Error("INV-A14-10: a token whose tuple drifted from its consent must fail closed")
	}
}

// 🔒 INV-A14-10b — the SIXTH predicate, `c.revoked_at IS NULL`, is not belt-and-braces. It is the only
// thing that stops a token inserted AFTER a revoke's cascade from being live for its full TTL.
//
// The interleaving is simulated by revoking the consent and then inserting a token row directly — the
// state a ConsumeAuthorizationCode transaction that commits after the cascade leaves behind. A port
// that "optimized" the join down to the foreign key would authorize this row.
func TestATokenInsertedPastARevokeCascadeIsStillRefused(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "cascade-race@example.com"
	consent := f.rememberConsent(principal)

	revoked, err := f.store.RevokeConsent(f.ctx, consent.ID, principal)
	if err != nil || !revoked {
		t.Fatalf("RevokeConsent: %v (revoked=%v)", err, revoked)
	}

	// The row the cascade already ran past: live, unexpired, unrevoked, pointing at a revoked consent.
	const orphan = "pma_committed-after-the-cascade"
	_, err = f.db.Pool.Exec(f.ctx,
		`INSERT INTO proxy_token
		     (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id)
		   VALUES ($1, 'MCP_ACCESS', $2, '[]'::jsonb, now() + interval '10 minutes', $3, $4, $5, 'pmf_orphan', $6)`,
		SHA256Hex(orphan), principal, storeResource, storeClientID, CanonicalScopes(storeScopes), consent.ID)
	if err != nil {
		t.Fatalf("insert the orphan token: %v", err)
	}
	// It really is unrevoked on its own row — so only the consent's revoked_at can be what refuses it.
	var tokenRevoked *time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at FROM proxy_token WHERE token_hash = $1`, SHA256Hex(orphan)).Scan(&tokenRevoked); err != nil {
		t.Fatalf("read the orphan row: %v", err)
	}
	if tokenRevoked != nil {
		t.Fatal("premise broken: the orphan row is itself revoked, so this proves nothing")
	}

	if f.resolveAccess(orphan) != nil {
		t.Error("INV-A14-10b: a live token under a REVOKED consent must not resolve")
	}
}

// 🔒 INV-A14-18 — the partial unique index makes re-consent IDEMPOTENT while live and NON-blocking
// once revoked, and the `DO UPDATE` set-list deliberately leaves `created_at` alone.
func TestRememberConsentIsIdempotentWhileLiveAndPreservesTheFirstGrantTimestamp(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "consent-upsert@example.com"

	first := f.rememberConsent(principal)
	// A re-consent in the OTHER scope order must land on the SAME row — that is CanonicalScopes doing
	// its job as a join key.
	second, err := f.store.RememberConsent(f.ctx, principal, storeClientID, storeResource,
		[]string{"mcp:policies:write", "mcp:read"})
	if err != nil {
		t.Fatalf("RememberConsent: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("re-consent must be idempotent: got id %d, want %d", second.ID, first.ID)
	}
	if second.CreatedAt != first.CreatedAt {
		t.Errorf("createdAt must keep the FIRST grant's timestamp: %q then %q", first.CreatedAt, second.CreatedAt)
	}
	if second.UpdatedAt == first.UpdatedAt {
		t.Error("updatedAt must move on a re-consent")
	}

	// After a revoke, the same tuple creates a NEW row and leaves the revoked one in place — an audit
	// reader can still see a consent that once existed.
	if ok, err := f.store.RevokeConsent(f.ctx, first.ID, principal); err != nil || !ok {
		t.Fatalf("RevokeConsent: %v (%v)", err, ok)
	}
	third := f.rememberConsent(principal)
	if third.ID == first.ID {
		t.Error("a revoked row must not block, and must not be reused")
	}
	var rows int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM oauth_consent WHERE principal = $1`, principal).Scan(&rows); err != nil {
		t.Fatalf("count consents: %v", err)
	}
	if rows != 2 {
		t.Errorf("the revoked row must survive for audit: found %d rows, want 2", rows)
	}
}

// F34 — `listConsents` filters to LIVE rows and orders by `updated_at DESC` with NO TIEBREAKER. The
// ordering is asserted only where it is DETERMINED (distinct timestamps), because asserting a tie's
// order would pin behaviour the Kotlin does not define.
func TestListConsentsReturnsOnlyLiveRowsNewestUpdatedFirst(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "consent-list@example.com"

	older, err := f.store.RememberConsent(f.ctx, principal, storeClientID, storeResource, []string{"mcp:read"})
	if err != nil {
		t.Fatalf("RememberConsent: %v", err)
	}
	newer, err := f.store.RememberConsent(f.ctx, principal, storeClientID+"?2", storeResource, []string{"mcp:read"})
	if err != nil {
		t.Fatalf("RememberConsent: %v", err)
	}
	// Separate the two timestamps explicitly rather than relying on clock resolution.
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE oauth_consent SET updated_at = now() - interval '1 hour' WHERE id = $1`, older.ID); err != nil {
		t.Fatalf("age the older consent: %v", err)
	}

	list, err := f.store.ListConsents(f.ctx, principal)
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 2 || list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Fatalf("want [%d %d] newest-updated first, got %+v", newer.ID, older.ID, list)
	}

	if ok, err := f.store.RevokeConsent(f.ctx, older.ID, principal); err != nil || !ok {
		t.Fatalf("RevokeConsent: %v (%v)", err, ok)
	}
	list, err = f.store.ListConsents(f.ctx, principal)
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 1 || list[0].ID != newer.ID {
		t.Errorf("a revoked consent must not be listed, got %+v", list)
	}

	// 🔒 INV-A1-4 — a principal with nothing must produce `[]`, never nil, or the console's
	// `consents.map` throws.
	empty, err := f.store.ListConsents(f.ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if empty == nil {
		t.Error("ListConsents must return a non-nil empty slice")
	}
}

// 🔒 A `return@inTransaction null` COMMITS — the property 14-auth.md calls out as the one a Go port
// using `defer tx.Rollback()` would invert, reintroducing the replayable-code bug.
//
// The observable consequence: `used_at` is stamped BEFORE the consent re-check, so a code that fails
// that check is BURNT and cannot be retried after the consent comes back. Asserted directly on the
// column, because "the exchange returned nil" is true under both the correct and the inverted
// implementation.
func TestAFailedExchangeStillCommitsTheBurntCode(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "burnt-code@example.com"
	consent := f.rememberConsent(principal)
	code := f.createCode(principal, consent.ID)

	if ok, err := f.store.RevokeConsent(f.ctx, consent.ID, principal); err != nil || !ok {
		t.Fatalf("RevokeConsent: %v (%v)", err, ok)
	}
	if f.consume(code) != nil {
		t.Fatal("the exchange must fail once the consent is revoked")
	}

	var usedAt *time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT used_at FROM oauth_authorization_code WHERE code_hash = $1`, SHA256Hex(code),
	).Scan(&usedAt); err != nil {
		t.Fatalf("read used_at: %v", err)
	}
	if usedAt == nil {
		t.Fatal("INV-A14-15b: the code must stay BURNT after a failed exchange — the transaction commits")
	}

	// And re-granting the consent does not make the code redeemable again.
	fresh := f.rememberConsent(principal)
	if fresh.ID == consent.ID {
		t.Fatal("setup: the re-grant should be a new consent row")
	}
	if f.consume(code) != nil {
		t.Error("a burnt code must not survive a consent revoke/re-grant cycle")
	}
}

// 🔒 INV-A14-20 — `COALESCE(revoked_at, now())` preserves the FIRST revocation timestamp. All three
// call sites must keep it; this pins the family one, which is the one a re-triggered replay would
// otherwise rewrite on every attempt.
func TestRevokeFamilyPreservesTheFirstRevocationTimestamp(t *testing.T) {
	f := newStoreFixture(t)
	pair := f.issue("coalesce@example.com")
	if f.refresh(pair.RefreshToken) == nil {
		t.Fatal("setup: the rotation must succeed")
	}
	// First replay — revokes the family and stamps revoked_at.
	if f.refresh(pair.RefreshToken) != nil {
		t.Fatal("setup: the replay must be refused")
	}
	var first time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at FROM proxy_token WHERE token_hash = $1`, SHA256Hex(pair.AccessToken),
	).Scan(&first); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}

	// Second replay — the family is already dead, and the timestamp must NOT move.
	if f.refresh(pair.RefreshToken) != nil {
		t.Fatal("the second replay must also be refused")
	}
	var second time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at FROM proxy_token WHERE token_hash = $1`, SHA256Hex(pair.AccessToken),
	).Scan(&second); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if !second.Equal(first) {
		t.Errorf("INV-A14-20: revoked_at moved from %s to %s — the COALESCE was dropped", first, second)
	}
}

// 🔒 INV-A14-8's read side — the refresh grant rejects ON KIND, so an MCP ACCESS token cannot be
// presented to it. Without the kind gate, the access token of a live pair would rotate a new family.
func TestTheRefreshGrantRejectsAnAccessTokenOnKind(t *testing.T) {
	f := newStoreFixture(t)
	pair := f.issue("kind-gate@example.com")
	if f.refresh(pair.AccessToken) != nil {
		t.Error("an MCP_ACCESS token must not be accepted by the refresh grant")
	}
	// The access token is still live — the rejected attempt wrote nothing.
	if f.resolveAccess(pair.AccessToken) == nil {
		t.Error("a rejected refresh attempt must not have revoked anything")
	}
}

// F25 — the authorization-code TTL is `coerceIn(60, 600)`, NOT ClampTTLSeconds' [60, 86400], and the
// Kotlin default argument is 300. The pointer field is what keeps "omitted" and "explicitly zero"
// distinguishable; this asserts all three points of the window land where the Kotlin puts them.
func TestAuthorizationCodeTTLUsesItsOwnTighterWindow(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "code-ttl@example.com"
	consent := f.rememberConsent(principal)

	ttl := func(in *AuthorizationCodeInput) {}
	_ = ttl
	cases := []struct {
		name    string
		ttl     *int64
		wantSec float64
	}{
		{"omitted takes the Kotlin default of 300", nil, 300},
		{"an explicit 0 floors to 60, NOT to 300", int64Ptr(0), 60},
		{"1 floors to 60", int64Ptr(1), 60},
		{"600 is the ceiling", int64Ptr(600), 600},
		{"86400 clamps to 600, not to ClampTTLSeconds' 86400", int64Ptr(86_400), 600},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, err := f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
				ClientID: storeClientID, Principal: principal, RedirectURI: storeRedirectURI,
				Resource: storeResource, Scopes: storeScopes, CodeChallenge: storeChallenge,
				TTLSeconds: c.ttl, ConsentID: consent.ID,
			})
			if err != nil {
				t.Fatalf("CreateAuthorizationCode: %v", err)
			}
			var seconds float64
			if err := f.db.Pool.QueryRow(f.ctx,
				`SELECT extract(epoch FROM (expires_at - now())) FROM oauth_authorization_code WHERE code_hash = $1`,
				SHA256Hex(code)).Scan(&seconds); err != nil {
				t.Fatalf("read expires_at: %v", err)
			}
			// A couple of seconds of slack: `now()` is transaction-start time on the INSERT and
			// statement time on the read.
			if seconds < c.wantSec-5 || seconds > c.wantSec+1 {
				t.Errorf("code TTL = %.1fs, want ~%.0fs", seconds, c.wantSec)
			}
		})
	}
}

func int64Ptr(v int64) *int64 { return &v }

// 🔒 INV-A14-2 — the clamp is applied TWICE for one issuance, and the two sites are consumed by
// different parties. A refresh TTL above the 24h cap is silently capped in the DATABASE, and the
// `expiresIn` the CLIENT is told is clamped independently.
func TestIssuanceClampsBothTheStoredExpiryAndTheReportedExpiresIn(t *testing.T) {
	f := newStoreFixture(t)
	const principal = "clamp-both@example.com"
	consent := f.rememberConsent(principal)
	code := f.createCode(principal, consent.ID)

	pair, err := f.store.ConsumeAuthorizationCode(f.ctx, ConsumeAuthorizationCodeInput{
		Code: code, ClientID: storeClientID, RedirectURI: storeRedirectURI, Resource: storeResource,
		CodeVerifier: storeVerifier,
		// Both above the 24h cap — the operational trap 14-auth.md flags for PM_OAUTH_REFRESH_TTL.
		AccessTTLSeconds: 7 * 86_400, RefreshTTLSeconds: 7 * 86_400,
	})
	if err != nil {
		t.Fatalf("ConsumeAuthorizationCode: %v", err)
	}
	if pair == nil {
		t.Fatal("the exchange must succeed")
	}
	if pair.ExpiresIn != TokenMaxTTLSeconds {
		t.Errorf("expiresIn = %d, want the 86400 cap", pair.ExpiresIn)
	}
	for _, tok := range []struct {
		name  string
		value string
	}{{"access", pair.AccessToken}, {"refresh", pair.RefreshToken}} {
		var seconds float64
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT extract(epoch FROM (expires_at - now())) FROM proxy_token WHERE token_hash = $1`,
			SHA256Hex(tok.value)).Scan(&seconds); err != nil {
			t.Fatalf("read %s expires_at: %v", tok.name, err)
		}
		if seconds > float64(TokenMaxTTLSeconds)+1 {
			t.Errorf("%s expires_at is %.0fs out, want the 86400 cap", tok.name, seconds)
		}
	}
}

// The rotation lineage: `rotated_from` is recorded ONLY on the refresh row, and the family id is
// carried forward unchanged. Deliberate, per 14-auth.md §5, and invisible from the wire — so a test
// on the columns is the only way it stays true.
func TestRotationLineageIsRecordedOnTheRefreshRowOnly(t *testing.T) {
	f := newStoreFixture(t)
	first := f.issue("lineage@example.com")
	second := f.refresh(first.RefreshToken)
	if second == nil {
		t.Fatal("setup: the rotation must succeed")
	}

	var firstRefreshID int64
	var family string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT id, refresh_family FROM proxy_token WHERE token_hash = $1`,
		SHA256Hex(first.RefreshToken)).Scan(&firstRefreshID, &family); err != nil {
		t.Fatalf("read the predecessor: %v", err)
	}
	var newRefreshFrom *int64
	var newFamily string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT rotated_from, refresh_family FROM proxy_token WHERE token_hash = $1`,
		SHA256Hex(second.RefreshToken)).Scan(&newRefreshFrom, &newFamily); err != nil {
		t.Fatalf("read the successor refresh: %v", err)
	}
	if newRefreshFrom == nil || *newRefreshFrom != firstRefreshID {
		t.Errorf("the successor refresh must record its predecessor, got %v want %d", newRefreshFrom, firstRefreshID)
	}
	if newFamily != family {
		t.Errorf("a rotation keeps the SAME family: %q then %q", family, newFamily)
	}

	var newAccessFrom *int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT rotated_from FROM proxy_token WHERE token_hash = $1`,
		SHA256Hex(second.AccessToken)).Scan(&newAccessFrom); err != nil {
		t.Fatalf("read the successor access: %v", err)
	}
	if newAccessFrom != nil {
		t.Error("rotated_from is recorded ONLY on the refresh row")
	}

	// ⚠️ And the predecessor's ACCESS token is still live after a normal rotation — deliberate, and
	// the reason access TTLs are short.
	if f.resolveAccess(first.AccessToken) == nil {
		t.Error("a normal rotation must NOT revoke the predecessor's access token")
	}
}
