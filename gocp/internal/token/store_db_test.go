package token_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ---------------------------------------------------------------------------------------------
// The DB half of A4 §3.8 (`Tokens.kt`): the list/get/revoke lifecycle, plus the two REPRODUCE + PIN
// findings the port carries deliberately — F27 (Get has no kind filter) and F26 (the TTL ladder is
// not total).
//
// Every case runs against a fresh migrated database from internal/dbtest.
// ---------------------------------------------------------------------------------------------

type fixture struct {
	t     testing.TB
	ctx   context.Context
	db    *store.Db
	store *token.Store
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &fixture{t: t, ctx: context.Background(), db: db, store: token.NewStore(db.Pool)}
}

// issue mints through the PRODUCTION store on the pool (the autocommit overload), fataling on error.
func (f *fixture) issue(kind token.Kind, principal string, roles []string, name *string, ttl int64) token.Issued {
	f.t.Helper()
	out, err := f.store.Issue(f.ctx, f.db.Pool, kind, principal, roles, name, ttl)
	if err != nil {
		f.t.Fatalf("Issue(%s, %s): %v", kind, principal, err)
	}
	return out
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

const (
	owner  = "owner@example.com"
	other  = "other@example.com"
	oneDay = int64(3600)
)

// ---------------------------------------------------------------------------------------------
// issue / list / get / revoke
// ---------------------------------------------------------------------------------------------

// TestIssueReturnsInstantFormattedExpiry pins the DTO contract: `IssuedToken.expiresAt` is
// `Instant.toString()`, NOT Postgres's `::text` rendering of the column.
//
// The two differ in the date/time separator, the zone suffix and the fraction rule, so a port that
// scanned the column as text would put `2026-08-02 03:04:05.123456+00` on a wire that has only ever
// carried `2026-08-02T03:04:05.123456Z`. Nothing in the Kotlin suite asserts this because Kotlin gets
// it for free from `getTimestamp(...).toInstant().toString()`; the Go port has to choose, so the
// choice is asserted.
func TestIssueReturnsInstantFormattedExpiry(t *testing.T) {
	f := newFixture(t)
	got := f.issue(token.KindUser, owner, []string{"analyst"}, ptr("laptop"), oneDay)

	if !strings.HasSuffix(got.ExpiresAt, "Z") || !strings.Contains(got.ExpiresAt, "T") {
		t.Errorf("expiresAt = %q, want java.time.Instant.toString() form (…T…Z)", got.ExpiresAt)
	}
	if strings.Contains(got.ExpiresAt, " ") || strings.Contains(got.ExpiresAt, "+00") {
		t.Errorf("expiresAt = %q — that is Postgres ::text, not Instant.toString()", got.ExpiresAt)
	}
	if got.Kind != string(token.KindUser) {
		t.Errorf("IssuedToken.kind = %q, want USER", got.Kind)
	}
	if got.Name == nil || *got.Name != "laptop" {
		t.Errorf("IssuedToken.name = %v, want laptop", got.Name)
	}
	if !strings.HasPrefix(got.Token, "pmk_") {
		t.Errorf("USER token %q lacks the pmk_ prefix", got.Token)
	}
}

// TestListRestrictsToTheTwoManagedKinds is `list(principal)`'s
// `AND kind IN ('SESSION','USER')` — "excluding transient editor-channel credentials", and
// implicitly excluding the MCP kinds.
//
// The ORDER is `created_at DESC` and is asserted, because it is wire-observable in the console's
// token table and an unordered port would turn every differential-conformance run into noise.
func TestListRestrictsToTheTwoManagedKinds(t *testing.T) {
	f := newFixture(t)
	session := f.issue(token.KindSession, owner, nil, nil, oneDay)
	user := f.issue(token.KindUser, owner, nil, ptr("cli"), oneDay)
	editor := f.issue(token.KindEditor, owner, nil, nil, oneDay)
	approver := f.issue(token.KindApproverExec, owner, nil, nil, oneDay)
	// Another principal's token must never appear in this principal's list.
	f.issue(token.KindUser, other, nil, nil, oneDay)

	got, err := f.store.List(f.ctx, owner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d rows, want 2 (SESSION + USER only); got %+v", len(got), got)
	}
	// created_at DESC: the USER token was inserted second, so it comes first.
	if got[0].ID != user.ID || got[1].ID != session.ID {
		t.Errorf("List order = [%d %d], want [%d %d] (created_at DESC)",
			got[0].ID, got[1].ID, user.ID, session.ID)
	}
	for _, info := range got {
		if info.Kind == string(token.KindEditor) || info.Kind == string(token.KindApproverExec) {
			t.Errorf("List surfaced a transient %s credential (ids %d/%d must stay hidden)",
				info.Kind, editor.ID, approver.ID)
		}
		if info.Principal != owner {
			t.Errorf("List returned a row for %q", info.Principal)
		}
	}
	// INV-A1-4: an empty list is `[]`, never nil/null.
	empty, err := f.store.List(f.ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("List(nobody): %v", err)
	}
	if empty == nil {
		t.Error("List returned nil for a principal with no tokens; INV-A1-4 requires an empty slice")
	}
}

// 🔒 TestGetHasNoKindFilter is the REPRODUCE + PIN for F27 (task brief) = A4-F21
// (04-auth-session-tokens.md §5, `Tokens.kt:216,324`).
//
// `TokenStore.get(id)` has NO kind filter while `list` restricts to ('SESSION','USER'). Because
// `DELETE /api/tokens/{id}` loads the row through `get` BEFORE authorizing (INV-A4-5), the route can
// target a kind the caller could never have listed — including the two MCP kinds, for which
// `TokenKind.fromWire` returns null and the Cedar resource is therefore built with `kind` ABSENT,
// which per A2 INV-A2-3 is the PERMISSIVE direction for a kind-scoped forbid.
//
// 🔴 This test asserts the BUGGY behaviour on purpose. A later fix — adding
// `AND kind IN ('SESSION','USER')` to Get — must change these assertions deliberately and visibly
// rather than silently start passing.
func TestGetHasNoKindFilter(t *testing.T) {
	f := newFixture(t)
	editor := f.issue(token.KindEditor, owner, nil, nil, oneDay)

	// An MCP_ACCESS row, inserted directly: A4's Issue binds only the non-MCP columns, and V7's
	// `proxy_token_mcp_metadata_ck` requires the full resource/client/scope/family/consent set for
	// the MCP kinds. That constraint is exactly why A4 code cannot mint one — and exactly why this
	// row proves the reachability claim rather than a hypothetical.
	var consentID int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO oauth_consent (principal, client_id, resource, scope)
		     VALUES ($1, 'cli-1', 'https://pm.example/mcp', 'read') RETURNING id`, owner).Scan(&consentID); err != nil {
		t.Fatalf("seed oauth_consent: %v", err)
	}
	var mcpID int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO proxy_token (token_hash, kind, principal, roles, resource, client_id, scope,
		         refresh_family, consent_id, expires_at)
		     VALUES ($1, 'MCP_ACCESS', $2, '[]'::jsonb, 'https://pm.example/mcp', 'cli-1', 'read',
		             'fam-1', $3, now() + interval '1 hour')
		   RETURNING id`, "mcp-hash", owner, consentID).Scan(&mcpID); err != nil {
		t.Fatalf("seed MCP_ACCESS token: %v", err)
	}

	// Neither kind is listable...
	listed, err := f.store.List(f.ctx, owner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("List returned %d rows, want 0 — neither EDITOR nor MCP_ACCESS is listable", len(listed))
	}

	// ...but BOTH are reachable through Get. This is the finding.
	for _, tc := range []struct {
		name, wantKind string
		id             int64
	}{
		{"an ephemeral editor credential", "EDITOR", editor.ID},
		{"an MCP access token", "MCP_ACCESS", mcpID},
	} {
		got, err := f.store.Get(f.ctx, tc.id)
		if err != nil {
			t.Fatalf("Get(%d): %v", tc.id, err)
		}
		if got == nil {
			t.Fatalf("F27 REGRESSION: Get(%d) returned nothing for %s. If a kind filter was just "+
				"added to Get, that is a BEHAVIOUR FIX — it changes DELETE /api/tokens/{id} from 204 "+
				"to 404 on a security path. Take it as a separate decision and update this test "+
				"deliberately (00-INDEX.md PORT POLICY).", tc.id, tc.name)
		}
		if got.Kind != tc.wantKind {
			t.Errorf("Get(%d).kind = %q, want %q", tc.id, got.Kind, tc.wantKind)
		}
	}

	// And the second half of the finding: fromWire returns ok=false for the MCP kinds, so the route
	// builds its Cedar resource with `kind` ABSENT — the permissive case under A2 INV-A2-3.
	if _, ok := token.KindFromWire("MCP_ACCESS"); ok {
		t.Error("KindFromWire recognized MCP_ACCESS; the Kotlin enum has exactly four members and " +
			"the absent-kind Cedar resource is half of F27")
	}
}

// 🔒 TestRevokeEnforcesOwnershipAndIsIdempotent — `revoke(id, principal)`.
//
// Ownership is still enforced even under F27's cross-kind hole: `AND principal = ?` is a real second
// check, so the hole is cross-KIND, not cross-USER. A second revoke returns false, which the route
// maps to 404.
func TestRevokeEnforcesOwnershipAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(token.KindUser, owner, nil, nil, oneDay)

	// The wrong principal cannot revoke it, even with the right id.
	revoked, err := f.store.Revoke(f.ctx, tok.ID, other)
	if err != nil {
		t.Fatalf("Revoke(wrong principal): %v", err)
	}
	if revoked {
		t.Fatal("a token was revoked by a principal that does not own it")
	}
	if id, err := f.store.Resolve(f.ctx, tok.Token); err != nil || id == nil {
		t.Fatalf("the token must still resolve after a failed cross-user revoke: %v, %v", id, err)
	}

	if revoked, err = f.store.Revoke(f.ctx, tok.ID, owner); err != nil || !revoked {
		t.Fatalf("Revoke(owner) = %v, %v; want true", revoked, err)
	}
	if id, err := f.store.Resolve(f.ctx, tok.Token); err != nil || id != nil {
		t.Fatalf("a revoked token still resolves: %v, %v", id, err)
	}
	// Idempotent: the second revoke is a 404 at the route, not a second write.
	if revoked, err = f.store.Revoke(f.ctx, tok.ID, owner); err != nil || revoked {
		t.Fatalf("second Revoke = %v, %v; want false (idempotent → 404)", revoked, err)
	}
	// And the DTO now carries revokedAt, which was absent before.
	info, err := f.store.Get(f.ctx, tok.ID)
	if err != nil || info == nil {
		t.Fatalf("Get after revoke: %v, %v", info, err)
	}
	if info.RevokedAt == nil {
		t.Error("WireTokenInfo.revokedAt is absent on a revoked row")
	}
	if info.LastUsedAt != nil {
		t.Errorf("lastUsedAt = %v on a token that was only ever resolved; only validate() stamps it",
			*info.LastUsedAt)
	}
}

// 🔒 TestRevokeAllForPrincipalKillsLiveCredentialsOfEveryKind pins INV-A4-57.
//
// It is the deprovisioning backstop: a SCIM `active=false` push or a failed IdP liveness recheck
// kills live credentials mid-window rather than waiting for natural expiry. Three properties:
//
//  1. EVERY kind is revoked, including MCP_ACCESS/MCP_REFRESH — the one place A4 code touches them.
//  2. Already-EXPIRED rows are untouched, so the count means "how many LIVE credentials did this
//     deprovision actually kill".
//  3. Another principal's tokens are untouched.
//
// KT: DeprovisionDbTest.kt#revokeAllForPrincipal revokes every active token for that principal only
// KT: DeprovisionDbTest.kt#revokeAllForPrincipal is a no-op on an already-revoked or expired token — properties 2 and the second sweep
func TestRevokeAllForPrincipalKillsLiveCredentialsOfEveryKind(t *testing.T) {
	f := newFixture(t)
	// The Kotlin's t1/t2 (`revokeAllForPrincipal revokes every active token for that principal only`,
	// DeprovisionDbTest.kt:68-76) are held so the revocation is asserted ON THE ROWS, not only through
	// the count: it asserts `get(t1)!!.revokedAt` and `get(t2)!!.revokedAt` are non-null.
	t1 := f.issue(token.KindSession, owner, nil, nil, oneDay)
	t2 := f.issue(token.KindUser, owner, nil, nil, oneDay)
	f.issue(token.KindEditor, owner, nil, nil, oneDay)
	f.issue(token.KindApproverExec, owner, nil, nil, oneDay)
	survivor := f.issue(token.KindUser, other, nil, nil, oneDay)

	// One already-expired row for the same principal: backdate it past its own expiry.
	expired := f.issue(token.KindUser, owner, nil, nil, oneDay)
	f.exec(`UPDATE proxy_token SET expires_at = now() - interval '1 minute' WHERE id = $1`, expired.ID)

	// An MCP row, which A4's Issue cannot mint (V7's CHECK) but which a deprovision must still kill.
	var consentID int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO oauth_consent (principal, client_id, resource, scope)
		     VALUES ($1, 'cli-1', 'https://pm.example/mcp', 'read') RETURNING id`, owner).Scan(&consentID); err != nil {
		t.Fatalf("seed oauth_consent: %v", err)
	}
	f.exec(`INSERT INTO proxy_token (token_hash, kind, principal, roles, resource, client_id, scope,
	                refresh_family, consent_id, expires_at)
	            VALUES ('mcp-a', 'MCP_ACCESS', $1, '[]'::jsonb, 'https://pm.example/mcp', 'cli-1',
	                    'read', 'fam-1', $2, now() + interval '1 hour')`, owner, consentID)

	n, err := f.store.RevokeAllForPrincipal(f.ctx, nil, owner)
	if err != nil {
		t.Fatalf("RevokeAllForPrincipal: %v", err)
	}
	// 4 A4 kinds + 1 MCP_ACCESS = 5 live. The expired row is NOT counted.
	if n != 5 {
		t.Errorf("RevokeAllForPrincipal = %d, want 5 (four A4 kinds + MCP_ACCESS; the expired row "+
			"is excluded by `expires_at > now()`)", n)
	}
	// Idempotent.
	if again, err := f.store.RevokeAllForPrincipal(f.ctx, nil, owner); err != nil || again != 0 {
		t.Errorf("second RevokeAllForPrincipal = %d, %v; want 0 (idempotent)", again, err)
	}
	// The expired row was left alone — a deprovision reports kills, not tombstones.
	var expiredRevoked *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at::text FROM proxy_token WHERE id = $1`, expired.ID).Scan(&expiredRevoked); err != nil {
		t.Fatalf("read expired row: %v", err)
	}
	if expiredRevoked != nil {
		t.Errorf("an already-expired token was stamped revoked_at = %q", *expiredRevoked)
	}
	// 🔒 The principal's OWN rows carry revoked_at, and no longer resolve. The count alone would be
	// satisfied by a sweep that stamped some other column, or a different set of rows.
	for _, tok := range []token.Issued{t1, t2} {
		info, err := f.store.Get(f.ctx, tok.ID)
		if err != nil || info == nil {
			t.Fatalf("Get(%d) after the deprovision: %v, %v", tok.ID, info, err)
		}
		if info.RevokedAt == nil {
			t.Errorf("token %d (%s) has no revokedAt after RevokeAllForPrincipal", tok.ID, info.Kind)
		}
		if id, err := f.store.Resolve(f.ctx, tok.Token); err != nil || id != nil {
			t.Errorf("token %d still resolves after the deprovision: %v, %v", tok.ID, id, err)
		}
	}
	// The other principal survives — untouched, not merely still present: no revokedAt either.
	if id, err := f.store.Resolve(f.ctx, survivor.Token); err != nil || id == nil {
		t.Fatalf("another principal's token was revoked by this deprovision: %v, %v", id, err)
	}
	if info, err := f.store.Get(f.ctx, survivor.ID); err != nil || info == nil || info.RevokedAt != nil {
		t.Errorf("another principal's token was stamped revoked_at: %+v (err %v)", info, err)
	}
}

// 🔒 TestValidateExcludesTheEphemeralKinds closes 04-auth-session-tokens.md §4.17 gap 1 — "the single
// highest-value new test in the area", which NO Kotlin test covers.
//
// INV-A4-56: "A transient editor/approver-exec token authorizes exactly ONE proxy-mediated query via
// the per-query `resolve` path — it must NOT pass the wire-session handshake, so a leaked ephemeral
// token can't open a native MySQL/PG session as that principal within its short TTL."
//
// Widening `validate`'s IN list is a ONE-WORD change that turns every editor query token into a full
// native wire credential, and before this test no assertion anywhere would have failed.
func TestValidateExcludesTheEphemeralKinds(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []token.Kind{token.KindEditor, token.KindApproverExec} {
		tok := f.issue(kind, owner, []string{"analyst"}, nil, oneDay)

		// resolve accepts it — that is the per-query path, and the whole point of the kind.
		id, err := f.store.Resolve(f.ctx, tok.Token)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", kind, err)
		}
		if id == nil {
			t.Fatalf("Resolve refused a live %s token; the per-query path must accept it", kind)
		}
		// validate refuses it — that is the wire-session handshake.
		id, err = f.store.Validate(f.ctx, tok.Token)
		if err != nil {
			t.Fatalf("Validate(%s): %v", kind, err)
		}
		if id != nil {
			t.Fatalf("🔒 INV-A4-56 BROKEN: a %s token passed the wire-session handshake. A leaked "+
				"ephemeral token can now open a native MySQL/PG session as %s.", kind, owner)
		}
	}
	// The two managed kinds do pass, and validate stamps last_used_at while resolve does not
	// (INV-A4-55 — the hot path must not serialize on one row's UPDATE lock).
	for _, kind := range []token.Kind{token.KindSession, token.KindUser} {
		tok := f.issue(kind, owner, nil, nil, oneDay)
		if id, err := f.store.Resolve(f.ctx, tok.Token); err != nil || id == nil {
			t.Fatalf("Resolve(%s) = %v, %v; want the identity", kind, id, err)
		}
		if info, err := f.store.Get(f.ctx, tok.ID); err != nil || info == nil || info.LastUsedAt != nil {
			t.Errorf("Resolve stamped last_used_at on a %s token; INV-A4-55 says only validate writes", kind)
		}
		if id, err := f.store.Validate(f.ctx, tok.Token); err != nil || id == nil {
			t.Fatalf("Validate(%s) = %v, %v; want the identity", kind, id, err)
		}
		if info, err := f.store.Get(f.ctx, tok.ID); err != nil || info == nil || info.LastUsedAt == nil {
			t.Errorf("Validate did not stamp last_used_at on a %s token", kind)
		}
	}
}

// 🔒 TestResolveExcludesTheMCPKinds closes §4.17 gap 2: an MCP token must not be usable as a wire
// credential either. `resolve`'s IN list names four kinds and the MCP kinds are not among them.
func TestResolveExcludesTheMCPKinds(t *testing.T) {
	f := newFixture(t)
	var consentID int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO oauth_consent (principal, client_id, resource, scope)
		     VALUES ($1, 'cli-1', 'https://pm.example/mcp', 'read') RETURNING id`, owner).Scan(&consentID); err != nil {
		t.Fatalf("seed oauth_consent: %v", err)
	}
	const raw = "mcp_plaintext_token"
	f.exec(`INSERT INTO proxy_token (token_hash, kind, principal, roles, resource, client_id, scope,
	                refresh_family, consent_id, expires_at)
	            VALUES ($1, 'MCP_ACCESS', $2, '[]'::jsonb, 'https://pm.example/mcp', 'cli-1', 'read',
	                    'fam-1', $3, now() + interval '1 hour')`, token.Hash(raw), owner, consentID)

	if id, err := f.store.Resolve(f.ctx, raw); err != nil || id != nil {
		t.Fatalf("Resolve accepted an MCP_ACCESS token (%v, %v); it must be usable only on A11's "+
			"own surface, never as a wire credential", id, err)
	}
	if id, err := f.store.Validate(f.ctx, raw); err != nil || id != nil {
		t.Fatalf("Validate accepted an MCP_ACCESS token (%v, %v)", id, err)
	}
}

// TestIssueClampsTTLOnEveryPath pins the choke point: neither mint route clamps, `Issue` does, so the
// clamp is applied exactly once on all six issuance paths.
func TestIssueClampsTTLOnEveryPath(t *testing.T) {
	f := newFixture(t)
	// Well past the 24h ceiling. The stored expires_at must land at now()+24h, not now()+1 year.
	tok := f.issue(token.KindUser, owner, nil, nil, 365*24*3600)
	var withinADay bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT expires_at <= now() + interval '24 hours' + interval '5 seconds'
		     FROM proxy_token WHERE id = $1`, tok.ID).Scan(&withinADay); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	if !withinADay {
		t.Error("🔒 INV-A4-52 BROKEN: a one-year TTL request produced a token living past 24h. The " +
			"clamp must stay INSIDE Issue — moving it to the routes loses it on whichever of the " +
			"six issuance call sites is forgotten.")
	}
	// And the floor: a zero request is FLOORED to 60s, never rejected and never already-expired.
	zero := f.issue(token.KindUser, owner, nil, nil, 0)
	if id, err := f.store.Resolve(f.ctx, zero.Token); err != nil || id == nil {
		t.Fatalf("a ttl=0 request produced an unusable token (%v, %v); the clamp floors to 60s", id, err)
	}
}

// 🔒 TestMintForActivePrincipalLockedRefusesADeprovisionedPrincipal is the store half of
// `TokenRoutesDeactivationTest`'s two cases (INV-A4-58 / INV-A3-7).
//
// The Kotlin cases drive `POST /api/wire-tokens` and `POST /api/tokens` through testApplication and
// assert 403 `auth.principal_deprovisioned`. The routes are not ported (TODO(A4) in this package's
// doc), so what is asserted here is the property the 403 is derived from: the check and the INSERT
// run on ONE transaction under the per-principal advisory lock, and a deprovisioned principal mints
// NOTHING — no row, not merely no response.
//
//	TODO(A4): re-assert the 403 + the error code through the route once tokenRoutes lands.
func TestMintForActivePrincipalLockedRefusesADeprovisionedPrincipal(t *testing.T) {
	f := newFixture(t)
	users := identity.NewUserGroupStore(f.db.Pool)
	seed := dbtest.NewSeed(t, f.db)
	seed.User(owner)

	// Active: the mint happens.
	got, err := token.MintForActivePrincipalLocked(f.ctx, f.db.Pool, users, owner,
		func(ctx context.Context, c store.Queryer) (token.Issued, error) {
			return f.store.Issue(ctx, c, token.KindSession, owner, nil, nil, token.SessionTTLSeconds)
		})
	if err != nil {
		t.Fatalf("MintForActivePrincipalLocked(active): %v", err)
	}
	if got == nil {
		t.Fatal("an ACTIVE principal was refused a credential")
	}
	if id, err := f.store.Resolve(f.ctx, got.Token); err != nil || id == nil {
		t.Fatalf("the minted token does not resolve: %v, %v", id, err)
	}

	// Deprovisioned: nil, and — the part that matters — no row was written.
	seed.SetUserActive(owner, false)
	before := f.countTokens()
	refused, err := token.MintForActivePrincipalLocked(f.ctx, f.db.Pool, users, owner,
		func(ctx context.Context, c store.Queryer) (token.Issued, error) {
			return f.store.Issue(ctx, c, token.KindSession, owner, nil, nil, token.SessionTTLSeconds)
		})
	if err != nil {
		t.Fatalf("MintForActivePrincipalLocked(deprovisioned): %v", err)
	}
	if refused != nil {
		t.Fatalf("🔒 INV-A4-58 BROKEN: a deprovisioned principal minted %+v", *refused)
	}
	if after := f.countTokens(); after != before {
		t.Errorf("token count went %d → %d for a deprovisioned principal; the mint must leave NO row",
			before, after)
	}
}

func (f *fixture) countTokens() int64 {
	f.t.Helper()
	var n int64
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM proxy_token`).Scan(&n); err != nil {
		f.t.Fatalf("count proxy_token: %v", err)
	}
	return n
}

func ptr[T any](v T) *T { return &v }
