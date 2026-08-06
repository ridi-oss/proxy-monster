package oauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/gocp/internal/instant"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// McpTokenStore — 14-auth.md §4, the `/mcp` bearer gate
// ---------------------------------------------------------------------------------------------

// mcpAccessSelect is `resolveAccess`'s one statement (McpOAuth.kt:57-64), transcribed with `?` →
// `$n`. Every clause in it is load-bearing:
//
// 🔒 INV-A14-9 — AUDIENCE BINDING IS A WHERE CLAUSE, NOT A CALLER'S `if`. `t.resource = $2` sits
// inside the query, so a token minted for one MCP resource cannot resolve against another EVEN IF
// THE CALLING GATE FORGETS TO COMPARE. This is what makes a stolen token useless against a second
// proxy-monster deployment.
//
// 🔒 INV-A14-10 — THE JOIN RE-VERIFIES THE FULL CONSENT TUPLE, not just the foreign key. The token
// row carries a denormalized copy of (principal, client_id, resource, scope); joining on
// `c.id = t.consent_id` alone would authorize a token whose copy has DRIFTED from its consent. Five
// join columns means a drifted token fails closed. The predicate looks redundant; it is not.
//
// 🔒 INV-A14-10b — the SIXTH predicate, `c.revoked_at IS NULL`, is the only thing that closes a real
// revoke-versus-issue interleaving. RevokeConsent cascades onto the tokens that exist AT THAT MOMENT;
// a ConsumeAuthorizationCode transaction that started before the revoke and commits after it inserts
// fresh rows the cascade already ran past. Nothing rewrites them and no sweeper exists, so they are
// unusable ONLY because this query re-reads the consent's `revoked_at` on every request. "Optimizing"
// the join down to `c.id = t.consent_id` grants a live MCP token under a revoked consent for the full
// access TTL.
//
// ⚠️ F23 — `t.kind = 'MCP_ACCESS'` is a hardcoded literal, not [MCPAccessKind]. Reproduced.
const mcpAccessSelect = `SELECT t.principal, t.client_id, t.resource, t.scope, t.consent_id
	     FROM proxy_token t
	     JOIN oauth_consent c ON c.id = t.consent_id
	       AND c.principal = t.principal AND c.client_id = t.client_id
	       AND c.resource = t.resource AND c.scope = t.scope
	     WHERE t.token_hash = $1 AND t.kind = 'MCP_ACCESS' AND t.resource = $2
	       AND t.revoked_at IS NULL AND t.expires_at > now()
	       AND c.revoked_at IS NULL`

// MCPTokenStore is `class McpTokenStore(dataSource)` (McpOAuth.kt:54). Stateless.
type MCPTokenStore struct{ db store.Queryer }

// NewMCPTokenStore wires the store over the shared pool.
func NewMCPTokenStore(db store.Queryer) *MCPTokenStore { return &MCPTokenStore{db: db} }

// ResolveAccess is `resolveAccess(token, expectedResource)` (McpOAuth.kt:55-79): the identity behind
// a valid, live, correctly-audienced MCP access token, or nil. NON-NIL IS THE SOLE AUTHORIZATION TO
// ENTER THE `/mcp` SURFACE.
//
// "No such token" is a normal outcome, not an error: pgx.ErrNoRows ⇒ (nil, nil). A genuine query
// failure IS returned, because answering "no identity" to a database outage would silently 401 every
// MCP request instead of 500-ing visibly.
//
// 🔒 INV-A14-11 — the scopes come from the TOKEN row, not the consent row. By INV-A14-10 they are
// equal, so the choice is invisible today, but it is the correct one: a consent WIDENED after
// issuance must not retroactively widen an outstanding token.
//
// INV-A14-12 — expiry is evaluated by the DATABASE clock (`now()`), and issuance computes
// `expires_at` in Postgres too, so issuance and validation share one clock and a token can never be
// born expired by skew. ⚠️ [AuthorizationStore.RotateRefresh] breaks that symmetry deliberately; see
// INV-A14-16 there.
//
// What this method deliberately does NOT do, all three quoted from 14-auth.md §4:
//   - NO `last_used_at` write. Every `/mcp` request goes through here, so an UPDATE would put a write
//     (and a row lock, and WAL) on the hot path. Consequence to accept, not fix: an MCP token's
//     `last_used_at` is ALWAYS NULL.
//   - NO deactivation check. 🔒 INV-A14-13 — A11's gate does it separately
//     (`core.userGroupStore.isDeactivated(identity.principal)`, McpServer.kt:133). A port must not
//     "helpfully" move it into this query AND must not drop it from the gate: splitting it keeps this
//     package free of any dependency on A3's identity tables.
//   - NO scope check. Scope enforcement is A11's McpAuthorizer (INV-A11-7).
//
// ⚠️ The scope split filters `isNotBlank` while [CanonicalScopes] filters `isNotEmpty`. Equivalent on
// canonical input; the asymmetry is reproduced on both sides because THIS side parses STORED data
// that a legacy row could have left non-canonical.
func (s *MCPTokenStore) ResolveAccess(ctx context.Context, token, expectedResource string) (*AccessIdentity, error) {
	var (
		id    AccessIdentity
		scope string
	)
	err := s.db.QueryRow(ctx, mcpAccessSelect, SHA256Hex(token), expectedResource).
		Scan(&id.Principal, &id.ClientID, &id.Resource, &scope, &id.ConsentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id.Scopes = splitScopesNotBlank(scope)
	return &id, nil
}

// splitScopesNotBlank is `getString("scope").split(' ').filter(String::isNotBlank).toSet()`
// (McpOAuth.kt:74) — split on the SINGLE SPACE CHARACTER, not on runs of whitespace, then drop blanks.
// `strings.Fields` is NOT a substitute: it also splits on tabs and newlines, which a stored scope
// string could contain and which the Kotlin would keep inside one element.
func splitScopesNotBlank(scope string) []string {
	parts := strings.Split(scope, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if !isBlankKotlin(p) {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// OAuthAuthorizationStore — 14-auth.md §5
// ---------------------------------------------------------------------------------------------

// The two failure messages `createAuthorizationCode` raises, verbatim from McpOAuth.kt:133 and :161.
//
// 🔒 F30 / 14-auth.md Q7 — this is THE ONLY method in the store that signals failure by throwing
// rather than returning nil, and A11's `issueAuthorizationCode` wraps NOTHING in runCatching, so a
// consent revoked between FindActiveConsent and CreateAuthorizationCode surfaces as a 500 rather than
// an OAuth error response. REPRODUCE: the 500 is observable, and a typed error mapped to
// `invalid_request` is the right fix taken separately. [Routes.issueAuthorizationCode] therefore
// answers the StatusPages fallback here, not an OAuthError of its own.
var (
	ErrInvalidPKCEChallenge = errors.New("invalid PKCE challenge")
	ErrConsentMismatch      = errors.New("authorization code consent is absent, revoked, or mismatched")
)

// AuthorizationStore is `class OAuthAuthorizationStore(dataSource)` (McpOAuth.kt:131) — the
// authorization server's state machine. Stateless apart from the pool and the clock.
type AuthorizationStore struct {
	db store.DB
	// Now is the JVM clock [RotateRefresh] compares `expires_at` against. It is a field ONLY so that
	// F32's two-clock behaviour can be pinned deterministically instead of by sleeping; production
	// wiring leaves it nil, which means time.Now. See INV-A14-16 on [AuthorizationStore.RotateRefresh].
	Now func() time.Time
}

// NewAuthorizationStore wires the store over the shared pool.
//
// ⚠️ Lifecycle note, recorded only so a port author does not go looking for a `core.oauthStore` that
// does not exist: the Kotlin constructs this INSIDE `installMcpOAuthRoutes` (OAuthRoutes.kt:111), one
// instance per route installation, while `McpTokenStore` is held on ControlPlaneCore. Both are
// stateless, so the asymmetry is harmless and a Go port may put them wherever its wiring prefers.
func NewAuthorizationStore(db store.DB) *AuthorizationStore { return &AuthorizationStore{db: db} }

func (s *AuthorizationStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ---- createAuthorizationCode ------------------------------------------------------------------

// pruneAuthorizationCodesSQL is the opportunistic sweeper (McpOAuth.kt:138). Global across all
// principals, and the ONLY sweeper for this table — A1's background purge loop covers `device_login`,
// query results, editor sessions and the connection catalog, and NOT this. So issuance traffic is the
// sweeper.
//
// ⚠️ Three consequences, from 14-auth.md §5: (a) it deletes USED codes too, so a replay attempt after
// any later issuance takes the "row not found" path rather than the "not usable" path — same nil
// answer, no forensic record that a replay occurred; (b) it is not in a transaction with the INSERT,
// so a prune can commit while the INSERT fails; (c) F42 — the table's sole non-constraint index is
// PARTIAL, `ON (expires_at) WHERE used_at IS NULL` (V7:41-42), whose predicate is the NEGATION of the
// `OR used_at IS NOT NULL` branch, so that branch has no index at all.
const pruneAuthorizationCodesSQL = `DELETE FROM oauth_authorization_code
	     WHERE expires_at <= now() OR used_at IS NOT NULL`

// insertAuthorizationCodeSQL is McpOAuth.kt:141-146.
//
// 🔒 INV-A14-15a — THE CONSENT CHECK IS THE INSERT. Doing it as the INSERT's SELECT source makes
// "consent is valid" and "code is bound to it" a single atomic statement with NO TOCTOU WINDOW. A
// port that reads the consent, checks it in application code and then inserts opens a window in which
// the consent is revoked between check and insert. The five predicates also make this an OWNERSHIP
// check: a caller cannot bind a code to SOMEONE ELSE'S consent id.
const insertAuthorizationCodeSQL = `INSERT INTO oauth_authorization_code
	       (code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge, expires_at, consent_id)
	     SELECT $1, $2, $3, $4, $5, $6, $7, now() + ($8::bigint * interval '1 second'), id
	     FROM oauth_consent
	     WHERE id = $9 AND principal = $10 AND client_id = $11 AND resource = $12 AND scope = $13
	       AND revoked_at IS NULL`

// CreateAuthorizationCode is `createAuthorizationCode(input)` (McpOAuth.kt:132-165) — returns the
// PLAINTEXT authorization code.
//
// 🔒 INV-A14-14 — PKCE IS MANDATORY AT THE STORE, not only at the route. A11 checks it too
// (OAuthRoutes.kt:140) and V7 has a CHECK. Three layers, because
// `token_endpoint_auth_methods_supported = ["none"]` — there is NO CLIENT SECRET ANYWHERE in this
// design, so PKCE is the only thing binding a code to the client that requested it.
//
// ⚠️ F25 — the TTL window is `coerceIn(60, 600)`, NOT [ClampTTLSeconds]: a separate, tighter window
// for codes (1..10 minutes), written as INLINE MAGIC NUMBERS with no named constants unlike
// TOKEN_MIN/MAX_TTL_SECONDS right above them. Reproduced as literals for the same reason.
//
// Neither statement runs in a transaction — the Kotlin takes ONE autoCommit connection and issues
// both on it. Here they go through the pool, so they may land on two different connections; both are
// still independently autocommitted, and no predicate of either depends on the other's snapshot, so
// nothing observable changes. Recorded because "one connection" is what the Kotlin says.
func (s *AuthorizationStore) CreateAuthorizationCode(ctx context.Context, in AuthorizationCodeInput) (string, error) {
	if !IsValidPKCEChallenge(in.CodeChallenge) {
		return "", ErrInvalidPKCEChallenge
	}
	code, err := RandomSecret("pmc_", 32)
	if err != nil {
		return "", err
	}
	canonicalScope := CanonicalScopes(in.Scopes)

	if _, err := s.db.Exec(ctx, pruneAuthorizationCodesSQL); err != nil {
		return "", err
	}
	tag, err := s.db.Exec(ctx, insertAuthorizationCodeSQL,
		SHA256Hex(code), in.ClientID, in.Principal, in.RedirectURI, in.Resource, canonicalScope,
		in.CodeChallenge, coerceIn(in.ttlSeconds(), 60, 600),
		in.ConsentID, in.Principal, in.ClientID, in.Resource, canonicalScope,
	)
	if err != nil {
		// A `code_hash` collision surfaces here as a unique-constraint violation, astronomically
		// unlikely but NOT to be swallowed into "issuance failed silently" — the Kotlin lets the
		// SQLException out of the method for the same reason.
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", ErrConsentMismatch
	}
	return code, nil
}

// coerceIn is Kotlin's `Long.coerceIn(min, max)`.
func coerceIn(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- consumeAuthorizationCode -----------------------------------------------------------------

// codeRow is `private data class CodeRow` (McpOAuth.kt:453-462).
type codeRow struct {
	id          int64
	principal   string
	clientID    string
	redirectURI string
	resource    string
	scope       string
	challenge   string
	consentID   int64
}

// ConsumeAuthorizationCode is `consumeAuthorizationCode(input)` (McpOAuth.kt:167-217): exchanges a
// code for a fresh token family exactly once. Nil on any failure, with NO DISTINGUISHABLE REASONS.
//
// 🔒 A `return@inTransaction null` COMMITS. Every nil return below is a SUCCESSFUL transaction that
// commits whatever it already wrote, and that is load-bearing — it is how a burnt authorization code
// stays burnt after a failed exchange (INV-A14-15b). A Go port using `defer tx.Rollback()` with
// commit-on-success INVERTS this and reintroduces the replayable-code bug, so every nil path here
// returns a NIL ERROR and lets [store.InTx] commit.
//
// 🔒 INV-A14-15 — SINGLE USE IS GUARANTEED BY THE CONDITIONAL UPDATE (`AND used_at IS NULL`), not by
// the readback at step 2. Under `FOR UPDATE` it is belt-and-braces, but it is the primitive that
// survives a port that loses or weakens the row lock.
//
// 🔒 INV-A14-15b — THE CODE IS BURNT BEFORE THE CONSENT IS RE-CHECKED, on purpose. A code that fails
// the consent check must not survive to be retried later; the exchange failing and the code surviving
// would let a client hold a redeemable code across a consent revoke/re-grant cycle.
//
// ⚠️ F31 — step 2 is a REDUNDANT ROUND TRIP: both columns were available to step 1, and because
// Postgres' `now()` is transaction-start time and both statements share the transaction, the clock is
// identical either way. REPRODUCED: inefficiency is not grounds for OMIT, and the extra statement is
// observable to a lock-wait observer and to any differential harness watching the statement sequence.
//
// The PKCE comparison is a plain `!=`, NOT constant-time, and that is correct: the challenge is not a
// secret — the client sent it in the clear in the authorize request. Contrast the consent-CSRF check
// in routes.go, which IS constant-time because that value IS a secret.
func (s *AuthorizationStore) ConsumeAuthorizationCode(ctx context.Context, in ConsumeAuthorizationCodeInput) (*TokenPair, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*TokenPair, error) {
		var row codeRow
		err := tx.QueryRow(ctx,
			`SELECT id, principal, client_id, redirect_uri, resource, scope, code_challenge, consent_id
			     FROM oauth_authorization_code
			     WHERE code_hash = $1 FOR UPDATE`,
			SHA256Hex(in.Code),
		).Scan(&row.id, &row.principal, &row.clientID, &row.redirectURI, &row.resource, &row.scope,
			&row.challenge, &row.consentID)
		if errors.Is(err, pgx.ErrNoRows) {
			// Commits, writing nothing — the Kotlin's `return@inTransaction null`.
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		var usable bool
		err = tx.QueryRow(ctx,
			`SELECT used_at IS NULL AND expires_at > now() FROM oauth_authorization_code WHERE id = $1`,
			row.id).Scan(&usable)
		if errors.Is(err, pgx.ErrNoRows) {
			// `result.next() && result.getBoolean(1)` — no row is false, not an error.
			usable = false
		} else if err != nil {
			return nil, err
		}

		// One `if` with six disjuncts, exactly as McpOAuth.kt:194-197. Note what is NOT compared:
		// the PRINCIPAL (none is supplied — the code carries it) and the SCOPE (likewise).
		if !usable || row.clientID != in.ClientID || row.redirectURI != in.RedirectURI ||
			row.resource != in.Resource || !IsValidPKCEVerifier(in.CodeVerifier) ||
			PKCES256(in.CodeVerifier) != row.challenge {
			return nil, nil
		}

		tag, err := tx.Exec(ctx,
			`UPDATE oauth_authorization_code SET used_at = now() WHERE id = $1 AND used_at IS NULL`, row.id)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, nil
		}

		active, err := consentActive(ctx, tx, row.consentID, row.principal, row.clientID, row.resource, row.scope)
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, nil
		}

		// 🔒 A FRESH FAMILY PER CODE EXCHANGE, so two authorizations by the same principal+client are
		// independent breach domains: a replay detected on one cannot revoke the other.
		family, err := RandomSecret("pmf_", 24)
		if err != nil {
			return nil, err
		}
		return issuePair(ctx, tx, issuance{
			principal: row.principal, clientID: row.clientID, resource: row.resource,
			scope: row.scope, consentID: row.consentID, family: family,
			accessTTL: in.AccessTTLSeconds, refreshTTL: in.RefreshTTLSeconds, rotatedFrom: nil,
		})
	})
}

// ---- rotateRefresh ------------------------------------------------------------------------------

// refreshRow is `private data class RefreshRow` (McpOAuth.kt:464-475).
type refreshRow struct {
	id        int64
	principal string
	clientID  string
	resource  string
	scope     string
	family    *string
	consentID int64
	revoked   bool
	expired   bool
	rotated   bool
}

// RotateRefresh is `rotateRefresh(input)` (McpOAuth.kt:219-266): rotate a refresh token exactly once,
// or nil. On a REPLAY, additionally revoke the entire rotation family.
//
// 🔒 INV-A14-17 — REPLAY OF A ROTATED REFRESH TOKEN REVOKES THE WHOLE FAMILY, not just the presented
// token. `rotated_at != NULL` means this token was already exchanged, so SOMEONE ELSE holds its
// successor: either the legitimate client is replaying (a client bug) or the token was stolen. Both
// are indistinguishable, and the safe response is to invalidate every MCP_ACCESS and MCP_REFRESH
// sharing `refresh_family` and force a fresh authorization. This is OAuth 2.1 / RFC 6819
// refresh-rotation breach detection and it is the security core of the area.
//
// 🔒 ORDER IS THE INVARIANT. Step 4's `rotated` test runs BEFORE step 5's `revoked` test, so a replay
// of a normally-rotated token hits the family-revocation branch and not the quiet-deny branch.
// REVERSING STEPS 4 AND 5 SILENTLY DISABLES BREACH DETECTION. Step 6 sets BOTH `revoked_at` and
// `rotated_at`, which is what makes a normally-rotated token simultaneously revoked and rotated.
//
// ⚠️ F33 (index F23) — THE CLIENT/RESOURCE CHECK PRECEDES THE REPLAY CHECK, so replaying a stolen
// ROTATED token with a WRONG `client_id` returns a plain nil and does NOT trigger family revocation:
// the breach-detection alarm is side-steppable. The attacker gains nothing directly (both paths deny),
// but the family survives for the legitimate holder with no signal that a stolen token was seen.
// REPRODUCE + PIN — `TestF33AReplayWithTheWrongClientIdSkipsFamilyRevocation`.
//
// ⚠️ INV-A14-16 / F32 (index F28) — TWO CLOCKS DECIDE EXPIRY ON ONE COLUMN. `ResolveAccess` uses
// Postgres `now()` and `insertToken` computes `expires_at` in SQL, but THIS method compares against
// the application clock. The skew window is real: with the app clock behind the database's, an expired
// refresh token rotates successfully; ahead of it, a live one is refused. REPRODUCE + PIN — keeping
// the app-side read here and the Postgres-side read in ResolveAccess is what makes "who gets refused
// under skew" a visible, separate decision instead of a silent side effect of the rewrite.
// [AuthorizationStore.Now] exists so the pin can be deterministic.
//
// ⚠️ The predecessor's ACCESS token is NOT revoked on a normal rotation — only the refresh row is. So
// after a rotation the old access token stays valid until its own `expires_at`. Deliberate (access TTL
// defaults to 600s) and the reason access TTLs are short.
func (s *AuthorizationStore) RotateRefresh(ctx context.Context, in RefreshTokenInput) (*TokenPair, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*TokenPair, error) {
		var (
			row       refreshRow
			kind      string
			revokedAt *time.Time
			expiresAt time.Time
			rotatedAt *time.Time
		)
		err := tx.QueryRow(ctx,
			`SELECT id, kind, principal, client_id, resource, scope, refresh_family, consent_id,
			            revoked_at, expires_at, rotated_at
			     FROM proxy_token WHERE token_hash = $1 FOR UPDATE`,
			SHA256Hex(in.RefreshToken),
		).Scan(&row.id, &kind, &row.principal, &row.clientID, &row.resource, &row.scope,
			&row.family, &row.consentID, &revokedAt, &expiresAt, &rotatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		// 🔒 The read-side half of INV-A14-8: presenting an MCP_ACCESS, SESSION, USER, EDITOR or
		// APPROVER_EXEC token to the refresh grant is rejected ON KIND.
		if kind != MCPRefreshKind {
			return nil, nil
		}
		row.revoked = revokedAt != nil
		row.rotated = rotatedAt != nil
		// INV-A14-16: `getTimestamp("expires_at").toInstant() <= Instant.now()` — the APPLICATION
		// clock, not the database's.
		row.expired = !expiresAt.After(s.now())

		if row.clientID != in.ClientID || row.resource != in.Resource {
			return nil, nil // F33: no revokeFamily on this path, even for a rotated token.
		}
		if row.rotated {
			if err := revokeFamily(ctx, tx, row.family); err != nil {
				return nil, err
			}
			return nil, nil
		}
		if row.revoked || row.expired {
			// No family revocation: a revoked or expired token is a normal end-of-life, not evidence
			// of theft.
			return nil, nil
		}
		active, err := consentActive(ctx, tx, row.consentID, row.principal, row.clientID, row.resource, row.scope)
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, nil
		}

		tag, err := tx.Exec(ctx,
			`UPDATE proxy_token SET revoked_at = now(), rotated_at = now()
			     WHERE id = $1 AND revoked_at IS NULL`, row.id)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, nil
		}

		family := ""
		if row.family != nil {
			family = *row.family
		}
		return issuePair(ctx, tx, issuance{
			principal: row.principal, clientID: row.clientID, resource: row.resource,
			scope: row.scope, consentID: row.consentID, family: family,
			accessTTL: in.AccessTTLSeconds, refreshTTL: in.RefreshTTLSeconds, rotatedFrom: &row.id,
		})
	})
}

// ---- consents -----------------------------------------------------------------------------------

const consentSelect = `SELECT id, principal, client_id, resource, scope, created_at, updated_at
	     FROM oauth_consent`

// RememberConsent is `rememberConsent(principal, clientId, resource, scopes)` (McpOAuth.kt:268-285).
//
// 🔒 INV-A14-18 — THE CONFLICT TARGET IS A PARTIAL UNIQUE INDEX, and both halves of that matter.
// `oauth_consent_active_tuple_uq` is `UNIQUE (…4-tuple…) WHERE revoked_at IS NULL` (V7:20-21).
//   - IDEMPOTENT WHILE LIVE: re-consenting to the same tuple returns the SAME id and only bumps
//     `updated_at`. Minting a new id per authorization would create two live consent rows for one
//     tuple, and since RevokeConsent revokes exactly one id, revoking one would leave tokens on the
//     other alive. The partial index is what makes "revoke my consent" mean ALL of it.
//   - REVOKED ROWS DO NOT BLOCK: re-consenting after a revocation creates a NEW row with a NEW id and
//     leaves the revoked row in place, because `revoked_at` is a timestamp, not a delete.
//
// ⚠️ The `DO UPDATE` set-list is `updated_at` ONLY — `created_at` is deliberately not touched, so the
// wire-visible `createdAt` keeps the timestamp of the FIRST grant of that tuple. Adding
// `created_at = now()` here would silently rewrite consent history on every login. Mirror image of
// INV-A14-20's COALESCE.
//
// ⚠️ Go shape: the partial-index `ON CONFLICT … WHERE` target is Postgres-specific and must be
// reproduced exactly; `ON CONFLICT (cols)` without the WHERE predicate does not match this index and
// errors at runtime.
func (s *AuthorizationStore) RememberConsent(ctx context.Context, principal, clientID, resource string, scopes []string) (*Consent, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*Consent, error) {
		canonical := CanonicalScopes(scopes)
		var id int64
		err := tx.QueryRow(ctx,
			`INSERT INTO oauth_consent (principal, client_id, resource, scope)
			     VALUES ($1, $2, $3, $4)
			     ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL
			     DO UPDATE SET updated_at = now()
			     RETURNING id`,
			principal, clientID, resource, canonical).Scan(&id)
		if err != nil {
			return nil, err
		}
		// The Kotlin's `consent(connection, id)!!`. The `!!` is safe because the row was upserted in
		// this same transaction; a nil here would be a bug, not a caller error, so it is an error.
		c, err := scanConsent(tx.QueryRow(ctx, consentSelect+` WHERE id = $1`, id))
		if err != nil {
			return nil, err
		}
		if c == nil {
			return nil, errors.New("oauth: consent vanished inside its own transaction")
		}
		return c, nil
	})
}

// FindActiveConsent is `findActiveConsent(principal, clientId, resource, scopes)`
// (McpOAuth.kt:287-300): a plain SELECT on the 4-tuple with [CanonicalScopes] and
// `revoked_at IS NULL`. At most one row, by INV-A14-18. No transaction.
//
// Used by A11 to decide whether the consent screen can be skipped.
func (s *AuthorizationStore) FindActiveConsent(ctx context.Context, principal, clientID, resource string, scopes []string) (*Consent, error) {
	return scanConsent(s.db.QueryRow(ctx,
		consentSelect+` WHERE principal = $1 AND client_id = $2 AND resource = $3 AND scope = $4
		       AND revoked_at IS NULL`,
		principal, clientID, resource, CanonicalScopes(scopes)))
}

// ListConsents is `listConsents(principal)` (McpOAuth.kt:302-310).
//
// Served by `oauth_consent_principal_idx`, which is PARTIAL — `ON oauth_consent (principal) WHERE
// revoked_at IS NULL` (V7:22) — and whose predicate matches this query's exactly. Unverified as a plan
// claim; no EXPLAIN was run.
//
// ⚠️ F34 — `ORDER BY updated_at DESC` with NO TIEBREAKER, so rows sharing `updated_at` come back in an
// unspecified order on `GET /oauth/consents`. REPRODUCE: the order is observable, and adding `, id
// DESC` during the port turns every ordering difference the conformance harness sees into a triage
// item indistinguishable from a real regression.
//
// Returns a NON-NIL empty slice for a principal with no consents — INV-A1-4 puts `[]` on the wire.
func (s *AuthorizationStore) ListConsents(ctx context.Context, principal string) ([]Consent, error) {
	rows, err := s.db.Query(ctx,
		consentSelect+` WHERE principal = $1 AND revoked_at IS NULL ORDER BY updated_at DESC`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Consent{}
	for rows.Next() {
		c, err := scanConsent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// revokeConsentCascadeSQL is step 2 of `revokeConsent` (McpOAuth.kt:321-323).
//
// 🔒 INV-A14-20 — `COALESCE(revoked_at, now())` PRESERVES THE FIRST REVOCATION TIMESTAMP. A plain
// `SET revoked_at = now()` would rewrite history every time a revoke re-ran, and the earliest
// revocation time is the audit-relevant one. The same idiom is in [AuthorizationStore.Revoke] and
// [revokeFamily]; all three must keep it.
//
// ⚠️ The `kind IN (…)` filter here is PROVABLY REDUNDANT today: V7's CHECK forces `consent_id IS NULL`
// for every non-MCP kind, so no other row can match `consent_id = $1`. Keep it — it documents intent
// and survives a constraint relaxation — but do not read it as evidence that non-MCP rows can carry a
// consent. (Contrast [revokeFamilySQL], where the same-looking filter is what makes the partial index
// usable. F23: both hardcode the literals rather than using the constants.)
const revokeConsentCascadeSQL = `UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now())
	     WHERE consent_id = $1 AND kind IN ('MCP_ACCESS', 'MCP_REFRESH')`

// RevokeConsent is `revokeConsent(id, principal)` (McpOAuth.kt:312-325).
//
// 🔒 INV-A14-19 — THE OWNERSHIP CHECK IS A SQL PREDICATE, SO IDOR IS IMPOSSIBLE EVEN IF A ROUTE
// FORGETS. `AND principal = $2` means passing someone else's consent id revokes nothing and returns
// false. A11's route supplies `user.principal` from the session AND requires a CSRF header, but this
// store-level predicate is the one that cannot be bypassed.
//
// INV-A14-21 — revoking a consent does NOT delete outstanding authorization codes and does not need
// to: ConsumeAuthorizationCode re-checks `consentActive`, so an outstanding code becomes
// unredeemable. A second RevokeConsent returns false — idempotent, not an error.
func (s *AuthorizationStore) RevokeConsent(ctx context.Context, id int64, principal string) (bool, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx,
			`UPDATE oauth_consent SET revoked_at = now(), updated_at = now()
			     WHERE id = $1 AND principal = $2 AND revoked_at IS NULL`, id, principal)
		if err != nil {
			return false, err
		}
		if tag.RowsAffected() == 0 {
			return false, nil
		}
		if _, err := tx.Exec(ctx, revokeConsentCascadeSQL, id); err != nil {
			return false, err
		}
		return true, nil
	})
}

// ---- revoke -------------------------------------------------------------------------------------

// Revoke is `revoke(token)` (McpOAuth.kt:327-341). Its KDoc, verbatim: "RFC 7009: access closes only
// itself; refresh closes its entire rotation family."
//
// 🔒 INV-A14-22 — THE `else if` IS A CONTAINMENT BOUNDARY, NOT STYLE. A11's `/oauth/revoke` is
// UNAUTHENTICATED (it reads a form parameter and calls straight through). A bare `else` branch — or a
// future refactor to "revoke whatever row matched" — would let that endpoint revoke a daemon SESSION,
// a USER PAT, an EDITOR or an APPROVER_EXEC token. The caller must already hold the plaintext token,
// so it is not a blind DoS, but restricting by kind means a leaked wire token cannot be destroyed
// through the OAuth surface.
//
// 🔒 INV-A14-23 — AN UNKNOWN TOKEN IS A SILENT SUCCESS. RFC 7009 requires 200 for a token the server
// does not recognize, so revocation must not become an existence oracle.
//
// INV-A14-24 — the asymmetry between access and refresh revocation is the point: revoking an access
// token must not log the client out (it can still refresh), and revoking a refresh token must end the
// whole grant. Collapsing either direction breaks a documented RFC 7009 behaviour.
func (s *AuthorizationStore) Revoke(ctx context.Context, token string) error {
	return store.InTxDo(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		var (
			id     int64
			kind   string
			family *string
		)
		err := tx.QueryRow(ctx,
			`SELECT id, kind, refresh_family FROM proxy_token WHERE token_hash = $1 FOR UPDATE`,
			SHA256Hex(token)).Scan(&id, &kind, &family)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		switch kind {
		case MCPRefreshKind:
			return revokeFamily(ctx, tx, family)
		case MCPAccessKind:
			_, err := tx.Exec(ctx,
				`UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`, id)
			return err
		default:
			// INV-A14-22: any other kind is a silent no-op.
			return nil
		}
	})
}

// ---- issuance -----------------------------------------------------------------------------------

// issuance is `issuePair`'s ten parameters, grouped so the two call sites read as the Kotlin's named
// arguments do.
type issuance struct {
	principal   string
	clientID    string
	resource    string
	scope       string
	consentID   int64
	family      string
	accessTTL   int64
	refreshTTL  int64
	rotatedFrom *int64
}

// issuePair is `private fun issuePair(...)` (McpOAuth.kt:343-360).
//
// ⚠️ `rotated_from` is recorded ONLY on the refresh row, so the rotation lineage is traceable through
// refresh tokens alone and the access token has no predecessor of its own. Deliberate.
//
// 🔒 INV-A14-2 — [ClampTTLSeconds] is applied here for the `expiresIn` the CLIENT is told, and again
// inside [insertToken] for the value Postgres turns into `expires_at`. Both are needed.
func issuePair(ctx context.Context, tx pgx.Tx, in issuance) (*TokenPair, error) {
	access, err := RandomSecret("pma_", 32)
	if err != nil {
		return nil, err
	}
	refresh, err := RandomSecret("pmr_", 32)
	if err != nil {
		return nil, err
	}
	if err := insertToken(ctx, tx, access, MCPAccessKind, in, in.accessTTL, nil); err != nil {
		return nil, err
	}
	if err := insertToken(ctx, tx, refresh, MCPRefreshKind, in, in.refreshTTL, in.rotatedFrom); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    ClampTTLSeconds(in.accessTTL),
		Scope:        in.scope,
	}, nil
}

// insertTokenSQL is McpOAuth.kt:376-378.
//
// 🔒 INV-A14-25 — AN MCP TOKEN CARRIES NO ROLE SNAPSHOT. `roles` is the LITERAL `'[]'::jsonb`, never a
// parameter, and V7's CHECK REQUIRES `roles = '[]'::jsonb` for MCP kinds. An MCP token's authority is
// (consent scope) ∧ (roles resolved LIVE at each tool call — INV-A11-8). Baking roles into the token
// would make a role revocation invisible until expiry.
//
// 🔒 INV-A14-26 — `expires_at` IS COMPUTED BY POSTGRES from `now()`, not by the application: one clock
// for issuance across all replicas. Keep the arithmetic in SQL. The `$n::bigint * interval '1 second'`
// cast is required — binding an interval directly is driver-dependent.
//
// `name` and `last_used_at` are left at their defaults (NULL).
const insertTokenSQL = `INSERT INTO proxy_token
	       (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, rotated_from)
	     VALUES ($1, $2, $3, '[]'::jsonb, now() + ($4::bigint * interval '1 second'), $5, $6, $7, $8, $9, $10)`

// insertToken is `private fun insertToken(...)` (McpOAuth.kt:362-392).
//
// The Kotlin's `setNullableLong` helper disappears here: `database/sql`/pgx map a nil *int64 to SQL
// NULL with no type code, so what survives is the NULLABILITY of `rotated_from`, which is all the
// helper encoded. The column is `BIGINT REFERENCES proxy_token(id) ON DELETE SET NULL` — a
// SELF-REFERENCING FK whose ON DELETE SET NULL is why purging an ancestor severs the lineage chain
// instead of cascading the delete through the whole family.
func insertToken(ctx context.Context, tx pgx.Tx, token, kind string, in issuance, ttlSeconds int64, rotatedFrom *int64) error {
	_, err := tx.Exec(ctx, insertTokenSQL,
		SHA256Hex(token), kind, in.principal, ClampTTLSeconds(ttlSeconds),
		in.resource, in.clientID, in.scope, in.family, in.consentID, rotatedFrom)
	return err
}

// revokeFamilySQL is McpOAuth.kt:396-397.
//
// ⚠️ Served by `proxy_token_mcp_family_idx`, again PARTIAL — `ON proxy_token (refresh_family) WHERE
// kind IN ('MCP_ACCESS','MCP_REFRESH')` (V7:96-97) — whose predicate is byte-for-byte the `kind IN (…)`
// filter here. That is WHY the redundant-looking filter is in the statement at all: without it the
// partial index cannot be used. So unlike [revokeConsentCascadeSQL]'s, dropping this one costs the
// index. Unverified as a plan claim; no EXPLAIN was run.
const revokeFamilySQL = `UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now())
	     WHERE refresh_family = $1 AND kind IN ('MCP_ACCESS', 'MCP_REFRESH')`

// revokeFamily is `private fun revokeFamily(connection, family)` (McpOAuth.kt:394-399).
//
// The nil guard exists because [AuthorizationStore.Revoke] reads `refresh_family` from a row of ANY
// kind, where V7's CHECK makes it NULL — so a non-MCP row reaching here is a no-op rather than a
// `WHERE refresh_family = NULL` full-table scan-and-miss.
func revokeFamily(ctx context.Context, tx pgx.Tx, family *string) error {
	if family == nil {
		return nil
	}
	_, err := tx.Exec(ctx, revokeFamilySQL, *family)
	return err
}

// consentActive is `private fun consentActive(...)` (McpOAuth.kt:401-420).
//
// 🔒 The same FIVE-COLUMN tuple as [mcpAccessSelect]'s JOIN (INV-A14-10), for the same reason: a
// consent whose tuple no longer matches the token/code is treated as ABSENT, not as present and
// active. A missing row and a revoked row both yield false — one predicate, two failure modes,
// fail-closed on both.
func consentActive(ctx context.Context, tx pgx.Tx, id int64, principal, clientID, resource, scope string) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx,
		`SELECT revoked_at IS NULL FROM oauth_consent
		     WHERE id = $1 AND principal = $2 AND client_id = $3 AND resource = $4 AND scope = $5`,
		id, principal, clientID, resource, scope).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return active, nil
}

// scanConsent is `private fun ResultSet.toConsent()` (McpOAuth.kt:429-437) — the single place
// `created_at`/`updated_at` become `Instant.toString()` strings.
func scanConsent(row pgx.Row) (*Consent, error) {
	var (
		c                    Consent
		createdAt, updatedAt time.Time
	)
	err := row.Scan(&c.ID, &c.Principal, &c.ClientID, &c.Resource, &c.Scope, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = instant.Format(createdAt)
	c.UpdatedAt = instant.Format(updatedAt)
	return &c, nil
}
