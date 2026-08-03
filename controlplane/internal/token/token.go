// Package token is `Tokens.kt` — the `proxy_token` table (V7) and the wire-credential vocabulary:
// [Kind], [Hash], the TTL clamp, and the [Store] lifecycle `issue` / `resolve` / `validate` /
// `list` / `get` / `revoke` / `revokeAllForPrincipal`.
//
// Area doc: plans/proxy-monster-go-port/04-auth-session-tokens.md §3.8 (`Tokens.kt`).
//
// # Scope, stated so the gap is visible rather than assumed
//
// The STORE is complete. The `/api/tokens` + `/api/wire-tokens` ROUTES are not, and neither is A11's
// MCP token family. The web-session half of A4 lives in internal/session.
//
//	TODO(A4): tokenRoutes — GET/POST /api/tokens, DELETE /api/tokens/{id}, POST /api/wire-tokens.
//	          Both mint routes must call requireAuthz(TOKEN_MINT, …) BEFORE receive() (the ordering
//	          is observable: an unauthorized caller with a garbage body must get 401/403, never 400)
//	          and must wrap the INSERT in [MintForActivePrincipalLocked]. `POST /api/tokens` answers
//	          201, `POST /api/wire-tokens` answers 200 — an inconsistency web/ and pmon depend on.
//	TODO(A11): the MCP_ACCESS / MCP_REFRESH kinds and their rotation family. They are NOT members of
//	          [Kind] — see below — but they ARE rows in this table, which is the root of F27.
//	TODO(A3): relocate [MintForActivePrincipalLocked] to internal/identity when Deprovision.kt lands.
//
// # The two SQL predicates are the security content
//
// 🔒 INV-A4-56 — `validate` accepts kinds ('SESSION','USER') while `resolve` accepts all four. That
// four-kind vs two-kind IN list, plus the `last_used_at` write, is the ENTIRE difference between the
// two statements. Widening `validate` turns every ephemeral editor query token into a full native
// wire credential (04-auth-session-tokens.md §3.8, quoting Tokens.kt:178-181).
//
// 🔒 INV-A4-55 — `resolve` is `validate` MINUS the write, for the per-query hot path: many concurrent
// queries sharing one daemon token must not serialize on a single row's UPDATE lock. Unifying the two
// either serializes the hot path or opens INV-A4-56's hole.
//
// 🔒 INV-A4-53 — [Hash] is the ONE hashing definition, shared by the `proxy_token.token_hash` column
// and A7's requester-IP registry. Two hashers would silently desynchronize the decide-time IP lookup
// from the token row.
package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// Kind is `enum class TokenKind` — exactly four values (04-auth-session-tokens.md §3.8).
//
// ⚠️ The DB additionally holds MCP_ACCESS / MCP_REFRESH (V7__tokens.sql:48-57, owned by A11); they
// are deliberately NOT members of this type, exactly as they are not members of the Kotlin enum.
type Kind string

const (
	// KindSession is a daemon/CLI wire session token, prefix `pmt_`.
	KindSession Kind = "SESSION"
	// KindUser is a named, expiring token a human generates for headless use, prefix `pmk_`.
	KindUser Kind = "USER"
	// KindEditor is the one-shot console-editor credential. Excluded from `validate`.
	KindEditor Kind = "EDITOR"
	// KindApproverExec is the approver's execute-under-R credential. Excluded from `validate`.
	KindApproverExec Kind = "APPROVER_EXEC"
)

// KindFromWire is `TokenKind.fromWire(value)` (Tokens.kt:26-29): the enum member whose NAME equals
// value, or ok=false on anything unrecognized — "so callers fail closed rather than throw".
//
// ⚠️ F21 records that the one HTTP call site where this matters (DELETE /api/tokens/{id}) does the
// OPPOSITE of failing closed with the null. A10's `decide` is the call site that does fail closed
// (UNAUTHENTICATED "token kind is not valid for query decisions"), and it is the only caller here.
func KindFromWire(value string) (Kind, bool) {
	switch Kind(value) {
	case KindSession:
		return KindSession, true
	case KindUser:
		return KindUser, true
	case KindEditor:
		return KindEditor, true
	case KindApproverExec:
		return KindApproverExec, true
	default:
		return "", false
	}
}

// Prefix is `if (kind == SESSION) "pmt_" else "pmk_"`.
//
// ⚠️ EDITOR and APPROVER_EXEC tokens are therefore prefix-INDISTINGUISHABLE from USER tokens on the
// wire. Never infer a kind from a prefix; resolve it from the row.
func (k Kind) Prefix() string {
	if k == KindSession {
		return "pmt_"
	}
	return "pmk_"
}

// TTL bounds — `clampTtlSeconds(ttl) = ttl.coerceIn(60, 86_400)`.
const (
	// MinTTLSeconds floors a zero/negative request rather than rejecting it, so a buggy client
	// cannot mint an already-expired token.
	MinTTLSeconds int64 = 60
	// MaxTTLSeconds is 24h. 🔒 INV-A4-52 — no token is permanent and this clamp is the ONLY
	// enforcement; `expires_at` is NOT NULL in V7 and every INSERT computes it as now() + ttl.
	MaxTTLSeconds int64 = 86_400
)

// The two per-route TTL DEFAULTS — `SESSION_TTL_SECONDS` and `DEFAULT_USER_TTL_SECONDS`
// (Tokens.kt:77-78). They are `TokenStore`'s two PUBLIC fields in the Kotlin precisely because
// `tokenRoutes` reads them as the defaults for the two mint routes.
//
// # Where these live, and why they are HERE rather than in internal/config
//
// The task brief said all four TTL symbols live in the auth module per 14-auth.md. Checked: only two
// of them do. 14-auth.md:198 states outright that "SESSION_TTL_SECONDS (12h) and
// DEFAULT_USER_TTL_SECONDS (1h) do **not** live here", and 14-auth.md:1267-1268 confirms every one of
// the five names resolves to "the same-package declarations in Tokens.kt:75-81 (A4)". So:
//
//   - SessionTTLSeconds / DefaultUserTTLSeconds — A4 only, one declaration, this package.
//   - ClampTTLSeconds / MinTTLSeconds / MaxTTLSeconds — declared TWICE, byte-identically, in
//     auth/McpOAuth.kt:15-18 and control-plane/Tokens.kt:75-81 (A14 F21 / index F93). The AUTH copy
//     is already ported, at internal/config/auth_borrowed.go, where `Config.fromEnv` reaches it for
//     PM_OAUTH_ACCESS_TTL / PM_OAUTH_REFRESH_TTL exactly as `Config.kt:3` imports it. This is the A4
//     copy, and `TokenTtlTest` binds to THIS one (14-auth.md:1461). 🔴 Do NOT collapse them: the
//     duplication is REPRODUCE, and unifying it silently re-couples MCP TTL policy to wire-token TTL
//     policy with no compile error at the seam.
//
// A1's config reaches these two as package constants — there is no PM_* variable for either, so
// nothing needs to flow the other way.
const (
	// SessionTTLSeconds (12h) is `POST /api/wire-tokens`'s default when the client omits ttlSeconds.
	SessionTTLSeconds int64 = 43_200
	// DefaultUserTTLSeconds (1h) is `POST /api/tokens`'s default. The two differ, deliberately.
	DefaultUserTTLSeconds int64 = 3_600
)

// ClampTTLSeconds is `clampTtlSeconds`.
//
// 🔒 It is THE single choke point. Neither mint route clamps: the clamp lives inside [Store.Issue],
// so it is applied exactly once on every path — `/api/wire-tokens`, `/api/tokens`,
// `/auth/session/renew`, the device poll, and A7's two ephemeral kinds. A port that moved the clamp
// out to the routes would have to clamp at all six call sites or lose INV-A4-52 on whichever one it
// forgot. KEEP IT IN Issue.
//
// ⚠️ 🔒 F26 (00-INDEX.md:215) — REPRODUCED, NOT FIXED. THE TIMEOUT LADDER IS NOT TOTAL.
// A7 computes `runTokenTtlSeconds = max(900, queryTimeout + 180)` and passes it through here, where
// it is capped at [MaxTTLSeconds] (86 400). `PM_QUERY_TIMEOUT` is bounded only by an overflow guard
// (`MAX_QUERY_TIMEOUT_SECONDS = 9_223_372_006`, Config.kt:138). So for any query timeout above
// 86_400 - 180 = 86_220 s (~23 h 57 m), the run token is SILENTLY CLAMPED TO EXPIRE MID-STATEMENT —
// exactly the failure `TOKEN_TTL_GRACE_SECONDS` exists to prevent, and the ladder A1's and A7's own
// docs asserted was unconditional.
//
// 🔴 DO NOT ADD THE MISSING BOUND HERE, and do not add one to the config guard either. The fix is a
// separate, reviewable decision taken before or after cutover, never inside the port
// (00-INDEX.md:13-29). `ConfigGuardTest.kt:65-79` asserts only the PURE function and passes
// regardless, which is why the hole survived; TestClampTTLSecondsLadderIsNotTotal in this package is
// the REPRODUCE+PIN test that makes a later fix change an assertion visibly.
func ClampTTLSeconds(ttlSeconds int64) int64 {
	if ttlSeconds < MinTTLSeconds {
		return MinTTLSeconds
	}
	if ttlSeconds > MaxTTLSeconds {
		return MaxTTLSeconds
	}
	return ttlSeconds
}

// Hash is `tokenHash(token)` (Tokens.kt:85-90): SHA-256 hex over the token's UTF-8 bytes.
//
// 🔒 INV-A4-53. Kotlin's `token.toByteArray()` uses the platform default charset, which is UTF-8 in
// practice; Go strings are already UTF-8, so the bytes match.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Identity is the row `resolve` / `validate` project — Kotlin's WireIdentity(principal, roles, kind).
//
// ⚠️ Roles is the SNAPSHOT stored on the row at issuance, not a server-side resolution. A10's
// ValidateToken returns it verbatim (F25), while A10's `decide` uses it ONLY as the assume-role set
// for the two ephemeral kinds and NEVER for SESSION/USER (INV-A10-12/-13).
type Identity struct {
	Principal string
	Roles     []string
	Kind      string
}

// Issued is `IssuedToken(token, id, kind, name, expiresAt)` (04-auth-session-tokens.md §1.3).
//
// Token is the plaintext secret — "Returned exactly once at issuance, the only time the plaintext
// token is visible" (Tokens.kt:58). Nothing may log it and nothing may re-derive it: only
// `token_hash` is stored.
//
// ExpiresAt is a STRING because the Kotlin DTO's is: `Instant.toString()`, variable-precision, via
// internal/instant.Format. `expires_at::text` (Postgres's own rendering, `2026-08-02 03:04:05+00`)
// is NOT that format and would be a silent wire break — see [Store.Issue].
type Issued struct {
	Token     string  `json:"token"`
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Name      *string `json:"name,omitempty"`
	ExpiresAt string  `json:"expiresAt"`
}

// Info is `WireTokenInfo` (04-auth-session-tokens.md §1.3) — the row shape `GET /api/tokens` lists
// and `DELETE /api/tokens/{id}` loads before authorizing.
//
// All four timestamps are `getTimestamp(...)?.toInstant()?.toString()`. `expiresAt` is
// NON-nullable — its Kotlin comment is "always set — proxy-monster issues only expiring tokens",
// which is INV-A4-52 restated at the DTO — while `revokedAt` and `lastUsedAt` are nullable and are
// therefore OMITTED when absent, per INV-A1-4's explicitNulls=false. Hence *string for those two and
// a plain string for `expiresAt`.
type Info struct {
	ID         int64   `json:"id"`
	Kind       string  `json:"kind"`
	Principal  string  `json:"principal"`
	Name       *string `json:"name,omitempty"`
	CreatedAt  string  `json:"createdAt"`
	ExpiresAt  string  `json:"expiresAt"`
	RevokedAt  *string `json:"revokedAt,omitempty"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

// Store is `class TokenStore(dataSource)`.
type Store struct{ db store.DB }

// NewStore wires the store over the shared pool.
func NewStore(db store.DB) *Store { return &Store{db: db} }

// RandomToken is `randomToken(prefix)`: prefix + base64url-nopad(32 bytes) = 256 bits of CSPRNG.
func RandomToken(kind Kind) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("token CSPRNG read failed: %w", err)
	}
	return kind.Prefix() + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Issue is `issue(kind, principal, roles, name, ttlSeconds[, c])`.
//
// The two Kotlin overloads (`:115` no-connection / `:125` connection-taking) are ONE method here
// taking a [store.Queryer]; the pool satisfies it for the autocommit case. Duplicating the SQL is how
// the two forms drift apart (04-auth-session-tokens.md §3.8).
//
// 🔒 INV-A4-54 — `expires_at` comes back from RETURNING on the SAME connection, never from a second
// read that could see a different/uncommitted view of the row.
func (s *Store) Issue(
	ctx context.Context, c store.Queryer, kind Kind, principal string, roles []string, name *string, ttlSeconds int64,
) (Issued, error) {
	tok, err := RandomToken(kind)
	if err != nil {
		return Issued{}, err
	}
	if roles == nil {
		roles = []string{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return Issued{}, err
	}
	var (
		id        int64
		expiresAt time.Time
	)
	err = c.QueryRow(ctx,
		`INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at)
		     VALUES ($1, $2, $3, $4::jsonb, $5, now() + ($6::bigint * interval '1 second'))
		     RETURNING id, expires_at`,
		Hash(tok), string(kind), principal, string(rolesJSON), name, ClampTTLSeconds(ttlSeconds),
	).Scan(&id, &expiresAt)
	if err != nil {
		return Issued{}, err
	}
	// `IssuedToken.expiresAt` is `Instant.toString()`, not Postgres's `::text` rendering. The two
	// differ in the separator (' ' vs 'T'), the zone suffix ('+00' vs 'Z') and the fraction rule, so
	// scanning the column as text would put a shape on the wire that `pmon` and web/ have never seen.
	return Issued{Token: tok, ID: id, Kind: string(kind), Name: name, ExpiresAt: instant.Format(expiresAt)}, nil
}

// Resolve is `resolve(token)` — the per-query READ path.
//
// 🔒 INV-A4-55 / INV-A10-10: same existence/revocation/expiry predicate as [Store.Validate] but
// WITHOUT the `last_used_at` write, and accepting all FOUR kinds.
func (s *Store) Resolve(ctx context.Context, tok string) (*Identity, error) {
	return s.scanIdentity(ctx, s.db.QueryRow(ctx,
		`SELECT principal, roles, kind FROM proxy_token
		     WHERE token_hash = $1
		       AND kind IN ('SESSION','USER','EDITOR','APPROVER_EXEC')
		       AND revoked_at IS NULL
		       AND expires_at > now()`,
		Hash(tok)))
}

// Validate is `validate(token)` — the once-per-session handshake WRITE path.
//
// 🔒 INV-A4-56 / INV-A10-21: the two ephemeral kinds are excluded, so a leaked EDITOR or
// APPROVER_EXEC token can never open a native MySQL/PG session as that principal within its TTL.
func (s *Store) Validate(ctx context.Context, tok string) (*Identity, error) {
	return s.scanIdentity(ctx, s.db.QueryRow(ctx,
		`UPDATE proxy_token SET last_used_at = now()
		     WHERE token_hash = $1
		       AND kind IN ('SESSION','USER')
		       AND revoked_at IS NULL
		       AND expires_at > now()
		     RETURNING principal, roles, kind`,
		Hash(tok)))
}

// infoSelect is the projection [Store.List] and [Store.Get] share. All four timestamps come back as
// TIMESTAMPTZ and are rendered by internal/instant, never by `::text`.
const infoSelect = `SELECT id, kind, principal, name, created_at, expires_at, revoked_at, last_used_at
	                      FROM proxy_token`

// List is `list(principal)`: `WHERE principal = ? AND kind IN ('SESSION','USER') ORDER BY created_at
// DESC`.
//
// The two-kind filter excludes the transient editor-channel credentials (EDITOR, APPROVER_EXEC) —
// a one-shot console-editor token is not a credential a human manages — and implicitly excludes the
// MCP kinds, which A11's own surface owns.
//
// Returns an EMPTY slice, never nil: the route puts it straight on the wire and INV-A1-4 requires
// `[]` for an empty list.
func (s *Store) List(ctx context.Context, principal string) ([]Info, error) {
	rows, err := s.db.Query(ctx,
		infoSelect+` WHERE principal = $1 AND kind IN ('SESSION','USER') ORDER BY created_at DESC`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Info{}
	for rows.Next() {
		info, err := scanInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// Get is `get(id)`: `WHERE id = ?` — WITH NO KIND FILTER AT ALL, unlike [Store.List].
//
// ⚠️ 🔒 F27 (task brief) = A4-F21 (04-auth-session-tokens.md §5, `Tokens.kt:216,324`) — REPRODUCED
// AND PINNED, NOT FIXED. This asymmetry is the whole finding, and it is a live authorization hazard:
//
//  1. `DELETE /api/tokens/{id}` loads the row through THIS method (INV-A4-5 — before authorizing, so
//     Cedar decides against the token's REAL owner and kind). Because there is no kind filter, the id
//     may name an `MCP_ACCESS`, `MCP_REFRESH`, `EDITOR` or `APPROVER_EXEC` row — none of which
//     [Store.List] would ever have shown the caller.
//  2. The route then builds the Cedar resource with `TokenKind.fromWire(row.kind)`. For the two MCP
//     kinds that returns nil ([KindFromWire] has only the four enum members), so the resource is
//     built with `kind` ABSENT — and per A2 INV-A2-3 ABSENCE IS THE PERMISSIVE DIRECTION for a
//     kind-scoped forbid. `Tokens.kt:26-30` claims the null makes "callers fail closed"; at this call
//     site it does the exact opposite.
//  3. Reachability is LIVE, not theoretical: the shipped `system:token-admin` seed permits
//     `token.revoke` on any principal's tokens (V8__seed.sql:128-129) and the neighbouring hard
//     forbid `system:token-no-cross-mint` covers `token.mint` ONLY (:136-137). No shipped seed
//     forbids by kind. So an admin can already revoke another principal's MCP access token or
//     in-flight editor token through this route.
//
// Ownership IS still enforced — [Store.Revoke]'s `AND principal = ?` is a real second check — so the
// hole is a cross-KIND one, not a cross-USER one.
//
// 🔴 Adding `AND kind IN ('SESSION','USER')` here would fix the finding and change an observable
// status code (404 instead of 204) on a security path. That is a separate decision. See
// TestGetHasNoKindFilter.
func (s *Store) Get(ctx context.Context, id int64) (*Info, error) {
	info, err := scanInfo(s.db.QueryRow(ctx, infoSelect+` WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &info, nil
}

// Revoke is `revoke(id, principal)`: `UPDATE … SET revoked_at = now() WHERE id = ? AND principal = ?
// AND revoked_at IS NULL` → rows > 0.
//
// Idempotent: a second revoke of the same token returns false, which the route maps to 404. The
// `principal = ?` predicate is INV-A4-5's belt-and-braces ownership check — the Cedar gate at the
// route is the real one, but this one is what keeps ownership enforced even under the F27 kind hole
// documented on [Store.Get].
//
// ⚠️ The previous signature in this package took only an id. It was A10's sliver of the revoke path
// (proving INV-A10-9: a mid-session revocation takes effect on the NEXT query, not at session end)
// and had no callers; it is replaced here by the Kotlin's real two-argument shape rather than kept
// alongside it, because two revokes with different ownership semantics is precisely the drift the
// Kotlin's single method avoids. A10's property is unchanged — pass the token's own principal.
func (s *Store) Revoke(ctx context.Context, id int64, principal string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE proxy_token SET revoked_at = now()
		     WHERE id = $1 AND principal = $2 AND revoked_at IS NULL`, id, principal)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RevokeAllForPrincipal is `revokeAllForPrincipal(principal[, c])` → rows revoked.
//
// 🔒 INV-A4-57 — THE DEPROVISIONING BACKSTOP KILLS LIVE CREDENTIALS MID-WINDOW. Verbatim
// (Tokens.kt:236-241): "a SCIM `active=false` push or a failed IdP liveness recheck kills live
// credentials mid-window, without waiting for natural expiry."
//
// The `expires_at > now()` predicate makes it idempotent AND leaves already-expired rows untouched,
// so the returned count means "how many LIVE credentials did this deprovision actually kill" — a
// number a teardown asserts on (A3's DeprovisionDbTest case 4 sums exactly 6).
//
// ⚠️ It revokes EVERY kind, including MCP_ACCESS and MCP_REFRESH — correct for a deprovision, and the
// one place in A4's code where the MCP kinds are handled at all. Do not narrow the statement to the
// four enum members: the enum is not the table's kind vocabulary.
func (s *Store) RevokeAllForPrincipal(ctx context.Context, c store.Queryer, principal string) (int64, error) {
	if c == nil {
		c = s.db
	}
	tag, err := c.Exec(ctx,
		`UPDATE proxy_token SET revoked_at = now()
		     WHERE principal = $1 AND revoked_at IS NULL AND expires_at > now()`, principal)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// scanInfo is the private `ResultSet.toInfo()`.
func scanInfo(row pgx.Row) (Info, error) {
	var (
		info                  Info
		createdAt, expiresAt  time.Time
		revokedAt, lastUsedAt *time.Time
	)
	if err := row.Scan(&info.ID, &info.Kind, &info.Principal, &info.Name,
		&createdAt, &expiresAt, &revokedAt, &lastUsedAt); err != nil {
		return Info{}, err
	}
	info.CreatedAt = instant.Format(createdAt)
	info.ExpiresAt = instant.Format(expiresAt)
	info.RevokedAt = instant.FormatPtr(revokedAt)
	info.LastUsedAt = instant.FormatPtr(lastUsedAt)
	return info, nil
}

// Deactivation is the narrow slice of A3's UserGroupStore [MintForActivePrincipalLocked] needs. It is
// satisfied by *identity.UserGroupStore.
type Deactivation interface {
	IsDeactivatedOn(ctx context.Context, c store.Queryer, principal string) (bool, error)
}

// MintForActivePrincipalLocked is A3's `DataSource.mintForActivePrincipalLocked(principal,
// userGroupStore, mint)` (Deprovision.kt:99). A nil result means DEPROVISIONED, which every mint
// route maps to 403 `auth.principal_deprovisioned`.
//
// 🔒 INV-A3-7 / INV-A4-58 — THE CHECK AND THE MINT RUN ON ONE TRANSACTION UNDER THE PER-PRINCIPAL
// ADVISORY LOCK. Both mint routes call `requireAuthz(TOKEN_MINT, …)` AND THEN wrap the INSERT in
// this. Verbatim (Tokens.kt:279-282): "A deprovisioned principal must not mint fresh wire
// credentials, even mid-session — and the check + the INSERT run on ONE transaction under the
// per-principal advisory lock, so a concurrent SCIM/liveness teardown can't slip its revoke between
// them and leave a token that survives the deprovision (resurrectable on a later reactivation)."
// A concurrent teardown takes the SAME lock, so it either commits fully before the lock is acquired
// (the check then reads deactivated → nil, nothing is minted) or fully after this transaction commits
// (its sweep revokes whatever the mint just inserted).
//
//	TODO(A3): this symbol is A3's, and it is hosted here only because internal/identity has not
//	          ported Deprovision.kt yet and A4's two mint routes are the named funnels for it (plus
//	          the device-poll session mint). RELOCATE it to internal/identity when A3 lands, and
//	          delete this copy — do not leave two.
//
// It is a free generic function because the mint result is the caller's type and a Go method cannot
// take a type parameter.
func MintForActivePrincipalLocked[T any](
	ctx context.Context, db store.Beginner, deact Deactivation, principal string,
	mint func(ctx context.Context, c store.Queryer) (T, error),
) (*T, error) {
	return store.InTx(ctx, db, func(ctx context.Context, tx pgx.Tx) (*T, error) {
		if err := store.AdvisoryLockPrincipal(ctx, tx, principal); err != nil {
			return nil, err
		}
		deactivated, err := deact.IsDeactivatedOn(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if deactivated {
			return nil, nil
		}
		out, err := mint(ctx, tx)
		if err != nil {
			return nil, err
		}
		return &out, nil
	})
}

// scanIdentity is shared by the two predicates above. `roles` defaults to "[]" when the column reads
// NULL, exactly as the Kotlin does.
func (s *Store) scanIdentity(_ context.Context, row pgx.Row) (*Identity, error) {
	var (
		principal string
		rolesRaw  *string
		kind      string
	)
	if err := row.Scan(&principal, &rolesRaw, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	raw := "[]"
	if rolesRaw != nil {
		raw = *rolesRaw
	}
	var roles []string
	if err := json.Unmarshal([]byte(raw), &roles); err != nil {
		return nil, fmt.Errorf("decode proxy_token.roles: %w", err)
	}
	if roles == nil {
		roles = []string{}
	}
	return &Identity{Principal: principal, Roles: roles, Kind: kind}, nil
}
