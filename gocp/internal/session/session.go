package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// The `principal_session.kind` discriminator (DaemonSession.kt:95-113). One table, two kinds.
const (
	// KindDaemon is a `pmon` CLI login: a renewal secret, a TTL, no idle deadline, no device binding.
	KindDaemon = "DAEMON"
	// KindWeb is a browser console login: a device binding, a session key, and an idle deadline.
	KindWeb = "WEB"
)

// Liveness statuses — `LIVENESS_ACTIVE` / `LIVENESS_INACTIVE` (DaemonSession.kt:52-53).
const (
	LivenessActive   = "ACTIVE"
	LivenessInactive = "INACTIVE"
)

// The six `ENDED_*` reasons (DaemonSession.kt:54-59) — a CLOSED wire vocabulary.
//
// 🔒 INV-A4-3 — only three of them ever reach the browser. A1's respondSessionUnauthorized collapses
// the set into four `SessionStatusError.reason` values; see [WireReason].
const (
	// EndedSignedOut is an explicit logout, written by PrincipalSessionStorage.invalidate.
	EndedSignedOut = "SIGNED_OUT"
	// EndedDisplaced is newest-wins: a fresher login for the same principal ended this one.
	EndedDisplaced = "DISPLACED"
	// EndedDeactivated is a SCIM `active=false` / local deprovision teardown.
	EndedDeactivated = "DEACTIVATED"
	// EndedGroupRevoked is a group-membership revocation that dropped the principal to zero roles.
	EndedGroupRevoked = "GROUP_REVOKED"
	// EndedIdpRejected is the liveness sweep observing the IdP retire the identity.
	EndedIdpRejected = "IDP_REJECTED"
	// EndedDeviceBindMismatch is INV-A4-19: a live row presented from the wrong device, or from NO
	// device at all.
	EndedDeviceBindMismatch = "DEVICE_BIND_MISMATCH"
)

// The four wire reasons A1's `respondSessionUnauthorized` (App.kt:242-253) emits.
const (
	WireReasonNone         = "none"
	WireReasonDisplaced    = "displaced"
	WireReasonBindMismatch = "bind_mismatch"
	WireReasonExpired      = "expired"
)

// WireReason is A1's `respondSessionUnauthorized` mapping, hosted here because the vocabulary it
// collapses is this package's (App.kt:242-253; 04-auth-session-tokens.md INV-A4-3).
//
// 🔒 INV-A4-3 — six stored reasons, exactly four wire values, and the collapse is deliberate:
//
//	nil (no failed-session attribute at all) → "none"
//	DISPLACED                                → "displaced"
//	DEVICE_BIND_MISMATCH                     → "bind_mismatch"
//	EVERYTHING else                          → "expired"
//
// The "everything else" arm swallows SIGNED_OUT, DEACTIVATED, GROUP_REVOKED, IDP_REJECTED and a row
// that merely ran past a deadline (whose `ended_reason` is NULL, which [Store.WebEndedReason] also
// returns as nil — so a live-but-expired row and a never-ended row give the same answer here, and
// "expired" is the correct one for both). Not surfacing DEACTIVATED avoids telling an
// unauthenticated caller that a specific account was deprovisioned. A port that leaks it changes the
// disclosure surface.
//
// The three surfaced reasons are the three the console must explain differently: "someone signed in
// elsewhere", "this browser is not the one that signed in", "your session ran out".
func WireReason(endedReason *string) string {
	if endedReason == nil {
		return WireReasonNone
	}
	switch *endedReason {
	case EndedDisplaced:
		return WireReasonDisplaced
	case EndedDeviceBindMismatch:
		return WireReasonBindMismatch
	default:
		return WireReasonExpired
	}
}

// Default web-session windows — `PrincipalSessionStore`'s constructor defaults
// (DaemonSession.kt:117-118). A1 overrides both from config (App.kt:386 passes
// `config.webSessionIdleSeconds` and `config.webSessionSlideSeconds`); these are the values a
// caller that supplies neither gets, exactly as in the Kotlin.
const (
	DefaultWebSessionIdleSeconds  int64 = 900
	DefaultWebSessionSlideSeconds int64 = 120
)

// RenewalTokenPrefix is the `pmr_` bearer-secret prefix (DaemonSession.kt `newRenewalToken`).
const RenewalTokenPrefix = "pmr_"

// DB is the handle [Store] needs.
//
// It is store.DB PLUS Acquire, and the extra method is not convenience: `create`, `touchWeb`,
// `endWeb`, `endWebBySessionKey` and `endAllWebForPrincipal` each run TWO statements that must land
// on ONE connection — `dataSource.connection.use { c -> … }` in the Kotlin — while staying in
// AUTOCOMMIT. Wrapping them in a transaction instead would freeze `now()` at the transaction's first
// statement, which is exactly the confusion INV-A4-16 and INV-A4-32 exist to prevent. *pgxpool.Pool
// satisfies this; the compile-time assertion below proves it.
type DB interface {
	store.DB
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
}

var _ DB = (*pgxpool.Pool)(nil)

// Crypto is the AES-256-GCM at-rest encryptor for `refresh_token_enc`. It is satisfied by
// *result.Crypto; the interface exists so this package does not depend on A7's store.
//
// 🔒 INV-A4-14 — a nil Crypto (PM_RESULT_KEY unset) means the refresh token is DROPPED, not stored
// in plaintext. The column stays NULL, silent renewal and the session window still work, and the IdP
// liveness recheck degrades to "can't verify, leave the cached status alone".
type Crypto interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(blob []byte) ([]byte, error)
}

// EndSeam is `onWebSessionEnded: ((String, Connection) -> Unit)?`.
//
// 🔒 INV-A4-18 / INV-A4-23 / INV-A4-30 — see this package's doc.go. The connection argument is the
// contract: the callback MUST run its writes on c, never on a handle of its own, or a rolled-back
// teardown leaves a committed delete behind.
//
// Kotlin's callback returns Unit and cannot fail visibly. Go's returns an error, which every caller
// propagates — the one deliberate divergence in this seam, recorded because it converts a silent
// cleanup failure into a failed end-write. Kotlin would have thrown out of the same `.use` block, so
// the observable outcome (the transaction does not commit) is the same.
type EndSeam func(ctx context.Context, principal string, c store.Queryer) error

// Options are the constructor arguments beyond the pool.
type Options struct {
	// Crypto is `crypto: ResultCrypto?`. nil ⇒ INV-A4-14.
	Crypto Crypto
	// WebSessionIdleSeconds is `webSessionIdleSeconds`. Zero ⇒ [DefaultWebSessionIdleSeconds].
	//
	// ⚠️ F29 — the idle window is specified TWICE: here, read by [Store.TouchWeb], and again as
	// [MintWebInput.IdleSeconds], read by [Store.MintWeb]. Nothing enforces agreement; A1 happens to
	// pass the same config value to both (App.kt:386). REPRODUCE — do not collapse them.
	WebSessionIdleSeconds int64
	// WebSessionSlideSeconds is `webSessionSlideSeconds`. Zero ⇒ [DefaultWebSessionSlideSeconds].
	WebSessionSlideSeconds int64
	// OnWebSessionEnded is the end seam.
	//
	//	TODO(A1): wire `queryResultStore.deleteEditorResultsForPrincipal` (A7) and
	//	          `runExecService.closeSessionsForPrincipal` (A7) here. Neither is ported yet, so the
	//	          seam ships defined-but-unwired: the ordering guarantee it exists for is a property
	//	          of THIS package and is pinned by its tests, independently of who eventually
	//	          registers a callback.
	OnWebSessionEnded EndSeam
}

// Store is `class PrincipalSessionStore(dataSource, crypto, webSessionIdleSeconds,
// webSessionSlideSeconds, onWebSessionEnded)` — the central symbol of A4.
type Store struct {
	db                     DB
	crypto                 Crypto
	webSessionIdleSeconds  int64
	webSessionSlideSeconds int64
	onWebSessionEnded      EndSeam
}

// NewStore builds the store over the shared pool.
func NewStore(db DB, opts Options) *Store {
	s := &Store{
		db:                     db,
		crypto:                 opts.Crypto,
		webSessionIdleSeconds:  opts.WebSessionIdleSeconds,
		webSessionSlideSeconds: opts.WebSessionSlideSeconds,
		onWebSessionEnded:      opts.OnWebSessionEnded,
	}
	if s.webSessionIdleSeconds == 0 {
		s.webSessionIdleSeconds = DefaultWebSessionIdleSeconds
	}
	if s.webSessionSlideSeconds == 0 {
		s.webSessionSlideSeconds = DefaultWebSessionSlideSeconds
	}
	return s
}

// ---------------------------------------------------------------------------------------------
// Row types — `DaemonSession.kt` §3.3
// ---------------------------------------------------------------------------------------------

// DaemonRow is `data class DaemonSessionRow`.
//
// ⚠️ SessionExpiresAt maps the **absolute_expires_at** column: the field is renamed in the Kotlin,
// the column is shared with WEB rows. Renaming it back would make the daemon/web column sharing
// invisible at the call sites that rely on it.
type DaemonRow struct {
	ID              int64
	Principal       string
	Handle          *string
	RefreshTokenEnc []byte
	TTLSeconds      int64
	// SessionExpiresAt is `absolute_expires_at`.
	SessionExpiresAt time.Time
	LastIdpCheckAt   *time.Time
	LivenessStatus   string
	CreatedAt        time.Time
}

// WebRow is `data class WebSessionRow`.
//
// Now is `clock_timestamp()` read ON THE SAME QUERY, so the client's countdown is computed in the
// DB's clock domain rather than the process's. WebRow deliberately carries NO ciphertext
// (DaemonSession.kt:311-315) — that is why [Store.WebRefreshToken] exists as a separate narrow read.
type WebRow struct {
	ID                int64
	Principal         string
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
	IdleExpiresAt     time.Time
	Now               time.Time
	DebugRequesterIP  *string
}

// LivenessCandidate is `data class LivenessCandidate` — the sweep's per-row input.
type LivenessCandidate struct {
	ID              int64
	Kind            string
	Principal       string
	RefreshTokenEnc []byte
	LastIdpCheckAt  *time.Time
}

// CreatedDaemon is `PrincipalSessionStore.CreatedDaemonSession(row, renewalToken)`. RenewalToken is
// the plaintext `pmr_` secret, "visible ONLY at creation time".
type CreatedDaemon struct {
	Row          DaemonRow
	RenewalToken string
}

// ---------------------------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------------------------

// NewRenewalToken is `newRenewalToken()`: `"pmr_" + base64url-nopad(32 random bytes)` = 256 bits.
func NewRenewalToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session: renewal-token CSPRNG read failed: %w", err)
	}
	return RenewalTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// SHA256Hex is `sha256Hex(s)` — the hash `renewal_token_hash` stores.
//
// ⚠️ Deliberate duplication in the Kotlin (DaemonSession.kt:39-43): it is "the SAME idiom
// [TokenStore]'s private hash() uses for proxy_token.token_hash, kept self-contained here rather than
// reaching into [TokenStore] (that's a different part's file; this store persists its own hashed
// secret in its own column)". The Go port keeps two functions for the same reason — token.Hash stays
// A4's token-table hasher and INV-A4-53's single definition for A7's requester-IP registry, this one
// stays the session table's. The VALUES are byte-identical either way, which is the only property
// anything depends on, and TestRenewalHashMatchesTokenHash pins it.
//
// 🔒 The hash is computed HERE, in the process, and bound as a parameter. There is no SQL-side digest
// call anywhere in this area, and adding one would put the plaintext secret into the statement text
// and therefore into pg_stat_statements and the query log.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------------------------
// Connection plumbing
// ---------------------------------------------------------------------------------------------

// withConn is `c ?: dataSource.connection.use { … }`: run body on the caller's handle when there is
// one, else on ONE pooled connection in autocommit mode.
//
// It is a free generic function rather than a method because Go methods cannot take type parameters.
func withConn[T any](
	ctx context.Context, s *Store, c store.Queryer, body func(context.Context, store.Queryer) (T, error),
) (T, error) {
	if c != nil {
		return body(ctx, c)
	}
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	defer conn.Release()
	return body(ctx, conn)
}

// ---------------------------------------------------------------------------------------------
// §3.4 — daemon lifecycle
// ---------------------------------------------------------------------------------------------

// daemonSelect is the private `companion SELECT` constant. Callers append `AND …`.
//
// 🔒 INV-A4-13 — `kind = 'DAEMON'` is hard-coded HERE so no daemon lookup can forget it.
const daemonSelect = `SELECT id, principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at,
	                          last_idp_check_at, liveness_status, created_at
	                     FROM principal_session WHERE kind = 'DAEMON'`

// Create is `create(principal, handle, refreshToken, windowSeconds, ttlSeconds[, c])`.
//
// windowSeconds is a float64 because the Kotlin binds it with `setDouble` into
// `make_interval(secs => ?)` — a fractional window is expressible and a test may use one.
//
// 🔒 INV-A4-14 — the refresh token is encrypted only when BOTH it and the crypto are present.
// Otherwise the column stays NULL and the token is dropped, never written in plaintext.
//
// 🔒 INV-A4-15 — the row is read back on the CALLER's connection (the just-inserted, still-
// uncommitted row), never through the plain [Store.GetByID], which would open a second connection
// with a different view. `respondWithMintedSession` composes create + token-issue inside
// `mintForActivePrincipalLocked`'s transaction; a second pooled connection would see nothing.
func (s *Store) Create(
	ctx context.Context, c store.Queryer,
	principal string, handle *string, refreshToken *string, windowSeconds float64, ttlSeconds int64,
) (CreatedDaemon, error) {
	enc, err := s.encryptRefresh(refreshToken)
	if err != nil {
		return CreatedDaemon{}, err
	}
	renewal, err := NewRenewalToken()
	if err != nil {
		return CreatedDaemon{}, err
	}
	return withConn(ctx, s, c, func(ctx context.Context, c store.Queryer) (CreatedDaemon, error) {
		var id int64
		err := c.QueryRow(ctx,
			`INSERT INTO principal_session (principal, handle, refresh_token_enc, ttl_seconds,
			        absolute_expires_at, liveness_status, renewal_token_hash, kind)
			      VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::double precision), $6, $7, 'DAEMON')
			   RETURNING id`,
			principal, handle, enc, ttlSeconds, windowSeconds, LivenessActive, SHA256Hex(renewal),
		).Scan(&id)
		if err != nil {
			return CreatedDaemon{}, err
		}
		row, err := s.queryOneOn(ctx, c, daemonSelect+` AND id = $1`, id)
		if err != nil {
			return CreatedDaemon{}, err
		}
		if row == nil {
			// Kotlin's `!!` on the read-back. It cannot be nil on the same connection; if it is,
			// something is very wrong and a nil row must not travel.
			return CreatedDaemon{}, fmt.Errorf("session: daemon row %d vanished between insert and read-back", id)
		}
		return CreatedDaemon{Row: *row, RenewalToken: renewal}, nil
	})
}

// GetByID is `getById(id)` — daemon-scoped through [daemonSelect].
func (s *Store) GetByID(ctx context.Context, id int64) (*DaemonRow, error) {
	return s.queryOneOn(ctx, s.db, daemonSelect+` AND id = $1`, id)
}

// GetByHandle is `getByHandle(handle)`.
func (s *Store) GetByHandle(ctx context.Context, handle string) (*DaemonRow, error) {
	return s.queryOneOn(ctx, s.db, daemonSelect+` AND handle = $1`, handle)
}

// GetByPrincipal is `getByPrincipal(principal)` — "a principal may be logged in from more than one
// daemon", so this is the MOST RECENT: `ORDER BY created_at DESC, id DESC LIMIT 1`.
func (s *Store) GetByPrincipal(ctx context.Context, principal string) (*DaemonRow, error) {
	return s.queryOneOn(ctx, s.db,
		daemonSelect+` AND principal = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, principal)
}

// GetByRenewalTokenHash is `getByRenewalTokenHash(hash)`.
//
// 🔒 INV-A4-26 — renewal resolves by the SHA-256 hash of its bearer secret and by NOTHING else.
// "Never look this up by a caller-supplied principal/handle; that was the unauthenticated-renewal
// flaw." RenewalWindowTest case 2 is the named regression.
func (s *Store) GetByRenewalTokenHash(ctx context.Context, hash string) (*DaemonRow, error) {
	return s.queryOneOn(ctx, s.db, daemonSelect+` AND renewal_token_hash = $1`, hash)
}

// WithinWindow is `withinWindow(principal)` — is the principal's most recent daemon renewal window
// still open? NO ROW ⇒ false, fail-closed.
//
// 🔒 INV-A4-27 — the `absolute_expires_at > now()` comparison runs in the DATABASE clock domain, the
// SAME clock that STAMPS the column on create and on deactivate. A CP-vs-DB clock skew must not let
// a window that was just closed to `now()` momentarily read as still open. Do NOT scan the timestamp
// and compare it against time.Now() in Go.
func (s *Store) WithinWindow(ctx context.Context, principal string) (bool, error) {
	var within bool
	err := s.db.QueryRow(ctx,
		`SELECT absolute_expires_at > now() AS within FROM principal_session
		     WHERE principal = $1 AND kind = 'DAEMON'
		     ORDER BY created_at DESC, id DESC LIMIT 1`, principal).Scan(&within)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return within, err
}

// MarkCheck is `markCheck(id, status[, c])`.
//
// ⚠️ NO `kind` filter — deliberately covers both kinds, and it is one of only two statements here
// that do (the other is [Store.StaleSessions]).
//
// 🔒 INV-A4-28 — the CASE is what stops a check-stamp from RESURRECTING an ended row's liveness. The
// sweep's Active branch calls MarkCheck(ACTIVE) after possibly having ended every web session for a
// zero-role principal; without the guard that write would flip the just-ended row back to ACTIVE.
func (s *Store) MarkCheck(ctx context.Context, c store.Queryer, id int64, status string) error {
	_, err := withConn(ctx, s, c, func(ctx context.Context, c store.Queryer) (struct{}, error) {
		_, err := c.Exec(ctx,
			`UPDATE principal_session
			     SET last_idp_check_at = now(),
			         liveness_status = CASE WHEN ended_at IS NULL THEN $1 ELSE liveness_status END
			     WHERE id = $2`, status, id)
		return struct{}{}, err
	})
	return err
}

// DeactivateAllForPrincipal is `deactivateAllForPrincipal(principal[, c])` → rows affected.
//
// 🔒 INV-A4-29 — deprovision closes EVERY daemon window for the principal, and the closure is
// DURABLE. Deactivating by principal rather than by one row id is what closes the pull-deprovision
// hole: a principal may hold several daemon sessions (several machines, re-logins), and a liveness
// sweep that finds ONE inactive must tear down every sibling, else the untouched siblings' renewal
// secrets keep minting fresh tokens. Dropping `absolute_expires_at` to now() means a later
// `/auth/session/renew` fails its WINDOW check too, not merely the liveness-status check — and it
// stays failed across a later reactivation. The `> now()` predicate makes it idempotent.
func (s *Store) DeactivateAllForPrincipal(ctx context.Context, c store.Queryer, principal string) (int64, error) {
	return withConn(ctx, s, c, func(ctx context.Context, c store.Queryer) (int64, error) {
		tag, err := c.Exec(ctx,
			`UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now()
			     WHERE principal = $1 AND kind = 'DAEMON' AND absolute_expires_at > now()`, principal)
		if err != nil {
			return 0, err
		}
		return tag.RowsAffected(), nil
	})
}

// CloseDaemonWindow is `closeDaemonWindow(id)` — [Store.DeactivateAllForPrincipal]'s UPDATE scoped to
// ONE row.
//
// ⚠️ The asymmetry with DeactivateAllForPrincipal is intentional and load-bearing: an IdP rejection
// of one refresh token is evidence about THAT TOKEN, not about the account, so it must not cascade
// to the principal's sibling sessions or their credentials.
func (s *Store) CloseDaemonWindow(ctx context.Context, id int64) (int64, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now()
		     WHERE id = $1 AND kind = 'DAEMON' AND absolute_expires_at > now()`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// StaleSessions is `staleSessions(recheckIntervalSeconds)` — the ONLY query spanning both kinds.
//
// Never-checked rows (`last_idp_check_at IS NULL`) are INCLUDED. Ended and expired rows are excluded
// in both arms, so the sweep can neither resurrect nor re-warn about a dead session.
func (s *Store) StaleSessions(ctx context.Context, recheckIntervalSeconds int64) ([]LivenessCandidate, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, kind, principal, refresh_token_enc, last_idp_check_at
		     FROM principal_session
		     WHERE (last_idp_check_at IS NULL
		            OR last_idp_check_at < now() - make_interval(secs => $1::double precision))
		       AND ((kind = 'DAEMON' AND absolute_expires_at > now())
		            OR (kind = 'WEB' AND ended_at IS NULL AND absolute_expires_at > now()
		                AND idle_expires_at > now()))`, float64(recheckIntervalSeconds))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LivenessCandidate{}
	for rows.Next() {
		var cand LivenessCandidate
		if err := rows.Scan(&cand.ID, &cand.Kind, &cand.Principal, &cand.RefreshTokenEnc, &cand.LastIdpCheckAt); err != nil {
			return nil, err
		}
		out = append(out, cand)
	}
	return out, rows.Err()
}

// UpdateRefresh is `updateRefresh(id, refreshToken)`.
//
// 🔒 INV-A4-14 — a NO-OP (early return) when no crypto is configured. It does NOT fall back to
// storing plaintext and it does NOT NULL the column.
func (s *Store) UpdateRefresh(ctx context.Context, id int64, refreshToken string) error {
	if s.crypto == nil {
		return nil
	}
	enc, err := s.crypto.Encrypt([]byte(refreshToken))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE principal_session SET refresh_token_enc = $1 WHERE id = $2`, enc, id)
	return err
}

// DecryptRefresh is `decryptRefresh(enc)`: nil when either the blob or the crypto is absent.
func (s *Store) DecryptRefresh(enc []byte) (*string, error) {
	if enc == nil || s.crypto == nil {
		return nil, nil
	}
	pt, err := s.crypto.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	out := string(pt)
	return &out, nil
}

// DecryptRefreshRow is `decryptRefresh(row)`.
func (s *Store) DecryptRefreshRow(row DaemonRow) (*string, error) {
	return s.DecryptRefresh(row.RefreshTokenEnc)
}

// encryptRefresh is `refreshToken?.let { crypto?.encrypt(it.toByteArray()) }` — nil when EITHER is
// absent. INV-A4-14.
func (s *Store) encryptRefresh(refreshToken *string) ([]byte, error) {
	if refreshToken == nil || s.crypto == nil {
		return nil, nil
	}
	return s.crypto.Encrypt([]byte(*refreshToken))
}

// ---------------------------------------------------------------------------------------------
// §3.4 — web lifecycle
// ---------------------------------------------------------------------------------------------

// MintWebInput carries [Store.MintWeb]'s arguments. Kotlin passes them positionally with two
// defaulted trailing parameters; a struct keeps the two optionals visible at the call site.
type MintWebInput struct {
	Principal    string
	RefreshToken *string
	// AbsoluteSeconds is the hard cap — `config.webSessionAbsoluteSeconds`.
	AbsoluteSeconds int64
	// IdleSeconds is the initial idle deadline. ⚠️ F29: [Store.TouchWeb] reads
	// [Options.WebSessionIdleSeconds] instead, and nothing enforces agreement.
	IdleSeconds int64
	// DeviceID is the `pm_did` cookie value. nil writes a NULL binding, which INV-A4-19 then treats
	// as a permanent mismatch on the first resolve — see [Store.ResolveWeb].
	DeviceID *string
	// DebugRequesterIP is the dev-only simulated source address (V10__debug_requester_ip.sql). NULL
	// on every non-debug login.
	DebugRequesterIP *string
}

// MintWeb is `mintWeb(...)`: the newest-wins web login. Returns the new row's id.
//
// c == nil runs the whole body in its own transaction; a non-nil c "must already be inside a
// transaction so the principal advisory lock remains held through commit".
//
// Order, and every step of it matters:
//
//  1. the per-principal advisory lock — the FIRST statement;
//  2. INSERT through a `WITH t AS (SELECT clock_timestamp())` CTE;
//  3. displace the principal's OTHER live web rows;
//  4. fire the end seam if anything was displaced.
//
// 🔒 INV-A4-16 — the three timestamps come from ONE post-lock `clock_timestamp()`, never `now()`.
// Verbatim, because a "cleanup" to now() reintroduces a live bug (DaemonSession.kt:181-186):
// "Postgres freezes now()/transaction_timestamp() at the transaction's first statement, which here is
// the advisory lock above — and that lock can block behind a concurrent login for the full idle
// window. A now()-based idle_expires_at would then be minted already in the past and 401 the very
// session it just created. clock_timestamp() reflects the real current instant; one CTE reading
// shares it across all three columns so the new row is internally consistent."
//
// 🔒 INV-A4-17 — newest-wins is scoped to (principal, kind='WEB') and EXCLUDES the new row by id.
// Sibling DAEMON rows and other principals' web rows are untouched; `id <> new` is what stops the
// mint from ending itself. Postcondition: at most one row with
// `principal = P AND kind='WEB' AND ended_at IS NULL`.
//
// 🔒 INV-A4-18 — displacement fires the end seam ON THIS CONNECTION, inside the mint transaction, so
// a rolled-back mint reverts the cleanup too and never displaces+deletes under a mint that aborts.
func (s *Store) MintWeb(ctx context.Context, c store.Queryer, in MintWebInput) (int64, error) {
	enc, err := s.encryptRefresh(in.RefreshToken)
	if err != nil {
		return 0, err
	}
	body := func(ctx context.Context, c store.Queryer) (int64, error) {
		// STEP 1 — the lock, FIRST. Everything after it is measured from a clock read taken AFTER
		// the wait, which is INV-A4-16's entire point.
		if err := store.AdvisoryLockPrincipal(ctx, c, in.Principal); err != nil {
			return 0, err
		}
		var id int64
		err := c.QueryRow(ctx,
			`WITH t AS (SELECT clock_timestamp() AS ts)
			   INSERT INTO principal_session (kind, principal, refresh_token_enc, device_id, created_at,
			           absolute_expires_at, idle_expires_at, liveness_status, debug_requester_ip)
			   SELECT 'WEB', $1, $2, $3, t.ts,
			          t.ts + make_interval(secs => $4::double precision),
			          t.ts + make_interval(secs => $5::double precision),
			          'ACTIVE', $6
			     FROM t
			   RETURNING id`,
			in.Principal, enc, in.DeviceID,
			float64(in.AbsoluteSeconds), float64(in.IdleSeconds), in.DebugRequesterIP,
		).Scan(&id)
		if err != nil {
			return 0, err
		}
		tag, err := c.Exec(ctx,
			`UPDATE principal_session
			     SET ended_at = clock_timestamp(), ended_reason = $1, liveness_status = 'INACTIVE'
			     WHERE principal = $2 AND kind = 'WEB' AND ended_at IS NULL AND id <> $3`,
			EndedDisplaced, in.Principal, id)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() > 0 && s.onWebSessionEnded != nil {
			if err := s.onWebSessionEnded(ctx, in.Principal, c); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	if c != nil {
		return body(ctx, c)
	}
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (int64, error) { return body(ctx, tx) })
}

// resolveWebSQL is the shared predicate. All three clocks are `clock_timestamp()`.
const resolveWebSQL = `SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
	                              debug_requester_ip, clock_timestamp() AS db_now
	                         FROM principal_session
	                        WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL
	                          AND absolute_expires_at > clock_timestamp()
	                          AND idle_expires_at > clock_timestamp()`

// ResolveWeb is `resolveWeb(id, deviceId)` on its own connection.
func (s *Store) ResolveWeb(ctx context.Context, id int64, deviceID *string) (*WebRow, error) {
	return withConn(ctx, s, nil, func(ctx context.Context, c store.Queryer) (*WebRow, error) {
		return s.resolveWebOn(ctx, c, id, deviceID)
	})
}

// resolveWebOn is the private `resolveWeb(id, deviceId, c)`.
//
// 🔒 INV-A4-19 — DEVICE BINDING FAILS CLOSED IN THREE WAYS, AND A MISMATCH IS TERMINAL. A live row
// presented with (a) a DIFFERENT pm_did, (b) NO pm_did at all (deviceID == nil), or (c) a
// `device_id` that is NULL in the database (a pre-binding legacy row) is not merely rejected — it is
// ENDED with DEVICE_BIND_MISMATCH, so even the correctly-bound browser cannot resurrect it.
//
// ⚠️ 🔒 F35 — THE REASON FOR (b) EXISTS ONLY IN TEST COMMENTS IN THE KOTLIN. Production
// `resolveWeb` (DaemonSession.kt:248-280) carries NO comment on this branch at all; the single most
// security-load-bearing three-way condition in the file is unannotated in exactly the function a
// "harmless" optimization would touch. 04-auth-session-tokens.md F35 requires the Go port to restate
// it here, verbatim from PrincipalSessionStoreDbTest.kt:295-297:
//
//	"A live, correctly-bound row presented with NO device id (null) must be rejected and ended, not
//	 resolved: a stolen pm_session replayed without a pm_did is exactly what device-binding defends
//	 against, so an absent device can never be treated as a wildcard match."
//
// and its companion at WebSessionRoutesDbTest.kt:542 — an absent pm_did resolves "to bind_mismatch
// exactly like a wrong one, never resolve as a wildcard match". AN ABSENT DEVICE COOKIE IS A
// MISMATCH, NOT A WILDCARD.
//
// Making the mismatch terminal converts a silent theft into a visible, self-reported session kill:
// the console gets `bind_mismatch` and the legitimate user re-authenticates.
//
// 🔒 INV-A4-20 — resolution NEVER extends idle and an expired clock never slides back to life.
// Neither branch writes `idle_expires_at` or `last_seen_at`. The no-row case writes nothing at all.
func (s *Store) resolveWebOn(ctx context.Context, c store.Queryer, id int64, deviceID *string) (*WebRow, error) {
	var (
		row            WebRow
		storedDeviceID *string
	)
	err := c.QueryRow(ctx, resolveWebSQL, id).Scan(
		&row.ID, &row.Principal, &row.CreatedAt, &row.AbsoluteExpiresAt, &row.IdleExpiresAt,
		&storedDeviceID, &row.DebugRequesterIP, &row.Now)
	if errors.Is(err, pgx.ErrNoRows) {
		// No row ⇒ nil, with NO write of any kind.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// (c) NULL in the database, (b) absent from the request, (a) different from the request — one
	// branch, three ways in, all terminal. See F35 above.
	if storedDeviceID == nil || deviceID == nil || *storedDeviceID != *deviceID {
		if _, err := s.EndWeb(ctx, c, id, EndedDeviceBindMismatch); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &row, nil
}

// TouchWeb is `touchWeb(id, deviceId)` — the session heartbeat, and the ONLY idle-extending path.
//
// 🔒 INV-A4-21 — the slide is THROTTLED, and the throttle is in the WHERE clause, not in Go. Within
// `webSessionSlideSeconds` of the last slide the UPDATE matches zero rows, so a chatty client cannot
// write the row on every request; the subsequent resolve still returns the (unmoved) session, so the
// caller sees success either way. Moving the throttle into Go would make it per-process rather than
// per-row and lose it entirely across two control-plane replicas.
//
// 🔒 INV-A4-22 — TouchWeb can NEVER move `absolute_expires_at`: it is not in the SET list. That is
// the whole point of having two clocks — idle is a convenience, absolute is the security bound.
//
// ⚠️ The device predicate is `device_id = $3` in SQL, which is NULL-unsafe: a NULL-`device_id` row
// never matches, and neither does a NULL request device. Same fail-closed outcome as INV-A4-19 but
// reached through SQL three-valued logic rather than an explicit branch — and then the resolve that
// follows takes the explicit branch and ENDS the row. REPRODUCE both mechanisms; they compose.
//
// Both statements run on ONE autocommit connection, per [DB].
func (s *Store) TouchWeb(ctx context.Context, id int64, deviceID *string) (*WebRow, error) {
	return withConn(ctx, s, nil, func(ctx context.Context, c store.Queryer) (*WebRow, error) {
		_, err := c.Exec(ctx,
			`UPDATE principal_session
			     SET idle_expires_at = now() + make_interval(secs => $2::double precision),
			         last_seen_at = now()
			     WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL
			       AND absolute_expires_at > clock_timestamp()
			       AND idle_expires_at > clock_timestamp()
			       AND device_id = $3
			       AND (last_seen_at IS NULL
			            OR last_seen_at < now() - make_interval(secs => $4::double precision))`,
			id, float64(s.webSessionIdleSeconds), deviceID, float64(s.webSessionSlideSeconds))
		if err != nil {
			return nil, err
		}
		return s.resolveWebOn(ctx, c, id, deviceID)
	})
}

// EndWeb is `endWeb(id, reason, c = null)`.
//
// 🔒 INV-A4-23 — the callback runs on the SAME connection as the end-write, and ONLY on a real
// transition. The `ended_at IS NULL` guard makes a repeat end idempotent and preserves the FIRST
// reason — critical, because a session ended DISPLACED must not be relabelled SIGNED_OUT by a later
// logout, or INV-A4-3's UX inverts ("someone signed in elsewhere" silently becomes "your session ran
// out"). No row ⇒ false and NO callback.
//
// ⚠️ F30 — `now()` here, `clock_timestamp()` in [Store.MintWeb]'s displacement. Not currently
// reachable differently. REPRODUCE.
func (s *Store) EndWeb(ctx context.Context, c store.Queryer, id int64, reason string) (bool, error) {
	return withConn(ctx, s, c, func(ctx context.Context, c store.Queryer) (bool, error) {
		var principal string
		err := c.QueryRow(ctx,
			`UPDATE principal_session
			     SET ended_at = now(), ended_reason = $1, liveness_status = 'INACTIVE'
			     WHERE id = $2 AND kind = 'WEB' AND ended_at IS NULL
			   RETURNING principal`, reason, id).Scan(&principal)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if s.onWebSessionEnded != nil {
			if err := s.onWebSessionEnded(ctx, principal, c); err != nil {
				return false, err
			}
		}
		return true, nil
	})
}

// WebEndedReason is `webEndedReason(id)`: `SELECT ended_reason … WHERE id = ? AND kind='WEB'`.
//
// Returns nil for a DAEMON row, for a nonexistent id, AND for a live web row (whose `ended_reason`
// is NULL). That third case is what makes A1's "expired" the answer for a row that merely ran past a
// deadline — see [WireReason] and INV-A4-3. Consumed only by `respondSessionUnauthorized`.
func (s *Store) WebEndedReason(ctx context.Context, id int64) (*string, error) {
	var reason *string
	err := s.db.QueryRow(ctx,
		`SELECT ended_reason FROM principal_session WHERE id = $1 AND kind = 'WEB'`, id).Scan(&reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return reason, err
}

// WebRefreshToken is `webRefreshToken(id)`.
//
// 🔒 INV-A4-24 — the `ended_at IS NULL` filter is a SECURITY check, not a convenience. Verbatim
// (DeviceAuth.kt:331-333): "webRefreshToken() is read from the STILL-LIVE row (ended_at IS NULL): a
// session the liveness sweep rejected between resolve and here is already ended, so this returns null
// and the guard below refuses to approve from it — a credential is never minted off an
// authentication that was just invalidated."
func (s *Store) WebRefreshToken(ctx context.Context, id int64) (*string, error) {
	var enc []byte
	err := s.db.QueryRow(ctx,
		`SELECT refresh_token_enc FROM principal_session
		     WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL`, id).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.DecryptRefresh(enc)
}

// WebSessionIsLive is `webSessionIsLive(id)` — re-check RIGHT NOW, because a request's resolved
// identity is cached per call (INV-A4-11).
//
// ⚠️ F30, both halves, REPRODUCED: `now()` rather than `clock_timestamp()`, and `idle_expires_at IS
// NULL` TOLERATED where [Store.ResolveWeb] rejects it. Neither is currently reachable differently —
// the caller runs on a fresh autocommit connection with no advisory lock, and WEB rows always have an
// idle deadline — but the file's own comments argue at length that the choice is load-bearing, so the
// divergence is carried across rather than smoothed over.
func (s *Store) WebSessionIsLive(ctx context.Context, id int64) (bool, error) {
	var one int
	err := s.db.QueryRow(ctx,
		`SELECT 1 FROM principal_session
		     WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL AND absolute_expires_at > now()
		       AND (idle_expires_at IS NULL OR idle_expires_at > now())`, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// EndAllWebForPrincipal is `endAllWebForPrincipal(principal, reason[, c])` → rows ended.
//
// 🔒 INV-A4-30 — the bulk end composes into the CALLER's teardown transaction. Verbatim
// (DaemonSession.kt:491-497): "Deprovision + group-revocation both bulk-end here; route through the
// same end seam as logout so the principal's saved editor results are dropped. Composed onto the
// caller-supplied connection [c] so it is part of deprovision's atomic teardown transaction — a
// later statement that aborts the teardown rolls the result deletion back too, instead of a separate
// committed delete orphaning a session the rollback keeps alive."
func (s *Store) EndAllWebForPrincipal(ctx context.Context, c store.Queryer, principal, reason string) (int64, error) {
	return withConn(ctx, s, c, func(ctx context.Context, c store.Queryer) (int64, error) {
		tag, err := c.Exec(ctx,
			`UPDATE principal_session
			     SET ended_at = now(), ended_reason = $1, liveness_status = 'INACTIVE'
			     WHERE principal = $2 AND kind = 'WEB' AND ended_at IS NULL`, reason, principal)
		if err != nil {
			return 0, err
		}
		ended := tag.RowsAffected()
		if ended > 0 && s.onWebSessionEnded != nil {
			if err := s.onWebSessionEnded(ctx, principal, c); err != nil {
				return 0, err
			}
		}
		return ended, nil
	})
}

// ---------------------------------------------------------------------------------------------
// §3.2 — the Ktor tracker-id ↔ row linkage, as an explicit three-function seam
// ---------------------------------------------------------------------------------------------

// ErrUnknownWebSessionKey is `PrincipalSessionStorage.read`'s `NoSuchElementException("Unknown web
// session key")` — Ktor's contract for "no session". Go has no exceptions, so the sentinel carries
// the same signal to the cookie middleware.
var ErrUnknownWebSessionKey = errors.New("Unknown web session key")

// LinkWebSessionKey is `linkWebSessionKey(rowId, key)` — the `write` half of the seam.
//
// 🔒 INV-A4-25 — the STEAL must precede the CLAIM, in ONE transaction.
// `idx_principal_session_session_key` is a PARTIAL UNIQUE index (`WHERE session_key IS NOT NULL`,
// V6__sessions.sql:71-72), so claiming before releasing would violate it. Both statements in one
// transaction means a crash can never leave the key orphaned on a stale row.
func (s *Store) LinkWebSessionKey(ctx context.Context, rowID int64, key string) error {
	return store.InTxDo(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE principal_session SET session_key = NULL
			     WHERE session_key = $1 AND kind = 'WEB' AND id <> $2`, key, rowID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE principal_session SET session_key = $1 WHERE id = $2 AND kind = 'WEB'`, key, rowID)
		return err
	})
}

// WebIDBySessionKey is `webIdBySessionKey(key)` — the `read` half. Returns
// [ErrUnknownWebSessionKey] when nothing matches.
//
// 🔒 INV-A4-12 — THERE IS NO `ended_at` FILTER, DELIBERATELY. Class doc
// (PrincipalSessionStorage.kt:6-11): "reading returns refs for live or ended rows without sliding
// idle time, because request-time resolution owns liveness, device binding, and the ended-reason
// surface; invalidation ends only an active row and preserves a prior terminal reason."
//
// This is load-bearing for INV-A4-3: if the lookup filtered out ended rows, `webSession()` would
// never learn the sessionId, FAILED_WEB_SESSION would stay unset, and every terminated session would
// report "none" instead of "displaced" / "bind_mismatch". A Go port that "optimizes" this by adding
// `AND ended_at IS NULL` silently destroys the whole ended-reason UX.
func (s *Store) WebIDBySessionKey(ctx context.Context, key string) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx,
		`SELECT id FROM principal_session WHERE session_key = $1 AND kind = 'WEB'`, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUnknownWebSessionKey
	}
	return id, err
}

// EndWebBySessionKey is `endWebBySessionKey(key, reason)` — the `invalidate` half, called at logout
// with [EndedSignedOut].
//
// 🔒 INV-A4-7 — A1's `/auth/logout` only CLEARS the cookie; the end-write happens here. A Go port
// with no session-storage abstraction MUST call this explicitly at logout, or logout stops ending
// rows and a "signed out" session stays resolvable from a replayed cookie.
//
// Same first-reason-wins guard as [Store.EndWeb], and the same end seam on the same autocommit
// connection.
func (s *Store) EndWebBySessionKey(ctx context.Context, key, reason string) (bool, error) {
	return withConn(ctx, s, nil, func(ctx context.Context, c store.Queryer) (bool, error) {
		var principal string
		err := c.QueryRow(ctx,
			`UPDATE principal_session
			     SET ended_at = now(), ended_reason = $1, liveness_status = 'INACTIVE'
			     WHERE session_key = $2 AND kind = 'WEB' AND ended_at IS NULL
			   RETURNING principal`, reason, key).Scan(&principal)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if s.onWebSessionEnded != nil {
			if err := s.onWebSessionEnded(ctx, principal, c); err != nil {
				return false, err
			}
		}
		return true, nil
	})
}

// ---------------------------------------------------------------------------------------------
// §3.4 — renewal
// ---------------------------------------------------------------------------------------------

// RenewLocked is `renewLocked(row, isDeactivated, mint)` — the locked core of
// `POST /auth/session/renew`. A nil result is the route's 401 `auth.session_window_expired`.
//
// 🔒 INV-A4-31 — EVERY fail-closed check is re-run UNDER THE LOCK against a FRESH read. Verbatim
// (DaemonSession.kt:550-556): "open a transaction, take the per-principal advisory lock first,
// re-select [row] by id, and re-run every fail-closed check against that fresh read. Authoritative
// deprovisioning takes the same lock, so it either commits before this re-read or tears down the
// credential after this transaction commits." The pre-lock row handed in by the route is ONLY an
// identifier carrier; none of its field values are trusted.
//
// 🔒 INV-A4-34 — renewal reads CACHED liveness and never calls the IdP. The timer sweep is the sole
// revalidator. Two reasons: renew is on `pmon`'s critical path and must not inherit IdP latency, and
// an IdP outage must not become a fleet-wide logout.
//
// It is a free generic function because the mint result is A4's `IssuedToken` (internal/token) and a
// Go method cannot take a type parameter — keeping it generic is also what stops this package from
// depending on the token store.
func RenewLocked[T any](
	ctx context.Context, s *Store, row DaemonRow,
	isDeactivated func(ctx context.Context, principal string, c store.Queryer) (bool, error),
	mint func(ctx context.Context, fresh DaemonRow, c store.Queryer) (T, error),
) (*T, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*T, error) {
		// "may block for a while behind a concurrent teardown" — which is precisely why the window
		// check below must use clock_timestamp().
		if err := store.AdvisoryLockPrincipal(ctx, tx, row.Principal); err != nil {
			return nil, err
		}
		fresh, err := s.queryOneOn(ctx, tx, daemonSelect+` AND id = $1`, row.ID)
		if err != nil {
			return nil, err
		}
		if fresh == nil {
			return nil, nil
		}
		within, err := s.withinWindowOn(ctx, tx, fresh.ID)
		if err != nil {
			return nil, err
		}
		if !within {
			return nil, nil
		}
		deactivated, err := isDeactivated(ctx, fresh.Principal, tx)
		if err != nil {
			return nil, err
		}
		if deactivated || fresh.LivenessStatus == LivenessInactive {
			return nil, nil
		}
		out, err := mint(ctx, *fresh, tx)
		if err != nil {
			return nil, err
		}
		return &out, nil
	})
}

// withinWindowOn is the private `withinWindowOn(c, id)`.
//
// 🔒 INV-A4-32 — `clock_timestamp()`, NOT `now()`, and the reason is the lock wait. Verbatim
// (DaemonSession.kt:576-583): "Postgres's now() is frozen at the enclosing TRANSACTION's start, not
// the current instant — [renewLocked] takes the advisory lock before this check and can block on it
// for a while, so now() here could still reflect a moment BEFORE that wait, letting a window that has
// since actually expired read as still open." The mirror image of INV-A4-16, the same class of bug,
// and invisible to any test that does not hold the lock.
func (s *Store) withinWindowOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	var within bool
	err := c.QueryRow(ctx,
		`SELECT absolute_expires_at > clock_timestamp() FROM principal_session
		     WHERE id = $1 AND kind = 'DAEMON'`, id).Scan(&within)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return within, err
}

// ---------------------------------------------------------------------------------------------
// private scan helpers — `queryOne` / `queryOneOn` / `ResultSet.toRow`
// ---------------------------------------------------------------------------------------------

func (s *Store) queryOneOn(ctx context.Context, c store.Queryer, sql string, args ...any) (*DaemonRow, error) {
	var row DaemonRow
	err := c.QueryRow(ctx, sql, args...).Scan(
		&row.ID, &row.Principal, &row.Handle, &row.RefreshTokenEnc, &row.TTLSeconds,
		&row.SessionExpiresAt, &row.LastIdpCheckAt, &row.LivenessStatus, &row.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}
