package identity

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ---------------------------------------------------------------------------------------------
// The DB support for the principal-mutating-write suites — the Go form of
// `UserAdminDeprovisionDbTest`'s `seedCredentials(principal, roleName)` / `assertWebEnded` /
// `assertWebLive` helpers, which 03-identity-scim.md:1280 says to "port these first".
//
// 🔒 THE THREE CREDENTIAL STORES ARE REAL, and that is the whole point of this fixture. Every claim
// these suites make is "after this directory write, is that credential still usable" — a question
// only the rows answer. A faked teardown would prove the store called SOMETHING, which is exactly the
// bug INV-A3-5 describes (three of four classes revoked looks identical to four of four).
//
// The one FAKE is [recordingTeardown], used only where the claim is about WHICH PRINCIPAL was torn
// down and HOW MANY TIMES — INV-A3-16's two independent branches. That is a claim about the caller,
// not about the rows, and counting is the only way to see it.
// ---------------------------------------------------------------------------------------------

type writeFixture struct {
	t   testing.TB
	ctx context.Context
	db  *store.Db

	seed  *dbtest.Seed
	store *UserGroupStore

	tokens   *token.Store
	grants   *access.Store
	sessions *session.Store
	creds    *Credentials
}

func newWriteFixture(t testing.TB) *writeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	tokens := token.NewStore(db.Pool)
	grants := access.NewStore(db.Pool)
	// Crypto is nil: nothing here mints a refresh token, and A4's own suites cover the crypto path.
	sessions := session.NewStore(db.Pool, session.Options{})
	return &writeFixture{
		t: t, ctx: context.Background(), db: db,
		seed:   dbtest.NewSeed(t, db),
		store:  NewUserGroupStore(db.Pool),
		tokens: tokens, grants: grants, sessions: sessions,
		creds: NewCredentials(db.Pool, tokens, grants, sessions),
	}
}

func (f *writeFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *writeFixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

// seededCredentials is what [writeFixture.seedCredentials] hands back so a case can address the rows
// it planted.
type seededCredentials struct {
	tokenID   int64
	grantID   int64
	daemonID  int64
	webID     int64
	principal string
}

// seedCredentials mints ONE of every credential class for principal — the four INV-A3-5 names — and
// is the direct port of UserAdminDeprovisionDbTest's helper of the same name.
func (f *writeFixture) seedCredentials(principal, roleName string) seededCredentials {
	f.t.Helper()
	roleID := f.seed.Role(roleName)

	issued, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, []string{roleName}, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue token for %s: %v", principal, err)
	}

	// The grant row A6's AccessStore.approve would have written. ⚠️ TODO(A6): re-point at the real
	// approve path — a fixture with its own INSERT is a second definition of a valid grant.
	grantID := f.scalarInt64(
		`INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
		 VALUES ($1, $2, 'approver@example.com', now() + interval '1 hour') RETURNING id`,
		principal, roleID)

	daemon, err := f.sessions.Create(f.ctx, nil, principal, nil, nil, 3600, 900)
	if err != nil {
		f.t.Fatalf("create daemon session for %s: %v", principal, err)
	}

	webID, err := f.sessions.MintWeb(f.ctx, nil, session.MintWebInput{
		Principal: principal, AbsoluteSeconds: 7200, IdleSeconds: 900,
	})
	if err != nil {
		f.t.Fatalf("mint web session for %s: %v", principal, err)
	}

	return seededCredentials{
		tokenID: issued.ID, grantID: grantID,
		daemonID: daemon.Row.ID, webID: webID, principal: principal,
	}
}

// assertAllRevoked is the "this principal has nothing usable left" assertion, all four classes.
func (f *writeFixture) assertAllRevoked(c seededCredentials, what string) {
	f.t.Helper()
	f.assertTokenRevoked(c.tokenID, true, what)
	f.assertGrantRevoked(c.grantID, true, what)
	f.assertDaemonWindowClosed(c.daemonID, true, what)
	f.assertWebEnded(c.webID, what)
}

// assertAllLive is the negative twin — a bystander must be untouched.
func (f *writeFixture) assertAllLive(c seededCredentials, what string) {
	f.t.Helper()
	f.assertTokenRevoked(c.tokenID, false, what)
	f.assertGrantRevoked(c.grantID, false, what)
	f.assertDaemonWindowClosed(c.daemonID, false, what)
	f.assertWebLive(c.webID, what)
}

func (f *writeFixture) assertTokenRevoked(id int64, want bool, what string) {
	f.t.Helper()
	var revoked bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NOT NULL FROM proxy_token WHERE id = $1`, id).Scan(&revoked); err != nil {
		f.t.Fatalf("%s: read token %d: %v", what, id, err)
	}
	if revoked != want {
		f.t.Errorf("%s: token %d revoked=%v, want %v", what, id, revoked, want)
	}
}

func (f *writeFixture) assertGrantRevoked(id int64, want bool, what string) {
	f.t.Helper()
	var revoked bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NOT NULL FROM access_grant WHERE id = $1`, id).Scan(&revoked); err != nil {
		f.t.Fatalf("%s: read grant %d: %v", what, id, err)
	}
	if revoked != want {
		f.t.Errorf("%s: grant %d revoked=%v, want %v", what, id, revoked, want)
	}
}

// assertDaemonWindowClosed checks BOTH halves of INV-A4-29's durability: the liveness flag AND the
// dropped absolute window. Checking only the flag would pass for a teardown that leaves a renewal
// secret able to mint again.
func (f *writeFixture) assertDaemonWindowClosed(id int64, want bool, what string) {
	f.t.Helper()
	var inactive, windowClosed bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT liveness_status = 'INACTIVE', absolute_expires_at <= now()
		   FROM principal_session WHERE id = $1`, id).Scan(&inactive, &windowClosed); err != nil {
		f.t.Fatalf("%s: read daemon session %d: %v", what, id, err)
	}
	if inactive != want || windowClosed != want {
		f.t.Errorf("%s: daemon %d inactive=%v windowClosed=%v, want both %v",
			what, id, inactive, windowClosed, want)
	}
}

// assertWebEnded asserts the row is ended AND carries the DEACTIVATED reason — the string A4's
// WireReason maps for the console.
func (f *writeFixture) assertWebEnded(id int64, what string) {
	f.t.Helper()
	reason, err := f.sessions.WebEndedReason(f.ctx, id)
	if err != nil {
		f.t.Fatalf("%s: read web session %d: %v", what, id, err)
	}
	if reason == nil {
		f.t.Errorf("%s: web session %d is still live, want ended", what, id)
		return
	}
	if *reason != EndedDeactivated {
		f.t.Errorf("%s: web session %d ended_reason %q, want %q", what, id, *reason, EndedDeactivated)
	}
}

func (f *writeFixture) assertWebLive(id int64, what string) {
	f.t.Helper()
	reason, err := f.sessions.WebEndedReason(f.ctx, id)
	if err != nil {
		f.t.Fatalf("%s: read web session %d: %v", what, id, err)
	}
	if reason != nil {
		f.t.Errorf("%s: web session %d was ended (%q), want still live", what, id, *reason)
	}
}

// recordingTeardown is the counting fake, for the claims that are about the CALLER rather than the
// rows: which principal strings a write asked to tear down, in what order, and how many times.
//
// It is the only way to see INV-A3-16 directly — with the real teardown, "revoked both strings" and
// "revoked one string that happened to own everything" produce the same rows.
type recordingTeardown struct {
	principals []string
	// err, when set, is returned instead of doing anything — used to prove the write rolls back with
	// the teardown rather than committing a half-torn-down state.
	err error
}

func (r *recordingTeardown) RevokeActiveCredentialsOn(
	_ context.Context, _ store.Queryer, principal string,
) (int64, error) {
	r.principals = append(r.principals, principal)
	return 0, r.err
}

func (r *recordingTeardown) assert(t *testing.T, what string, want ...string) {
	t.Helper()
	if len(r.principals) != len(want) {
		t.Fatalf("%s: revoked %v, want exactly %v", what, r.principals, want)
	}
	for i := range want {
		if r.principals[i] != want[i] {
			t.Errorf("%s: revoke #%d was %q, want %q (full order: %v)",
				what, i, r.principals[i], want[i], r.principals)
		}
	}
}

// user reads a row back by id, failing the test if it vanished.
func (f *writeFixture) user(id int64, what string) AppUser {
	f.t.Helper()
	out, err := f.store.GetUser(f.ctx, id)
	if err != nil {
		f.t.Fatalf("%s: getUser(%d): %v", what, id, err)
	}
	if out == nil {
		f.t.Fatalf("%s: user %d does not exist", what, id)
	}
	return *out
}

// userByPrincipal is the same read keyed on the string, returning nil when the row is gone — which is
// what the tombstone cases assert about.
func (f *writeFixture) userByPrincipal(principal string) *AppUser {
	f.t.Helper()
	out, err := f.store.GetUserByPrincipal(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("getUserByPrincipal(%s): %v", principal, err)
	}
	return out
}

func (f *writeFixture) isDeactivated(principal string) bool {
	f.t.Helper()
	out, err := f.store.IsDeactivated(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("isDeactivated(%s): %v", principal, err)
	}
	return out
}
