package session_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `POST /auth/session/renew` — 04-auth-session-tokens.md §3.5, and the ROUTE half of
// `RenewalWindowTest` (§4.12).
//
// renewal_db_test.go already ports the nine STORE-level cases against [session.RenewLocked] and
// records the three route-level ones as owed:
//
//	"TODO(A4): case 2 (a principal-only JSON body with no bearer is refused — the
//	 unauthenticated-renewal attack), case 3 (a wrong or garbage bearer secret is refused) and case 4
//	 (a missing Authorization header entirely is refused) assert the route's THREE distinct 401 codes
//	 […] What is still unported is the STATUS-CODE distinction."
//
// This file discharges that TODO and re-runs the store-level refusals THROUGH the route, because
// nine green store cases plus a route that forgets to call RenewLocked is a fleet that renews
// deprovisioned credentials. Case 1 and cases 5-9 are re-asserted end to end for that reason; cases
// 10-12 (the advisory-lock serialization) stay at the store, where they are already deterministic —
// re-running them over HTTP would add a goroutine and prove nothing new about the route.
//
// The suite stands up the REAL token store and the REAL identity teardown, so the two seams
// [session.RenewRoutes] takes as functions are the production ones and not fixtures. That is the
// point of the file: `renewLocked` was already proven; what was not is that this route wires SESSION,
// the empty role snapshot, the ROW's TTL, and the locked connection into it.
// ---------------------------------------------------------------------------------------------

type renewRouteFixture struct {
	t       *testing.T
	ctx     context.Context
	db      *store.Db
	handler http.Handler
	store   *session.Store
	tokens  *token.Store
	users   *identity.UserGroupStore
	creds   *identity.Credentials
}

func newRenewRouteFixture(t *testing.T) *renewRouteFixture {
	t.Helper()
	base := newFixture(t, fixtureOpts{})
	tokens := token.NewStore(base.db.Pool)
	users := identity.NewUserGroupStore(base.db.Pool)
	accessStore := access.NewStore(base.db.Pool)
	creds := identity.NewCredentials(base.db.Pool, tokens, accessStore, base.store)

	// 🔒 THE TWO SEAMS ARE WIRED THE WAY THE COMPOSITION ROOT MUST WIRE THEM, and the four contract
	// points on RenewRoutes.Mint are all here: kind SESSION, an EMPTY role snapshot, the TTL from the
	// FRESH row, and the mint running on `c` — the locked transaction RenewLocked opened.
	// ⚠️ THE ARGUMENT ORDER DIFFERS AND AN ADAPTER IS UNAVOIDABLE. [session.RenewLocked] takes
	// `(ctx, principal, c)` because Kotlin's callback is `{ principal, c -> … }`, while
	// internal/identity follows the port's `…On(ctx, c, …)` convention. Two defensible conventions
	// meeting at one seam; the closure is where they meet, and it is two lines rather than a
	// re-ordering of either side.
	routes := session.NewRenewRoutes(base.store,
		func(ctx context.Context, principal string, c store.Queryer) (bool, error) {
			return users.IsDeactivatedOn(ctx, c, principal)
		},
		func(ctx context.Context, fresh session.DaemonRow, c store.Queryer) (session.Minted, error) {
			issued, err := tokens.Issue(ctx, c, token.KindSession, fresh.Principal, nil, nil, fresh.TTLSeconds)
			if err != nil {
				return session.Minted{}, err
			}
			return session.Minted{Token: issued.Token, ExpiresAt: issued.ExpiresAt}, nil
		}, nil)

	router := httpapi.NewRouter(httpapi.RouterOptions{})
	router.Mount(routes)

	return &renewRouteFixture{
		t: t, ctx: base.ctx, db: base.db, handler: router.Handler(),
		store: base.store, tokens: tokens, users: users, creds: creds,
	}
}

// renew sends `POST /auth/session/renew` with the given Authorization header (empty = none) and body.
func (f *renewRouteFixture) renew(authHeader, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, "/auth/session/renew", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/auth/session/renew", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func (f *renewRouteFixture) createDaemon(principal, handle string, window float64, ttl int64) session.CreatedDaemon {
	f.t.Helper()
	out, err := f.store.Create(f.ctx, nil, principal, &handle, nil, window, ttl)
	if err != nil {
		f.t.Fatalf("Create(%s): %v", principal, err)
	}
	return out
}

func assertRenewStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

func assertRenewCode(t *testing.T, rec *httptest.ResponseRecorder, wantCode, what string) {
	t.Helper()
	var body types.ApiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body is not an ApiError (%v): %s", what, err, rec.Body.String())
	}
	if body.Code != wantCode {
		t.Errorf("%s: code %q, want %q", what, body.Code, wantCode)
	}
}

// ---------------------------------------------------------------------------------------------

// PORT of case 1, `renew with the correct bearer secret inside the window mints a fresh token`.
//
// The Kotlin's assertion is `assertNotNull(tokenStore.validate(body.token))`, and that is reproduced
// verbatim rather than paraphrased — [token.Store.Validate] is the two-kind predicate, so a token
// that passes it is by construction SESSION or USER, which pins RenewRoutes.Mint's contract point 1
// (INV-A4-56: a renewed credential must be able to open a wire session, so it cannot be one of the
// ephemeral kinds).
// KT: RenewalWindowTest.kt#renew with the correct bearer secret inside the window mints a fresh token
func TestRenewWithTheCorrectBearerInsideTheWindowMintsAFreshToken(t *testing.T) {
	f := newRenewRouteFixture(t)
	created := f.createDaemon("within@example.com", "dvc_within", 3600, 900)

	rec := f.renew("Bearer "+created.RenewalToken, "")
	assertRenewStatus(t, rec, http.StatusOK, "renew inside the window")

	var body session.RenewSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not a RenewSessionResponse: %s", rec.Body.String())
	}
	if strings.TrimSpace(body.Token) == "" {
		t.Fatal("the response carries no token")
	}
	if body.ExpiresAt == "" {
		t.Error("the response carries no expiresAt")
	}
	identity, err := f.tokens.Validate(f.ctx, body.Token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if identity == nil {
		t.Fatal("the freshly-minted token does not validate")
	}
	if identity.Kind != string(token.KindSession) {
		t.Errorf("kind %q, want SESSION", identity.Kind)
	}
	if identity.Principal != "within@example.com" {
		t.Errorf("principal %q, want within@example.com", identity.Principal)
	}
	// Mint contract point 2 — the role snapshot is EMPTY (INV-A4-2).
	if len(identity.Roles) != 0 {
		t.Errorf("roles %v, want [] — a renewed token must not freeze a role set", identity.Roles)
	}
	// Mint contract point 3 — the TTL came from the ROW (900s), not from a route default.
	if got := f.ttlOf(body.Token); got != 900 {
		t.Errorf("ttl %ds, want the row's 900s", got)
	}

	// ⚠️ The response is RenewSessionResponse, NOT IssuedToken: no id, no kind, no name.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body is not an object: %s", rec.Body.String())
	}
	if len(raw) != 2 {
		t.Errorf("body has %d keys (%v), want exactly token + expiresAt", len(raw), raw)
	}
}

func (f *renewRouteFixture) ttlOf(tok string) int64 {
	f.t.Helper()
	var secs float64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT EXTRACT(EPOCH FROM (expires_at - created_at)) FROM proxy_token WHERE token_hash = $1`,
		token.Hash(tok)).Scan(&secs); err != nil {
		f.t.Fatalf("read ttl: %v", err)
	}
	return int64(secs + 0.5)
}

// PORT of cases 2, 3 and 4 — the THREE distinct 401s, which is the whole of the TODO
// renewal_db_test.go left open.
//
// 🔒 CASE 2 IS THE NAMED SECURITY REGRESSION: "a principal-only JSON body with no bearer is refused —
// the unauthenticated-renewal attack". The vulnerable shape is knowledge of the principal string
// alone. It must be refused as auth.missing_renewal_token — i.e. the route must not read the body at
// ALL, not merely fail to trust it. INV-A4-26: the row is found by the secret's hash and by nothing
// else.
//
// ⚠️ The three codes are deliberately different and the split is reproduced verbatim
// (DaemonSession.kt:642 vs :648 vs :659): "you sent no credential", "what you sent is not one I
// know", and "your window has closed" are three different things to a daemon, and only the third
// means `pmon login` again.
func TestTheThreeDistinctRenewalRefusals(t *testing.T) {
	f := newRenewRouteFixture(t)
	created := f.createDaemon("public-principal@example.com", "dvc_public", 3600, 900)

	// KT: RenewalWindowTest.kt#a principal-only JSON body with no bearer is refused — the unauthenticated-renewal attack
	t.Run("case 2 — a principal-only JSON body with no bearer", func(t *testing.T) {
		rec := f.renew("", `{"principal":"public-principal@example.com"}`)
		assertRenewStatus(t, rec, http.StatusUnauthorized, "the unauthenticated-renewal attack")
		assertRenewCode(t, rec, session.CodeMissingRenewalToken, "the unauthenticated-renewal attack")
	})

	// KT: RenewalWindowTest.kt#a wrong or garbage bearer secret is refused
	t.Run("case 3 — a wrong or garbage bearer secret", func(t *testing.T) {
		rec := f.renew("Bearer pmr_not-the-real-secret", "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "wrong secret")
		assertRenewCode(t, rec, "common.unauthenticated", "wrong secret")
	})

	// KT: RenewalWindowTest.kt#missing Authorization header entirely is refused
	t.Run("case 4 — no Authorization header at all", func(t *testing.T) {
		rec := f.renew("", "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "missing header")
		assertRenewCode(t, rec, session.CodeMissingRenewalToken, "missing header")
	})

	t.Run("a non-Bearer scheme is the MISSING code, not the unknown-secret one", func(t *testing.T) {
		rec := f.renew("Basic "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "wrong scheme")
		assertRenewCode(t, rec, session.CodeMissingRenewalToken, "wrong scheme")
	})

	// ⚠️ `removePrefix("Bearer ")` IS CASE-SENSITIVE, so a lowercase scheme is refused even though
	// RFC 7235 declares it case-insensitive. REPRODUCED — the SCIM gate carries the same quirk and
	// A5's bearerWirePrincipal deliberately does not.
	t.Run("a lowercase bearer scheme is refused", func(t *testing.T) {
		rec := f.renew("bearer "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "lowercase scheme")
		assertRenewCode(t, rec, session.CodeMissingRenewalToken, "lowercase scheme")
	})

	// ⚠️ The trim is what makes a double space work — `removePrefix(...).trim()`.
	t.Run("extra whitespace after the scheme is trimmed", func(t *testing.T) {
		rec := f.renew("Bearer  "+created.RenewalToken+" ", "")
		assertRenewStatus(t, rec, http.StatusOK, "padded secret")
	})

	// The control: the SAME session, with the SAME secret, correctly presented, renews. Without it
	// every refusal above would also pass against a route that answers 401 unconditionally.
	t.Run("control — the real secret renews", func(t *testing.T) {
		rec := f.renew("Bearer "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusOK, "control")
	})
}

// PORT of cases 5, 6, 7 — the three fail-closed refusals, driven THROUGH the route so that a route
// which skipped [session.RenewLocked] (or read the pre-lock row's fields instead of the fresh ones)
// fails here even though renewal_db_test.go stays green.
//
// 🔒 ALL THREE ANSWER THE SAME CODE. RenewLocked returns a bare nil for every one, so the route is
// STRUCTURALLY unable to tell a bearer-holder which check refused — the four re-checks stay
// re-checks rather than becoming a status API.
func TestEveryFailClosedCheckRefusesThroughTheRoute(t *testing.T) {
	f := newRenewRouteFixture(t)

	// KT: RenewalWindowTest.kt#renew after the window closed is refused even with the correct secret
	t.Run("case 5 — after the window closed, even with the correct secret", func(t *testing.T) {
		created := f.createDaemon("after@example.com", "dvc_after", 3600, 900)
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = $1`,
			created.Row.ID); err != nil {
			t.Fatalf("close the window: %v", err)
		}
		rec := f.renew("Bearer "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "closed window")
		assertRenewCode(t, rec, session.CodeSessionWindowExpired, "closed window")
	})

	// KT: RenewalWindowTest.kt#renew for a deprovisioned principal is refused even inside the window
	t.Run("case 6 — a deprovisioned principal, inside the window", func(t *testing.T) {
		const principal = "deprovisioned@example.com"
		if _, err := f.users.CreateUser(f.ctx, identity.AppUserInput{Principal: principal}, f.creds); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if _, err := f.users.SetUserActive(f.ctx, principal, false); err != nil {
			t.Fatalf("SetUserActive: %v", err)
		}
		created := f.createDaemon(principal, "dvc_deprov", 3600, 900)
		rec := f.renew("Bearer "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "deprovisioned")
		assertRenewCode(t, rec, session.CodeSessionWindowExpired, "deprovisioned")
	})

	// KT: RenewalWindowTest.kt#renew for a liveness-INACTIVE session is refused even inside the window
	t.Run("case 7 — a liveness-INACTIVE session, inside the window", func(t *testing.T) {
		created := f.createDaemon("inactive-liveness@example.com", "dvc_inactive", 3600, 900)
		if err := f.store.MarkCheck(f.ctx, nil, created.Row.ID, session.LivenessInactive); err != nil {
			t.Fatalf("MarkCheck: %v", err)
		}
		rec := f.renew("Bearer "+created.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized, "liveness INACTIVE")
		assertRenewCode(t, rec, session.CodeSessionWindowExpired, "liveness INACTIVE")
	})
}

// PORT of cases 8 and 9 — the deprovision is AUTHORITATIVE (it closes every sibling window) and
// DURABLE (reactivation cannot resurrect the secret), asserted through the route.
//
// 🔒 CASE 9 IS THE RESURRECTION TEST AND IT IS THE REASON INV-A3-5 DEMANDS ALL FOUR CREDENTIAL
// CLASSES. Deprovision is durable because the WINDOW was closed, not merely because the isDeactivated
// flag is set — so flipping the flag back must not reopen it. A teardown that revoked tokens and
// grants but left the daemon window alone would pass the "deprovisioned" case above and FAIL here.
func TestDeprovisionRefusesEverySiblingAndSurvivesReactivationThroughTheRoute(t *testing.T) {
	f := newRenewRouteFixture(t)

	// KT: RenewalWindowTest.kt#authoritative principal deprovision refuses renewal on every sibling session
	t.Run("case 8 — every sibling session", func(t *testing.T) {
		const principal = "two-daemons@example.com"
		f.createDaemon(principal, "dvc_sibling_a", 3600, 900)
		sibling := f.createDaemon(principal, "dvc_sibling_b", 3600, 900)

		// Sanity: the sibling renews BEFORE the deprovision.
		assertRenewStatus(t, f.renew("Bearer "+sibling.RenewalToken, ""), http.StatusOK, "before the teardown")

		if _, err := f.store.DeactivateAllForPrincipal(f.ctx, nil, principal); err != nil {
			t.Fatalf("DeactivateAllForPrincipal: %v", err)
		}
		rec := f.renew("Bearer "+sibling.RenewalToken, "")
		assertRenewStatus(t, rec, http.StatusUnauthorized,
			"a sibling session must not survive the principal's deprovision")
	})

	// KT: RenewalWindowTest.kt#a deprovision-then-reactivate cannot resurrect the old renewal secret (window stays closed)
	t.Run("case 9 — a deprovision-then-reactivate cannot resurrect the old renewal secret", func(t *testing.T) {
		const principal = "resurrect@example.com"
		if _, err := f.users.CreateUser(f.ctx, identity.AppUserInput{Principal: principal}, f.creds); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		created := f.createDaemon(principal, "dvc_resurrect", 3600, 900)

		// SCIM active=false: setUserActive(false) + the credential teardown.
		if _, err := f.users.SetUserActive(f.ctx, principal, false); err != nil {
			t.Fatalf("SetUserActive: %v", err)
		}
		if _, err := f.store.DeactivateAllForPrincipal(f.ctx, nil, principal); err != nil {
			t.Fatalf("DeactivateAllForPrincipal: %v", err)
		}
		assertRenewStatus(t, f.renew("Bearer "+created.RenewalToken, ""), http.StatusUnauthorized,
			"renew is refused while deprovisioned")

		// SCIM active=true again, INSIDE the original window. The secret must stay dead.
		if _, err := f.users.SetUserActive(f.ctx, principal, true); err != nil {
			t.Fatalf("SetUserActive: %v", err)
		}
		assertRenewStatus(t, f.renew("Bearer "+created.RenewalToken, ""), http.StatusUnauthorized,
			"reactivation must not resurrect the pre-deprovision renewal secret")
	})
}

// PORT of case 10, `renew mints under the lock, so an immediately-following teardown sweeps up the
// just-minted token`.
//
// 🔒 THE SHARED-LOCK CONTRACT, OBSERVED FROM THE MINT SIDE. Mint and teardown take the SAME
// per-principal advisory lock, so a teardown landing right after a renew must sweep up the token the
// renew just committed — never race past it. The token is minted through the ROUTE and torn down
// through the REAL [identity.Credentials], so this is the production pair, not two fixtures agreeing.
//
// The third assertion is the durability half: the teardown also closed the window, so the SAME
// renewal secret is refused afterwards. Without it a teardown that revoked only the token would pass.
// KT: RenewalWindowTest.kt#renew mints under the lock, so an immediately-following teardown sweeps up the just-minted token
func TestRenewMintsUnderTheLockSoAnImmediateTeardownSweepsUpTheToken(t *testing.T) {
	f := newRenewRouteFixture(t)
	const principal = "mint-then-revoke@example.com"
	created := f.createDaemon(principal, "dvc_mint_then_revoke", 3600, 900)

	rec := f.renew("Bearer "+created.RenewalToken, "")
	assertRenewStatus(t, rec, http.StatusOK, "renew")
	var minted session.RenewSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("body: %s", rec.Body.String())
	}
	if id, err := f.tokens.Validate(f.ctx, minted.Token); err != nil || id == nil {
		t.Fatalf("sanity: the freshly-minted token must validate (%v, %v)", id, err)
	}

	revoked, err := f.creds.RevokeActiveCredentials(f.ctx, principal)
	if err != nil {
		t.Fatalf("RevokeActiveCredentials: %v", err)
	}
	if revoked < 1 {
		t.Errorf("the teardown revoked %d credentials, want at least the token", revoked)
	}
	if id, err := f.tokens.Validate(f.ctx, minted.Token); err != nil || id != nil {
		t.Errorf("a teardown immediately following renew must revoke the just-minted token (got %v, %v)", id, err)
	}
	assertRenewStatus(t, f.renew("Bearer "+created.RenewalToken, ""), http.StatusUnauthorized,
		"renew after the teardown must be refused (closed window)")
}

// PORT of case 12, `revokeActiveCredentials itself blocks behind a concurrent holder of the SAME
// principal's advisory lock`.
//
// 🔒 THE OTHER HALF OF THE SHARED-LOCK CONTRACT. renewal_db_test.go's
// TestRenewBlocksBehindTheSamePrincipalLockAndObservesCommittedState proves the RENEW side takes the
// lock. This proves the TEARDOWN side does. Both are needed and neither implies the other: a teardown
// that dropped the advisory lock while still revoking sequentially would pass every renew-side test
// and reopen the renew-vs-sweep race, because serialization is a property of the PAIR.
//
// It lives here rather than in internal/identity because this file already wires the real
// [identity.Credentials] over the real token, grant and session stores — the production teardown, not
// a fixture. The lock is taken with the LITERAL `pg_advisory_xact_lock(hashtext(<principal>))`
// expression (see the fixture's holdPrincipalLock), so an implementation that hashed in-process and
// passed an integer would not serialize against this and would fail here.
//
// The Kotlin also asserts the token is STILL LIVE while the teardown is blocked. That is the
// assertion that distinguishes "blocked" from "already finished and we measured late", so it is
// reproduced rather than paraphrased.
// KT: RenewalWindowTest.kt#revokeActiveCredentials itself blocks behind a concurrent holder of the SAME principal's advisory lock
func TestRevokeActiveCredentialsBlocksBehindTheSamePrincipalLock(t *testing.T) {
	f := newRenewRouteFixture(t)
	const principal = "revoke-serializes@example.com"

	issued, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, nil, nil, 3600)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// An independent connection holds the SAME per-principal lock, mid-transaction.
	holder, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin lock holder: %v", err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()
	if _, err := holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, principal); err != nil {
		t.Fatalf("take the advisory lock: %v", err)
	}

	type result struct {
		revoked int64
		err     error
	}
	done := make(chan result, 1)
	go func() {
		n, err := f.creds.RevokeActiveCredentials(context.Background(), principal)
		done <- result{n, err}
	}()

	// It must BLOCK. The lock is taken by RevokeActiveCredentialsOn as its FIRST statement, so nothing
	// can have been revoked yet.
	select {
	case r := <-done:
		t.Fatalf("🔒 RevokeActiveCredentials completed (%d, %v) while another connection held the "+
			"principal's advisory lock. Renewal takes the SAME lock; without the wait a teardown can "+
			"slip between renew's re-check and its mint.", r.revoked, r.err)
	case <-time.After(1500 * time.Millisecond):
	}
	// …and nothing has been revoked while it waits — the assertion that makes "blocked" mean blocked.
	if got, err := f.tokens.Validate(f.ctx, issued.Token); err != nil || got == nil {
		t.Errorf("the token was revoked (%v, %v) while the teardown was still blocked on the lock", got, err)
	}

	if err := holder.Commit(f.ctx); err != nil { // releases the advisory lock
		t.Fatalf("commit the lock holder: %v", err)
	}

	var r result
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("RevokeActiveCredentials never completed after the lock was released")
	}
	if r.err != nil {
		t.Fatalf("RevokeActiveCredentials: %v", r.err)
	}
	if r.revoked < 1 {
		t.Errorf("the teardown revoked %d credentials; once the lock releases it must proceed and "+
			"revoke at least the token", r.revoked)
	}
	if got, err := f.tokens.Validate(f.ctx, issued.Token); err != nil || got != nil {
		t.Errorf("the token still validates after the teardown completed (%v, %v)", got, err)
	}
}

// ⚠️ THE ROUTE READS NO BODY AT ALL, on any path — INV-A4-26 restated as an input-space sweep.
//
// A garbage body, a huge body and a body that looks like a credential are all irrelevant: the answer
// is decided entirely by the header. A port that added a body read "for diagnostics" would start
// answering 500 common.fallback to a well-authenticated daemon that happened to send a stray byte.
func TestTheRouteIgnoresTheBodyEntirely(t *testing.T) {
	f := newRenewRouteFixture(t)
	created := f.createDaemon("body-ignored@example.com", "dvc_body", 3600, 900)

	for _, body := range []string{
		"",
		"{}",
		`{not json at all`,
		`{"principal":"someone-else@example.com"}`,
		`{"renewalToken":"pmr_forged"}`,
	} {
		t.Run("body="+body, func(t *testing.T) {
			rec := f.renew("Bearer "+created.RenewalToken, body)
			assertRenewStatus(t, rec, http.StatusOK, "the body is never read")
		})
	}
}

// compile-time proof that the group mounts as a plain RouteGroup. internal/session cannot NAME
// httpapi.RouteGroup (httpapi imports this package), so the structural match is asserted from a test
// that can see both.
var _ httpapi.RouteGroup = (*session.RenewRoutes)(nil)
