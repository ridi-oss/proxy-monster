package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `tokenRoutes` — 04-auth-session-tokens.md §2.1 and §3.8.
//
// ORACLE. Two cases are 1:1 ports of `TokenRoutesDeactivationTest` (its whole content — the suite has
// exactly two @Test methods) and are marked as such. The rest are NEW, written against §2.1's route
// table and §3.8's symbol notes, because §4.17's coverage-gap list is explicit that nothing else in
// the Kotlin suite HTTP-calls these four endpoints: INV-A4-5's load-before-authorize, INV-A4-6's
// absent kind, the 200-vs-201 split, the two differing TTL defaults and F27 all have zero assertions
// anywhere in the JVM tree.
// ---------------------------------------------------------------------------------------------

const (
	caller = "caller@example.com"
	victim = "victim@example.com"
)

// ---- fixture -----------------------------------------------------------------------------------

type fakeStorage struct{ keys map[string]int64 }

func newFakeStorage() *fakeStorage { return &fakeStorage{keys: map[string]int64{}} }

func (f *fakeStorage) Write(_ context.Context, key string, ref session.WebSessionRef) error {
	f.keys[key] = ref.SessionID
	return nil
}

func (f *fakeStorage) Read(_ context.Context, key string) (session.WebSessionRef, error) {
	id, ok := f.keys[key]
	if !ok {
		return session.WebSessionRef{}, session.ErrUnknownWebSessionKey
	}
	return session.WebSessionRef{SessionID: id}, nil
}

func (f *fakeStorage) Invalidate(_ context.Context, key string) error {
	delete(f.keys, key)
	return nil
}

type fakeResolver struct{ rows map[int64]*session.WebRow }

func newFakeResolver() *fakeResolver { return &fakeResolver{rows: map[int64]*session.WebRow{}} }

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(context.Context, int64) (*string, error) { return nil, nil }

// recordingAuthorizer captures every (action, resource) the gate asked about.
//
// 🔒 RECORDING, NOT MERELY ANSWERING, IS THE POINT for this surface. INV-A4-6's claim is about a
// resource ATTRIBUTE BEING ABSENT and INV-A4-5's is about WHOSE token the resource names — neither is
// observable from a status code. A fixture that only returned Allow/Deny would pass with every route
// asking `token.mint` on `Token(caller, USER)`.
type recordingAuthorizer struct {
	actions   []authz.AuthzAction
	resources []authz.AuthzResource
	allowed   bool
	reason    string
}

func (a *recordingAuthorizer) Authorize(
	_ string, action authz.AuthzAction, resource authz.AuthzResource, _ authz.AuthzContext,
) authz.AuthzDecision {
	a.actions = append(a.actions, action)
	a.resources = append(a.resources, resource)
	if a.allowed {
		return authz.Allow
	}
	return authz.Deny(a.reason)
}

func (a *recordingAuthorizer) reset() { a.actions, a.resources = nil, nil }

func (a *recordingAuthorizer) onlyToken(t *testing.T) (authz.AuthzAction, authz.ResourceToken) {
	t.Helper()
	if len(a.actions) != 1 {
		t.Fatalf("expected exactly one authorization, got %d: %v", len(a.actions), a.actions)
	}
	res, ok := a.resources[0].(authz.ResourceToken)
	if !ok {
		t.Fatalf("resource is %T, want authz.ResourceToken", a.resources[0])
	}
	return a.actions[0], res
}

type routeFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	handler  http.Handler
	sessions *httpapi.Sessions
	resolver *fakeResolver
	gates    *httpapi.Gates
	authz    *recordingAuthorizer
	store    *Store
	users    *identity.UserGroupStore
	seed     *dbtest.Seed
}

// routeConfig has the dev bypass OFF: with it on, requireAuthz short-circuits before Cedar and every
// gate-map claim below would be vacuous.
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = false
	cfg.SecretToken = nil
	cfg.SessionSecret = "token-route-test-session-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)

	cfg := routeConfig()
	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         newFakeStorage(),
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	az := &recordingAuthorizer{allowed: true, reason: "no policy permits it"}
	gates := &httpapi.Gates{Config: cfg, Authz: az, Sessions: sessions}

	tokenStore := NewStore(db.Pool)
	users := identity.NewUserGroupStore(db.Pool)

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(NewRoutes(gates, tokenStore, users, nil))

	return &routeFixture{
		t: t, ctx: context.Background(), db: db, handler: router.Handler(),
		sessions: sessions, resolver: resolver, gates: gates, authz: az,
		store: tokenStore, users: users, seed: dbtest.NewSeed(t, db),
	}
}

func (f *routeFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	id := int64(len(f.resolver.rows) + 1)
	now := time.Now().UTC()
	f.resolver.rows[id] = &session.WebRow{
		ID: id, Principal: principal, CreatedAt: now, Now: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	rec := httptest.NewRecorder()
	if err := f.sessions.SetWebSession(context.Background(), rec, id); err != nil {
		f.t.Fatalf("SetWebSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.SessionCookie {
			return c
		}
	}
	f.t.Fatalf("no %s cookie was written", session.SessionCookie)
	return nil
}

// do runs the request through the full plugin stack, so a decode failure surfaces as the 500
// StatusPages writes rather than as a panic escaping the test.
func (f *routeFixture) do(method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func (f *routeFixture) issue(kind Kind, principal string, name *string, ttl int64) Issued {
	f.t.Helper()
	out, err := f.store.Issue(f.ctx, f.db.Pool, kind, principal, nil, name, ttl)
	if err != nil {
		f.t.Fatalf("Issue(%s, %s): %v", kind, principal, err)
	}
	return out
}

// issueMCP writes an `MCP_ACCESS` row DIRECTLY, because A4's [Store.Issue] cannot: V7's
// `proxy_token_mcp_metadata_ck` demands the full resource/client/scope/family/consent set for an MCP
// kind and Issue binds none of them. That asymmetry IS F27's precondition — the row exists in the
// table but not in this package's vocabulary — so the fixture has to reach past the store to build it.
func (f *routeFixture) issueMCP(principal string) int64 {
	f.t.Helper()
	var consentID int64
	err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO oauth_consent (principal, client_id, resource, scope)
		     VALUES ($1, 'cli', 'https://mcp.example', 'read') RETURNING id`, principal).Scan(&consentID)
	if err != nil {
		f.t.Fatalf("seed oauth_consent: %v", err)
	}
	var id int64
	err = f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO proxy_token
		     (token_hash, kind, principal, roles, resource, client_id, scope, refresh_family, consent_id, expires_at)
		     VALUES ($1, 'MCP_ACCESS', $2, '[]'::jsonb, 'https://mcp.example', 'cli', 'read', 'fam-1', $3,
		             now() + interval '1 hour')
		     RETURNING id`,
		Hash("mcp-secret-"+principal), principal, consentID).Scan(&id)
	if err != nil {
		f.t.Fatalf("seed MCP token: %v", err)
	}
	return id
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

func assertAPIError(t *testing.T, rec *httptest.ResponseRecorder, wantCode, what string) types.ApiError {
	t.Helper()
	var body types.ApiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body is not an ApiError (%v): %s", what, err, rec.Body.String())
	}
	if body.Code != wantCode {
		t.Errorf("%s: code %q, want %q (body: %s)", what, body.Code, wantCode, rec.Body.String())
	}
	return body
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------------------------
// The gate map — 04-auth-session-tokens.md §2.1
// ---------------------------------------------------------------------------------------------

// 🔒 ALL FOUR ROUTES' (action, resource) PAIRS IN ONE SWEEP, INCLUDING THE THREE DIFFERENT KINDS.
//
// The kind on the resource is not decoration: A2 INV-A2-3 makes it the hook a policy uses to permit
// short sessions while forbidding long-lived PATs, and the three values here (SESSION, nil, USER)
// are what make that policy expressible. A route asking with the wrong one, or with a placeholder
// instead of nil, disables the policy silently.
func TestTheA4TokenGateMapIsExactlyTheSpecTable(t *testing.T) {
	f := newRouteFixture(t)
	existing := f.issue(KindUser, caller, types.Ptr("pat"), 3600)

	for _, tc := range []struct {
		name       string
		method     string
		target     string
		body       string
		wantAction authz.AuthzAction
		wantKind   *authz.TokenKind
		wantOwner  string
		wantStatus int
	}{
		{
			name: "POST /api/wire-tokens", method: http.MethodPost, target: "/api/wire-tokens", body: "{}",
			wantAction: authz.ActionTokenMint, wantKind: types.Ptr(authz.TokenKindSession),
			wantOwner: caller, wantStatus: http.StatusOK,
		},
		{
			name: "GET /api/tokens", method: http.MethodGet, target: "/api/tokens",
			wantAction: authz.ActionTokenList, wantKind: nil,
			wantOwner: caller, wantStatus: http.StatusOK,
		},
		{
			name: "POST /api/tokens", method: http.MethodPost, target: "/api/tokens", body: `{"name":"pat"}`,
			wantAction: authz.ActionTokenMint, wantKind: types.Ptr(authz.TokenKindUser),
			wantOwner: caller, wantStatus: http.StatusCreated,
		},
		{
			name: "DELETE /api/tokens/{id}", method: http.MethodDelete,
			target:     "/api/tokens/" + strconv.FormatInt(existing.ID, 10),
			wantAction: authz.ActionTokenRevoke, wantKind: types.Ptr(authz.TokenKindUser),
			wantOwner: caller, wantStatus: http.StatusNoContent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.authz.allowed, f.authz.actions, f.authz.resources = true, nil, nil
			rec := f.do(tc.method, tc.target, tc.body, f.login(caller))
			assertStatus(t, rec, tc.wantStatus, tc.name)

			action, res := f.authz.onlyToken(t)
			if action != tc.wantAction {
				t.Errorf("action %q, want %q", action, tc.wantAction)
			}
			if res.Owner != tc.wantOwner {
				t.Errorf("owner %q, want %q", res.Owner, tc.wantOwner)
			}
			switch {
			case tc.wantKind == nil && res.Kind != nil:
				t.Errorf("kind %q, want ABSENT (INV-A4-6/INV-A2-3)", *res.Kind)
			case tc.wantKind != nil && res.Kind == nil:
				t.Errorf("kind ABSENT, want %q", *tc.wantKind)
			case tc.wantKind != nil && *res.Kind != *tc.wantKind:
				t.Errorf("kind %q, want %q", *res.Kind, *tc.wantKind)
			}
		})
	}
}

// ⚠️ THE TWO MINT ROUTES ANSWER DIFFERENT SUCCESS STATUSES FOR THE SAME ACT — 200 and 201.
//
// It is stated as its own case because it is the kind of inconsistency a port "tidies" without
// noticing, and `web/` and `pmon` already depend on both (04-auth-session-tokens.md §3.8).
func TestTheTwoMintRoutesAnswerDifferentSuccessStatuses(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	cookie := f.login(caller)

	wire := f.do(http.MethodPost, "/api/wire-tokens", "{}", cookie)
	assertStatus(t, wire, http.StatusOK, "/api/wire-tokens is 200")
	user := f.do(http.MethodPost, "/api/tokens", "{}", cookie)
	assertStatus(t, user, http.StatusCreated, "/api/tokens is 201")

	// The prefixes differ too, and only by KIND: `pmt_` for SESSION, `pmk_` for everything else.
	var wireBody, userBody Issued
	decodeJSON(t, wire, &wireBody)
	decodeJSON(t, user, &userBody)
	if !strings.HasPrefix(wireBody.Token, "pmt_") {
		t.Errorf("wire token %q does not carry the SESSION prefix", wireBody.Token[:8])
	}
	if !strings.HasPrefix(userBody.Token, "pmk_") {
		t.Errorf("user token %q does not carry the non-SESSION prefix", userBody.Token[:8])
	}
	if wireBody.Kind != string(KindSession) || userBody.Kind != string(KindUser) {
		t.Errorf("kinds %q/%q, want SESSION/USER", wireBody.Kind, userBody.Kind)
	}
}

// 🔒 THE TWO TTL DEFAULTS DIFFER — 12 h for a wire session, 1 h for a generated PAT — and NEITHER
// route clamps; the clamp lives inside [Store.Issue].
//
// Measured against the ROW's own `expires_at - created_at`, in the database's clock domain, so the
// assertion is about what was actually written rather than about the constant that was read.
func TestTheTwoMintRoutesCarryDifferentTTLDefaults(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	cookie := f.login(caller)

	for _, tc := range []struct {
		target  string
		body    string
		wantTTL int64
		why     string
	}{
		{"/api/wire-tokens", "{}", SessionTTLSeconds, "wire-tokens defaults to SESSION_TTL_SECONDS (12h)"},
		{"/api/tokens", "{}", DefaultUserTTLSeconds, "tokens defaults to DEFAULT_USER_TTL_SECONDS (1h)"},
		{"/api/wire-tokens", `{"ttlSeconds":300}`, 300, "an explicit ttl is honoured verbatim"},
		{"/api/tokens", `{"ttlSeconds":999999}`, MaxTTLSeconds, "🔒 clamped by Issue, not by the route"},
		{"/api/tokens", `{"ttlSeconds":0}`, MinTTLSeconds, "🔒 zero is FLOORED to 60s, never minted expired"},
		{"/api/wire-tokens", `{"ttlSeconds":-5}`, MinTTLSeconds, "🔒 negative is floored too"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			rec := f.do(http.MethodPost, tc.target, tc.body, cookie)
			var issued Issued
			decodeJSON(t, rec, &issued)
			if got := f.ttlOf(issued.ID); got != tc.wantTTL {
				t.Errorf("%s: expires_at - created_at = %ds, want %ds", tc.why, got, tc.wantTTL)
			}
		})
	}
}

// ttlOf reads the row's own window, rounded to whole seconds.
func (f *routeFixture) ttlOf(id int64) int64 {
	f.t.Helper()
	var secs float64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT EXTRACT(EPOCH FROM (expires_at - created_at)) FROM proxy_token WHERE id = $1`, id,
	).Scan(&secs); err != nil {
		f.t.Fatalf("read ttl of %d: %v", id, err)
	}
	return int64(secs + 0.5)
}

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A4-58 — the deactivation backstop. PORT of `TokenRoutesDeactivationTest`.
// ---------------------------------------------------------------------------------------------

// PORT of `POST api-wire-tokens for a deactivated principal is refused before minting` and
// `POST api-tokens for a deactivated principal is refused before minting`.
//
// The Kotlin's kdoc: "Each assertion is written so that deleting the corresponding `isDeactivated`
// check in Tokens.kt makes exactly that test fail."
//
// This port adds a half the Kotlin leaves implicit: it asserts NO ROW WAS WRITTEN. "Refused before
// minting" is the claim, and a 403 alone is also what you would get from a route that minted and then
// noticed — which would leave a live credential for a deprovisioned principal, resurrectable on a
// later reactivation, and that is the exact failure INV-A4-58 exists to prevent.
//
// ⚠️ The Kotlin runs under `authDebug = true` with no cookie, so the caller is the `"debug-user"`
// literal and the Cedar gate is bypassed. Reproduced exactly: the fixture deactivates
// [DebugPrincipal] and sends no session, which is also what makes the case prove the LOCKED CHECK
// rather than the gate — with Cedar short-circuited, the 403 can only come from the mint.
// KT: TokenRoutesDeactivationTest.kt#POST api-tokens for a deactivated principal is refused before minting
// KT: TokenRoutesDeactivationTest.kt#POST api-wire-tokens for a deactivated principal is refused before minting
func TestMintForADeactivatedPrincipalIsRefusedBeforeMinting(t *testing.T) {
	f := newRouteFixture(t)
	f.gates.Config.AuthDebug = true
	f.seed.User(DebugPrincipal)
	f.seed.SetUserActive(DebugPrincipal, false)

	for _, target := range []string{"/api/wire-tokens", "/api/tokens"} {
		t.Run(target, func(t *testing.T) {
			before := f.countTokens(DebugPrincipal)
			rec := f.do(http.MethodPost, target, "{}")
			assertStatus(t, rec, http.StatusForbidden, target)
			assertAPIError(t, rec, CodeDeprovisioned, target)
			if after := f.countTokens(DebugPrincipal); after != before {
				t.Errorf("%s minted %d row(s) for a deprovisioned principal", target, after-before)
			}
		})
	}
}

// 🔒 THE SAME PRINCIPAL, REACTIVATED, MINTS AGAIN. The control for the case above: without it, a
// route that answered 403 unconditionally would pass, and so would one whose deactivation check was
// really a broken query returning true for everyone.
func TestAReactivatedPrincipalMintsAgain(t *testing.T) {
	f := newRouteFixture(t)
	f.gates.Config.AuthDebug = true
	f.seed.User(DebugPrincipal)
	f.seed.SetUserActive(DebugPrincipal, false)

	assertStatus(t, f.do(http.MethodPost, "/api/tokens", "{}"), http.StatusForbidden, "deactivated")
	f.seed.SetUserActive(DebugPrincipal, true)
	assertStatus(t, f.do(http.MethodPost, "/api/tokens", "{}"), http.StatusCreated, "reactivated")
}

func (f *routeFixture) countTokens(principal string) int64 {
	f.t.Helper()
	var n int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM proxy_token WHERE principal = $1`, principal).Scan(&n); err != nil {
		f.t.Fatalf("count tokens: %v", err)
	}
	return n
}

// 🔒 THE GATE RUNS BEFORE THE BODY IS READ, ON BOTH MINT ROUTES.
//
// 04-auth-session-tokens.md §2.1: "an unauthorized caller with a garbage body gets the gate's
// 401/403, never the 400. A Go port that parses the body first inverts the disclosure order — it
// tells an unauthorized caller that its JSON was malformed."
//
// Both directions are asserted: with Cedar DENYING, garbage answers 403; with Cedar ALLOWING, the
// same garbage answers the decode failure. Without the second half the first would also pass on a
// route that never read the body at all.
func TestTheMintGateRunsBeforeTheBodyIsRead(t *testing.T) {
	f := newRouteFixture(t)
	cookie := f.login(caller)

	for _, target := range []string{"/api/wire-tokens", "/api/tokens"} {
		t.Run(target+" denied + garbage", func(t *testing.T) {
			f.authz.allowed, f.authz.actions, f.authz.resources = false, nil, nil
			rec := f.do(http.MethodPost, target, `{not json`, cookie)
			assertStatus(t, rec, http.StatusForbidden, "denied first")
			assertAPIError(t, rec, "common.forbidden", "denied first")
		})
		t.Run(target+" allowed + garbage", func(t *testing.T) {
			f.authz.allowed, f.authz.actions, f.authz.resources = true, nil, nil
			rec := f.do(http.MethodPost, target, `{not json`, cookie)
			// ⚠️ D6: Ktor's ContentNegotiation answers a framework 400 here; Go's StatusPages
			// analogue answers 500 common.fallback. The port-wide divergence, recorded once on
			// CedarPolicyRoutes.receiveInput and reached here through a BARE receive.
			assertStatus(t, rec, http.StatusInternalServerError, "allowed, then the body fails")
			assertAPIError(t, rec, "common.fallback", "allowed, then the body fails")
		})
	}
}

// ⚠️ `name` IS NORMALISED: blank becomes NULL, and an absent optional is OMITTED from the response
// rather than emitted as `null` (INV-A1-4's explicitNulls=false).
func TestABlankNameIsStoredAsNullAndOmittedFromTheResponse(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	cookie := f.login(caller)

	for _, tc := range []struct{ body, why string }{
		{`{}`, "absent name"},
		{`{"name":""}`, "empty name"},
		{`{"name":"   "}`, "whitespace-only name"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			rec := f.do(http.MethodPost, "/api/tokens", tc.body, cookie)
			assertStatus(t, rec, http.StatusCreated, tc.why)
			if strings.Contains(rec.Body.String(), `"name"`) {
				t.Errorf("%s: response carries a name key: %s", tc.why, rec.Body.String())
			}
			var issued Issued
			decodeJSON(t, rec, &issued)
			info, err := f.store.Get(f.ctx, issued.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if info.Name != nil {
				t.Errorf("%s: stored name %q, want NULL", tc.why, *info.Name)
			}
		})
	}

	t.Run("a real name survives", func(t *testing.T) {
		rec := f.do(http.MethodPost, "/api/tokens", `{"name":"laptop"}`, cookie)
		var issued Issued
		decodeJSON(t, rec, &issued)
		if issued.Name == nil || *issued.Name != "laptop" {
			t.Errorf("name %v, want laptop", issued.Name)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// GET /api/tokens
// ---------------------------------------------------------------------------------------------

// ⚠️ `?principal=` DEFAULTS TO THE CALLER, and PRESENT-BUT-EMPTY IS NOT ABSENT.
//
// Go's Query().Get() returns "" for both, so a port using it alone would silently list the caller's
// tokens for `?principal=` — where the Kotlin (`queryParameters["principal"] ?: principalOf(call)`)
// lists the EMPTY principal's, i.e. none, and authorizes against `Token(owner: "")`.
func TestTheListPrincipalParamDistinguishesAbsentFromEmpty(t *testing.T) {
	f := newRouteFixture(t)
	f.issue(KindUser, caller, types.Ptr("mine"), 3600)
	f.issue(KindUser, victim, types.Ptr("theirs"), 3600)
	cookie := f.login(caller)

	for _, tc := range []struct {
		query     string
		wantOwner string
		wantRows  int
	}{
		{"", caller, 1},
		{"?principal=" + victim, victim, 1},
		{"?principal=", "", 0},
	} {
		t.Run("query="+tc.query, func(t *testing.T) {
			f.authz.allowed, f.authz.actions, f.authz.resources = true, nil, nil
			rec := f.do(http.MethodGet, "/api/tokens"+tc.query, "", cookie)
			assertStatus(t, rec, http.StatusOK, tc.query)
			_, res := f.authz.onlyToken(t)
			if res.Owner != tc.wantOwner {
				t.Errorf("authorized against owner %q, want %q", res.Owner, tc.wantOwner)
			}
			var rows []Info
			decodeJSON(t, rec, &rows)
			if len(rows) != tc.wantRows {
				t.Errorf("got %d rows, want %d", len(rows), tc.wantRows)
			}
		})
	}
}

// ⚠️ A CROSS-PRINCIPAL LIST IS AN OUTRIGHT 403, NOT A FILTERED `[]`.
//
// Worth stating because A6's neighbouring grant list does the OPPOSITE for the same `?principal=`
// shape: it forward-filters per row (INV-A6-28). Two different answers to "may you see someone else's
// rows", both reproduced as they are, and a port that unified them would break one surface or the
// other.
func TestACrossPrincipalListIsA403NotAnEmptyList(t *testing.T) {
	f := newRouteFixture(t)
	f.issue(KindUser, victim, types.Ptr("theirs"), 3600)

	f.authz.allowed = false
	rec := f.do(http.MethodGet, "/api/tokens?principal="+victim, "", f.login(caller))
	assertStatus(t, rec, http.StatusForbidden, "cross-principal list")
	assertAPIError(t, rec, "common.forbidden", "cross-principal list")
}

// 🔒 THE LIST EXCLUDES THE TWO EPHEMERAL KINDS AND THE MCP KINDS — and that exclusion is exactly what
// makes F27 below a hole rather than a curiosity: the DELETE route can reach rows this route would
// never have shown.
func TestListShowsOnlySessionAndUserKinds(t *testing.T) {
	f := newRouteFixture(t)
	f.issue(KindSession, caller, nil, 3600)
	f.issue(KindUser, caller, types.Ptr("pat"), 3600)
	f.issue(KindEditor, caller, nil, 3600)
	f.issue(KindApproverExec, caller, nil, 3600)
	f.issueMCP(caller)

	f.authz.allowed = true
	rec := f.do(http.MethodGet, "/api/tokens", "", f.login(caller))
	var rows []Info
	decodeJSON(t, rec, &rows)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (SESSION + USER only): %+v", len(rows), rows)
	}
	for _, row := range rows {
		if row.Kind != string(KindSession) && row.Kind != string(KindUser) {
			t.Errorf("kind %q leaked into the list", row.Kind)
		}
	}
}

// 🔒 INV-A1-4 — a principal with no tokens gets `[]`, not `null`.
func TestAnEmptyTokenListIsAnEmptyArray(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	rec := f.do(http.MethodGet, "/api/tokens", "", f.login(caller))
	assertStatus(t, rec, http.StatusOK, "empty list")
	if got := rec.Body.String(); got != "[]" {
		t.Errorf("body %q, want []", got)
	}
}

// ---------------------------------------------------------------------------------------------
// DELETE /api/tokens/{id} — INV-A4-5 and F27
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A4-5 — THE ROW IS LOADED BEFORE THE GATE, so Cedar decides against the token's REAL owner
// and kind, and a missing id is a 404 "before any authorization is revealed".
//
// The zero-authorizations assertion on the 404 is the load-bearing half: it is the only observable
// that distinguishes read-then-gate from gate-then-read.
func TestDeleteLoadsTheRowBeforeTheGate(t *testing.T) {
	f := newRouteFixture(t)
	theirs := f.issue(KindUser, victim, types.Ptr("theirs"), 3600)

	t.Run("the resource names the TOKEN's owner, not the caller", func(t *testing.T) {
		f.authz.allowed, f.authz.actions, f.authz.resources = false, nil, nil
		rec := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(theirs.ID, 10), "", f.login(caller))
		assertStatus(t, rec, http.StatusForbidden, "denied delete")
		_, res := f.authz.onlyToken(t)
		if res.Owner != victim {
			t.Errorf("owner %q, want the token's owner %q (not the caller %q)", res.Owner, victim, caller)
		}
		if res.Kind == nil || *res.Kind != authz.TokenKindUser {
			t.Errorf("kind %v, want USER read off the row", res.Kind)
		}
	})

	t.Run("an unknown id is 404 with no authorization at all", func(t *testing.T) {
		f.authz.allowed, f.authz.actions, f.authz.resources = false, nil, nil
		rec := f.do(http.MethodDelete, "/api/tokens/999999", "", f.login(caller))
		assertStatus(t, rec, http.StatusNotFound, "unknown id")
		body := assertAPIError(t, rec, "common.not_found", "unknown id")
		if body.Params["resource"] != NotFoundToken {
			t.Errorf("resource %q, want %q", body.Params["resource"], NotFoundToken)
		}
		if len(f.authz.actions) != 0 {
			t.Errorf("Cedar was consulted for a token that does not exist: %v", f.authz.actions)
		}
	})

	t.Run("a malformed id is 400", func(t *testing.T) {
		f.authz.allowed, f.authz.actions, f.authz.resources = false, nil, nil
		rec := f.do(http.MethodDelete, "/api/tokens/abc", "", f.login(caller))
		assertStatus(t, rec, http.StatusBadRequest, "malformed id")
		assertAPIError(t, rec, "common.bad_id", "malformed id")
		if len(f.authz.actions) != 0 {
			t.Errorf("Cedar was consulted for a malformed id: %v", f.authz.actions)
		}
	})
}

// ⚠️ 🔒 F27 / A4-F21 — REPRODUCED AND PINNED. THE DELETE ROUTE CAN TARGET AN MCP ROW, AND THE CEDAR
// RESOURCE IS THEN BUILT WITH `kind` ABSENT — THE PERMISSIVE DIRECTION.
//
// Three facts in one case, because the finding is the CONJUNCTION of all three and any one alone is
// harmless:
//
//  1. [Store.Get] has no kind filter, so the id resolves (the row is reachable at all);
//  2. [KindFromWire] does not know `MCP_ACCESS`, so `cedarKind` yields nil, so the Cedar `kind`
//     attribute is ABSENT — and per A2 INV-A2-3 an absent attribute is what a kind-scoped FORBID
//     fails to match on;
//  3. the revoke then SUCCEEDS with 204, so this is a live authorization path and not a dead branch.
//
// 🔴 If a later change adds `AND kind IN ('SESSION','USER')` to [Store.Get] — the obvious fix — this
// test FAILS at step 1 with a 404, which is the point: the fix changes an observable status code on a
// security path and must be a deliberate, reviewed decision rather than a silent tightening during
// the port.
func TestDeleteOfAnMcpRowBuildsAnAbsentCedarKind(t *testing.T) {
	f := newRouteFixture(t)
	mcpID := f.issueMCP(caller)

	// Fact 0 — the list would NEVER have shown this row.
	f.authz.allowed = true
	list := f.do(http.MethodGet, "/api/tokens", "", f.login(caller))
	if got := list.Body.String(); got != "[]" {
		t.Fatalf("the MCP row is visible in the list (%s), so this is not F27's precondition", got)
	}

	f.authz.actions, f.authz.resources = nil, nil
	rec := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(mcpID, 10), "", f.login(caller))
	assertStatus(t, rec, http.StatusNoContent, "F27: the MCP row IS revocable through this route")

	action, res := f.authz.onlyToken(t)
	if action != authz.ActionTokenRevoke {
		t.Errorf("action %q, want token.revoke", action)
	}
	if res.Kind != nil {
		t.Errorf("kind %q — F27 says it must be ABSENT for an MCP row (fromWire returns null)", *res.Kind)
	}
	if res.Owner != caller {
		t.Errorf("owner %q, want %q", res.Owner, caller)
	}

	// And the row really was revoked — the hole has an effect, it is not merely a decision shape.
	var revoked bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NOT NULL FROM proxy_token WHERE id = $1`, mcpID).Scan(&revoked); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if !revoked {
		t.Error("the MCP token was not actually revoked")
	}
}

// ⚠️ F27's OTHER HALF: an EDITOR row is equally reachable, but its kind IS in the enum, so the
// resource carries `kind: EDITOR` and a kind-scoped forbid COULD match it.
//
// Stated separately because the two halves have different security shapes: the editor case is a
// policy-expressible hole, the MCP case is not. Collapsing them into one test would lose that.
func TestDeleteOfAnEphemeralRowCarriesItsKind(t *testing.T) {
	f := newRouteFixture(t)
	editor := f.issue(KindEditor, caller, nil, 3600)

	f.authz.allowed, f.authz.actions, f.authz.resources = true, nil, nil
	rec := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(editor.ID, 10), "", f.login(caller))
	assertStatus(t, rec, http.StatusNoContent, "an in-flight editor token is revocable here")
	_, res := f.authz.onlyToken(t)
	if res.Kind == nil || *res.Kind != authz.TokenKindEditor {
		t.Errorf("kind %v, want EDITOR — fromWire knows this one", res.Kind)
	}
}

// ⚠️ THE OWNERSHIP PREDICATE IN [Store.Revoke] IS VACUOUS AT THIS CALL SITE, AND CEDAR IS THE REAL
// BOUND.
//
// The route passes `token.principal` — the row's OWN owner — so `WHERE … AND principal = ?` can never
// fail to match. 04-auth-session-tokens.md calls it a "belt-and-braces second check"; measured, it is
// belt-and-braces against nothing this route can produce, because the value is read from the very row
// being updated. What actually keeps one principal from revoking another's token is the Cedar
// decision on `Token(owner = …)` asserted in [TestDeleteLoadsTheRowBeforeTheGate].
//
// Pinned as an OBSERVATION rather than changed: a cross-principal revoke that Cedar permits (the
// shipped `system:token-admin` oversight seed) MUST succeed, and this case proves it does — which is
// also what proves the argument is the token's owner and not the caller's. A port that "fixed" the
// vacuity by passing the CALLER's principal would break token administration and fail here with a 404.
func TestRevokePassesTheTokensOwnerSoAPermittedCrossPrincipalRevokeSucceeds(t *testing.T) {
	f := newRouteFixture(t)
	theirs := f.issue(KindUser, victim, types.Ptr("theirs"), 3600)

	f.authz.allowed = true // stands in for the system:token-admin oversight seed
	rec := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(theirs.ID, 10), "", f.login(caller))
	assertStatus(t, rec, http.StatusNoContent, "an admin-permitted cross-principal revoke")

	info, err := f.store.Get(f.ctx, theirs.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.RevokedAt == nil {
		t.Error("the token was not revoked")
	}
}

// ⚠️ A SECOND DELETE IS 404, NOT AN IDEMPOTENT 204 — [Store.Revoke]'s `revoked_at IS NULL` guard
// surfaces the lost race as a missing resource, with the SAME body as an unknown id so the two are
// indistinguishable to a caller.
func TestASecondDeleteIs404WithTheSameBodyAsAnUnknownId(t *testing.T) {
	f := newRouteFixture(t)
	tok := f.issue(KindUser, caller, types.Ptr("pat"), 3600)
	cookie := f.login(caller)
	f.authz.allowed = true

	first := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(tok.ID, 10), "", cookie)
	assertStatus(t, first, http.StatusNoContent, "first delete")
	if first.Body.Len() != 0 {
		t.Errorf("204 must have no body, got %q", first.Body.String())
	}
	second := f.do(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(tok.ID, 10), "", cookie)
	unknown := f.do(http.MethodDelete, "/api/tokens/999999", "", cookie)
	assertStatus(t, second, http.StatusNotFound, "second delete")
	if second.Body.String() != unknown.Body.String() {
		t.Errorf("an already-revoked token (%s) is distinguishable from an unknown one (%s)",
			second.Body.String(), unknown.Body.String())
	}
}

// ---------------------------------------------------------------------------------------------

// Every route refuses a sessionless non-debug request with 401 common.unauthenticated. None of the
// four calls requireApi — requireAuthz subsumes it, and this is what proves the absence is not a hole.
func TestEveryTokenRouteRefusesASessionlessNonDebugRequest(t *testing.T) {
	f := newRouteFixture(t)
	tok := f.issue(KindUser, caller, nil, 3600)

	for _, tc := range []struct{ method, target, body string }{
		{http.MethodPost, "/api/wire-tokens", "{}"},
		{http.MethodGet, "/api/tokens", ""},
		{http.MethodPost, "/api/tokens", "{}"},
		{http.MethodDelete, "/api/tokens/" + strconv.FormatInt(tok.ID, 10), ""},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			f.authz.reset()
			rec := f.do(tc.method, tc.target, tc.body)
			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			assertAPIError(t, rec, "common.unauthenticated", "no session")
		})
	}
}

// ⚠️ 🔒 THE ROLES SNAPSHOT ON EVERY MINTED TOKEN IS EMPTY, EVEN FOR A LIVE SESSION.
//
// `rolesOf(call)` reads `userSession()?.roles`, and `UserSession` is constructed as
// `UserSession(it.principal)` with roles defaulting to `emptyList()` — so no session ever carries
// roles and every SESSION/USER token ships with `roles = []`. §6 Q4 asks whether that is intentional;
// REPRODUCE either way, because a port that "helpfully" resolved roles here would freeze an elevation
// into a credential that outlives the grant.
func TestEveryMintedTokenCarriesAnEmptyRolesSnapshot(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	cookie := f.login(caller)

	for _, target := range []string{"/api/wire-tokens", "/api/tokens"} {
		t.Run(target, func(t *testing.T) {
			rec := f.do(http.MethodPost, target, "{}", cookie)
			var issued Issued
			decodeJSON(t, rec, &issued)
			var roles string
			if err := f.db.Pool.QueryRow(f.ctx,
				`SELECT roles::text FROM proxy_token WHERE id = $1`, issued.ID).Scan(&roles); err != nil {
				t.Fatalf("read roles: %v", err)
			}
			if roles != "[]" {
				t.Errorf("roles %s, want [] — a session never carries roles (INV-A4-2)", roles)
			}
		})
	}
}

// compile-time proof that the production identity store satisfies the route group's narrow
// deactivation seam with no adapter. If it stops holding, the wiring breaks HERE rather than in
// internal/app.
var _ Deactivation = (*identity.UserGroupStore)(nil)
