package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// testScimConfig is `internal fun testScimConfig(scimToken, trustedProxies = emptySet()): Config`
// (ScimAuthTest.kt:106) — "a full Config where every field but scimToken/trustedProxies is inert.
// PORT THIS FIXTURE; it is the only place a minimal valid Config is constructed for a gate test."
//
// 🔒 `AuthDebug: true` is the load-bearing field, not an incidental one: it is what makes every case
// in scim_gate_test.go a proof of INV-A3-38 / F33 — the SCIM gate has no PM_AUTH_DEBUG bypass even
// though two documentation files say it does. Do not "clean this up" to false.
func testScimConfig(scimToken *string, trustedProxies ...string) config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = true
	cfg.SecretToken = nil
	cfg.SessionSecret = "test-only-session-secret"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = scimToken
	cfg.SessionWindowSeconds = 3600
	cfg.IdpRecheckIntervalSeconds = 600
	cfg.DevMarker = true
	cfg.TrustedProxies = map[string]struct{}{}
	for _, p := range trustedProxies {
		cfg.TrustedProxies[p] = struct{}{}
	}
	return cfg
}

// gateConfig is the fixture for the three session-based gates: like testScimConfig but with the
// bypass OFF, because a gate suite with authDebug on tests only step 1.
func gateConfig() config.Config {
	cfg := testScimConfig(nil)
	cfg.AuthDebug = false
	cfg.SessionSecret = "gate-test-session-secret-at-least-32-chars"
	return cfg
}

// ---------------------------------------------------------------------------------------------
// Fakes for the two session seams
//
// internal/session's own DB suites prove the SQL behind these (storage_db_test.go, websession_db_test.go).
// What THIS package owns is the request-time plumbing over them, so the seams are faked: the suites
// stay container-free and can drive the failure modes — an unknown key, a resolver error, a NULL
// ended_reason — that are awkward to stage against a real row.
// ---------------------------------------------------------------------------------------------

type fakeStorage struct {
	// keys is the session_key -> row id map linkWebSessionKey maintains.
	keys map[string]int64
	// ended records the keys invalidate() was called with, in order.
	ended []string
	// readErr, when set, is returned by Read instead of a lookup.
	readErr error
}

func newFakeStorage() *fakeStorage { return &fakeStorage{keys: map[string]int64{}} }

func (f *fakeStorage) Write(_ context.Context, key string, ref session.WebSessionRef) error {
	f.keys[key] = ref.SessionID
	return nil
}

func (f *fakeStorage) Read(_ context.Context, key string) (session.WebSessionRef, error) {
	if f.readErr != nil {
		return session.WebSessionRef{}, f.readErr
	}
	id, ok := f.keys[key]
	if !ok {
		return session.WebSessionRef{}, session.ErrUnknownWebSessionKey
	}
	return session.WebSessionRef{SessionID: id}, nil
}

func (f *fakeStorage) Invalidate(_ context.Context, key string) error {
	f.ended = append(f.ended, key)
	return nil
}

type fakeResolver struct {
	// rows is the id -> live row map resolveWeb answers from.
	rows map[int64]*session.WebRow
	// endedReasons is the id -> ended_reason map webEndedReason answers from. An id ABSENT here
	// answers nil, which is what a row that merely ran past its deadline looks like.
	endedReasons map[int64]string
	// resolveErr, when set, is returned by ResolveWeb — the "database is down mid-request" path.
	resolveErr error
	// resolveCalls counts round trips, so the per-request caching invariant is observable.
	resolveCalls int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{rows: map[int64]*session.WebRow{}, endedReasons: map[int64]string{}}
}

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	f.resolveCalls++
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(_ context.Context, id int64) (*string, error) {
	reason, ok := f.endedReasons[id]
	if !ok {
		return nil, nil
	}
	return &reason, nil
}

// ---------------------------------------------------------------------------------------------

// testSessions builds a Sessions over the fakes, with a codec whose secret matches gateConfig's.
func testSessions(storage SessionStorage, resolver WebSessionResolver) *Sessions {
	return &Sessions{
		Codec:           session.NewCookieCodec(gateConfig().SessionSecret, "http://127.0.0.1:8080"),
		Storage:         storage,
		Resolver:        resolver,
		AbsoluteSeconds: 7200,
	}
}

// requestWithIdentity builds a request that has been through [Sessions.Install], which every real
// request has.
func requestWithIdentity(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, &resolvedIdentity{}))
}

// loginCookie mints a tracker key, links it to rowID, and returns the cookie a browser would send.
func loginCookie(t *testing.T, s *Sessions, storage *fakeStorage, rowID int64) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := s.SetWebSession(context.Background(), rec, rowID); err != nil {
		t.Fatalf("SetWebSession: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != session.SessionCookie {
		t.Fatalf("expected exactly one %s cookie, got %+v", session.SessionCookie, cookies)
	}
	if len(storage.keys) != 1 {
		t.Fatalf("expected the tracker key to be linked before the cookie was written, got %v", storage.keys)
	}
	return cookies[0]
}

// decodeBody unmarshals a recorded response body into dst, failing the test on malformed JSON.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("response body is not JSON (%v): %s", err, rec.Body.String())
	}
}

// assertStatus fails with the body attached, which is the difference between a five-second and a
// five-minute diagnosis on a gate test.
func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

var errStoreDown = errors.New("connection refused")
