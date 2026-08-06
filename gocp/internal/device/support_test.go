package device

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The DB + route fixture for DeviceLoginStoreDbTest's port.
//
// 🔴 The daemon-session half is the REAL A4 store — [session.Store] — not a double. Only the two
// seams that genuinely do not exist yet are stood in for, and each is written to be
// behaviour-faithful rather than merely to compile:
//
//   - [testWebLogin] stands in for `ApplicationCall.webSession()` (Auth.kt), the request-level helper
//     A1 owns. It resolves a cookie to a REAL principal_session WEB row through session.Store, so the
//     ended/live behaviour INV-A4-47 depends on comes from the store rather than from a flag in a map.
//   - [testMinter] stands in for A3's mintForActivePrincipalLocked, and it is NOT a stub: it takes
//     the REAL per-principal advisory lock (store.AdvisoryLockPrincipal) inside a REAL transaction
//     and re-checks deprovisioning through the REAL identity.UserGroupStore, exactly as
//     Deprovision.kt:99 does. Case 14 asserts "exactly one session row", which is a claim about
//     transactionality — a double that committed each write separately could pass it by luck.
//
//	TODO(A4): delete testWebLogin in favour of Auth.kt's webSession() port.
//	TODO(A3): delete testMinter in favour of Deprovision.kt's mintForActivePrincipalLocked.

// testWebLogin resolves the fixture's session cookie to a live WEB row through the real store.
type testWebLogin struct {
	store *session.Store
}

// sessionCookie is the fixture's pm_session: the row id, in plaintext. It is NOT A4's signed cookie —
// this fixture only needs "which session is this browser", and A4's real cookie is exercised by
// internal/session's own suites.
const sessionCookie = "pm_session_test"

func (s testWebLogin) WebSession(ctx context.Context, r *http.Request) (*WebSession, error) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil
	}
	id, err := strconv.ParseInt(ck.Value, 10, 64)
	if err != nil {
		return nil, nil
	}
	// 🔒 ResolveWeb enforces both web clocks AND the pm_did bind (INV-A4-19), so the request's own
	// device cookie has to be passed. A nil here is NOT a shortcut: a NULL/mismatched binding ENDS
	// the row permanently, which is exactly the behaviour the Kotlin's webSession() relies on.
	row, err := s.store.ResolveWeb(ctx, id, session.DeviceCookieID(r))
	if err != nil || row == nil {
		return nil, err
	}
	return &WebSession{ID: row.ID, Principal: row.Principal}, nil
}

// testMinter is A3's mintForActivePrincipalLocked, implemented against the REAL primitives.
type testMinter struct {
	db    store.DB
	users *identity.UserGroupStore
}

func (m testMinter) MintForActivePrincipalLocked(
	ctx context.Context, principal string, body func(ctx context.Context, c store.Queryer) error,
) (bool, error) {
	return store.InTx(ctx, m.db, func(ctx context.Context, tx pgx.Tx) (bool, error) {
		// 🔒 INV-A3-3 — the lock is taken FIRST, before any read or write.
		if err := store.AdvisoryLockPrincipal(ctx, tx, principal); err != nil {
			return false, err
		}
		// 🔒 INV-A3-7 — the deprovisioning check reads on the SAME transaction that holds the lock.
		deactivated, err := m.users.IsDeactivatedOn(ctx, tx, principal)
		if err != nil {
			return false, err
		}
		if deactivated {
			return false, nil
		}
		if err := body(ctx, tx); err != nil {
			return false, err
		}
		return true, nil
	})
}

// deviceFixture is the wired device-route host.
type deviceFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	store    *LoginStore
	sessions *session.Store
	tokens   *token.Store
	server   *httptest.Server
	client   *http.Client
	cfg      config.Config
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)

	// The Kotlin fixture's `resultKey = ByteArray(32) { it.toByte() }`.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypto, err := result.NewCrypto(key)
	if err != nil {
		t.Fatalf("result crypto: %v", err)
	}

	cfg := config.Defaults()
	cfg.AuthDebug = true
	cfg.SessionSecret = "test-secret-at-least-32-chars-long!!"
	cfg.SessionWindowSeconds = 3600
	cfg.ResultKey = key

	sessions := session.NewStore(db.Pool, session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
	})
	f := &deviceFixture{
		t: t, ctx: context.Background(), db: db,
		store:    NewLoginStore(db.Pool, crypto),
		sessions: sessions,
		tokens:   token.NewStore(db.Pool),
		cfg:      cfg,
	}

	rt := &Routes{
		Config:   cfg,
		Store:    f.store,
		Web:      testWebLogin{store: sessions},
		Sessions: sessions,
		Tokens:   f.tokens,
		Minter:   testMinter{db: db.Pool, users: identity.NewUserGroupStore(db.Pool)},
		// The REAL codec, so the pm_device_verify cookie under test is the one production writes.
		Cookies: session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
	}
	mux := http.NewServeMux()
	rt.Register(mux)
	// The Kotlin fixture's /test/login-as/{principal}.
	mux.HandleFunc("GET /test/login-as/{principal}", func(w http.ResponseWriter, r *http.Request) {
		// The Kotlin fixture's comment: "Bind the session to this browser's device cookie exactly as
		// the real OIDC callback does — resolveWeb refuses a session whose stored device_id doesn't
		// match the request's cookie."
		deviceID, err := session.EnsureDeviceCookie(w, r, false)
		if err != nil {
			t.Errorf("ensure device cookie: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		id, err := sessions.MintWeb(r.Context(), nil, session.MintWebInput{
			Principal:       r.PathValue("principal"),
			RefreshToken:    types.Ptr("web-refresh-secret"),
			AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
			IdleSeconds:     cfg.WebSessionIdleSeconds,
			DeviceID:        &deviceID,
		})
		if err != nil {
			t.Errorf("login-as: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: itoa(id), Path: "/"})
		w.WriteHeader(http.StatusOK)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	f.client = &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return f
}

func (f *deviceFixture) do(method, path, body string) *http.Response {
	f.t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, f.server.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, f.server.URL+path, nil)
	}
	if err != nil {
		f.t.Fatalf("build %s %s: %v", method, path, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// startLogin is the Kotlin helper of the same name, including its three shape assertions.
func (f *deviceFixture) startLogin() StartResponse {
	f.t.Helper()
	resp := f.do(http.MethodPost, "/auth/device/start", "{}")
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("start status = %d, want 200", resp.StatusCode)
	}
	var out StartResponse
	decode(f.t, resp, &out)
	if out.Handle == "" || out.UserCode == "" {
		f.t.Fatalf("start returned a blank handle/userCode: %+v", out)
	}
	if want := "/device?user_code=" + out.UserCode; !strings.HasSuffix(out.VerificationURIComplete, want) {
		f.t.Fatalf("verificationUriComplete = %q, want it to end with %q — start must point at the web /device page",
			out.VerificationURIComplete, want)
	}
	return out
}

func (f *deviceFixture) confirm(userCode string) *http.Response {
	return f.do(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+userCode+`"}`)
}

func (f *deviceFixture) authorize(userCode string) *http.Response {
	return f.do(http.MethodGet, "/auth/device/authorize?user_code="+userCode, "")
}

func (f *deviceFixture) poll(handle string) *http.Response {
	return f.do(http.MethodPost, "/auth/device/poll", `{"handle":"`+handle+`"}`)
}

func (f *deviceFixture) loginAs(principal string) {
	f.t.Helper()
	if resp := f.do(http.MethodGet, "/test/login-as/"+principal, ""); resp.StatusCode != http.StatusOK {
		f.t.Fatalf("login-as status = %d", resp.StatusCode)
	}
}

func (f *deviceFixture) row(handle string) *LoginRow {
	f.t.Helper()
	row, err := f.store.Get(f.ctx, handle)
	if err != nil {
		f.t.Fatalf("Get(%q): %v", handle, err)
	}
	return row
}

func (f *deviceFixture) statusOf(handle string) string {
	f.t.Helper()
	row := f.row(handle)
	if row == nil {
		f.t.Fatalf("no device_login row for %q", handle)
	}
	return row.Status
}

func decode(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}

func location(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// itoa is the fixture's session-id cookie rendering.
func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// lastSessionID is the most recently minted web row — the fixture's single browser session.
func (f *deviceFixture) lastSessionID() int64 {
	f.t.Helper()
	var id int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT id FROM principal_session WHERE kind = 'WEB' ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		f.t.Fatalf("read the web session id: %v", err)
	}
	return id
}
