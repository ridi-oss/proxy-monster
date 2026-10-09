package routetest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/oidc"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

type Env struct {
	St        dbtest.Store
	Srv       *httptest.Server
	Forwarded []string
	Authz     fakeAuthz
	Kotlin    FakeKotlin
}

// FakeKotlin records what Go told Kotlin and answers attached as the datasources with a proxy.
type FakeKotlin struct {
	Ended, Deleted, Attached, Notified []string
}

func (k *FakeKotlin) SessionsEnded(_ context.Context, p string) error {
	k.Ended = append(k.Ended, p)
	return nil
}

func (k *FakeKotlin) ProxiesAttached(context.Context) ([]string, error) { return k.Attached, nil }

func (k *FakeKotlin) DatasourceDeleted(_ context.Context, name string) error {
	k.Deleted = append(k.Deleted, name)
	return nil
}

func (k *FakeKotlin) RequestNotified(_ context.Context, id int64, event string) error {
	k.Notified = append(k.Notified, fmt.Sprintf("%d:%s", id, event))
	return nil
}

// fakeAuthz allows what allow lists and records every decision asked for.
type fakeAuthz struct {
	Allow     map[string]bool
	Asked     []string
	Resources []bridge.Resource
	Scopes    []bridge.Scope
	Changed   int
	// AtSignal, when set, records what another connection sees each time PoliciesChanged runs.
	AtSignal func() string
	Seen     []string
}

// Validate rejects any source containing BAD, standing in for Kotlin's Cedar validator.
func (f *fakeAuthz) Validate(_ context.Context, src string) ([]string, error) {
	if strings.Contains(src, "BAD") {
		return []string{"unrecognized action `BAD`"}, nil
	}
	return nil, nil
}

func (f *fakeAuthz) PoliciesChanged(context.Context) error {
	f.Changed++
	if f.AtSignal != nil {
		f.Seen = append(f.Seen, f.AtSignal())
	}
	return nil
}

func (f *fakeAuthz) Authorize(_ context.Context, principal, action string, resource bridge.Resource, ip string) (bool, string, error) {
	key := principal + " " + action + " " + resource.Type + ":" + resource.Principal
	f.Asked = append(f.Asked, key+" @"+ip)
	f.Resources = append(f.Resources, resource)
	if f.Allow[key] {
		return true, "", nil
	}
	return false, "no permit for " + action, nil
}

func (f *fakeAuthz) AuthorizeIn(ctx context.Context, principal, action string, resource bridge.Resource, ip string, s bridge.Scope) (bool, string, error) {
	f.Scopes = append(f.Scopes, s)
	return f.Authorize(ctx, principal, action, resource, ip)
}

func (f *fakeAuthz) MayRequest(_ context.Context, principal string, id int64, ip string) (bool, error) {
	key := fmt.Sprintf("%s task.request %d", principal, id)
	f.Asked = append(f.Asked, key+" @"+ip)
	return f.Allow[key], nil
}

func (f *fakeAuthz) MayConnect(_ context.Context, principal string, ids []int64, ip string) ([]bool, error) {
	out := make([]bool, len(ids))
	for i, id := range ids {
		key := fmt.Sprintf("%s datasource.connect %d", principal, id)
		f.Asked = append(f.Asked, key+" @"+ip)
		out[i] = f.Allow[key]
	}
	return out, nil
}

func (f *fakeAuthz) AuthorizeEach(ctx context.Context, principal, action string, resources []bridge.Resource, ip string) ([]bool, error) {
	out := make([]bool, len(resources))
	for i, r := range resources {
		out[i], _, _ = f.Authorize(ctx, principal, action, r, ip)
	}
	return out, nil
}

func Setup(t *testing.T) *Env { return SetupWith(t, nil) }

// SetupWith serves the routes with authz deciding, or the recording fake when authz is nil.
func SetupWith(t *testing.T, authz func(*pgxpool.Pool) api.Authorizer, login ...oidc.Login) *Env {
	t.Helper()
	return SetupConfig(t, Config{Authz: authz, Login: append(login, oidc.Login{})[0]})
}

// SetupSettings is SetupWith under other session settings.
func SetupSettings(t *testing.T, settings session.Settings, authz func(*pgxpool.Pool) api.Authorizer, login ...oidc.Login) *Env {
	return SetupConfig(t, Config{Settings: &settings, Authz: authz, Login: append(login, oidc.Login{})[0]})
}

type Config struct {
	Authz func(*pgxpool.Pool) api.Authorizer
	// Local decides with the Go engine over the stored policies; PoliciesChanged still reaches the fake.
	Local bool
	// Edges is PM_TRUSTED_PROXIES; "127.0.0.1" makes the test client a trusted edge.
	Edges []string
	Login oidc.Login
	// Settings replaces dbtest.Settings.
	Settings *session.Settings
}

func SetupConfig(t *testing.T, c Config) *Env {
	t.Helper()
	settings := dbtest.Settings
	if c.Settings != nil {
		settings = *c.Settings
	}
	e := &Env{St: dbtest.Open(t)}
	var decider api.Authorizer = &e.Authz
	switch {
	case c.Local:
		decider = authz.Local{Engine: authz.New(e.St.Pool), Kotlin: &e.Authz}
	case c.Authz != nil:
		decider = c.Authz(e.St.Pool)
	}
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.Forwarded = append(e.Forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	mux := http.NewServeMux()
	routes.Register(mux, e.St.Pool, api.Gate{
		Sessions:  session.NewResolver(e.St.Pool, settings),
		Kotlin:    &e.Kotlin,
		Edges:     front.ParseTrustedEdges(c.Edges),
		AuthDebug: true,
		Authz:     decider,
	}, c.Login)
	e.Srv = httptest.NewServer(front.Route(mux, forward))
	t.Cleanup(e.Srv.Close)
	return e
}

func (e *Env) Do(t *testing.T, method, path, body string, cookies []*http.Cookie) (int, string) {
	t.Helper()
	return e.DoHeader(t, method, path, body, cookies)
}

// DoHeader is Do with header name, value pairs set on the request.
func (e *Env) DoHeader(t *testing.T, method, path, body string, cookies []*http.Cookie, header ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.Srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (e *Env) EndedReason(t *testing.T, key string) string {
	t.Helper()
	var reason *string
	if err := e.St.Pool.QueryRow(context.Background(), `SELECT ended_reason FROM principal_session WHERE session_key = $1`, key).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

func (e *Env) Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.St.Pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (e *Env) Count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.St.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
