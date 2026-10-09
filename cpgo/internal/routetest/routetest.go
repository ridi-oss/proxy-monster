package routetest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

type env struct {
	St        dbtest.Store
	srv       *httptest.Server
	Forwarded []string
	Ended     []string
	Authz     fakeAuthz
}

// fakeAuthz allows what allow lists and records every decision asked for.
type fakeAuthz struct {
	Allow     map[string]bool
	Asked     []string
	Resources []bridge.Resource
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

func (f *fakeAuthz) AuthorizeEach(ctx context.Context, principal, action string, resources []bridge.Resource, ip string) ([]bool, error) {
	out := make([]bool, len(resources))
	for i, r := range resources {
		out[i], _, _ = f.Authorize(ctx, principal, action, r, ip)
	}
	return out, nil
}

func Setup(t *testing.T) *env {
	t.Helper()
	e := &env{St: dbtest.Open(t)}
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.Forwarded = append(e.Forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	mux := http.NewServeMux()
	routes.Register(mux, e.St.Pool, api.Gate{
		Sessions:      session.NewResolver(e.St.Pool, dbtest.Secret),
		EndMismatched: func(r *http.Request) { e.Ended = append(e.Ended, r.Header.Get("Cookie")) },
		AuthDebug:     true,
		Authz:         &e.Authz,
	})
	e.srv = httptest.NewServer(front.Route(mux, forward))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) Do(t *testing.T, method, path, body string, cookies []*http.Cookie) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}
