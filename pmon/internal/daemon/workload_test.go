package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers"
	"github.com/ridi-oss/proxy-monster/pmon/internal/workload"
)

type workloadCP struct {
	*httptest.Server
	mu        sync.Mutex
	seen      []string
	revoked   []string
	principal string
	minted    atomic.Int32
	refuse    atomic.Bool
	ttl       time.Duration
}

func newWorkloadCP(t *testing.T, datasources []driver.Endpoint) *workloadCP {
	t.Helper()
	cp := &workloadCP{ttl: 15 * time.Minute, principal: "svc:batch-settlement"}
	cp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/workload/exchange":
			var in struct{ Token, Purpose string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			cp.mu.Lock()
			replayed := strings.Contains(strings.Join(cp.seen, " "), in.Token)
			cp.seen = append(cp.seen, in.Token)
			cp.mu.Unlock()
			switch {
			case in.Purpose != "wire":
				w.WriteHeader(http.StatusBadRequest)
			case cp.refuse.Load():
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":"workload.no_binding","params":{}}`))
			case replayed:
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":"workload.token_replayed","params":{}}`))
			default:
				n := cp.minted.Add(1)
				cp.mu.Lock()
				principal := cp.principal
				cp.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("pms_%d", n), "id": n, "kind": "SERVICE",
					"name": "batch-settlement", "principal": principal, "expiresAt": time.Now().Add(cp.ttl).UTC().Format(time.RFC3339)})
			}
		case "/api/workload/revoke":
			cp.mu.Lock()
			cp.revoked = append(cp.revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			cp.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case "/api/datasources":
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer pms_") {
				t.Errorf("discovery Authorization = %q, want the SERVICE token", got)
			}
			_ = json.NewEncoder(w).Encode(datasources)
		case "/api/instance":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected control-plane path %q", r.URL.Path)
		}
	}))
	t.Cleanup(cp.Close)
	return cp
}

type countingSource struct {
	n         atomic.Int32
	audiences chan string
}

func (s *countingSource) Token(_ context.Context, audience string) (string, error) {
	select {
	case s.audiences <- audience:
	default:
	}
	return fmt.Sprintf("jwt-%d", s.n.Add(1)), nil
}

func withSource(t *testing.T, src workload.Source) {
	t.Helper()
	prev := parseWorkloadSource
	parseWorkloadSource = func(spec string) (workload.Source, error) {
		if spec != "env:TEST_JWT" && spec != "file:/test/jwt" {
			return nil, fmt.Errorf("unexpected spec %q", spec)
		}
		return src, nil
	}
	t.Cleanup(func() { parseWorkloadSource = prev })
}

func TestWorkloadLoginBrokersWithAServiceTokenAndNoPrompt(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, []driver.Endpoint{{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)}})
	src := &countingSource{audiences: make(chan string, 4)}
	withSource(t, src)
	d := New("test", providers.Builtins())
	if err := d.ensureLocalPassword(); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL + "/", Workload: "env:TEST_JWT"}, func(ev control.LoginEvent) {
		kinds = append(kinds, ev.Kind)
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()
	if len(kinds) != 1 || kinds[0] != "done" {
		t.Errorf("events = %v, want only done", kinds)
	}
	if got := <-src.audiences; got != strings.TrimSuffix(cp.URL, "/") {
		t.Errorf("audience = %q, want the control plane origin", got)
	}
	s := d.Status()
	srv := s.Server("default")
	if srv == nil || !srv.LoggedIn || srv.Principal != "svc:batch-settlement" || srv.Workload != "env:TEST_JWT" {
		t.Fatalf("server = %+v", srv)
	}
	saved := d.snapshot().Servers["default"]
	if saved.Token != "pms_1" || saved.RenewalToken != "" {
		t.Errorf("saved = %+v", saved)
	}
	if len(s.Datasources) != 1 || !s.Datasources[0].Brokered {
		t.Fatalf("datasources = %+v", s.Datasources)
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.Datasources[0].LocalPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial the broker: %v", err)
	}
	c.Close()
}

func TestWorkloadRenewalExchangesAFreshTokenAndRetriesARefusal(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	cp.ttl = 2 * time.Minute
	src := &countingSource{audiences: make(chan string, 8)}
	withSource(t, src)
	d := New("test", providers.Builtins())
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "file:/test/jwt", Audience: "https://pm.example.com"},
		func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()
	if got := <-src.audiences; got != "https://pm.example.com" {
		t.Errorf("audience = %q, want the override", got)
	}

	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	if got := d.snapshot().Servers["default"].Token; got != "pms_2" {
		t.Fatalf("token after renewal = %q, want a fresh exchange", got)
	}
	cp.mu.Lock()
	seen := strings.Join(cp.seen, ",")
	cp.mu.Unlock()
	if got := seen; got != "jwt-1,jwt-2" {
		t.Errorf("exchanged %s, want a fresh platform token each time", got)
	}

	cp.refuse.Store(true)
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	srv := d.snapshot().Servers["default"]
	if srv.Token != "pms_2" || !srv.LoggedIn() {
		t.Fatalf("a refused renewal dropped the login: %+v", srv)
	}
	d.mu.Lock()
	refused := d.reauthRequired["default"]
	d.mu.Unlock()
	if refused {
		t.Error("a refused workload renewal must keep retrying, not wait for a human")
	}
	cp.refuse.Store(false)
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	if got := d.snapshot().Servers["default"].Token; got != "pms_3" {
		t.Errorf("token after recovery = %q", got)
	}
}

func TestWorkloadRenewalWaitsForTheLeadTime(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	withSource(t, &countingSource{audiences: make(chan string, 4)})
	d := New("test", providers.Builtins())
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "file:/test/jwt"}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	if n := cp.minted.Load(); n != 1 {
		t.Errorf("a fresh 15-minute token was renewed early: %d exchanges", n)
	}
}

func TestLogoutForgetsTheWorkloadSource(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	withSource(t, &countingSource{audiences: make(chan string, 4)})
	d := New("test", providers.Builtins())
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "env:TEST_JWT"}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := d.Logout(control.LogoutRequest{}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if srv := d.snapshot().Servers["default"]; srv.LoggedIn() || srv.Workload != "" || srv.Audience != "" {
		t.Errorf("after logout %+v", srv)
	}
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	if n := cp.minted.Load(); n != 1 {
		t.Errorf("renewed a logged-out workload: %d exchanges", n)
	}
}

func (cp *workloadCP) revokedTokens() string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return strings.Join(cp.revoked, ",")
}

func TestAnEnvWorkloadUsesTheCLITokenOnceAndIsNeverRenewed(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	cp.ttl = 2 * time.Minute
	src := &countingSource{audiences: make(chan string, 4)}
	withSource(t, src)
	d := New("test", providers.Builtins())
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "env:TEST_JWT", WorkloadToken: "cli-jwt"},
		func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	cp.mu.Lock()
	seen := strings.Join(cp.seen, ",")
	cp.mu.Unlock()
	if seen != "cli-jwt" || src.n.Load() != 0 {
		t.Errorf("exchanged %q with %d daemon-side fetches, want only the CLI's token", seen, src.n.Load())
	}
}

func TestLogoutAndReloginRevokeTheServiceToken(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	withSource(t, &countingSource{audiences: make(chan string, 4)})
	d := New("test", providers.Builtins())
	login := func() {
		if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "file:/test/jwt"}, func(control.LoginEvent) {}); err != nil {
			t.Fatalf("Login: %v", err)
		}
	}
	login()
	login()
	if got := cp.revokedTokens(); got != "pms_1" {
		t.Errorf("after re-login revoked %q, want the replaced token", got)
	}
	if _, err := d.Logout(control.LogoutRequest{}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := cp.revokedTokens(); got != "pms_1,pms_2" {
		t.Errorf("after logout revoked %q", got)
	}
}

func TestARenewalThatChangesThePrincipalIsRefused(t *testing.T) {
	isolate(t)
	cp := newWorkloadCP(t, nil)
	cp.ttl = 2 * time.Minute
	withSource(t, &countingSource{audiences: make(chan string, 4)})
	d := New("test", providers.Builtins())
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL, Workload: "file:/test/jwt"}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()
	cp.mu.Lock()
	cp.principal = "svc:other"
	cp.mu.Unlock()
	d.maybeRenewServer(context.Background(), "default", *d.snapshot().Servers["default"])
	srv := d.snapshot().Servers["default"]
	d.mu.Lock()
	refused := d.reauthRequired["default"]
	d.mu.Unlock()
	if srv.Token != "pms_1" || srv.Principal != "svc:batch-settlement" || !refused {
		t.Errorf("principal change accepted: %+v reauth=%v", srv, refused)
	}
	if got := cp.revokedTokens(); got != "pms_2" {
		t.Errorf("revoked %q, want the token minted for the other principal", got)
	}
}
