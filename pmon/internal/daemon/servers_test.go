package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

func loginTo(t *testing.T, d *Daemon, server, url string) {
	t.Helper()
	if err := d.Login(context.Background(), control.LoginRequest{Server: server, ControlPlane: url}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login %s: %v", server, err)
	}
}

func portOf(t *testing.T, s control.Status, server, name string) int {
	t.Helper()
	for _, ds := range s.Datasources {
		if ds.Server == server && ds.Name == name {
			return ds.LocalPort
		}
	}
	t.Fatalf("no %s/%s in %+v", server, name, s.Datasources)
	return 0
}

func dialable(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// The same datasource name on two servers gets two brokers on two ports, and logging out of one server
// closes only its own.
func TestTwoServersBrokerTheSameNameSeparately(t *testing.T) {
	isolate(t)
	ds := []driver.Endpoint{{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)}}
	a, b := newFakeCP(t, ds), newFakeCP(t, ds)

	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	loginTo(t, d, "", a.URL)
	loginTo(t, d, "dev", b.URL)

	s := d.Status()
	if len(s.Servers) != 2 || !s.Server("default").LoggedIn || !s.Server("dev").LoggedIn {
		t.Fatalf("servers = %+v, want default and dev logged in", s.Servers)
	}
	pa, pb := portOf(t, s, "default", "acme-mysql"), portOf(t, s, "dev", "acme-mysql")
	if pa == pb || !dialable(pa) || !dialable(pb) {
		t.Fatalf("ports default=%d dev=%d, want two distinct live brokers", pa, pb)
	}

	if err := d.Logout(control.LogoutRequest{Server: "dev"}); err != nil {
		t.Fatalf("Logout dev: %v", err)
	}
	waitFor(t, "dev's broker to close", func() bool { return !dialable(pb) })
	if !dialable(pa) {
		t.Error("logging out of dev closed the default server's broker")
	}
	s = d.Status()
	if !s.Server("default").LoggedIn || s.Server("dev").LoggedIn {
		t.Errorf("servers after logout dev = %+v", s.Servers)
	}

	if err := d.Logout(control.LogoutRequest{All: true}); err != nil {
		t.Fatalf("Logout all: %v", err)
	}
	waitFor(t, "default's broker to close", func() bool { return !dialable(pa) })
	if d.Status().LoggedIn {
		t.Error("still logged in after logout --all")
	}
}

func TestLoginWithoutAServerExplainsHowToSetOne(t *testing.T) {
	isolate(t)
	d := New("test", providers.Builtins())
	err := d.Login(context.Background(), control.LoginRequest{}, func(control.LoginEvent) {})
	if err == nil || !strings.Contains(err.Error(), "pmon server set --url") {
		t.Fatalf("Login with no server = %v, want a hint to set one", err)
	}
	err = d.Login(context.Background(), control.LoginRequest{Server: "dev"}, func(control.LoginEvent) {})
	if err == nil || !strings.Contains(err.Error(), "pmon server set dev --url") {
		t.Fatalf("Login to an unknown server = %v, want a hint to set it", err)
	}
}

// A token is only good against the control plane that minted it, so moving a server logs it out.
func TestSetServerToANewURLLogsItOut(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []driver.Endpoint{{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)}})
	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	loginTo(t, d, "", cp.URL)
	port := portOf(t, d.Status(), "default", "acme-mysql")

	res, err := d.SetServer(control.SetServerRequest{ControlPlane: cp.URL + "/"})
	if err != nil || res.Changed || res.LoggedOut {
		t.Fatalf("SetServer to the same URL = %+v, %v; want a no-op", res, err)
	}
	res, err = d.SetServer(control.SetServerRequest{ControlPlane: "https://elsewhere.example"})
	if err != nil || !res.LoggedOut {
		t.Fatalf("SetServer to a new URL = %+v, %v; want it logged out", res, err)
	}
	waitFor(t, "the broker to close", func() bool { return !dialable(port) })
	srv := d.Status().Server("default")
	if srv.LoggedIn || srv.ControlPlane != "https://elsewhere.example" {
		t.Errorf("server after move = %+v", srv)
	}
	onDisk, err := state.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := onDisk.Servers["default"]; got.Token != "" || got.Ports["acme-mysql"] != port {
		t.Errorf("disk after move = %+v, want no token and the sticky port kept", got)
	}

	if _, err := d.SetServer(control.SetServerRequest{ControlPlane: "localhost:8080"}); err == nil {
		t.Error("SetServer accepted a URL with no scheme")
	}
	if _, err := d.SetServer(control.SetServerRequest{Name: "Bad Name", ControlPlane: cp.URL}); err == nil {
		t.Error("SetServer accepted an invalid name")
	}
}

func TestUnsetServerLogsOutAndDeletesIt(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []driver.Endpoint{{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)}})
	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	loginTo(t, d, "dev", cp.URL)
	port := portOf(t, d.Status(), "dev", "acme-mysql")

	if err := d.UnsetServer(control.UnsetServerRequest{Name: "dev"}); err != nil {
		t.Fatalf("UnsetServer: %v", err)
	}
	waitFor(t, "the broker to close", func() bool { return !dialable(port) })
	if s := d.Status(); len(s.Servers) != 0 || len(s.Datasources) != 0 {
		t.Errorf("status after unset = %+v", s)
	}
	onDisk, err := state.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Servers) != 0 {
		t.Errorf("servers on disk after unset = %+v", onDisk.Servers)
	}
	if err := d.UnsetServer(control.UnsetServerRequest{Name: "dev"}); err == nil {
		t.Error("unsetting an unknown server succeeded")
	}
}

// Each server's broker resolves its own endpoint and credentials, never another server's.
func TestEachServerResolvesItsOwnSession(t *testing.T) {
	isolate(t)
	a := newFakeCPAs(t, "prod@example.com", "tok-prod", []driver.Endpoint{{Name: "acme", Engine: "mysql", DbName: "app", AdvertiseAddr: "prod-proxy:3306"}})
	b := newFakeCPAs(t, "dev@example.com", "tok-dev", []driver.Endpoint{{Name: "acme", Engine: "mysql", DbName: "app", AdvertiseAddr: "dev-proxy:3306"}})
	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	loginTo(t, d, "", a.URL)
	loginTo(t, d, "dev", b.URL)

	for server, want := range map[string][3]string{
		"default": {"prod-proxy:3306", "prod@example.com", "tok-prod"},
		"dev":     {"dev-proxy:3306", "dev@example.com", "tok-dev"},
	} {
		key := dsKey{server, "acme"}
		d.mu.Lock()
		ln := d.listeners[key]
		d.mu.Unlock()
		if ln == nil {
			t.Fatalf("%s has no listener", server)
		}
		ep, creds, ok := d.resolveSession(key, ln)
		if !ok || ep.AdvertiseAddr != want[0] || creds.Principal != want[1] || creds.Token != want[2] {
			t.Errorf("%s resolved %v %+v %v, want %v", server, ep.AdvertiseAddr, creds, ok, want)
		}
	}
}

// Logins to two servers at once must both stick: neither may install a config snapshot older than the other's.
func TestConcurrentLoginsToTwoServersBothStick(t *testing.T) {
	isolate(t)
	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	var cps []*fakeCP
	for i := range 6 {
		cp := newFakeCPAs(t, fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("tok-%d", i), nil)
		cps = append(cps, cp)
		if _, err := d.SetServer(control.SetServerRequest{Name: fmt.Sprintf("s%d", i), ControlPlane: cp.URL}); err != nil {
			t.Fatal(err)
		}
	}
	errs := make(chan error, len(cps))
	for i := range cps {
		go func() {
			errs <- d.Login(context.Background(), control.LoginRequest{Server: fmt.Sprintf("s%d", i)}, func(control.LoginEvent) {})
		}()
	}
	for range cps {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for _, srv := range d.Status().Servers {
		if !srv.LoggedIn {
			t.Errorf("%s lost its login to a concurrent one", srv.Name)
		}
	}
}

// A discovery that started before a logout must not write its results back afterwards.
func TestLogoutDuringDiscoveryLeavesNoRows(t *testing.T) {
	isolate(t)
	discovering, release := make(chan struct{}), make(chan struct{})
	cp := newFakeCP(t, []driver.Endpoint{{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)}, {Name: "unsupported", Engine: "sqlite"}})
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/datasources" && r.Header.Get("X-Gate") == "" {
			select {
			case <-discovering:
			default:
				close(discovering)
				<-release
			}
		}
		req, _ := http.NewRequest(r.Method, cp.URL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer gate.Close()

	d := New("test", providers.Builtins())
	defer d.closeAllListeners()
	if err := d.commit(func(c *state.Config) error {
		c.Servers["dev"] = &state.Server{ID: "x", ControlPlane: gate.URL, Principal: "you@example.com", Token: "pmk_tok", RenewalToken: "r", Ports: map[string]int{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); d.openListeners(context.Background()) }()
	<-discovering
	if err := d.UnsetServer(control.UnsetServerRequest{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if s := d.Status(); len(s.Datasources) != 0 || len(s.Servers) != 0 {
		t.Errorf("status after unset during discovery = %+v, want nothing", s)
	}
}
