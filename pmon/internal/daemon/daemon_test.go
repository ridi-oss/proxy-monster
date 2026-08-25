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
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// isolate points the state directory at a temp dir and moves the broker port range out of the way, so a test
// neither touches the real user config nor fights a real daemon (or a sibling test) for 6100+.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	t.Setenv("PMON_PORT_BASE", fmt.Sprintf("%d", freeTCPPort(t)))
}

// freeTCPPort returns a port nothing is listening on, for use as an isolated broker-port base.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// fakeCP is a control plane that serves the device-auth flow and the datasource list.
type fakeCP struct {
	*httptest.Server
	datasources []Datasource
}

func newFakeCP(t *testing.T, datasources []Datasource) *fakeCP {
	t.Helper()
	cp := &fakeCP{datasources: datasources}
	cp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verificationUri": "https://idp.example/activate", "verificationUriComplete": "https://idp.example/activate?c=1",
				"userCode": "ABCD", "handle": "h-1", "interval": 1,
			})
		case "/auth/device/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal": "you@example.com", "token": "pmk_tok",
				"expiresAt":    time.Now().Add(12 * time.Hour).Format(time.RFC3339),
				"renewalToken": "pmr_abc",
			})
		case "/api/datasources":
			if got := r.Header.Get("Authorization"); got != "Bearer pmk_tok" {
				t.Errorf("discovery Authorization = %q, want the wire token as a bearer", got)
			}
			_ = json.NewEncoder(w).Encode(cp.datasources)
		default:
			t.Errorf("unexpected control-plane path %q", r.URL.Path)
		}
	}))
	t.Cleanup(cp.Close)
	return cp
}

// freePort reserves and releases a port, giving an address nothing is listening on.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestLoginOpensBrokersImmediately is the design's central behavior: there is no separate "start brokering"
// step, so a completed login must leave the listeners up and a connection string renderable.
func TestLoginOpensBrokersImmediately(t *testing.T) {
	isolate(t)
	proxyAddr := freePort(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: proxyAddr, CertChainPEM: "abc"},
	})

	d := New("test")
	if err := d.ensureLocalPassword(); err != nil {
		t.Fatalf("ensureLocalPassword: %v", err)
	}

	var kinds []string
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(ev control.LoginEvent) {
		kinds = append(kinds, ev.Kind)
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(kinds) < 2 || kinds[len(kinds)-1] != "done" {
		t.Fatalf("login events = %v, want a prompt then done", kinds)
	}

	s := d.Status()
	if !s.LoggedIn || s.Principal != "you@example.com" {
		t.Fatalf("status after login = %+v, want a logged-in principal", s)
	}
	if len(s.Datasources) != 1 {
		t.Fatalf("status datasources = %+v, want exactly the brokered one", s.Datasources)
	}
	ds := s.Datasources[0]
	if !ds.Brokered || ds.LocalPort < state.PortBase() {
		t.Errorf("datasource = %+v, want brokered on a port at or above %d", ds, state.PortBase())
	}
	if !ds.TLSVerified {
		t.Error("datasource reports Pinned=false although the control plane advertised a cert fingerprint")
	}
	// The listener is real: something accepts on the advertised local port.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ds.LocalPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial the broker port: %v", err)
	}
	c.Close()

	d.closeAllListeners()
}

func TestFreshLoginClosesExistingSessions(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})
	d := New("test")
	ctx := context.Background()
	if err := d.Login(ctx, control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("first Login: %v", err)
	}
	defer d.closeAllListeners()

	client, server := net.Pipe()
	defer client.Close()
	closed := make(chan struct{})
	tracked := &closeObserverConn{Conn: server, onClose: func() { close(closed) }}
	deregister := d.addConn("acme-mysql", tracked)
	defer deregister()

	if err := d.Login(ctx, control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("second Login: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("a session opened under the previous login survived the fresh login")
	}
	status := d.Status()
	if len(status.Datasources) != 1 || !status.Datasources[0].Brokered {
		t.Fatalf("replacement login did not reopen the broker: %+v", status.Datasources)
	}
}

func TestFreshLoginDrainKeepsCurrentGeneration(t *testing.T) {
	d := New("test")
	oldClient, oldServer := net.Pipe()
	defer oldClient.Close()
	oldClosed := make(chan struct{})
	deregisterOld := d.addConn("acme-mysql", &closeObserverConn{Conn: oldServer, onClose: func() { close(oldClosed) }})
	defer deregisterOld()

	d.mu.Lock()
	d.tokenGeneration++
	currentGeneration := d.tokenGeneration
	d.mu.Unlock()
	newClient, newServer := net.Pipe()
	defer newClient.Close()
	newClosed := make(chan struct{})
	deregisterNew := d.addConn("acme-mysql", &closeObserverConn{Conn: newServer, onClose: func() { close(newClosed) }})
	defer deregisterNew()

	d.closeTokenGenerationsBefore(currentGeneration)
	select {
	case <-oldClosed:
	case <-time.After(time.Second):
		t.Fatal("the previous login generation survived the fresh-login drain")
	}
	select {
	case <-newClosed:
		t.Fatal("the fresh-login drain closed a session using the current login generation")
	case <-time.After(100 * time.Millisecond):
	}
	newServer.Close()
}

func TestConcurrentLoginAndLogoutLeaveLoggedOutState(t *testing.T) {
	isolate(t)
	polling := make(chan struct{})
	releasePoll := make(chan struct{})
	var pollingOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releasePoll) }) }
	defer release()

	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verificationUri": "https://idp.example/activate", "userCode": "ABCD",
				"handle": "h-1", "interval": 1,
			})
		case "/auth/device/poll":
			pollingOnce.Do(func() { close(polling) })
			<-releasePoll
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal": "you@example.com", "token": "pmk_tok",
				"expiresAt":    time.Now().Add(12 * time.Hour).Format(time.RFC3339),
				"renewalToken": "pmr_abc",
			})
		case "/api/datasources":
			_ = json.NewEncoder(w).Encode([]Datasource{})
		default:
			t.Errorf("unexpected control-plane path %q", r.URL.Path)
		}
	}))
	defer cp.Close()

	d := New("test")
	loginDone := make(chan error, 1)
	go func() {
		loginDone <- d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {})
	}()
	select {
	case <-polling:
	case <-time.After(2 * time.Second):
		t.Fatal("login did not reach device polling")
	}

	logoutDone := make(chan error, 1)
	go func() { logoutDone <- d.Logout() }()
	select {
	case err := <-logoutDone:
		t.Fatalf("Logout returned before the concurrent Login transition completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	if err := <-loginDone; err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := <-logoutDone; err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if d.Status().LoggedIn {
		t.Fatal("daemon remains logged in after concurrent Login and Logout")
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LoggedIn() || cfg.Token != "" || cfg.RenewalToken != "" {
		t.Fatalf("credentials remain on disk after concurrent Login and Logout: %+v", cfg)
	}
}

// TestBrokeringImpliesALocalPassword locks the invariant a connection string depends on: if any broker is
// listening, the sticky loopback password exists — otherwise `pmon show` would emit a string with an empty
// password. Asserted without the explicit ensureLocalPassword() that Run does, so the guarantee holds on every
// path that opens listeners, not just at startup.
func TestBrokeringImpliesALocalPassword(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})

	d := New("test")
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	s := d.Status()
	if len(s.Datasources) == 0 || !s.Datasources[0].Brokered {
		t.Fatal("expected a brokered datasource")
	}
	if s.LocalPassword == "" {
		t.Error("a broker is listening but Status carries no local password; `pmon show` would emit an empty one")
	}
}

// TestStatusReportsUnbrokerableDatasourcesWithAReason: a PG or address-less datasource must still appear, with
// an explanation — a silently short list would read as "you have no access".
func TestStatusReportsUnbrokerableDatasourcesWithAReason(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "pg", Engine: "postgres", DbName: "app", AdvertiseAddr: freePort(t)},
		{Name: "no-addr", Engine: "mysql", DbName: "app"},
	})

	d := New("test")
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	s := d.Status()
	if len(s.Datasources) != 2 {
		t.Fatalf("datasources = %+v, want both unbrokerable ones listed", s.Datasources)
	}
	for _, ds := range s.Datasources {
		if ds.Brokered {
			t.Errorf("%s reports Brokered=true", ds.Name)
		}
		if ds.Reason == "" {
			t.Errorf("%s has no Reason; a peer would show a blank explanation", ds.Name)
		}
	}
}

// TestRediscoveryClosesARevokedDatasource covers the security-relevant half of discovery: a datasource that
// drops out of the connectable set must stop being brokered, or the daemon keeps handing the wire token to an
// address the principal is no longer authorized for.
func TestRediscoveryClosesARevokedDatasource(t *testing.T) {
	isolate(t)
	proxyAddr := freePort(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: proxyAddr},
	})

	d := New("test")
	ctx := context.Background()
	if err := d.Login(ctx, control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	port := d.Status().Datasources[0].LocalPort
	if port == 0 {
		t.Fatal("no local port assigned after login")
	}

	// Revoke it, then rediscover.
	cp.datasources = nil
	d.openListeners(ctx)

	s := d.Status()
	for _, ds := range s.Datasources {
		if ds.Name == "acme-mysql" && ds.Brokered {
			t.Fatal("a revoked datasource is still brokered")
		}
	}
	waitFor(t, "the revoked broker port to close", func() bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err != nil {
			return true
		}
		c.Close()
		return false
	})

	// The sticky port assignment survives, so a later re-grant reuses the same saved connection string.
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Ports["acme-mysql"] != port {
		t.Errorf("sticky port for a revoked datasource = %d, want it kept at %d", cfg.Ports["acme-mysql"], port)
	}
}

// TestLogoutClosesBrokersButKeepsTheDaemonIdle: logout must not stop the daemon, because a peer has to be able
// to log back in through it.
func TestLogoutClosesBrokersButKeepsTheDaemonIdle(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})

	d := New("test")
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	port := d.Status().Datasources[0].LocalPort

	if err := d.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	s := d.Status()
	if s.LoggedIn || s.Principal != "" {
		t.Errorf("status after logout = %+v, want logged out", s)
	}
	if len(s.Datasources) != 0 {
		t.Errorf("datasources after logout = %+v, want none", s.Datasources)
	}
	waitFor(t, "the broker port to close after logout", func() bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err != nil {
			return true
		}
		c.Close()
		return false
	})

	// Credentials are gone from disk, but the sticky local password survives — a re-login must not invalidate
	// saved client connections.
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "" || cfg.RenewalToken != "" {
		t.Errorf("logout left credentials on disk: %+v", cfg)
	}
	if cfg.LocalPassword == "" {
		t.Error("logout cleared the sticky local password; saved connections would break on the next login")
	}
}

// TestDiscoveryFailureIsSurfacedNotFatal: a control plane that is down must leave the daemon running with a
// visible error, so a peer shows "discovery failing" instead of an empty list that reads as "no access".
func TestDiscoveryFailureIsSurfacedNotFatal(t *testing.T) {
	isolate(t)
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = "http://127.0.0.1:1" // nothing listening
		c.Principal, c.Token = "you@example.com", "pmk_tok"
		return nil
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	d := New("test")
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg
	d.openListeners(context.Background())

	s := d.Status()
	if s.LastDiscoveryError == "" {
		t.Error("a failed discovery left LastDiscoveryError empty; the peer would show a blank list with no reason")
	}
	if len(s.Datasources) != 0 {
		t.Errorf("datasources = %+v, want none after a failed discovery", s.Datasources)
	}
}

// TestConcurrentDiscoveryKeepsTheStickyPort covers the race between a login and the rediscover ticker (or a
// peer's /reload): two passes could each see a datasource as needing a listener, and the loser's bind would
// fail on the winner's port and then FREE the sticky assignment — leaving the datasource brokered but reporting
// port 0, so `pmon show` emitted a connection string with port 0.
func TestConcurrentDiscoveryKeepsTheStickyPort(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})

	d := New("test")
	ctx := context.Background()
	// Seed credentials WITHOUT opening listeners, so every racing pass below starts from "no listener yet" —
	// the state in which two passes both decide the datasource needs one. Logging in first would open the
	// listener and close the window the race lives in.
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = cp.URL
		c.Principal, c.Token = "you@example.com", "pmk_tok"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg
	defer d.closeAllListeners()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); d.openListeners(ctx) }()
	}
	wg.Wait()

	want := state.PortBase()

	s := d.Status()
	if len(s.Datasources) != 1 {
		t.Fatalf("datasources = %+v, want exactly one", s.Datasources)
	}
	if got := s.Datasources[0]; got.LocalPort != want || !got.Brokered {
		t.Errorf("after concurrent discovery: port %d brokered=%v, want port %d still brokered",
			got.LocalPort, got.Brokered, want)
	}
	onDisk, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if onDisk.Ports["acme-mysql"] != want {
		t.Errorf("sticky port on disk = %d, want %d preserved", onDisk.Ports["acme-mysql"], want)
	}
}

// TestStaleRenewalDoesNotClobberANewerSession: a renewal in flight when a login lands must be discarded. Left
// unguarded it wrote the OLD session's wire token over the new one, pairing it with the new session's principal
// and renewal secret.
func TestStaleRenewalDoesNotClobberANewerSession(t *testing.T) {
	isolate(t)
	d := New("test")

	// Pin the interleaving a login completing mid-round-trip produces: the request ARRIVING proves the renewal
	// already snapshotted the old session, so the test swaps in the new one only then, and the response that
	// comes back is genuinely stale. Without this handshake the snapshot could read the NEW session, in which
	// case applying the result would be correct and the test would prove nothing.
	requestArrived := make(chan struct{})
	loginLanded := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer pmr_old" {
			t.Errorf("renew presented %q, want the OLD session's renewal token", got)
		}
		close(requestArrived)
		<-loginLanded
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":     "tok-renewed-from-OLD-session",
			"expiresAt": time.Now().Add(12 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	// Seed a session whose token is close enough to expiry that a renewal is due.
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = srv.URL
		c.Principal, c.Token = "you@example.com", "tok-old"
		c.RenewalToken = "pmr_old"
		c.ExpiresAt = time.Now().Add(1 * time.Minute).Format(time.RFC3339)
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg

	done := make(chan struct{})
	go func() { defer close(done); d.maybeRenew(context.Background()) }()

	// A login lands while the renewal is in flight, replacing the whole session — ON DISK as well as in memory,
	// the way Login actually does it, so the guards that re-check under the config lock are exercised.
	<-requestArrived
	if err := state.Update(func(c *state.Config) error {
		c.Principal, c.Token, c.RenewalToken = "new@example.com", "tok-new", "pmr_new"
		return nil
	}); err != nil {
		t.Fatalf("simulate login: %v", err)
	}
	d.mu.Lock()
	d.cfg.Principal, d.cfg.Token, d.cfg.RenewalToken = "new@example.com", "tok-new", "pmr_new"
	d.mu.Unlock()
	close(loginLanded)
	<-done

	s := d.snapshot()
	if s.Token != "tok-new" || s.RenewalToken != "pmr_new" {
		t.Errorf("a stale renewal disturbed the newer session in memory: token=%q renewal=%q", s.Token, s.RenewalToken)
	}
	// And on DISK — that is what the next daemon start reads, so a stale token persisted there outlives the
	// process even if memory looked right.
	onDisk, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if onDisk.Token != "tok-new" || onDisk.RenewalToken != "pmr_new" {
		t.Errorf("a stale renewal was persisted: disk token=%q renewal=%q", onDisk.Token, onDisk.RenewalToken)
	}
	// And a refusal for the superseded session must not demand reauth for the fresh one.
	if d.Status().ReauthRequired {
		t.Error("ReauthRequired set from a superseded session's renewal")
	}
}

// TestRenewalWithNoExpiryIsRetriedNotPersisted: persisting an empty ExpiresAt would make every later tick fail
// to parse it, so the daemon would silently stop renewing forever.
func TestRenewalWithNoExpiryIsRetriedNotPersisted(t *testing.T) {
	isolate(t)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "tok-fresh"}) // no expiresAt
	}))
	defer srv.Close()

	d := New("test")
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = srv.URL
		c.Principal, c.Token = "you@example.com", "tok-old"
		c.RenewalToken = "pmr_x"
		c.ExpiresAt = time.Now().Add(1 * time.Minute).Format(time.RFC3339)
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg

	d.maybeRenew(context.Background())
	if calls != 1 {
		t.Fatalf("renew calls = %d, want 1", calls)
	}
	s := d.snapshot()
	if s.Token != "tok-old" {
		t.Errorf("token = %q, want the old one kept (an expiry-less renewal must not be persisted)", s.Token)
	}
	// Still due, so the next tick retries rather than going quiet.
	d.maybeRenew(context.Background())
	if calls != 2 {
		t.Errorf("renew calls = %d after a second tick, want 2 (it must keep retrying)", calls)
	}
}

// TestLiveConnsCountsARealConnection locks the number the stop/restart confirmation depends on: it is what warns
// a user before their in-flight queries are dropped, so an undercount would silently kill live work. Asserted
// through a real dial to the broker port rather than a direct addConn call.
func TestLiveConnsCountsARealConnection(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})
	d := New("test")
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	port := d.Status().Datasources[0].LocalPort
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial the broker port: %v", err)
	}
	defer c.Close()

	// The broker registers the connection on its own goroutine, so poll rather than assume it is immediate.
	waitFor(t, "the connection to be counted in Status", func() bool {
		return d.Status().Datasources[0].LiveConns == 1
	})
	total := d.Status()
	if got := total.TotalLiveConns(); got != 1 {
		t.Errorf("TotalLiveConns() = %d, want 1 (this is what the stop confirmation reads)", got)
	}

	c.Close()
	waitFor(t, "the closed connection to be dropped from the count", func() bool {
		s := d.Status()
		return s.TotalLiveConns() == 0
	})
}

// TestTrackedConnectionsAreNeverInvisibleToStatus is the guard for a real undercount: LiveConns used to be
// emitted only for datasources present in BOTH the listener and datasource maps, so a session whose datasource
// had been pruned — revoked mid-query, or a broker still parked in the upstream handshake — counted as ZERO.
// stop/quit read this number to decide whether to warn, so an invisible session is an in-flight query dropped
// with no confirmation at all.
func TestTrackedConnectionsAreNeverInvisibleToStatus(t *testing.T) {
	isolate(t)
	d := New("test")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Registered with NO listener and NO discovered datasource — exactly the pruned-mid-session state.
	deregister := d.addConn("acme-mysql", server)
	defer deregister()

	s := d.Status()
	if got := s.TotalLiveConns(); got != 1 {
		t.Errorf("TotalLiveConns() = %d, want 1: a tracked session with no listener row must still be counted", got)
	}
	// And it must be visible as a row, with a reason, rather than silently absent from the list.
	var found bool
	for _, ds := range s.Datasources {
		if ds.Name == "acme-mysql" {
			found = true
			if ds.LiveConns != 1 {
				t.Errorf("row LiveConns = %d, want 1", ds.LiveConns)
			}
			if ds.Brokered {
				t.Error("row reports Brokered=true with no listener")
			}
			if ds.Reason == "" {
				t.Error("row has no Reason; a peer would show a blank explanation")
			}
		}
	}
	if !found {
		t.Error("a datasource with a live session is missing from Status entirely")
	}
}

// TestLogoutDuringDiscoveryLeavesNoListener covers a leak that made `pmon logout` report the opposite of the
// truth: openListeners snapshots the login, does network I/O, then binds — so a logout landing in that window
// left an open loopback port that no later pass reaps (each returns early once logged out), while the CLI printed
// "the brokers are closed and the daemon is idle".
func TestLogoutDuringDiscoveryLeavesNoListener(t *testing.T) {
	isolate(t)

	discovering := make(chan struct{})
	release := make(chan struct{})
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})
	// Wrap discovery so the test can land a logout while it is in flight.
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/datasources" {
			close(discovering)
			<-release
		}
		http.Redirect(w, r, cp.URL+r.URL.Path+"?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
	}))
	defer gate.Close()

	d := New("test")
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = gate.URL
		c.Principal, c.Token = "you@example.com", "pmk_tok"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg

	done := make(chan struct{})
	go func() { defer close(done); d.openListeners(context.Background()) }()

	<-discovering
	if err := d.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	close(release)
	<-done

	s := d.Status()
	if s.LoggedIn {
		t.Fatal("still logged in after Logout")
	}
	d.mu.Lock()
	leaked := len(d.listeners)
	d.mu.Unlock()
	if leaked != 0 {
		t.Errorf("%d listener(s) left open after a logout during discovery; the CLI reports the brokers closed", leaked)
	}
	for _, ds := range s.Datasources {
		if ds.Brokered {
			t.Errorf("logged out but %q still reports Brokered=true on port %d", ds.Name, ds.LocalPort)
		}
	}
}

// TestLogoutClosesEstablishedSessions: closing a listener only stops NEW accepts, so without closing tracked
// connections a logged-out daemon kept piping live sessions under the credentials just cleared — meaning
// `pmon logout` did not actually close the brokers.
func TestLogoutClosesEstablishedSessions(t *testing.T) {
	isolate(t)
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = "https://cp.example"
		c.Token = "pmk_token"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d := New("test")
	d.mu.Lock()
	d.cfg.ControlPlane = "https://cp.example"
	d.cfg.Token = "pmk_token"
	d.mu.Unlock()

	client, server := net.Pipe()
	defer client.Close()
	loggedInAtClose := make(chan bool, 1)
	tracked := &closeObserverConn{Conn: server, onClose: func() {
		cfg := d.snapshot()
		loggedInAtClose <- cfg.LoggedIn()
	}}
	deregister := d.addConn("acme-mysql", tracked)
	defer deregister()

	before := d.Status()
	if got := before.TotalLiveConns(); got != 1 {
		t.Fatalf("TotalLiveConns() = %d before logout, want 1", got)
	}
	if err := d.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if <-loggedInAtClose {
		t.Error("logout closed sessions before invalidating in-memory credentials")
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Error("the established session survived logout; it must be closed")
	}
}

func TestBrokerRejectsConnectionAcceptedBeforeLogout(t *testing.T) {
	isolate(t)
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = "https://cp.example"
		c.Token = "pmk_old"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	d := New("test")
	d.mu.Lock()
	d.cfg.ControlPlane = "https://cp.example"
	d.cfg.Token = "pmk_old"
	d.cfg.LocalPassword = "pmlocal_test"
	d.datasources["mysql"] = Datasource{Name: "mysql", Engine: "mysql", AdvertiseAddr: target.Addr().String()}
	d.nextListenerGeneration++
	acceptedGeneration := d.nextListenerGeneration
	d.listenerGenerations["mysql"] = acceptedGeneration
	d.mu.Unlock()
	if err := d.Logout(); err != nil {
		t.Fatal(err)
	}

	d.mu.Lock()
	d.cfg.ControlPlane = "https://cp.example"
	d.cfg.Token = "pmk_new"
	d.datasources["mysql"] = Datasource{Name: "mysql", Engine: "mysql", AdvertiseAddr: target.Addr().String()}
	d.nextListenerGeneration++
	d.listenerGenerations["mysql"] = d.nextListenerGeneration
	d.mu.Unlock()

	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		d.broker(server, "mysql", acceptedGeneration)
		close(done)
	}()
	_, packet, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) == 0 || packet[0] != 0xff {
		t.Fatalf("stale accepted connection response = %x, want ERR", packet)
	}
	<-done

	if err := target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if c, err := target.Accept(); err == nil {
		c.Close()
		t.Fatal("a connection accepted before logout used the new login")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("accept after stale broker: %v", err)
	}
}

// TestRevocationClosesEstablishedSessions: same for a datasource that drops out of the connectable set — an open
// session would otherwise keep piping to an address the principal is no longer authorized for.
func TestRevocationClosesEstablishedSessions(t *testing.T) {
	isolate(t)
	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})

	d := New("test")
	ctx := context.Background()
	if err := d.Login(ctx, control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deregister := d.addConn("acme-mysql", server)
	defer deregister()

	cp.datasources = nil // revoke
	d.openListeners(ctx)

	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Error("a session on a revoked datasource survived; it must be closed")
	}
}

// TestRenewalDoesNotResurrectALoggedOutSession: a renewal in flight when a logout lands must not write a token
// back. LoggedIn() needs only a token + control plane, so the daemon would report itself logged in again with no
// principal and no renewal secret.
func TestRenewalDoesNotResurrectALoggedOutSession(t *testing.T) {
	isolate(t)
	d := New("test")

	requestArrived := make(chan struct{})
	logoutDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestArrived)
		<-logoutDone
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":     "tok-renewed-after-logout",
			"expiresAt": time.Now().Add(12 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = srv.URL
		c.Principal, c.Token = "you@example.com", "tok-old"
		c.RenewalToken = "pmr_old"
		c.ExpiresAt = time.Now().Add(1 * time.Minute).Format(time.RFC3339)
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.cfg = *cfg

	done := make(chan struct{})
	go func() { defer close(done); d.maybeRenew(context.Background()) }()

	<-requestArrived
	if err := d.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	close(logoutDone)
	<-done

	if s := d.Status(); s.LoggedIn {
		t.Errorf("a renewal resurrected a logged-out session: principal=%q loggedIn=%v", s.Principal, s.LoggedIn)
	}
	onDisk, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if onDisk.Token != "" {
		t.Errorf("logged-out config carries token %q; a stale renewal wrote it back", onDisk.Token)
	}
}

// TestSubscribeDropsRatherThanBlocking: a stuck peer must never wedge the daemon, so publish drops events past
// the buffer instead of blocking on the channel.
func TestSubscribeDropsRatherThanBlocking(t *testing.T) {
	isolate(t)
	d := New("test")
	_, cancel := d.Subscribe() // never drained
	defer cancel()

	done := make(chan struct{})
	go func() {
		for range 1000 {
			d.publish(control.Event{Kind: "status"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publish blocked on an undrained subscriber; a stuck peer would wedge the daemon")
	}
}

// TestRenewLeadIsNeverNarrowerThanTheSampleInterval: the renewal loop only checks every renewCheckInterval, so a
// lead shorter than that can fall entirely between two checks and the token expires un-renewed. Sizing the lead
// to a short token's lifetime must not trade "renews every tick" for "never renews" — the control plane clamps
// TTL to a 60s floor, so those tokens are real.
func TestRenewLeadIsNeverNarrowerThanTheSampleInterval(t *testing.T) {
	floor := 2 * renewCheckInterval
	for _, ttl := range []time.Duration{60 * time.Second, 2 * time.Minute, 10 * time.Minute, 12 * time.Hour} {
		issued := time.Now()
		expiry := issued.Add(ttl)
		cfg := state.Config{IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expiry.Format(time.RFC3339)}
		lead := renewLead(cfg, expiry)
		if lead < floor {
			t.Errorf("ttl %s: lead %s is narrower than %s, so the loop can skip past expiry", ttl, lead, floor)
		}
		if lead > maxRenewLeadTime {
			t.Errorf("ttl %s: lead %s exceeds the %s cap", ttl, lead, maxRenewLeadTime)
		}
	}
	// A config predating IssuedAt falls back to the fixed cap rather than computing a nonsense lifetime.
	expiry := time.Now().Add(12 * time.Hour)
	if lead := renewLead(state.Config{}, expiry); lead != maxRenewLeadTime {
		t.Errorf("legacy config (no IssuedAt) lead = %s, want the %s fallback", lead, maxRenewLeadTime)
	}
}

// TestStatusReportsThePersistedLocalPassword: the in-memory copy is only populated by ensureLocalPassword, and
// Run tolerates that failing — so a daemon whose config already holds a password must still report it, or
// `pmon show` emits a connection string with an EMPTY password while brokers are listening.
func TestStatusReportsThePersistedLocalPassword(t *testing.T) {
	isolate(t)
	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane, c.Principal, c.Token = "http://cp", "you@example.com", "pmk_tok"
		c.LocalPassword = "pmlocal_fromDisk"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := state.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := New("test")
	d.cfg = *cfg // as Run does, without calling ensureLocalPassword

	if got := d.Status().LocalPassword; got != "pmlocal_fromDisk" {
		t.Errorf("Status.LocalPassword = %q, want the persisted %q", got, "pmlocal_fromDisk")
	}
}

// TestAPortCollisionIsVisibleNotSilent: when a foreign service holds a datasource's sticky port, the datasource
// used to land in NO map — so `pmon status` printed "no datasources yet", telling the user they had no access
// when the real cause was a local port collision. It must appear with the reason instead.
func TestAPortCollisionIsVisibleNotSilent(t *testing.T) {
	isolate(t)
	// Occupy the port the daemon will assign first.
	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.PortBase()))
	if err != nil {
		t.Skipf("could not occupy the base port: %v", err)
	}
	defer blocker.Close()

	cp := newFakeCP(t, []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", AdvertiseAddr: freePort(t)},
	})
	d := New("test")
	if err := d.Login(context.Background(), control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer d.closeAllListeners()

	s := d.Status()
	if len(s.Datasources) == 0 {
		t.Fatal("a datasource whose port is occupied vanished from Status; the user is told they have no access")
	}
	ds := s.Datasources[0]
	if ds.Brokered {
		t.Error("reports Brokered=true although the bind failed")
	}
	if !strings.Contains(ds.Reason, "in use") {
		t.Errorf("Reason = %q, want it to name the port collision", ds.Reason)
	}
}

// TestSnapshotDoesNotAliasThePortsMap: a bare struct copy shares the map header, so a caller reading Ports off a
// snapshot outside the lock would race with port assignment — with no compiler or race-detector warning until the
// timing happened to line up. Asserted by mutating the snapshot and checking the daemon is untouched.
func TestSnapshotDoesNotAliasThePortsMap(t *testing.T) {
	isolate(t)
	d := New("test")
	d.mu.Lock()
	d.cfg.Ports = map[string]int{"acme-mysql": 6100}
	d.mu.Unlock()

	snap := d.snapshot()
	snap.Ports["acme-mysql"] = 9999
	snap.Ports["injected"] = 1234

	d.mu.Lock()
	live := d.cfg.Ports
	d.mu.Unlock()
	if live["acme-mysql"] != 6100 {
		t.Errorf("mutating a snapshot changed the daemon's port map: %d, want 6100 (the map is aliased)", live["acme-mysql"])
	}
	if _, ok := live["injected"]; ok {
		t.Error("a key added to a snapshot appeared in the daemon's map (the map is aliased)")
	}
}

type closeObserverConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeObserverConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}
