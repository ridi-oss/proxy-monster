package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// unixHTTPClient is a raw HTTP client over the control socket, for asserting transport-level behavior the
// typed Client deliberately hides.
func unixHTTPClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

// fakeBackend is a Backend whose calls are recorded, so a test can assert what the API drove without a real
// daemon.
type fakeBackend struct {
	mu           sync.Mutex
	status       Status
	loginCalls   int
	logoutCalls  int
	reloadCalls  int
	shutdowns    int
	loginEvents  []LoginEvent
	loginErr     error
	events       chan Event
	subscribed   int
	unsubscribed int
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		status: Status{Principal: "you@example.com", LoggedIn: true, ControlPlane: "http://cp"},
		events: make(chan Event, 8),
	}
}

func (f *fakeBackend) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeBackend) Login(_ context.Context, _ LoginRequest, onEvent func(LoginEvent)) error {
	f.mu.Lock()
	f.loginCalls++
	evs, err := f.loginEvents, f.loginErr
	f.mu.Unlock()
	for _, ev := range evs {
		onEvent(ev)
	}
	return err
}

func (f *fakeBackend) Logout() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoutCalls++
	return nil
}

func (f *fakeBackend) Reload() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadCalls++
}

func (f *fakeBackend) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdowns++
}

func (f *fakeBackend) Subscribe() (<-chan Event, func()) {
	f.mu.Lock()
	f.subscribed++
	f.mu.Unlock()
	return f.events, func() {
		f.mu.Lock()
		f.unsubscribed++
		f.mu.Unlock()
	}
}

func (f *fakeBackend) counts() (login, logout, reload, shutdown int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCalls, f.logoutCalls, f.reloadCalls, f.shutdowns
}

// serve starts a control server on an isolated state dir and returns a client for it.
func serve(t *testing.T, backend Backend) *Client {
	t.Helper()
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())

	srv, err := Listen(backend)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		srv.Close()
		<-done
	})

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestStatusRoundTrips(t *testing.T) {
	backend := newFakeBackend()
	backend.status.Datasources = []Datasource{
		{Name: "acme-mysql", Engine: "mysql", DbName: "app", LocalPort: 6100, Brokered: true, LiveConns: 2},
		{Name: "unsupported", Engine: "sqlite", Brokered: false, Reason: "engine \"sqlite\" not brokered"},
	}
	c := serve(t, backend)

	s, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if s.Principal != "you@example.com" || !s.LoggedIn {
		t.Errorf("status = %+v, want the backend's identity", s)
	}
	if len(s.Datasources) != 2 || s.Datasources[0].LocalPort != 6100 {
		t.Errorf("datasources = %+v", s.Datasources)
	}
	if got := s.TotalLiveConns(); got != 2 {
		t.Errorf("TotalLiveConns() = %d, want 2", got)
	}
}

// TestSocketIsOwnerOnly locks the control API's whole authentication model: there is no token, so the socket's
// mode (inside a 0700 dir) is what keeps another OS user out.
func TestSocketIsOwnerOnly(t *testing.T) {
	serve(t, newFakeBackend())

	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("Stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm = %o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket dir perm = %o, want 0700", perm)
	}
}

// TestListenClearsAStaleSocket covers recovery after a killed daemon: the socket file survives, so a plain
// bind would fail with EADDRINUSE forever. Listen is only reached by a daemon that already holds the pid lock,
// so any socket present is necessarily stale.
func TestListenClearsAStaleSocket(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	// Leave a stale socket file behind, exactly as a SIGKILLed daemon would.
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}

	srv, err := Listen(newFakeBackend())
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	srv.Close()
}

// TestClientReportsDaemonNotRunning locks the error every peer branches on: with nothing listening, a call must
// return ErrDaemonNotRunning (so the peer offers to start one) rather than an opaque dial error.
func TestClientReportsDaemonNotRunning(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Status(context.Background()); !errors.Is(err, ErrDaemonNotRunning) {
		t.Fatalf("Status with no daemon = %v, want ErrDaemonNotRunning", err)
	}
	if _, err := Connect(context.Background()); !errors.Is(err, ErrDaemonNotRunning) {
		t.Errorf("Connect with no daemon = %v, want ErrDaemonNotRunning", err)
	}
	// Shutdown is idempotent: asking a daemon that is already gone to stop is success, not an error.
	if err := c.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown with no daemon = %v, want nil (already stopped)", err)
	}
}

// TestLoginStreamsPromptBeforeDone is the property that lets both peers show the verification code while the
// flow is still running: events arrive incrementally, not batched at the end.
func TestLoginStreamsPromptBeforeDone(t *testing.T) {
	backend := newFakeBackend()
	backend.loginEvents = []LoginEvent{
		{Kind: "prompt", VerificationURI: "https://idp.example/activate", UserCode: "ABCD"},
		{Kind: "done", Principal: "you@example.com", ExpiresAt: "2026-07-26T00:00:00Z"},
	}
	c := serve(t, backend)

	var kinds []string
	if err := c.Login(context.Background(), LoginRequest{}, func(ev LoginEvent) {
		kinds = append(kinds, ev.Kind)
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(kinds) != 2 || kinds[0] != "prompt" || kinds[1] != "done" {
		t.Fatalf("login event kinds = %v, want [prompt done]", kinds)
	}
	if login, _, _, _ := backend.counts(); login != 1 {
		t.Errorf("backend saw %d logins, want 1", login)
	}
}

// TestLoginSurfacesAnError: a failed flow must reach the peer as an error, not a silent empty stream.
func TestLoginSurfacesAnError(t *testing.T) {
	backend := newFakeBackend()
	backend.loginErr = errors.New("device poll failed")
	c := serve(t, backend)

	err := c.Login(context.Background(), LoginRequest{}, nil)
	if err == nil {
		t.Fatal("Login returned nil for a failing flow")
	}
	if got := err.Error(); got != "device poll failed" {
		t.Errorf("error = %q, want the backend's message", got)
	}
}

func TestLogoutAndReloadDriveTheBackend(t *testing.T) {
	backend := newFakeBackend()
	c := serve(t, backend)
	ctx := context.Background()

	if err := c.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if err := c.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	_, logout, reload, _ := backend.counts()
	if logout != 1 || reload != 1 {
		t.Errorf("backend saw logout=%d reload=%d, want 1 and 1", logout, reload)
	}
}

func TestShutdownDrivesTheBackend(t *testing.T) {
	backend := newFakeBackend()
	c := serve(t, backend)

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, sd := backend.counts(); sd == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the backend never saw a shutdown")
}

// TestEventsSendsCurrentStateFirst means a peer renders correctly the moment it subscribes, with no separate
// /status call and no blank window.
func TestEventsSendsCurrentStateFirst(t *testing.T) {
	backend := newFakeBackend()
	c := serve(t, backend)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan Event, 4)
	go func() { _ = c.Events(ctx, func(ev Event) { got <- ev }) }()

	select {
	case ev := <-got:
		if ev.Kind != "status" || ev.Status == nil || ev.Status.Principal != "you@example.com" {
			t.Fatalf("first event = %+v, want the current status", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no initial status event within 3s")
	}

	// A subsequent backend event reaches the peer on the same stream.
	backend.events <- Event{Kind: "reauth", Message: "the session window has closed"}
	select {
	case ev := <-got:
		if ev.Kind != "reauth" {
			t.Errorf("second event = %+v, want the reauth push", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reauth event within 3s")
	}
}

// sameFile compares two paths by identity rather than by string: on macOS /tmp is a symlink to /private/tmp and
// resolution deliberately calls EvalSymlinks, so equal files have unequal path strings.
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// TestDaemonBinaryPrefersASiblingPmon is the regression for a bug that made the menu-bar app's Start and Log in
// unusable: resolving the daemon as os.Executable() meant a peer that is NOT pmon re-exec'd ITSELF with a
// `daemon` argument, launching a second copy of that app instead of a daemon, and every start died on the
// readiness timeout. A non-pmon host must resolve the sibling pmon that ships beside it in the .app bundle.
func TestDaemonBinaryPrefersASiblingPmon(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "pmontray")
	sibling := filepath.Join(dir, "pmon")
	for _, p := range []string{host, sibling} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
	}

	// Simulate being run as the tray: resolution must pick the sibling, never the host.
	got, err := daemonBinaryFrom(host, "", false)
	if err != nil {
		t.Fatalf("daemonBinaryFrom: %v", err)
	}
	if sameFile(t, got, host) {
		t.Fatal("resolved the running binary (a non-pmon host); it would re-exec itself instead of the daemon")
	}
	if !sameFile(t, got, sibling) {
		t.Errorf("resolved %q, want the sibling %q", got, sibling)
	}
}

// TestDaemonBinaryUsesItselfWhenItIsPmon: the CLI's own case stays a direct self-exec, with no PATH lookup that
// could pick up a different pmon than the one the user invoked.
func TestDaemonBinaryUsesItselfWhenItIsPmon(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "pmon")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := daemonBinaryFrom(self, "", true)
	if err != nil {
		t.Fatalf("daemonBinaryFrom: %v", err)
	}
	if !sameFile(t, got, self) {
		t.Errorf("resolved %q, want the running pmon %q", got, self)
	}
}

// TestDaemonBinaryHonorsTheOverride covers the dev loop: an explicit binary wins over any search.
func TestDaemonBinaryHonorsTheOverride(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "pmon-dev")
	if err := os.WriteFile(override, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := daemonBinaryFrom(filepath.Join(dir, "pmontray"), override, false)
	if err != nil {
		t.Fatalf("daemonBinaryFrom: %v", err)
	}
	if got != override {
		t.Errorf("resolved %q, want the override %q", got, override)
	}
	// A non-runnable override is an error, not a silent fallback that would start the wrong binary.
	if _, err := daemonBinaryFrom(filepath.Join(dir, "pmontray"), filepath.Join(dir, "missing"), false); err == nil {
		t.Error("a missing override was accepted; it must fail rather than fall back")
	}
}

// TestDaemonBinaryFailsWhenNoPmonExists: with no sibling and nothing on PATH, resolution must return a clear
// error rather than a path that cannot serve.
func TestDaemonBinaryFailsWhenNoPmonExists(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "pmontray")
	if err := os.WriteFile(host, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir) // no pmon here
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("resolved %q with no pmon available; want an error", got)
	}
}

// TestMutationsRejectGET is a small hardening check: the control socket can start a login, so a route that
// mutates must not be reachable by a bare GET.
func TestMutationsRejectGET(t *testing.T) {
	serve(t, newFakeBackend())
	sock, _ := state.SocketPath()
	client := unixHTTPClient(sock)

	for _, path := range []string{PathLogin, PathLogout, PathReload, PathShutdown} {
		resp, err := client.Get("http://pmon" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = HTTP %d, want 405", path, resp.StatusCode)
		}
	}
}

// TestIsDialFailureCoversAnyDialError: a peer branches on ErrDaemonNotRunning to decide whether to offer a start.
// Keying on an essno allow-list meant an unlisted failure — a stale non-socket file at the path, a permission
// problem — looked like a LIVE daemon and blocked auto-start entirely. Any dial-op error must read as "no daemon".
func TestIsDialFailureCoversAnyDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ENOENT", &net.OpError{Op: "dial", Err: syscall.ENOENT}, true},
		{"ECONNREFUSED", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		// The cases the allow-list missed:
		{"EACCES on dial", &net.OpError{Op: "dial", Err: syscall.EACCES}, true},
		{"ECONNABORTED on dial", &net.OpError{Op: "dial", Err: syscall.ECONNABORTED}, true},
		{"a non-socket file", &net.OpError{Op: "dial", Err: syscall.ENOTSOCK}, true},
		// Not a dial: a mid-request failure against a live daemon must NOT read as "not running".
		{"read error", &net.OpError{Op: "read", Err: syscall.EINVAL}, false},
	}
	for _, tc := range tests {
		if got := isDialFailure(tc.err); got != tc.want {
			t.Errorf("%s: isDialFailure(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// TestDaemonBinaryTrustsSelfDeclarationNotFilename covers the install layouts a filename check broke: a release
// artifact (pmon_0.3.0_darwin_arm64) and a symlinked install (Homebrew / /usr/local/bin) are genuine pmon
// binaries under another name, and must be able to start their own daemon.
func TestDaemonBinaryTrustsSelfDeclarationNotFilename(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // no pmon on PATH, so a wrong answer fails rather than silently working
	for _, name := range []string{"pmon_0.3.0_darwin_arm64", "pmon2", "pmon"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := daemonBinaryFrom(p, "", true) // it declares itself the daemon host
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !sameFile(t, got, p) {
			t.Errorf("%s: resolved %q, want itself %q", name, got, p)
		}
	}
}

// TestDaemonBinaryRejectsANonRegularSibling: a FIFO, socket, or device node with an execute bit was accepted as
// the daemon binary and exec'd, hanging or failing opaquely.
func TestDaemonBinaryRejectsANonRegularSibling(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	host := filepath.Join(dir, "pmontray")
	if err := os.WriteFile(host, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fifo := filepath.Join(dir, "pmon")
	if err := syscall.Mkfifo(fifo, 0o755); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("accepted a FIFO as the daemon binary: %q", got)
	}
}

// TestDaemonBinaryRejectsAGroupWritableTarget: a found-by-search target runs with this user's privileges and
// inherits the wire token and control socket, so one another user could replace must be refused. Installs under
// a group-writable prefix (a single-admin Mac's /usr/local/bin is staff-writable) are the real case.
func TestDaemonBinaryRejectsAGroupWritableTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	host := filepath.Join(dir, "pmontray")
	sibling := filepath.Join(dir, "pmon")
	for _, p := range []string{host, sibling} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	if _, err := daemonBinaryFrom(host, "", false); err != nil {
		t.Fatalf("precondition: a 0755 sibling should be accepted: %v", err)
	}
	if err := os.Chmod(sibling, 0o775); err != nil { // group-writable
		t.Fatalf("Chmod: %v", err)
	}
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("accepted a group-writable spawn target: %q", got)
	}
}

// TestStartDaemonUsesTheResolvedBinary pins the ACTUAL bug the resolution exists for: StartDaemon must exec the
// resolved pmon, not os.Executable(). Without this, reverting StartDaemon to os.Executable() — the original
// tray-launches-itself bug — leaves the suite green because only DaemonBinary is covered.
func TestStartDaemonUsesTheResolvedBinary(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	dir := t.TempDir()
	// A stub that records the argv it was invoked with, standing in for the real pmon daemon.
	marker := filepath.Join(dir, "spawned.txt")
	stub := filepath.Join(dir, "pmon")
	script := "#!/bin/sh\necho \"$0 $*\" > " + marker + "\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(daemonBinaryEnv, stub)

	if err := StartDaemon(); err != nil {
		t.Fatalf("StartDaemon: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(marker); err == nil {
			got := string(data)
			if !strings.Contains(got, "pmon") || !strings.Contains(got, "daemon") {
				t.Errorf("spawned %q, want the resolved pmon with the daemon subcommand", got)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("StartDaemon never executed the resolved binary; it likely re-exec'd the test binary instead")
}

// TestDaemonBinaryRejectsALooseDirectory closes the loop log's review found: unlink permission on Unix comes from
// the parent DIRECTORY, not the file, so a 0755 binary we own inside a 0777 directory is still swappable by any
// local user — a file-only check asserted a trust it did not establish.
func TestDaemonBinaryRejectsALooseDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("PATH", dir)
	host := filepath.Join(dir, "pmontray")
	sibling := filepath.Join(dir, "pmon")
	for _, p := range []string{host, sibling} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	if _, err := daemonBinaryFrom(host, "", false); err != nil {
		t.Fatalf("precondition: a 0755 sibling in a 0755 dir should be accepted: %v", err)
	}

	// The file stays 0755 and ours; only the directory loosens.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("accepted %q in a world-writable directory; another user could replace it there", got)
	} else if !strings.Contains(err.Error(), "directory") {
		t.Errorf("refused with %q; want the directory named as the cause", err)
	}
}
