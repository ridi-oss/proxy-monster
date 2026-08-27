package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/singleinstance"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

var daemonLockForTest *singleinstance.Daemon

func acquireDaemonLock(ctx context.Context) (bool, error) {
	if _, err := state.EnsureDir(); err != nil {
		return false, err
	}
	instance, err := state.DaemonInstance()
	if err != nil {
		return false, err
	}
	lock, acquired, err := instance.Acquire(ctx)
	if err == nil && acquired {
		daemonLockForTest = lock
	}
	return acquired, err
}

func releaseDaemonLock() error {
	lock := daemonLockForTest
	daemonLockForTest = nil
	return lock.Close()
}

func runningDaemonPID(ctx context.Context) (int, bool, error) {
	instance, err := state.DaemonInstance()
	if err != nil {
		return 0, false, err
	}
	owner, err := instance.Client().Owner(ctx)
	if err != nil || owner == nil {
		return 0, false, err
	}
	return owner.PID(), true, nil
}

func currentDaemonOwner(t *testing.T) *singleinstance.Owner {
	t.Helper()
	instance, err := state.DaemonInstance()
	if err != nil {
		t.Fatalf("DaemonInstance: %v", err)
	}
	owner, err := instance.Client().Owner(context.Background())
	if err != nil || owner == nil {
		t.Fatalf("Owner = %#v, %v; want owner", owner, err)
	}
	return owner
}

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
	loginStarted chan struct{}
	loginRelease <-chan struct{}
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

func (f *fakeBackend) Login(ctx context.Context, _ LoginRequest, onEvent func(LoginEvent)) error {
	f.mu.Lock()
	f.loginCalls++
	evs, err := f.loginEvents, f.loginErr
	started, release := f.loginStarted, f.loginRelease
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})

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
		{Name: "pg", Engine: "postgres", Brokered: false, Reason: "postgres brokering not yet supported"},
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

func TestReleasedClientPathReachesNewDaemon(t *testing.T) {
	backend := newFakeBackend()
	serve(t, backend)
	paths, err := state.SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("SocketPaths = %v, want canonical and released paths", paths)
	}
	info, err := os.Lstat(paths[1])
	if err != nil {
		t.Fatalf("Lstat released path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("released path mode = %v, want symlink", info.Mode())
	}
	if target, err := os.Readlink(paths[1]); err != nil || target != paths[0] {
		t.Fatalf("released path target = %q, %v; want %q", target, err, paths[0])
	}

	resp, err := unixHTTPClient(paths[1]).Get("http://pmon" + PathStatus)
	if err != nil {
		t.Fatalf("GET status through released path: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status through released path = HTTP %d, want 200", resp.StatusCode)
	}
}

func TestNewClientReachesReleasedDaemonPath(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })
	paths, err := state.SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("SocketPaths = %v, want canonical and released paths", paths)
	}
	ln, err := net.Listen("unix", paths[1])
	if err != nil {
		t.Fatalf("listen on released path: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, Status{Principal: "released-daemon"})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status through released daemon path: %v", err)
	}
	if status.Principal != "released-daemon" {
		t.Errorf("Status principal = %q, want released-daemon", status.Principal)
	}
}

func TestBlockedReleasedPathDoesNotDisableCanonicalSocket(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	paths, err := state.SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("SocketPaths = %v, want canonical and released paths", paths)
	}
	if err := os.Mkdir(paths[1], 0o700); err != nil {
		t.Fatalf("Mkdir released path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths[1], "blocked"), nil, 0o600); err != nil {
		t.Fatalf("seed blocked released path: %v", err)
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })

	server, err := Listen(newFakeBackend())
	if err != nil {
		t.Fatalf("Listen with blocked released path: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		server.Close()
		<-done
	})
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status through canonical socket: %v", err)
	}
}

// The socket mode and its 0700 parent directory authenticate the control API.
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

func TestOwnerPinnedClientRejectsReplacementPeerBeforeRequest(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	requested := make(chan struct{}, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested <- struct{}{}
		_ = json.NewEncoder(w).Encode(Status{})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client, err := newClient(os.Getpid() + 1)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "daemon changed") {
		t.Fatalf("Status through a replacement peer = %v, want daemon-changed error", err)
	}
	select {
	case <-requested:
		t.Fatal("owner-pinned client sent a request to the replacement peer")
	default:
	}
}

func TestStopDaemonHonorsCanceledContextBeforePidFallback(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := StopDaemon(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("StopDaemon with a canceled context = %v, want context.Canceled", err)
	}
}

func TestConnectHonorsContextWhilePidPublicationIsStalled(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	pidPath, err := state.PidPath()
	if err != nil {
		t.Fatalf("PidPath: %v", err)
	}
	transitionFile, err := os.OpenFile(pidPath+".transition", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open transition lock: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		transitionFile.Close()
		t.Fatalf("lock transition: %v", err)
	}
	t.Cleanup(func() {
		syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
		transitionFile.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := Connect(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect while pid publication is stalled = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Connect took %s, want at most 1s", elapsed)
	}
}

func TestWaitForOwnerExitHonorsDeadlineWhilePidPublicationIsStalled(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })
	owner := currentDaemonOwner(t)
	pidPath, err := state.PidPath()
	if err != nil {
		t.Fatalf("PidPath: %v", err)
	}
	transitionFile, err := os.OpenFile(pidPath+".transition", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open transition lock: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		transitionFile.Close()
		t.Fatalf("lock transition: %v", err)
	}
	t.Cleanup(func() {
		syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
		transitionFile.Close()
	})

	const timeout = 100 * time.Millisecond
	started := time.Now()
	err = waitForOwnerExit(context.Background(), owner, timeout)
	if err == nil || !strings.Contains(err.Error(), "did not exit within") {
		t.Fatalf("waitForOwnerExit while pid publication is stalled = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("waitForOwnerExit took %s, want at most 1s", elapsed)
	}
}

func TestWaitForOwnerExitRetriesPidLockOperationTimeout(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	owner := currentDaemonOwner(t)
	released := false
	t.Cleanup(func() {
		if !released {
			_ = releaseDaemonLock()
		}
	})
	pidPath, err := state.PidPath()
	if err != nil {
		t.Fatalf("PidPath: %v", err)
	}
	transitionFile, err := os.OpenFile(pidPath+".transition", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open transition lock: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		transitionFile.Close()
		t.Fatalf("lock transition: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- waitForOwnerExit(context.Background(), owner, 4*time.Second)
	}()
	time.Sleep(2200 * time.Millisecond)
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("unlock transition: %v", err)
	}
	if err := transitionFile.Close(); err != nil {
		t.Fatalf("close transition: %v", err)
	}
	if err := releaseDaemonLock(); err != nil {
		t.Fatalf("ReleasePidLock: %v", err)
	}
	released = true

	if err := <-result; err != nil {
		t.Fatalf("waitForOwnerExit after an internal pid-lock timeout = %v, want nil", err)
	}
}

func TestDaemonSignalErrorAcceptsAnExitedDaemon(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	owner := currentDaemonOwner(t)
	if err := releaseDaemonLock(); err != nil {
		t.Fatalf("ReleasePidLock: %v", err)
	}
	err = handleDaemonSignalError(context.Background(), owner, fmt.Errorf("signal: %w", syscall.ESRCH))
	if err != nil {
		t.Fatalf("handleDaemonSignalError after lock release = %v, want nil", err)
	}
}

func TestDaemonSignalErrorDoesNotHideALiveOwner(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })
	owner := currentDaemonOwner(t)

	err = handleDaemonSignalError(context.Background(), owner, fmt.Errorf("signal: %w", syscall.ESRCH))
	if err == nil || !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("handleDaemonSignalError with a live owner = %v, want ESRCH", err)
	}
}

func TestDaemonSignalErrorPreservesOtherFailures(t *testing.T) {
	want := errors.New("signal failed")
	if got := handleDaemonSignalError(context.Background(), nil, want); !errors.Is(got, want) {
		t.Fatalf("handleDaemonSignalError = %v, want %v", got, want)
	}
}

const foregroundDaemonHelperEnv = "PMON_CONTROL_FOREGROUND_DAEMON_HELPER"

func TestStopDaemonSignalsForegroundLockOwner(t *testing.T) {
	configDir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestForegroundDaemonLockHelper$")
	command.Env = append(os.Environ(),
		"PMON_CONFIG_DIR="+configDir,
		foregroundDaemonHelperEnv+"=1",
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start foreground daemon helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("foreground daemon helper readiness = %q, %v", line, err)
	}
	pid := command.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("Getpgid(%d): %v", pid, err)
	}
	if pgid != pid {
		t.Fatalf("foreground daemon helper does not lead its process group: pid=%d pgid=%d", pid, pgid)
	}
	t.Setenv("PMON_CONFIG_DIR", configDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := StopDaemon(ctx); err != nil {
		t.Fatalf("StopDaemon against a foreground lock owner: %v", err)
	}
	_ = command.Wait()
	waited = true
}

func TestForegroundDaemonLockHelper(t *testing.T) {
	if os.Getenv(foregroundDaemonHelperEnv) == "" {
		return
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	select {}
}

const gracefulShutdownHelperEnv = "PMON_CONTROL_GRACEFUL_SHUTDOWN_HELPER"

func TestStopDaemonLetsGracefulShutdownFinish(t *testing.T) {
	configDir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestGracefulShutdownHelper$")
	command.Env = append(os.Environ(),
		"PMON_CONFIG_DIR="+configDir,
		gracefulShutdownHelperEnv+"=1",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start graceful shutdown helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("graceful shutdown helper readiness = %q, %v", line, err)
	}

	t.Setenv("PMON_CONFIG_DIR", configDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := StopDaemon(ctx); err != nil {
		t.Fatalf("StopDaemon during graceful cleanup: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("graceful shutdown helper was signaled before cleanup finished: %v", err)
	}
	waited = true
}

func TestGracefulShutdownHelper(t *testing.T) {
	if os.Getenv(gracefulShutdownHelperEnv) == "" {
		return
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		go func() {
			time.Sleep(1500 * time.Millisecond)
			if err := releaseDaemonLock(); err != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}()
	})}
	go func() { _ = srv.Serve(ln) }()
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	select {}
}

const replacementDaemonHelperEnv = "PMON_CONTROL_REPLACEMENT_DAEMON_HELPER"
const replacementDaemonPathEnv = "PMON_CONTROL_REPLACEMENT_DAEMON_PATH"

func TestStopDaemonDoesNotSignalReplacementOwner(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("PMON_CONFIG_DIR", configDir)
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() { _ = releaseDaemonLock() })

	pidPath, err := state.PidPath()
	if err != nil {
		t.Fatalf("PidPath: %v", err)
	}
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReplacementDaemonLockHelper$")
	command.Env = append(os.Environ(),
		replacementDaemonHelperEnv+"=1",
		replacementDaemonPathEnv+"="+pidPath,
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("replacement daemon stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("replacement daemon stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start replacement daemon: %v", err)
	}
	stdoutReader := bufio.NewReader(stdout)
	if line, err := stdoutReader.ReadString('\n'); err != nil || line != "waiting\n" {
		t.Fatalf("replacement daemon startup = %q, %v", line, err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	handoffErr := make(chan error, 1)
	handoff := func() error {
		transitionFile, err := os.OpenFile(pidPath+".transition", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX); err != nil {
			_ = transitionFile.Close()
			return err
		}
		defer func() {
			_ = syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
			_ = transitionFile.Close()
		}()
		if err := releaseDaemonLock(); err != nil {
			return err
		}
		if _, err := stdin.Write([]byte("acquire\n")); err != nil {
			return err
		}
		if err := stdin.Close(); err != nil {
			return err
		}
		line, err := stdoutReader.ReadString('\n')
		if err != nil || line != "ready\n" {
			return fmt.Errorf("replacement daemon readiness = %q: %v", line, err)
		}
		return nil
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := handoff(); err != nil {
			handoffErr <- err
			http.Error(w, "handoff failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	err = StopDaemon(ctx)
	select {
	case handoffErr := <-handoffErr:
		t.Fatalf("replace daemon owner: %v", handoffErr)
	default:
	}
	if !errors.Is(err, ErrDaemonReplaced) {
		t.Fatalf("StopDaemon during owner replacement = %v, want ErrDaemonReplaced", err)
	}

	ownerPID, running, err := runningDaemonPID(context.Background())
	if err != nil || !running || ownerPID != command.Process.Pid {
		t.Fatalf("replacement lock owner = %d, %t, %v; want %d, true, nil", ownerPID, running, err, command.Process.Pid)
	}
	if err := syscall.Kill(command.Process.Pid, 0); err != nil {
		_, _ = command.Process.Wait()
		waited = true
		t.Fatalf("StopDaemon signaled replacement pid %d: %v", command.Process.Pid, err)
	}
}

func TestReplacementDaemonLockHelper(t *testing.T) {
	if os.Getenv(replacementDaemonHelperEnv) == "" {
		return
	}
	if _, err := os.Stdout.WriteString("waiting\n"); err != nil {
		t.Fatalf("write startup readiness: %v", err)
	}
	if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil || line != "acquire\n" {
		t.Fatalf("wait for lock handoff = %q, %v", line, err)
	}
	path := os.Getenv(replacementDaemonPathEnv)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open daemon lock: %v", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("lock daemon: %v", err)
	}
	if err := file.Truncate(0); err != nil {
		t.Fatalf("truncate daemon pid: %v", err)
	}
	if _, err := file.WriteAt([]byte(fmt.Sprintf("%d", os.Getpid())), 0); err != nil {
		t.Fatalf("write daemon pid: %v", err)
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	select {}
}

func TestShortControlRequestTimesOutAfterAccept(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		close(release)
		_ = srv.Close()
	})

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	started := time.Now()
	if _, err := c.Status(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status against a silent listener = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > controlRequestTimeout+time.Second {
		t.Errorf("Status took %s, want at most %s", elapsed, controlRequestTimeout+time.Second)
	}

	started = time.Now()
	_, err = Connect(context.Background())
	if !errors.Is(err, ErrDaemonUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect against a silent listener = %v, want unreachable with deadline exceeded", err)
	}
	maxConnectTime := controlRequestTimeout + daemonStartRaceGrace + time.Second
	if elapsed := time.Since(started); elapsed > maxConnectTime {
		t.Errorf("Connect took %s, want at most %s", elapsed, maxConnectTime)
	}
}

func TestConnectWaitsForAStartingDaemonSocket(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}

	type serverResult struct {
		srv *http.Server
		err error
	}
	serverReady := make(chan serverResult, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			serverReady <- serverResult{err: err}
			return
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(Status{})
		})}
		serverReady <- serverResult{srv: srv}
		_ = srv.Serve(ln)
	}()

	client, connectErr := Connect(context.Background())
	result := <-serverReady
	if result.err != nil {
		t.Fatalf("delayed listen: %v", result.err)
	}
	t.Cleanup(func() { _ = result.srv.Close() })
	if connectErr != nil || client == nil {
		t.Fatalf("Connect while the daemon bound its socket = %v, want a client", connectErr)
	}
}

const delayedControlHelperEnv = "PMON_CONTROL_DELAYED_HELPER"
const delayedControlMarkerEnv = "PMON_CONTROL_DELAYED_HELPER_MARKER"

func TestPeersWaitForAStartingDaemonToReplaceTheSocket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		connect func(context.Context) (*Client, error)
	}{
		{name: "Connect", connect: Connect},
		{name: "EnsureDaemon", connect: EnsureDaemon},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testPeerWaitsForAStartingDaemonToReplaceTheSocket(t, tc.connect)
		})
	}
}

func testPeerWaitsForAStartingDaemonToReplaceTheSocket(
	t *testing.T,
	connect func(context.Context) (*Client, error),
) {
	t.Helper()
	configDir := t.TempDir()
	t.Setenv("PMON_CONFIG_DIR", configDir)
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	staleListener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on stale socket: %v", err)
	}
	t.Cleanup(func() { _ = staleListener.Close() })
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := staleListener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	marker := filepath.Join(configDir, "replace-socket")
	command := exec.Command(os.Args[0], "-test.run=^TestDelayedControlHelper$")
	command.Env = append(os.Environ(),
		"PMON_CONFIG_DIR="+configDir,
		delayedControlHelperEnv+"=1",
		delayedControlMarkerEnv+"="+marker,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start delayed control helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("delayed control helper readiness = %q, %v", line, err)
	}

	result := make(chan struct {
		client *Client
		err    error
	}, 1)
	go func() {
		client, err := connect(context.Background())
		result <- struct {
			client *Client
			err    error
		}{client: client, err: err}
	}()
	select {
	case accepted := <-accepted:
		if accepted.err != nil {
			t.Fatalf("accept stale control connection: %v", accepted.err)
		}
		defer accepted.conn.Close()
	case <-time.After(time.Second):
		t.Fatal("peer did not reach the stale control socket")
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatalf("release delayed control helper: %v", err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.client == nil {
			t.Fatalf("peer while the daemon replaced its stale socket = %v, want a client", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not follow the daemon to its replacement socket")
	}
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
	waited = true
}

func TestDelayedControlHelper(t *testing.T) {
	if os.Getenv(delayedControlHelperEnv) == "" {
		return
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	marker := os.Getenv(delayedControlMarkerEnv)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat release marker: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv, err := Listen(newFakeBackend())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestConnectReportsUnreachableDaemonWhenPidLockIsHeld(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil {
		t.Fatalf("AcquirePidLock: %v", err)
	}
	if !held {
		t.Fatal("AcquirePidLock reported an unexpected live daemon")
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})

	if _, err := Connect(context.Background()); !errors.Is(err, ErrDaemonUnreachable) {
		t.Errorf("Connect with a held pid lock and no socket = %v, want ErrDaemonUnreachable", err)
	}
}

func TestEnsureDaemonReplacesFailingSocketWithoutPidLock(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not pmon", http.StatusInternalServerError)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	binDir := t.TempDir()
	marker := filepath.Join(binDir, "spawned")
	stub := filepath.Join(binDir, "pmon")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n: > \"$PMON_TEST_MARKER\"\n"), 0o755); err != nil {
		t.Fatalf("write daemon stub: %v", err)
	}
	t.Setenv(daemonBinaryEnv, stub)
	t.Setenv("PMON_TEST_MARKER", marker)
	type replacementResult struct {
		server   *http.Server
		lockHeld bool
		err      error
	}
	replaced := make(chan replacementResult, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				replaced <- replacementResult{err: errors.New("daemon stub did not start")}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		held, err := acquireDaemonLock(context.Background())
		if err != nil || !held {
			replaced <- replacementResult{err: errors.New("replacement daemon could not acquire the pid lock")}
			return
		}
		result := replacementResult{lockHeld: true}
		if err := os.Remove(sock); err != nil {
			result.err = err
			replaced <- result
			return
		}
		realListener, err := net.Listen("unix", sock)
		if err != nil {
			result.err = err
			replaced <- result
			return
		}
		result.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(Status{})
		})}
		go func() { _ = result.server.Serve(realListener) }()
		replaced <- result
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, ensureErr := EnsureDaemon(ctx)
	result := <-replaced
	if result.lockHeld {
		t.Cleanup(func() {
			if err := releaseDaemonLock(); err != nil {
				t.Errorf("ReleasePidLock: %v", err)
			}
		})
	}
	if result.server != nil {
		t.Cleanup(func() { _ = result.server.Close() })
	}
	if result.err != nil {
		t.Fatalf("replace stale control socket: %v", result.err)
	}
	if ensureErr != nil || client == nil {
		t.Fatalf("EnsureDaemon through a replaced socket = %v, want a client", ensureErr)
	}
}

func TestPeersReportUnreachableDaemonWhenStatusFails(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "status unavailable", http.StatusInternalServerError)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	for name, connect := range map[string]func(context.Context) (*Client, error){
		"Connect":      Connect,
		"EnsureDaemon": EnsureDaemon,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := connect(context.Background()); !errors.Is(err, ErrDaemonUnreachable) {
				t.Errorf("%s with a held pid lock and failing status = %v, want ErrDaemonUnreachable", name, err)
			}
		})
	}
}

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

func TestLoginFlushesHeadersBeforeTheDeviceFlowResponds(t *testing.T) {
	backend := newFakeBackend()
	backend.loginStarted = make(chan struct{})
	release := make(chan struct{})
	backend.loginRelease = release
	c := serve(t, backend)
	const headerTimeout = 100 * time.Millisecond
	c.loginHTTP.Transport.(*http.Transport).ResponseHeaderTimeout = headerTimeout

	result := make(chan error, 1)
	go func() {
		result <- c.Login(context.Background(), LoginRequest{}, nil)
	}()
	select {
	case <-backend.loginStarted:
	case <-time.After(time.Second):
		t.Fatal("login did not reach the backend")
	}
	select {
	case err := <-result:
		t.Fatalf("Login returned before the device flow completed: %v", err)
	case <-time.After(2 * headerTimeout):
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Login did not finish after the device flow completed")
	}
}

func TestLoginWaitsForReleasedDaemonResponseHeaders(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	held, err := acquireDaemonLock(context.Background())
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %t, %v; want true, nil", held, err)
	}
	t.Cleanup(func() {
		if err := releaseDaemonLock(); err != nil {
			t.Errorf("ReleasePidLock: %v", err)
		}
	})
	sock, err := state.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathLogin {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(LoginEvent{Kind: "done"})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = srv.Close()
	})

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	const shortHeaderTimeout = 50 * time.Millisecond
	c.http.Transport.(*http.Transport).ResponseHeaderTimeout = shortHeaderTimeout
	result := make(chan error, 1)
	go func() {
		result <- c.Login(context.Background(), LoginRequest{}, nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("login did not reach the released-style handler")
	}
	select {
	case err := <-result:
		t.Fatalf("Login returned before released daemon responded: %v", err)
	case <-time.After(2 * shortHeaderTimeout):
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Login did not finish after released daemon responded")
	}
}

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

func TestEventsFailsWhenHeartbeatsStop(t *testing.T) {
	c := serve(t, newFakeBackend())
	const idleTimeout = 100 * time.Millisecond

	var got []Event
	started := time.Now()
	err := c.events(context.Background(), func(ev Event) {
		got = append(got, ev)
	}, idleTimeout)
	if !errors.Is(err, errEventStreamIdle) {
		t.Fatalf("Events error = %v, want event-stream idle timeout", err)
	}
	if len(got) != 1 || got[0].Kind != "status" {
		t.Fatalf("events before timeout = %+v, want the initial status only", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("event stream took %s to detect a %s idle timeout", elapsed, idleTimeout)
	}
}

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

func TestDaemonBinaryPrefersASiblingPmon(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "pmontray")
	sibling := filepath.Join(dir, "pmon")
	for _, p := range []string{host, sibling} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
	}

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
	if _, err := daemonBinaryFrom(filepath.Join(dir, "pmontray"), filepath.Join(dir, "missing"), false); err == nil {
		t.Error("a missing override was accepted; it must fail rather than fall back")
	}
}

func TestDaemonBinaryFailsWhenNoPmonExists(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "pmontray")
	if err := os.WriteFile(host, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("resolved %q with no pmon available; want an error", got)
	}
}

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

func TestIsDialFailureCoversAnyDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ENOENT", &net.OpError{Op: "dial", Err: syscall.ENOENT}, true},
		{"ECONNREFUSED", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"EACCES on dial", &net.OpError{Op: "dial", Err: syscall.EACCES}, true},
		{"ECONNABORTED on dial", &net.OpError{Op: "dial", Err: syscall.ECONNABORTED}, true},
		{"a non-socket file", &net.OpError{Op: "dial", Err: syscall.ENOTSOCK}, true},
		{"read error", &net.OpError{Op: "read", Err: syscall.EINVAL}, false},
	}
	for _, tc := range tests {
		if got := isDialFailure(tc.err); got != tc.want {
			t.Errorf("%s: isDialFailure(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestDaemonBinaryTrustsSelfDeclarationNotFilename(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for _, name := range []string{"pmon_0.3.0_darwin_arm64", "pmon2", "pmon"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := daemonBinaryFrom(p, "", true)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !sameFile(t, got, p) {
			t.Errorf("%s: resolved %q, want itself %q", name, got, p)
		}
	}
}

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
	if err := os.Chmod(sibling, 0o775); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("accepted a group-writable spawn target: %q", got)
	}
}

type cancelAfterFirstErrContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAfterFirstErrContext) Err() error {
	c.checks++
	if c.checks == 1 {
		c.cancel()
		return nil
	}
	return c.Context.Err()
}

func TestStartDaemonHonorsCancellationBeforeSpawn(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned.txt")
	stub := filepath.Join(dir, "pmon")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(daemonBinaryEnv, stub)
	ctx, cancel := context.WithCancel(context.Background())
	cancelCtx := &cancelAfterFirstErrContext{Context: ctx, cancel: cancel}

	if err := StartDaemon(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartDaemon after cancellation during setup = %v, want context.Canceled", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spawn marker after canceled StartDaemon = %v, want not found", err)
	}
}

func TestStartDaemonUsesTheResolvedBinary(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned.txt")
	stub := filepath.Join(dir, "pmon")
	script := "#!/bin/sh\necho \"$0 $*\" > " + marker + "\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(daemonBinaryEnv, stub)

	if err := StartDaemon(context.Background()); err != nil {
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

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if got, err := daemonBinaryFrom(host, "", false); err == nil {
		t.Errorf("accepted %q in a world-writable directory; another user could replace it there", got)
	} else if !strings.Contains(err.Error(), "directory") {
		t.Errorf("refused with %q; want the directory named as the cause", err)
	}
}
