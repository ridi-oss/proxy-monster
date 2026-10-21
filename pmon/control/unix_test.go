//go:build !windows

package control

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

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
	held, err := state.AcquirePidLock()
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(state.ReleasePidLock)

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
		// The shell creates the file before echo writes it, so an empty read is not the answer yet.
		if data, err := os.ReadFile(marker); err == nil && len(data) > 0 {
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

func TestNewClientReachesReleasedDaemonPath(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	held, err := state.AcquirePidLock()
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v; want true, nil", held, err)
	}
	t.Cleanup(state.ReleasePidLock)
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
		writeJSON(w, http.StatusOK, Status{Version: "released-daemon"})
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
	if status.Version != "released-daemon" {
		t.Errorf("Status version = %q, want released-daemon", status.Version)
	}
}
