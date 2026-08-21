package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// isolate points the state directory at a temp dir, so a test never touches the real user config.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(dirEnv, dir)
	return dir
}

func TestAssignPortIsStickyAndCompact(t *testing.T) {
	c := &Config{Ports: map[string]int{}}
	base := PortBase()
	a := c.AssignPort("alpha")
	b := c.AssignPort("beta")
	if a != base || b != base+1 {
		t.Fatalf("first two datasources got ports %d,%d; want %d,%d", a, b, base, base+1)
	}
	if again := c.AssignPort("alpha"); again != a {
		t.Errorf("AssignPort(alpha) = %d on second call, want sticky %d", again, a)
	}
	// A freed slot (lower number) is reused before extending the range.
	delete(c.Ports, "alpha")
	if reused := c.AssignPort("gamma"); reused != a {
		t.Errorf("AssignPort(gamma) = %d, want the freed lowest slot %d", reused, a)
	}
}

func TestUpdateConcurrentWritersDoNotLoseUpdates(t *testing.T) {
	isolate(t)

	// Simulate the daemon's own concurrent writers — a login stamping the token while discovery assigns
	// sticky ports. Under the flock none are lost (a plain load/save would drop all but the last).
	const n = 25
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = Update(func(c *Config) error {
				c.Ports[fmt.Sprintf("ds-%d", i)] = PortBase() + i
				c.Token = "tok"
				return nil
			})
		}(i)
	}
	wg.Wait()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Ports) != n {
		t.Errorf("lost updates under concurrency: %d ports, want %d", len(cfg.Ports), n)
	}
	if cfg.Token != "tok" {
		t.Errorf("token not persisted: %q", cfg.Token)
	}
}

func TestEnsureLocalPasswordIsGeneratedOnceAndStable(t *testing.T) {
	c := &Config{}
	pw, err := c.EnsureLocalPassword()
	if err != nil {
		t.Fatalf("EnsureLocalPassword: %v", err)
	}
	if !strings.HasPrefix(pw, "pmlocal_") || len(pw) < 20 {
		t.Errorf("generated password %q looks wrong", pw)
	}
	if again, _ := c.EnsureLocalPassword(); again != pw {
		t.Errorf("EnsureLocalPassword rotated the password: %q -> %q (must be stable)", pw, again)
	}
}

// TestSaveTightensPreExistingWorldReadablePermissions guards against os.WriteFile's mode argument only
// applying on create: if config.json already exists (left over from a looser writer, or hand-chmod'd), Save
// must still force it to 0600 on every write — the file carries RenewalToken, a bearer secret.
func TestSaveTightensPreExistingWorldReadablePermissions(t *testing.T) {
	dir := isolate(t)
	p := filepath.Join(dir, ConfigName)
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := Save(&Config{ControlPlane: "http://localhost:8090", Token: "tok-abc", RenewalToken: "pmr_abc123"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config perm = %o, want 0600 (Save must tighten a pre-existing world-readable file)", perm)
	}
}

// TestSaveLeavesNoStrayTempFile guards the write-then-atomic-rename path: Save writes to a temp file (always
// created at 0600, unlike write-then-chmod, which would briefly leave the plaintext RenewalToken in a
// pre-existing 0644 inode) and renames it into place, leaving exactly config.json behind.
func TestSaveLeavesNoStrayTempFile(t *testing.T) {
	dir := isolate(t)
	if err := Save(&Config{ControlPlane: "http://localhost:8090", Token: "tok-abc", RenewalToken: "pmr_abc123"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != ConfigName {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("expected only %q in the state dir after Save, got %v", ConfigName, names)
	}
}

// TestLoggedInRequiresTokenAndControlPlane locks the condition the daemon brokers on: partial state (a
// principal with no token, a token with no control plane) must read as NOT logged in, so the daemon stays idle
// rather than opening listeners it cannot serve.
func TestLoggedInRequiresTokenAndControlPlane(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"complete", Config{ControlPlane: "http://cp", Token: "tok"}, true},
		{"no token", Config{ControlPlane: "http://cp", Principal: "you@example.com"}, false},
		{"no control plane", Config{Token: "tok"}, false},
		{"empty", Config{}, false},
	}
	for _, tc := range tests {
		if got := tc.cfg.LoggedIn(); got != tc.want {
			t.Errorf("%s: LoggedIn() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestEnsureDirIsOwnerOnly locks the property the control socket's security rests on: the state directory is
// 0700, so only the same OS user can reach the socket inside it.
func TestEnsureDirIsOwnerOnly(t *testing.T) {
	t.Setenv(dirEnv, filepath.Join(t.TempDir(), "nested", "proxy-monster"))
	dir, err := EnsureDir()
	if err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir perm = %o, want 0700", perm)
	}
}

// TestEnsureDirTightensALooseExistingDir is the other half of that property: MkdirAll's mode applies only on
// create, so a directory left at 0755 by an older version (or by a user's umask) must be tightened — the whole
// control-socket security model is "only the same OS user can reach it".
func TestEnsureDirTightensALooseExistingDir(t *testing.T) {
	dir := isolate(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir perm = %o after EnsureDir, want 0700 (a loose pre-existing dir must be tightened)", perm)
	}
}

// TestSocketPathFitsTheKernelLimit covers the case a deep worktree hits for real: a unix socket path longer
// than sun_path fails to bind with EINVAL, so SocketPath must fall back to a short path rather than hand back
// one the daemon cannot listen on.
func TestSocketPathFitsTheKernelLimit(t *testing.T) {
	// A state dir well past the limit on its own.
	deep := filepath.Join(t.TempDir(), strings.Repeat("nested-directory-segment/", 8), "proxy-monster")
	t.Setenv(dirEnv, deep)
	if socketFallbackRoot != "/tmp" {
		t.Fatalf("production fallback root = %q, want /tmp", socketFallbackRoot)
	}
	shortRoot := t.TempDir()
	oldRoot := socketFallbackRoot
	socketFallbackRoot = shortRoot
	t.Cleanup(func() { socketFallbackRoot = oldRoot })

	sock, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath for a deep state dir: %v", err)
	}
	if len(sock) > maxSocketPath {
		t.Errorf("socket path is %d bytes (%q), over the %d-byte limit", len(sock), sock, maxSocketPath)
	}
	wantDir := filepath.Join(shortRoot, fmt.Sprintf("pmon-%d", os.Getuid()))
	if got := filepath.Dir(sock); got != wantDir {
		t.Errorf("fallback socket dir = %q, want injected fixed root %q", got, wantDir)
	}
	// Deterministic: every peer must derive the same path from the same state dir, with no coordination.
	again, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath (second call): %v", err)
	}
	if again != sock {
		t.Errorf("SocketPath is not deterministic: %q then %q", sock, again)
	}
	// macOS GUI and terminal processes can carry different TMPDIR values. The daemon and CLI must still meet.
	t.Setenv("TMPDIR", t.TempDir())
	withDifferentTemp, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath with a different TMPDIR: %v", err)
	}
	if withDifferentTemp != sock {
		t.Errorf("SocketPath depends on TMPDIR: %q then %q", sock, withDifferentTemp)
	}
	// A different state dir must NOT collide with it.
	t.Setenv(dirEnv, filepath.Join(t.TempDir(), strings.Repeat("another-long-directory/", 8), "proxy-monster"))
	other, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath for a second deep dir: %v", err)
	}
	if other == sock {
		t.Error("two different state dirs derived the same fallback socket path")
	}

	// The fallback's directory is owner-only, which is this API's whole authentication.
	info, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("Stat fallback socket dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("fallback socket dir perm = %o, want 0700", perm)
	}
}

// TestShortSocketDirRefusesADirectoryOwnedByAnotherUser is the multi-user half of the fallback's safety. The
// temp dir is world-writable + sticky on Linux and the directory name is predictable, so another local user can
// pre-create it; MkdirAll succeeds on ANY existing directory regardless of owner, which would put a
// login-capable socket in a path someone else controls. Ownership must be verified, and a mismatch fatal.
func TestShortSocketDirRefusesADirectoryOwnedByAnotherUser(t *testing.T) {
	// root's uid (0) stands in for "not us" — a real attacker's dir is the same case. Skip when running AS root,
	// where the check would legitimately pass.
	if os.Getuid() == 0 {
		t.Skip("running as root: uid 0 is not a foreign owner here")
	}
	tmp := t.TempDir()
	d := filepath.Join(tmp, fmt.Sprintf("pmon-%d", os.Getuid()))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// A test cannot chown to another user, so drive the guard with a DIFFERENT expected owner — exactly the
	// comparison it makes when an attacker pre-created the path. Without this the uid branch is never exercised
	// and could be deleted with the suite still green.
	if _, err := shortSocketDirAt(tmp, os.Getuid()+1); err == nil {
		t.Error("a directory owned by another uid was accepted; it must fail closed")
	} else if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("refused with %q; want the ownership check to be what rejects it", err)
	}

	// Ours, so it is accepted — and tightened if loose.
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	got, err := shortSocketDirAt(tmp, os.Getuid())
	if err != nil {
		t.Fatalf("shortSocketDirAt on our own dir: %v", err)
	}
	if got != d {
		t.Errorf("shortSocketDir = %q, want %q", got, d)
	}
	after, err := os.Lstat(d)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if perm := after.Mode().Perm(); perm != 0o700 {
		t.Errorf("perm = %o after shortSocketDir, want 0700 (a loose dir must be tightened)", perm)
	}
}

// TestShortSocketDirRefusesASymlink: a symlink at the predictable path would redirect the socket somewhere the
// attacker controls, so it must be rejected rather than followed.
func TestShortSocketDirRefusesASymlink(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(tmp, fmt.Sprintf("pmon-%d", os.Getuid()))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := shortSocketDirAt(tmp, os.Getuid())
	if err == nil {
		t.Fatal("shortSocketDir followed a symlink at the fallback path; it must refuse")
	}
	// Pin the SYMLINK check specifically. A symlink-to-directory satisfies MkdirAll and IsDir, so without an
	// Lstat-based check the refusal would come from somewhere else (or not at all) and this test would pass
	// while an attacker-controlled redirect went unnoticed.
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refused with %q; want the symlink check to be what rejects it", err)
	}
}

// TestSocketPathStaysInTheStateDirWhenItFits: the fallback is for long paths only — a normal install keeps its
// socket beside the config, where it is discoverable.
func TestSocketPathStaysInTheStateDirWhenItFits(t *testing.T) {
	dir := isolate(t)
	sock, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if filepath.Dir(sock) != dir {
		t.Errorf("socket = %q, want it inside the state dir %q", sock, dir)
	}
}

// TestPidLockIsExclusiveAndReportsLiveness covers the daemon's single-instance guard: while the lock is held
// DaemonRunning is true and a second acquire fails without error (so a racing peer's spawn loses gracefully
// rather than producing two daemons); after release both invert.
func TestPidLockIsExclusiveAndReportsLiveness(t *testing.T) {
	isolate(t)

	if DaemonRunning() {
		t.Fatal("DaemonRunning() true before any lock was taken")
	}
	held, err := AcquirePidLock()
	if err != nil || !held {
		t.Fatalf("AcquirePidLock() = %v, %v; want true, nil", held, err)
	}
	if !DaemonRunning() {
		t.Error("DaemonRunning() false while the lock is held")
	}
	if pid := DaemonPid(); pid != os.Getpid() {
		t.Errorf("DaemonPid() = %d, want this process %d", pid, os.Getpid())
	}

	ReleasePidLock()
	if DaemonRunning() {
		t.Error("DaemonRunning() true after release")
	}
}

// TestReleasePidLockKeepsTheFile locks the reason the pid file is NOT unlinked on release: unlock-then-unlink let
// a second daemon lock the same inode before the first removed it, after which a third created and locked a fresh
// one — two daemons each believing it was the singleton, each entitled to unlink the other's control socket.
// Liveness comes from whether the flock can be taken, never from the pid inside, so stale contents are harmless.
func TestReleasePidLockKeepsTheFile(t *testing.T) {
	isolate(t)
	if _, err := AcquirePidLock(); err != nil {
		t.Fatalf("AcquirePidLock: %v", err)
	}
	p, err := PidPath()
	if err != nil {
		t.Fatalf("PidPath: %v", err)
	}
	ReleasePidLock()

	if _, err := os.Stat(p); err != nil {
		t.Errorf("the pid file was removed on release (%v); one stable inode must remain so the flock is the sole arbiter", err)
	}
	// And it is re-lockable, so a later daemon still starts.
	held, err := AcquirePidLock()
	if err != nil || !held {
		t.Errorf("AcquirePidLock after release = %v, %v; want true, nil", held, err)
	}
	ReleasePidLock()
}
