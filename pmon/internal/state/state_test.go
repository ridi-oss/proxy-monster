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
	c := &Config{Servers: map[string]*Server{"a": {}, "b": {}}}
	base := PortBase()
	a := c.AssignPort("a", "alpha")
	b := c.AssignPort("b", "alpha")
	if a != base || b != base+1 {
		t.Fatalf("the same name on two servers got ports %d,%d; want %d,%d", a, b, base, base+1)
	}
	if again := c.AssignPort("a", "alpha"); again != a {
		t.Errorf("AssignPort(a, alpha) = %d on second call, want sticky %d", again, a)
	}
	// A freed slot (lower number) is reused before extending the range.
	delete(c.Servers["a"].Ports, "alpha")
	if reused := c.AssignPort("b", "gamma"); reused != a {
		t.Errorf("AssignPort(b, gamma) = %d, want the freed lowest slot %d", reused, a)
	}
}

// A single-server config from an earlier release loads as the default server, keeping its login, sticky
// ports and password, so saved client connections survive the upgrade.
func TestLegacyConfigLoadsAsDefaultServer(t *testing.T) {
	dir := isolate(t)
	legacy := `{"controlPlane":"https://cp","principal":"you@example.com","token":"tok","localPassword":"pmlocal_x","ports":{"acme":6100}}`
	if err := os.WriteFile(filepath.Join(dir, ConfigName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv := c.Servers[DefaultServer]
	if srv == nil || srv.ControlPlane != "https://cp" || srv.Token != "tok" || srv.Ports["acme"] != 6100 {
		t.Fatalf("default server = %+v, want the legacy login and ports", srv)
	}
	if c.LocalPassword != "pmlocal_x" {
		t.Errorf("LocalPassword = %q, want the legacy one", c.LocalPassword)
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	again, err := Load()
	if err != nil || again.Servers[DefaultServer].Token != "tok" || len(again.Servers) != 1 {
		t.Fatalf("round trip = %+v, %v", again, err)
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
				if c.Servers[DefaultServer] == nil {
					c.Servers[DefaultServer] = &Server{Ports: map[string]int{}}
				}
				c.Servers[DefaultServer].Ports[fmt.Sprintf("ds-%d", i)] = PortBase() + i
				c.LocalPassword = "pw"
				return nil
			})
		}(i)
	}
	wg.Wait()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(cfg.Servers[DefaultServer].Ports); got != n {
		t.Errorf("lost updates under concurrency: %d ports, want %d", got, n)
	}
	if cfg.LocalPassword != "pw" {
		t.Errorf("password not persisted: %q", cfg.LocalPassword)
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

// TestSaveLeavesNoStrayTempFile guards the write-then-atomic-rename path: Save writes to a temp file (always
// created at 0600, unlike write-then-chmod, which would briefly leave the plaintext RenewalToken in a
// pre-existing 0644 inode) and renames it into place, leaving exactly config.json behind.
func TestSaveLeavesNoStrayTempFile(t *testing.T) {
	dir := isolate(t)
	if err := Save(&Config{Servers: map[string]*Server{DefaultServer: {ControlPlane: "http://localhost:8090", Token: "tok-abc", RenewalToken: "pmr_abc123"}}}); err != nil {
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
		cfg  Server
		want bool
	}{
		{"complete", Server{ControlPlane: "http://cp", Token: "tok"}, true},
		{"no token", Server{ControlPlane: "http://cp", Principal: "you@example.com"}, false},
		{"no control plane", Server{Token: "tok"}, false},
		{"empty", Server{}, false},
	}
	for _, tc := range tests {
		if got := tc.cfg.LoggedIn(); got != tc.want {
			t.Errorf("%s: LoggedIn() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSocketPathDistinguishesRelativeStateDirsAcrossWorkingDirectories(t *testing.T) {
	root := t.TempDir()
	firstWD := filepath.Join(root, "first")
	secondWD := filepath.Join(root, "second")
	for _, dir := range []string{firstWD, secondWD} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("Mkdir %s: %v", dir, err)
		}
	}
	relativeStateDir := filepath.Join(strings.Repeat("long-state-dir/", 10), "proxy-monster")
	t.Setenv(dirEnv, relativeStateDir)
	shortRoot := "short"

	t.Chdir(firstWD)
	first, err := socketPathAt(shortRoot)
	if err != nil {
		t.Fatalf("SocketPath from first working directory: %v", err)
	}
	t.Chdir(secondWD)
	second, err := socketPathAt(shortRoot)
	if err != nil {
		t.Fatalf("SocketPath from second working directory: %v", err)
	}
	if first == second {
		t.Fatalf("relative state dirs in different working directories share %q", first)
	}
}

func TestSocketPathUsesProductionRoot(t *testing.T) {
	isolate(t)
	sock, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	want := filepath.Join(socketRoot(), socketDirName())
	if got := filepath.Dir(sock); got != want {
		t.Errorf("socket directory = %q, want %q", got, want)
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

func TestNullServerIsAConfigError(t *testing.T) {
	if _, err := parse([]byte(`{"servers":{"dev":null}}`)); err == nil {
		t.Error("a null server loaded; the daemon would dereference it")
	}
}
