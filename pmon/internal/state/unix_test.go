//go:build !windows

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The state directory holds bearer credentials and must stay owner-only.
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

// TestSaveTightensPreExistingWorldReadablePermissions guards against os.WriteFile's mode argument only
// applying on create: if config.json already exists (left over from a looser writer, or hand-chmod'd), Save
// must still force it to 0600 on every write — the file carries RenewalToken, a bearer secret.
func TestSaveTightensPreExistingWorldReadablePermissions(t *testing.T) {
	dir := isolate(t)
	p := filepath.Join(dir, ConfigName)
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := Save(&Config{Servers: map[string]*Server{DefaultServer: {ControlPlane: "http://localhost:8090", Token: "tok-abc", RenewalToken: "pmr_abc123"}}}); err != nil {
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

func TestSocketDirEnforcesOwnerAndMode(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: uid 0 is not a foreign owner here")
	}
	tmp := t.TempDir()
	d := filepath.Join(tmp, fmt.Sprintf("pmon-%d", os.Getuid()))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := socketDirAt(tmp, os.Getuid()+1); err == nil {
		t.Error("a directory owned by another uid was accepted; it must fail closed")
	} else if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("refused with %q; want the ownership check to be what rejects it", err)
	}

	for _, mode := range []os.FileMode{0o777, 0o500} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatalf("Chmod %o: %v", mode, err)
		}
		got, err := socketDirAt(tmp, os.Getuid())
		if err != nil {
			t.Fatalf("socketDirAt on mode %o: %v", mode, err)
		}
		if got != d {
			t.Errorf("socketDir = %q, want %q", got, d)
		}
		after, err := os.Lstat(d)
		if err != nil {
			t.Fatalf("Lstat: %v", err)
		}
		if perm := after.Mode().Perm(); perm != 0o700 {
			t.Errorf("mode = %o after socketDirAt, want 0700", perm)
		}
	}
}

func TestSocketDirRefusesASymlink(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(tmp, fmt.Sprintf("pmon-%d", os.Getuid()))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := socketDirAt(tmp, os.Getuid())
	if err == nil {
		t.Fatal("socketDirAt followed a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refused with %q; want the symlink check to be what rejects it", err)
	}
}

func TestSocketPathAlwaysUsesFixedOwnerDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "proxy-monster")
	t.Setenv(dirEnv, stateDir)
	root := t.TempDir()

	sock, err := socketPathAt(root)
	if err != nil {
		t.Fatalf("socketPathAt: %v", err)
	}
	wantDir := filepath.Join(root, fmt.Sprintf("pmon-%d", os.Getuid()))
	if got := filepath.Dir(sock); got != wantDir {
		t.Errorf("socket directory = %q, want %q", got, wantDir)
	}
	if len(sock) > maxSocketPath {
		t.Errorf("socket path is %d bytes (%q), over the %d-byte limit", len(sock), sock, maxSocketPath)
	}

	t.Setenv("TMPDIR", t.TempDir())
	again, err := socketPathAt(root)
	if err != nil {
		t.Fatalf("socketPathAt with a different TMPDIR: %v", err)
	}
	if again != sock {
		t.Errorf("socket path changed with TMPDIR: %q then %q", sock, again)
	}

	t.Setenv(dirEnv, filepath.Join(t.TempDir(), "proxy-monster"))
	other, err := socketPathAt(root)
	if err != nil {
		t.Fatalf("socketPathAt for a second state directory: %v", err)
	}
	if other == sock {
		t.Error("two state directories derived the same socket path")
	}

	info, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("Stat socket directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket directory mode = %o, want 0700", perm)
	}
}

func TestSocketPathsDeduplicateEquivalentRoots(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), strings.Repeat("long-state-dir/", 10), "proxy-monster")
	t.Setenv(dirEnv, stateDir)
	aliasRoot := filepath.Join(t.TempDir(), "tmp-link")
	if err := os.Symlink(socketRoot(), aliasRoot); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Setenv("TMPDIR", aliasRoot)

	paths, err := SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("SocketPaths = %v, want one path for equivalent roots", paths)
	}
}

func TestSocketPathsIgnoreUnavailableReleasedLocation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), strings.Repeat("long-state-dir/", 10), "proxy-monster")
	t.Setenv(dirEnv, stateDir)
	blockedTemp := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedTemp, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("TMPDIR", blockedTemp)

	paths, err := SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("SocketPaths = %v, want canonical path only", paths)
	}
}

func TestSocketPathsPreserveReleasedLongLocation(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	stateDir := filepath.Join(strings.Repeat("long-state-dir/", 10), "proxy-monster")
	t.Setenv(dirEnv, stateDir)
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", tempRoot)

	paths, err := SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("SocketPaths = %v, want canonical and released paths", paths)
	}
	sum := sha256.Sum256([]byte(stateDir))
	want := filepath.Join(
		tempRoot,
		fmt.Sprintf("pmon-%d", os.Getuid()),
		fmt.Sprintf("pmon-%s.sock", hex.EncodeToString(sum[:8])),
	)
	if paths[1] != want {
		t.Errorf("released long socket path = %q, want %q", paths[1], want)
	}
}

func TestSocketPathsIncludeReleasedLocation(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv(dirEnv, stateDir)

	paths, err := SocketPaths()
	if err != nil {
		t.Fatalf("SocketPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("SocketPaths = %v, want canonical and released paths", paths)
	}
	if paths[0] == paths[1] {
		t.Fatalf("SocketPaths returned duplicate paths: %v", paths)
	}
	if want := filepath.Join(stateDir, "daemon.sock"); paths[1] != want {
		t.Errorf("released socket path = %q, want %q", paths[1], want)
	}
}
