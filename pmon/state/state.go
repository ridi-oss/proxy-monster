// Package state owns pmon's on-disk state: the config file, the paths derived from it, and the pid lock
// that makes the daemon single-instance. The DAEMON is the sole writer of the config — the CLI and the tray
// reach the daemon over its control socket and never write state themselves.
package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// Config is pmon's persisted state, written by the daemon and read back on its next start. Stored 0600 in
// the user config dir. A keychain backend belongs here later.
type Config struct {
	// ControlPlane is the control-plane base URL, saved by a login that supplied one and reused by later
	// logins that omit it, so the address is configured once.
	ControlPlane string `json:"controlPlane"`
	Principal    string `json:"principal"`
	// Token is the wire token the daemon injects upstream. Each login rewrites it; the daemon swaps it in
	// without restarting, so in-flight sessions keep flowing under the fresh token.
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	// IssuedAt is when the current wire token was stored, so the renewal loop can size its lead time against the
	// token's OWN lifetime. Without it a fixed lead would put any token shorter than that lead permanently past
	// its renewal threshold (the control plane clamps TTL to a 60s floor).
	IssuedAt string `json:"issuedAt"`
	// SessionExpiresAt is when the device-auth session window closes, past which a silent renewal is no
	// longer possible and a fresh login is required.
	SessionExpiresAt string `json:"sessionExpiresAt"`
	// RenewalToken is the daemon's bearer for POST /auth/session/renew within the session window. Minted
	// once at device-auth completion and returned only there (the control plane persists only its hash).
	RenewalToken string `json:"renewalToken"`
	// LocalPassword is a stable loopback DB password generated once, so a saved client connection uses one
	// never-changing password while the daemon rotates the wire token upstream. Regenerated only if absent.
	LocalPassword string `json:"localPassword"`
	// Ports is the STICKY datasource-name -> local loopback port map, persisted so a datasource keeps the
	// same port across daemon restarts. A newly-discovered one takes the next free port at or above PortBase.
	Ports map[string]int `json:"ports"`
}

// DefaultPortBase is the low end of the loopback port range handed out per datasource. Chosen high to avoid
// clashing with common local services; an assignment, once made, is sticky in [Config.Ports].
const DefaultPortBase = 6100

// portBaseEnv overrides [PortBase]. Needed whenever two pmon daemons run on one machine — parallel dev
// worktrees, or a test alongside a real daemon — because a separate config dir isolates their STATE but not
// their loopback ports, and the second daemon would fight the first for 6100+.
const portBaseEnv = "PMON_PORT_BASE"

// PortBase is the low end of the loopback port range, honoring [portBaseEnv]. An unparseable or out-of-range
// value falls back to [DefaultPortBase] rather than failing: a bad env var must not stop the daemon brokering.
func PortBase() int {
	if v := os.Getenv(portBaseEnv); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return DefaultPortBase
}

// localPasswordBytes is the entropy of the generated sticky loopback password (base64url, no padding).
const localPasswordBytes = 24

// dirEnv overrides the config directory. Set it to run several independent pmon instances on one machine
// (parallel dev worktrees), or to keep a test off the real user config dir.
const dirEnv = "PMON_CONFIG_DIR"

// Dir is the directory holding pmon's config, pid lock, and daemon log.
func Dir() (string, error) {
	if d := os.Getenv(dirEnv); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "proxy-monster"), nil
}

// EnsureDir creates the state directory 0700 and tightens a pre-existing directory that is looser.
func EnsureDir() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	info, err := os.Stat(d)
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(d, 0o700); err != nil {
			return "", fmt.Errorf("could not tighten %s to 0700 (it is %o): %w", d, perm, err)
		}
	}
	return d, nil
}

func pathIn(name string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// Path is the config file. ConfigName is exported so a directory watcher can filter to it.
func Path() (string, error) { return pathIn(ConfigName) }

// ConfigName is the config file's base name. A watcher must watch the DIRECTORY and filter on this: [Save]
// renames a fresh temp file into place, so the config inode is replaced on every write and a watch on the
// file itself would go deaf after the first save.
const ConfigName = "config.json"

// maxSocketPath is the shortest sun_path limit across the platforms pmon targets (104 on darwin/BSD, 108 on
// Linux), minus room for the NUL. A bind past it fails with EINVAL, so the path is checked, never assumed.
const maxSocketPath = 100

const socketRoot = "/tmp"

func SocketPath() (string, error) { return socketPathAt(socketRoot) }

// SocketPaths returns the canonical path followed by paths used by released peers.
func SocketPaths() ([]string, error) {
	canonical, err := SocketPath()
	if err != nil {
		return nil, err
	}
	legacy, err := legacySocketPath()
	if err != nil {
		return []string{canonical}, nil
	}
	if sameSocketPath(canonical, legacy) {
		return []string{canonical}, nil
	}
	return []string{canonical, legacy}, nil
}

func sameSocketPath(a, b string) bool {
	if a == b {
		return true
	}
	if filepath.Base(a) != filepath.Base(b) {
		return false
	}
	aDir, err := os.Stat(filepath.Dir(a))
	if err != nil {
		return false
	}
	bDir, err := os.Stat(filepath.Dir(b))
	return err == nil && os.SameFile(aDir, bDir)
}

func socketPathAt(root string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	short, err := socketDirAt(root, os.Getuid())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(dir))
	p := filepath.Join(short, fmt.Sprintf("pmon-%s.sock", hex.EncodeToString(sum[:8])))
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("no control-socket path fits the %d-byte limit (tried %q)", maxSocketPath, p)
	}
	return p, nil
}

func legacySocketPath() (string, error) {
	p, err := pathIn("daemon.sock")
	if err != nil {
		return "", err
	}
	if len(p) <= maxSocketPath {
		return p, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	short, err := socketDirAt(os.TempDir(), os.Getuid())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(dir))
	p = filepath.Join(short, fmt.Sprintf("pmon-%s.sock", hex.EncodeToString(sum[:8])))
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("no compatible control-socket path fits the %d-byte limit (tried %q)", maxSocketPath, p)
	}
	return p, nil
}

// Socket directories must be owned by the current user, mode 0700, and not symlinks.
func socketDirAt(root string, wantUID int) (string, error) {
	d := filepath.Join(root, fmt.Sprintf("pmon-%d", os.Getuid()))
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(d)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("control-socket directory %s is a symlink; refusing to use it", d)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("control-socket directory %s is not a directory", d)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot verify ownership of the control-socket directory %s", d)
	}
	if int(st.Uid) != wantUID {
		return "", fmt.Errorf("control-socket directory %s is owned by uid %d, not %d; refusing to use it", d, st.Uid, wantUID)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		if err := os.Chmod(d, 0o700); err != nil {
			return "", fmt.Errorf("could not set the control-socket directory %s to 0700 (it is %o): %w", d, perm, err)
		}
	}
	return d, nil
}

// PidPath is the flock-held pid file that makes the daemon single-instance.
func PidPath() (string, error) { return pathIn("daemon.pid") }

// LogPath is where a detached daemon's output goes, so a startup failure is diagnosable rather than silent.
func LogPath() (string, error) { return pathIn("daemon.log") }

// Update runs a read-modify-write under an exclusive file lock. The daemon is the only writer today, but the
// lock still guards its own concurrent writers (a login stamping the token while discovery assigns a sticky
// port) — the atomic rename in [Save] prevents torn reads, not lost updates. Unix-only (flock).
func Update(mutate func(*Config) error) error {
	dir, err := EnsureDir()
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(dir, ConfigName+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	// Start fresh ONLY when there is genuinely no config yet. Treating every load error as "no config" would let
	// corrupt JSON or a transient read error silently overwrite the principal, tokens, sticky loopback password,
	// and port assignments — destroying exactly the state that keeps saved client connections working.
	cfg, err := Load()
	if errors.Is(err, os.ErrNotExist) {
		cfg = &Config{Ports: map[string]int{}}
	} else if err != nil {
		return fmt.Errorf("refusing to overwrite an unreadable config (fix or remove it): %w", err)
	}
	if err := mutate(cfg); err != nil {
		return err
	}
	return Save(cfg)
}

// Load reads the config. A missing file is an error: "no state yet" is a legitimate condition the daemon
// starts up in, so callers treat it as not-logged-in rather than fatal.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Ports == nil {
		c.Ports = map[string]int{}
	}
	return &c, nil
}

// Save atomically replaces the config file.
func Save(c *Config) error {
	dir, err := EnsureDir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, ConfigName)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Write to a fresh temp file in the SAME directory (required for an atomic rename) and rename it into
	// place, rather than WriteFile-then-chmod: os.CreateTemp always creates at 0600, so the token + renewal
	// secret are never written into a world-readable inode even momentarily (WriteFile's mode only applies on
	// create, so overwriting a pre-existing 0644 file would leave the secret world-readable until a
	// separate chmod ran).
	tmp, err := os.CreateTemp(dir, "config-*.json.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, p)
}

// LoggedIn reports whether the config carries credentials the daemon can broker with.
func (c *Config) LoggedIn() bool {
	return c != nil && c.Token != "" && c.ControlPlane != ""
}

// EnsureLocalPassword generates the sticky loopback password once and persists it into c, returning it. A
// caller that already has one keeps it (never rotates), so saved client connections stay valid.
func (c *Config) EnsureLocalPassword() (string, error) {
	if c.LocalPassword != "" {
		return c.LocalPassword, nil
	}
	raw := make([]byte, localPasswordBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	c.LocalPassword = "pmlocal_" + base64.RawURLEncoding.EncodeToString(raw)
	return c.LocalPassword, nil
}

// AssignPort returns the sticky loopback port for a datasource name, allocating (and recording in
// [Config.Ports]) the next free port at or above [PortBase] on first sight. Existing names keep their port;
// new names fill the lowest free slot so the set stays compact.
func (c *Config) AssignPort(name string) int {
	if c.Ports == nil {
		c.Ports = map[string]int{}
	}
	if p, ok := c.Ports[name]; ok {
		return p
	}
	used := make(map[int]bool, len(c.Ports))
	for _, p := range c.Ports {
		used[p] = true
	}
	port := PortBase()
	for used[port] {
		port++
	}
	c.Ports[name] = port
	return port
}
