package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/singleinstance"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// ErrDaemonNotRunning reports that no daemon is listening. Every peer command handles this rather than
// failing: a stopped daemon is a normal state, and the peer offers to start one.
var ErrDaemonNotRunning = errors.New("the pmon daemon is not running")

// ErrDaemonUnreachable reports that the pid lock is held but no daemon answers at the current control socket.
var ErrDaemonUnreachable = errors.New("the pmon daemon is running but its control socket is unreachable; run `pmon restart`")

// ErrDaemonReplaced reports that the original stop target exited but another daemon took its place.
var ErrDaemonReplaced = errors.New("the pmon daemon changed while stopping; another daemon is still running")

const controlRequestTimeout = 2 * time.Second

// Client speaks the control API over the daemon's unix socket.
type Client struct {
	http      *http.Client
	loginHTTP *http.Client
}

// NewClient dials the socket lazily per request — so a Client constructed while the daemon is down starts
// working the moment one comes up, with no reconstruction.
func NewClient() (*Client, error) {
	return newClient(0)
}

func newClient(expectedOwnerPID int) (*Client, error) {
	sockets, err := state.SocketPaths()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: controlRequestTimeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialErr error
			for _, socket := range sockets {
				var d net.Dialer
				conn, err := d.DialContext(ctx, "unix", socket)
				if err != nil {
					dialErr = err
					if ctx.Err() != nil || !isDialFailure(err) {
						return nil, err
					}
					continue
				}
				peerPID, err := verifyDaemonPeer(ctx, conn)
				if err != nil {
					return nil, errors.Join(err, conn.Close())
				}
				if expectedOwnerPID != 0 && peerPID != expectedOwnerPID {
					return nil, errors.Join(
						fmt.Errorf("the daemon changed from pid %d to pid %d", expectedOwnerPID, peerPID),
						conn.Close(),
					)
				}
				return conn, nil
			}
			return nil, dialErr
		},
	}
	loginTransport := transport.Clone()
	loginTransport.ResponseHeaderTimeout = 0
	return &Client{
		http:      &http.Client{Transport: transport},
		loginHTTP: &http.Client{Transport: loginTransport},
	}, nil
}

func daemonSingleton() (*singleinstance.Client, error) {
	instance, err := state.DaemonInstance()
	if err != nil {
		return nil, err
	}
	return instance.Client(), nil
}

func verifyDaemonPeer(ctx context.Context, conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("control socket returned %T, not a Unix connection", conn)
	}
	peerPID, err := socketPeerPID(unixConn)
	if err != nil {
		return 0, fmt.Errorf("could not identify the control-socket peer: %w", err)
	}
	singleton, err := daemonSingleton()
	if err != nil {
		return 0, fmt.Errorf("could not identify the daemon lock owner: %w", err)
	}
	owner, err := singleton.Owner(ctx)
	if err != nil {
		return 0, fmt.Errorf("could not identify the daemon lock owner: %w", err)
	}
	if owner == nil {
		return 0, ErrDaemonNotRunning
	}
	if peerPID != owner.PID() {
		return 0, fmt.Errorf("control-socket peer pid %d does not own the daemon lock held by pid %d", peerPID, owner.PID())
	}
	return peerPID, nil
}

// do issues a control request. A dial failure becomes [ErrDaemonNotRunning] so callers branch on one error.
func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	return c.doWith(c.http, ctx, method, path, body)
}

func (c *Client) doWith(client *http.Client, ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(buf)
	}
	// The host is ignored for a unix socket but must parse, so use a fixed placeholder.
	req, err := http.NewRequestWithContext(ctx, method, "http://pmon"+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrDaemonNotRunning) || isDialFailure(err) {
			return nil, ErrDaemonNotRunning
		}
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e ErrorResponse
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("control API %s: HTTP %d", path, resp.StatusCode)
	}
	return resp, nil
}

// isDialFailure reports whether err means "nothing is listening on the control socket". It keys on the
// operation being a DIAL rather than on an essno allow-list: a stale non-socket file, a permission problem, or
// any other bind-time oddity must still read as "no daemon" so a peer offers to start one — an essno the list
// happened to omit would otherwise look like a live daemon and block auto-start entirely.
func isDialFailure(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// Status fetches the daemon's current state.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	ctx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, PathStatus, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Login runs a device-auth flow in the daemon, calling onEvent for each streamed step. It returns when the
// flow finishes; a "done" event means the daemon is logged in and its brokers are coming up.
func (c *Client) Login(ctx context.Context, req LoginRequest, onEvent func(LoginEvent)) error {
	resp, err := c.doWith(c.loginHTTP, ctx, http.MethodPost, PathLogin, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev LoginEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if onEvent != nil {
			onEvent(ev)
		}
		if ev.Kind == "error" {
			return fmt.Errorf("%s", ev.Error)
		}
	}
	return sc.Err()
}

// Logout clears the stored credentials and closes every broker, leaving the daemon running and idle.
func (c *Client) Logout(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, PathLogout, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Reload forces an immediate rediscovery instead of waiting for the next cycle.
func (c *Client) Reload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, PathReload, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Shutdown asks the daemon to exit gracefully. The daemon closes the connection as it goes, so a dial/EOF
// error after the request was accepted is success, not failure.
func (c *Client) Shutdown(ctx context.Context) error {
	err := c.shutdown(ctx)
	if errors.Is(err, ErrDaemonNotRunning) {
		return nil
	}
	return err
}

func (c *Client) shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, PathShutdown, nil)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

var errEventStreamIdle = errors.New("the daemon event stream stopped responding")

const eventStreamIdleTimeout = 2 * defaultEventKeepalive

type idleTimeoutReader struct {
	body    io.ReadCloser
	timeout time.Duration
}

func (r idleTimeoutReader) Read(p []byte) (int, error) {
	var timedOut atomic.Bool
	timerDone := make(chan struct{})
	timer := time.AfterFunc(r.timeout, func() {
		timedOut.Store(true)
		_ = r.body.Close()
		close(timerDone)
	})
	n, err := r.body.Read(p)
	if !timer.Stop() {
		<-timerDone
	}
	if timedOut.Load() && n == 0 {
		return 0, fmt.Errorf("%w after %s", errEventStreamIdle, r.timeout)
	}
	return n, err
}

// Events streams daemon state changes until ctx ends or the daemon stops responding.
func (c *Client) Events(ctx context.Context, onEvent func(Event)) error {
	return c.events(ctx, onEvent, eventStreamIdleTimeout)
}

func (c *Client) events(ctx context.Context, onEvent func(Event), idleTimeout time.Duration) error {
	resp, err := c.do(ctx, http.MethodGet, PathEvents, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(idleTimeoutReader{body: resp.Body, timeout: idleTimeout})
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if onEvent != nil {
			onEvent(ev)
		}
	}
	return sc.Err()
}

// daemonStartTimeout bounds how long a peer waits for a freshly spawned daemon to answer on its socket.
const daemonStartTimeout = 10 * time.Second

// daemonStartRaceGrace lets a concurrently starting daemon bind before it is reported unreachable.
const daemonStartRaceGrace = time.Second

const daemonGracefulShutdownTimeout = 10 * time.Second
const daemonSignalRaceGrace = time.Second

// EnsureDaemon returns a client to a live daemon, starting one if none is running. Both peers call this, so
// start-if-needed has exactly one implementation.
//
// It CONNECTS FIRST and only spawns on failure, which is what makes an orphaned daemon (its starting peer
// crashed) get adopted rather than duplicated. A lost spawn race is harmless anyway: the loser fails to take
// the pid lock and exits.
func EnsureDaemon(ctx context.Context) (*Client, error) {
	c, err := NewClient()
	if err != nil {
		return nil, err
	}
	_, statusErr := c.Status(ctx)
	if statusErr == nil {
		return c, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	singleton, err := daemonSingleton()
	if err != nil {
		return nil, fmt.Errorf("could not inspect the daemon lock: %w", err)
	}
	running, err := singleton.Running(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not inspect the daemon lock: %w", err)
	}
	if running {
		if err := waitForDaemon(ctx, c, daemonStartRaceGrace); err == nil {
			return c, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		running, err = singleton.Running(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not recheck the daemon lock: %w", err)
		}
		if running {
			if errors.Is(statusErr, ErrDaemonNotRunning) {
				return nil, ErrDaemonUnreachable
			}
			return nil, fmt.Errorf("%w: %w", ErrDaemonUnreachable, statusErr)
		}
	}
	if err := StartDaemon(ctx); err != nil {
		return nil, err
	}
	if err := waitForDaemon(ctx, c, daemonStartTimeout); err != nil {
		return nil, err
	}
	return c, nil
}

// Connect returns a client only if a daemon is already listening, without starting one. Used by peers that
// must render a stopped daemon rather than silently start it.
func Connect(ctx context.Context) (*Client, error) {
	c, err := NewClient()
	if err != nil {
		return nil, err
	}
	if _, statusErr := c.Status(ctx); statusErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		singleton, err := daemonSingleton()
		if err != nil {
			return nil, fmt.Errorf("could not inspect the daemon lock: %w", err)
		}
		running, err := singleton.Running(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not inspect the daemon lock: %w", err)
		}
		if running {
			if err := waitForDaemon(ctx, c, daemonStartRaceGrace); err == nil {
				return c, nil
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			running, err = singleton.Running(ctx)
			if err != nil {
				return nil, fmt.Errorf("could not recheck the daemon lock: %w", err)
			}
			if running {
				if errors.Is(statusErr, ErrDaemonNotRunning) {
					return nil, ErrDaemonUnreachable
				}
				return nil, fmt.Errorf("%w: %w", ErrDaemonUnreachable, statusErr)
			}
		}
		return nil, statusErr
	}
	return c, nil
}

// daemonBinaryEnv names the pmon binary to run the daemon, overriding the search below.
const daemonBinaryEnv = "PMON_BINARY"

// daemonBinaryName is the binary that understands the `daemon` subcommand.
const daemonBinaryName = "pmon"

// SelfRunsDaemon is set by the pmon CLI's own main package to declare that THIS binary understands the `daemon`
// subcommand. It is a positive self-identification, not a guess: resolving by filename would break a pmon
// installed under any other name (a release artifact like pmon_0.3.0_darwin_arm64) or reached through a symlink
// (the Homebrew / /usr/local/bin layout), while a peer that is a different program — the menu-bar app — must
// never re-exec itself and launch a second copy of itself instead of a daemon.
var SelfRunsDaemon bool

// DaemonBinary resolves the pmon binary that can run the daemon: this binary when it declares
// [SelfRunsDaemon], else a sibling `pmon` beside it (how the .app bundles the pair), else PATH.
// [daemonBinaryEnv] overrides everything, for a dev loop running an unbundled build.
func DaemonBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not locate the %s binary to start the daemon: %w", daemonBinaryName, err)
	}
	return daemonBinaryFrom(exe, os.Getenv(daemonBinaryEnv), SelfRunsDaemon)
}

// daemonBinaryFrom is [DaemonBinary]'s logic over explicit inputs, so the resolution order is testable without
// depending on the test binary's own identity or location.
func daemonBinaryFrom(exe, override string, selfRunsDaemon bool) (string, error) {
	if override != "" {
		if err := executable(override); err != nil {
			return "", fmt.Errorf("%s=%q is not runnable: %w", daemonBinaryEnv, override, err)
		}
		return override, nil
	}
	// This binary, when it says so. Checked BEFORE any filesystem search, so a CLI never prefers an adjacent
	// file over itself — a spawn target chosen by directory adjacency is attacker-influenced if the directory
	// is group- or world-writable.
	if selfRunsDaemon {
		return exe, nil
	}
	// A sibling pmon beside the running binary — how build-app.sh ships the pair inside the .app, so the daemon
	// and the front end cannot skew. Resolve symlinks first so the sibling is looked up next to the REAL file.
	dir := filepath.Dir(exe)
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		dir = filepath.Dir(resolved)
	}
	sibling := filepath.Join(dir, daemonBinaryName)
	if err := executable(sibling); err == nil {
		if err := trustedSpawnTarget(sibling); err != nil {
			return "", fmt.Errorf("refusing to start the daemon from %s: %w", sibling, err)
		}
		return sibling, nil
	}
	// PATH is a last resort. It invites version skew — a bundled tray finding an old pmon from a previous
	// install speaks a different control-API shape — so it is only offered with a clear error when it too fails.
	if p, err := exec.LookPath(daemonBinaryName); err == nil {
		// LookPath only checks for an execute bit — it happily returns a FIFO — so apply the same regularity and
		// ownership checks as the sibling path.
		if err := executable(p); err != nil {
			return "", fmt.Errorf("refusing to start the daemon from %s: %w", p, err)
		}
		if err := trustedSpawnTarget(p); err != nil {
			return "", fmt.Errorf("refusing to start the daemon from %s: %w", p, err)
		}
		return p, nil
	}
	return "", fmt.Errorf("could not find the %s binary to start the daemon: not beside %s, not on PATH (set %s)",
		daemonBinaryName, exe, daemonBinaryEnv)
}

// executable reports whether path is a REGULAR file with an execute bit. Regularity matters: a FIFO, socket, or
// device node with an execute bit would otherwise be accepted as the daemon binary and exec'd, hanging or
// failing opaquely.
func executable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}

// trustedSpawnTarget refuses a binary another user could have replaced. A found-by-search spawn target runs with
// this user's privileges and inherits the wire token and the control socket, so a target owned by someone else,
// or replaceable by them, is not safe to exec — installs under a group-writable prefix (a single-admin Mac's
// /usr/local/bin is staff-writable) would otherwise let a planted `pmon` be launched.
//
// The DIRECTORY is checked as well as the file, because on Unix the permission to unlink and replace a file comes
// from its parent directory, not from the file: a 0755 binary we own inside a 0777 directory is still swappable
// by anyone, so a file-only check would assert a trust it does not establish.
func trustedSpawnTarget(path string) error {
	if err := trustedPathComponent(path, "it"); err != nil {
		return err
	}
	return trustedPathComponent(filepath.Dir(path), "its directory")
}

// trustedPathComponent requires that path be owned by this user (or root) and not group/world-writable. `what`
// names it in the error, so a refusal says whether the binary or its directory was the problem.
func trustedPathComponent(path, what string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify %s ownership", what)
	}
	if uid := os.Getuid(); int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not %d or root", what, st.Uid, uid)
	}
	// A sticky directory (/tmp, mode 1777) still bars unlinking someone else's file, but nothing here needs to
	// live in one, so the simpler predicate is kept rather than carving out an exception that widens the surface.
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (%o)", what, perm)
	}
	return nil
}

// StartDaemon spawns a DETACHED daemon and returns once it is launched (not once it is ready — see
// [waitForDaemon]). Detached is required, not incidental: the peer that starts the daemon exits immediately
// (a CLI command returns; a tray may be quit), and the daemon must outlive it. So process-tree death is never
// the stop mechanism — stopping is always an explicit [Client.Shutdown].
func StartDaemon(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	exe, err := DaemonBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "daemon")
	// Send output to a log file rather than /dev/null so a startup failure is diagnosable.
	if logPath, e := state.LogPath(); e == nil {
		if _, e := state.EnsureDir(); e == nil {
			if lf, e := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); e == nil {
				cmd.Stdout, cmd.Stderr = lf, lf
				defer lf.Close()
			}
		}
	}
	// New session: the daemon must not die with the peer's process group, nor take its controlling terminal
	// signals (a Ctrl-C in the shell that ran `pmon login` must not kill the daemon).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start the daemon: %w", err)
	}
	return cmd.Process.Release() // detach; the daemon owns its own lifetime + pid lock
}

// waitForDaemon polls the socket until the daemon answers or the timeout expires.
func waitForDaemon(ctx context.Context, c *Client, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if _, err := c.Status(waitCtx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			logHint := ""
			if p, err := state.LogPath(); err == nil {
				logHint = fmt.Sprintf(" (see %s)", p)
			}
			return fmt.Errorf("the daemon did not come up within %s%s", timeout, logHint)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// StopDaemon stops a running daemon, falling back to SIGTERM when the control socket is unreachable but the
// pid lock shows a daemon alive (a wedged or half-crashed daemon still has to be stoppable).
func StopDaemon(ctx context.Context) error {
	singleton, err := daemonSingleton()
	if err != nil {
		return fmt.Errorf("could not identify the running daemon: %w", err)
	}
	owner, err := singleton.Owner(ctx)
	if err != nil {
		return fmt.Errorf("could not identify the running daemon: %w", err)
	}
	if owner == nil {
		return ErrDaemonNotRunning
	}
	c, err := newClient(owner.PID())
	if err != nil {
		return err
	}
	graceful := c.shutdown(ctx) == nil
	if !graceful {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if graceful {
		err := waitForOwnerExit(ctx, owner, daemonGracefulShutdownTimeout)
		if err == nil || errors.Is(err, ErrDaemonReplaced) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	current, err := owner.Current(ctx)
	if errors.Is(err, singleinstance.ErrOwnerReplaced) {
		return ErrDaemonReplaced
	}
	if err != nil {
		return fmt.Errorf("could not revalidate the running daemon: %w", err)
	}
	if !current {
		return nil
	}
	if err := owner.Signal(ctx, syscall.SIGTERM); err != nil {
		if errors.Is(err, singleinstance.ErrOwnerReplaced) {
			return ErrDaemonReplaced
		}
		return handleDaemonSignalError(ctx, owner, fmt.Errorf("could not signal the daemon (pid %d): %w", owner.PID(), err))
	}
	return waitForOwnerExit(ctx, owner, daemonGracefulShutdownTimeout)
}

func handleDaemonSignalError(ctx context.Context, owner *singleinstance.Owner, err error) error {
	if !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if waitErr := waitForOwnerExit(ctx, owner, daemonSignalRaceGrace); waitErr != nil {
		return errors.Join(err, waitErr)
	}
	return nil
}

func waitForOwnerExit(ctx context.Context, owner *singleinstance.Owner, timeout time.Duration) error {
	err := owner.WaitExit(ctx, timeout)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, singleinstance.ErrOwnerReplaced):
		return ErrDaemonReplaced
	case errors.Is(err, singleinstance.ErrOwnerExitTimeout):
		return fmt.Errorf("the daemon did not exit within %s", timeout)
	default:
		return fmt.Errorf("could not inspect the daemon lock: %w", err)
	}
}
