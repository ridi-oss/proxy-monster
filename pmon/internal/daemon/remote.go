package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

// remote is the SSH connection to one remote daemon.
type remote struct {
	target string
	cancel context.CancelFunc
	done   chan struct{}
	// recheck asks the connection to check the remote now rather than at its next tick.
	recheck chan struct{}
	info    control.RemoteInfo // guarded by Daemon.mu
}

// sshCommand runs ssh; replaceable in tests.
var sshCommand = func(ctx context.Context, args ...string) *exec.Cmd { return exec.CommandContext(ctx, "ssh", args...) }

// remoteCheckEvery is how often a connected remote is probed, and a remote without pmon retried.
var remoteCheckEvery = 15 * time.Second

// remoteShell runs a pmon command through the remote user's login shell: a non-interactive ssh session skips the
// profile that puts Homebrew's or mise's pmon on PATH.
func remoteShell(cmd string) string { return `exec "$SHELL" -lc '` + cmd + `'` }

// listDaemonSockets prints the remote user's live control sockets. Reaching a running daemon needs no pmon on
// the remote; only starting one does (startPmon). sh runs it, so zsh's no-match error and fish's syntax do not
// apply. Only a folder and sockets the user owns count, as the daemon itself requires, so another user cannot
// plant one; a socket no process holds open (lsof, else ss) is a crashed daemon's and does not count.
const listDaemonSockets = `sh -c 'd=/tmp/pmon-$(id -u); { [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ]; } || exit 0; ` +
	`if command -v lsof >/dev/null 2>&1; then live=$(lsof -a -U -u "$(id -u)" -Fn 2>/dev/null); ` +
	`elif command -v ss >/dev/null 2>&1; then live=$(ss -xl 2>/dev/null); else live=all; fi; ` +
	`for f in "$d"/pmon-*.sock; do [ -S "$f" ] && [ -O "$f" ] || continue; ` +
	`case "$live" in all|*"$f"*) echo "$f";; esac; done; true'`

// daemonSocket matches a daemon's socket, not a "-r<hash>" socket that machine forwards for its own remotes.
var daemonSocket = regexp.MustCompile(`/pmon-[0-9a-f]{16}\.sock$`)

// startPmon starts the remote daemon with the pmon the login shell finds, else Proxy Monster Desktop's bundled one.
const startPmon = `sh -c 'p=$("$SHELL" -lc "command -v pmon" 2>/dev/null | tail -n 1); ` +
	`for c in "$p" "$HOME/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon" "/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon"; do ` +
	`[ -n "$c" ] && [ -x "$c" ] && exec "$c" start; done; echo "no pmon on PATH or in Proxy Monster Desktop" >&2; exit 127'`

// findRemoteSocket is the running remote daemon's control socket, or "" when none runs. With several daemons, the
// remote's own pmon names the default one.
func findRemoteSocket(ctx context.Context, ctl, target string) (string, error) {
	out, err := sshOutput(ctx, "-S", ctl, "--", target, listDaemonSockets)
	if err != nil {
		return "", err
	}
	var socks []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); daemonSocket.MatchString(line) {
			socks = append(socks, line)
		}
	}
	switch len(socks) {
	case 0:
		return "", nil
	case 1:
		return socks[0], nil
	}
	if out, err := sshOutput(ctx, "-S", ctl, "--", target, remoteShell("pmon socket-path")); err == nil && slices.Contains(socks, lastLine(out)) {
		return lastLine(out), nil
	}
	return "", fmt.Errorf("%d pmon daemons run on %s, and no pmon there names the default one", len(socks), target)
}

func validTarget(target string) error {
	if !control.ValidTarget(target) {
		return fmt.Errorf("%q is not an ssh target", target)
	}
	return nil
}

// AddRemote saves an SSH target and starts its connection.
func (d *Daemon) AddRemote(req control.RemoteRequest) error {
	if err := validTarget(req.Target); err != nil {
		return err
	}
	if err := d.commit(func(c *state.Config) error {
		if !slices.Contains(c.Remotes, req.Target) {
			c.Remotes = append(c.Remotes, req.Target)
		}
		return nil
	}); err != nil {
		return err
	}
	d.startRemote(req.Target)
	return nil
}

// RemoveRemote closes a remote's connection and forgets it.
func (d *Daemon) RemoveRemote(req control.RemoteRequest) error {
	if err := d.commit(func(c *state.Config) error {
		if !slices.Contains(c.Remotes, req.Target) {
			return fmt.Errorf("unknown remote %q", req.Target)
		}
		c.Remotes = slices.DeleteFunc(c.Remotes, func(t string) bool { return t == req.Target })
		delete(c.RemotePorts, req.Target)
		return nil
	}); err != nil {
		return err
	}
	d.mu.Lock()
	r := d.remotes[req.Target]
	delete(d.remotes, req.Target)
	d.mu.Unlock()
	if r != nil {
		r.cancel()
		<-r.done
	}
	d.publishStatus()
	return nil
}

// StartRemote starts the pmon daemon on a connected remote over its ssh connection, and returns once it answers.
func (d *Daemon) StartRemote(ctx context.Context, req control.RemoteRequest) error {
	d.mu.Lock()
	r := d.remotes[req.Target]
	var info control.RemoteInfo
	if r != nil {
		info = r.info
	}
	d.mu.Unlock()
	if r == nil {
		return fmt.Errorf("unknown remote %q — `pmon remote add %s` first", req.Target, req.Target)
	}
	switch info.State {
	case control.RemoteConnected, control.RemoteNoDaemon, control.RemoteNoPmon:
	default:
		return fmt.Errorf("remote %q is %s: %s", req.Target, info.State, info.Error)
	}
	ctl, sock, err := state.RemotePaths(req.Target)
	if err != nil {
		return err
	}
	// The cached state can still say connected just after the remote stopped, so ask the remote itself.
	probe := control.NewClientAt(sock)
	defer probe.CloseIdle()
	answer, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = probe.Status(answer)
	cancel()
	if err == nil {
		return nil
	}
	if _, err := sshOutput(ctx, "-S", ctl, "--", req.Target, startPmon); err != nil {
		if strings.Contains(err.Error(), "no pmon on PATH") {
			d.setRemote(r, control.RemoteInfo{State: control.RemoteNoPmon, Error: err.Error()})
		}
		return fmt.Errorf("start the daemon on %s: %w", req.Target, err)
	}
	deadline := time.After(20 * time.Second)
	for {
		select {
		case r.recheck <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("the daemon on %s did not answer within 20s", req.Target)
		case <-time.After(500 * time.Millisecond):
		}
		answer, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := probe.Status(answer)
		cancel()
		if err == nil {
			return nil
		}
	}
}

func (d *Daemon) startRemotes() {
	for _, target := range d.snapshot().Remotes {
		d.startRemote(target)
	}
}

func (d *Daemon) startRemote(target string) {
	d.mu.Lock()
	if _, ok := d.remotes[target]; ok {
		d.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(d.ctx)
	r := &remote{target: target, cancel: cancel, done: make(chan struct{}), recheck: make(chan struct{}, 1),
		info: control.RemoteInfo{Target: target, State: control.RemoteConnecting}}
	d.remotes[target] = r
	d.mu.Unlock()
	d.publishStatus()
	go func() {
		defer close(r.done)
		d.runRemote(ctx, r)
	}()
}

// remoteInfos is the remotes for /status. Callers hold d.mu.
func (d *Daemon) remoteInfos() []control.RemoteInfo {
	out := make([]control.RemoteInfo, 0, len(d.remotes))
	for _, r := range d.remotes {
		out = append(out, r.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

func (d *Daemon) setRemote(r *remote, info control.RemoteInfo) {
	info.Target = r.target
	d.mu.Lock()
	changed := !reflect.DeepEqual(r.info, info)
	r.info = info
	d.mu.Unlock()
	if changed {
		d.publishStatus()
	}
}

// runRemote keeps one SSH connection to a remote, reconnecting with backoff until ctx ends.
func (d *Daemon) runRemote(ctx context.Context, r *remote) {
	ctl, sock, err := state.RemotePaths(r.target)
	if err != nil {
		d.setRemote(r, control.RemoteInfo{State: control.RemoteDown, Error: err.Error()})
		return
	}
	defer func() {
		_ = os.Remove(sock)
		_ = os.Remove(ctl)
	}()
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		began := time.Now()
		err := d.connectRemote(ctx, r, ctl, sock)
		if ctx.Err() != nil {
			return
		}
		d.setRemote(r, control.RemoteInfo{State: control.RemoteDown, Error: errText(err)})
		if time.Since(began) > time.Minute {
			backoff = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// connectRemote holds one SSH connection until it ends: it forwards the remote control socket to sock and
// reports whether the remote daemon answers.
func (d *Daemon) connectRemote(ctx context.Context, r *remote, ctl, sock string) error {
	d.setRemote(r, control.RemoteInfo{State: control.RemoteConnecting})
	_ = os.Remove(sock)
	_ = os.Remove(ctl)
	var stderr tailBuffer
	master := sshCommand(ctx, "-M", "-S", ctl, "-N",
		"-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "ControlPersist=no", "-o", "StreamLocalBindUnlink=yes", "--", r.target)
	master.Stderr = &stderr
	if err := master.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- master.Wait() }()
	ended := func(err error) error {
		if s := stderr.last(); s != "" {
			return errors.New(s)
		}
		if err != nil {
			return err
		}
		return errors.New("the ssh connection closed")
	}

	if err := waitForMaster(ctx, exited, ctl, r.target); err != nil {
		if errors.Is(err, errMasterExited) {
			return ended(nil)
		}
		_ = master.Process.Kill()
		<-exited
		return err
	}

	forwarded := ""
	forwards := map[string]portForward{}
	probeClient := control.NewClientAt(sock)
	defer probeClient.CloseIdle()
	check := func() {
		if forwarded == "" {
			remoteSock, err := findRemoteSocket(ctx, ctl, r.target)
			switch {
			case err != nil:
				d.setRemote(r, control.RemoteInfo{State: control.RemoteDown, Error: errText(err)})
				return
			case remoteSock == "":
				// Kept unless a start found no pmon, which only a new start attempt clears.
				d.mu.Lock()
				noPmon := r.info.State == control.RemoteNoPmon
				d.mu.Unlock()
				if !noPmon {
					d.setRemote(r, control.RemoteInfo{State: control.RemoteNoDaemon, Socket: sock})
				}
				return
			}
			if _, err := sshOutput(ctx, "-S", ctl, "-O", "forward", "-L", sock+":"+remoteSock, "--", r.target); err != nil {
				d.setRemote(r, control.RemoteInfo{State: control.RemoteDown, Error: errText(err)})
				return
			}
			forwarded = remoteSock
		}
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		st, err := probeClient.Status(probe)
		if err != nil {
			if errors.Is(err, control.ErrDaemonNotRunning) {
				// The socket may be a crashed daemon's: forget it, so the next check looks again.
				_, _ = sshOutput(ctx, "-S", ctl, "-O", "cancel", "-L", sock+":"+forwarded, "--", r.target)
				_ = os.Remove(sock)
				forwarded = ""
			}
			info := control.RemoteInfo{State: control.RemoteNoDaemon, Socket: sock, Ports: forwardedPorts(forwards)}
			if !errors.Is(err, control.ErrDaemonNotRunning) {
				info.Error = err.Error()
			}
			d.setRemote(r, info)
			return
		}
		ports, failed := d.syncForwards(ctx, r.target, ctl, *st, forwards)
		d.setRemote(r, control.RemoteInfo{State: control.RemoteConnected, Socket: sock, Ports: ports, Error: failed})
	}
	check()
	t := time.NewTicker(remoteCheckEvery)
	defer t.Stop()
	changed := make(chan struct{}, 1)
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go watchRemote(watchCtx, sock, changed)
	for {
		select {
		case <-changed:
			check()
		case <-r.recheck:
			check()
		case err := <-exited:
			return ended(err)
		case <-ctx.Done():
			_ = master.Process.Kill()
			<-exited
			return ctx.Err()
		case <-t.C:
			check()
		}
	}
}

// portForward is one remote datasource forwarded to a local port.
type portForward struct{ local, remote int }

func (f portForward) spec() string {
	return fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", f.local, f.remote)
}

// syncForwards makes forwards match the remote's brokered datasources: each gets its sticky local port. It returns
// the port map for /status and, when a forward failed (its local port is taken), why.
func (d *Daemon) syncForwards(ctx context.Context, target, ctl string, st control.Status, forwards map[string]portForward) (map[string]int, string) {
	want := map[string]int{}
	for _, ds := range st.Datasources {
		if ds.LocalPort > 0 {
			want[ds.Server+"/"+ds.Name] = ds.LocalPort
		}
	}
	for key, f := range forwards {
		if remotePort, ok := want[key]; !ok || remotePort != f.remote {
			_, _ = sshOutput(ctx, "-S", ctl, "-O", "cancel", "-L", f.spec(), "--", target)
			delete(forwards, key)
		}
	}
	var failed string
	for key, remotePort := range want {
		if _, ok := forwards[key]; ok {
			continue
		}
		var local int
		if err := d.commit(func(c *state.Config) error {
			if !slices.Contains(c.Remotes, target) {
				return errRemoteRemoved
			}
			local = c.AssignRemotePort(target, key)
			return nil
		}); err != nil {
			if !errors.Is(err, errRemoteRemoved) {
				failed = err.Error()
			}
			continue
		}
		f := portForward{local: local, remote: remotePort}
		if _, err := sshOutput(ctx, "-S", ctl, "-O", "forward", "-L", f.spec(), "--", target); err != nil {
			failed = fmt.Sprintf("%s: %v", key, err)
			continue
		}
		forwards[key] = f
	}
	return forwardedPorts(forwards), failed
}

func forwardedPorts(forwards map[string]portForward) map[string]int {
	ports := make(map[string]int, len(forwards))
	for key, f := range forwards {
		ports[key] = f.local
	}
	return ports
}

// watchRemote nudges changed whenever the remote daemon publishes an event, so a new datasource is forwarded
// at once rather than at the next check, and whenever the stream ends, so a remote that stopped shows at once.
func watchRemote(ctx context.Context, sock string, changed chan<- struct{}) {
	nudge := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	for ctx.Err() == nil {
		_ = control.NewClientAt(sock).Events(ctx, func(control.Event) { nudge() })
		nudge()
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

var errMasterExited = errors.New("ssh exited")

var errRemoteRemoved = errors.New("the remote was removed")

// stopRemotes ends every remote's ssh connection and waits for it, so no ssh outlives the daemon.
func (d *Daemon) stopRemotes() {
	d.mu.Lock()
	rs := make([]*remote, 0, len(d.remotes))
	for _, r := range d.remotes {
		rs = append(rs, r)
	}
	d.mu.Unlock()
	for _, r := range rs {
		r.cancel()
	}
	for _, r := range rs {
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	}
}

// waitForMaster waits until the shared connection's control socket answers. errMasterExited means it took ssh's
// exit from exited.
func waitForMaster(ctx context.Context, exited <-chan error, ctl, target string) error {
	deadline := time.After(30 * time.Second)
	for {
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := sshOutput(check, "-S", ctl, "-O", "check", "--", target)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-exited:
			return errMasterExited
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return errors.New("ssh did not connect within 30s")
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// sshOutput runs one ssh command and returns its trimmed stdout, or its last stderr line as the error.
func sshOutput(ctx context.Context, args ...string) (string, error) {
	cmd := sshCommand(ctx, args...)
	var out bytes.Buffer
	var stderr tailBuffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if s := stderr.last(); s != "" {
			return "", errors.New(s)
		}
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimSpace(s[strings.LastIndex(s, "\n")+1:])
}

// tailBuffer keeps the last few KB a process wrote, for its final error line.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > 4096 {
		b.buf = b.buf[len(b.buf)-4096:]
	}
	return len(p), nil
}

func (b *tailBuffer) last() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(b.buf)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
