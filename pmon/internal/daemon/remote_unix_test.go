//go:build !windows

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

// TestFakeSSH is the ssh the tunnel tests run: it plays the shared connection, its forwards, and a remote
// shell whose pmon reports FAKE_REMOTE_SOCK.
func TestFakeSSH(t *testing.T) {
	if os.Getenv("FAKE_SSH_LOG") == "" {
		t.Skip("helper process")
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	log := func(line string) {
		f, _ := os.OpenFile(os.Getenv("FAKE_SSH_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		fmt.Fprintln(f, line)
		f.Close()
	}
	ctl := args[slices.Index(args, "-S")+1]
	switch {
	case slices.Contains(args, "-M"):
		log(fmt.Sprintf("master %d", os.Getpid()))
		_ = os.WriteFile(ctl, nil, 0o600)
		time.Sleep(time.Hour)
	case slices.Contains(args, "check"):
		if _, err := os.Stat(ctl); err != nil {
			os.Exit(255)
		}
	case slices.Contains(args, "forward"):
		spec := args[slices.Index(args, "-L")+1]
		if local, remote, ok := strings.Cut(spec, ":"); ok && strings.HasSuffix(local, ".sock") {
			if err := os.Symlink(remote, local); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		log("forward " + spec)
	case slices.Contains(args, "cancel"):
		log("cancel " + args[slices.Index(args, "-L")+1])
	case strings.Contains(args[len(args)-1], "pmon socket-path"):
		fmt.Println(os.Getenv("FAKE_REMOTE_SOCK"))
	}
	os.Exit(0)
}

// fakeRemoteDaemon serves /status and /events on a unix socket, as a remote daemon brokering one datasource.
func fakeRemoteDaemon(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "pmrd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	st := control.Status{Version: "remote", Servers: []control.ServerInfo{{Name: "acme", LoggedIn: true}},
		Datasources: []control.Datasource{{Server: "acme", Name: "orders", Brokered: true, LocalPort: 6100}}}
	mux := http.NewServeMux()
	mux.HandleFunc(control.PathStatus, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(st) })
	mux.HandleFunc(control.PathEvents, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestRemoteTunnelLifecycle(t *testing.T) {
	isolate(t)
	logPath := filepath.Join(t.TempDir(), "ssh.log")
	t.Setenv("FAKE_SSH_LOG", logPath)
	t.Setenv("FAKE_REMOTE_SOCK", fakeRemoteDaemon(t))
	restore, every := sshCommand, remoteCheckEvery
	t.Cleanup(func() { sshCommand, remoteCheckEvery = restore, every })
	remoteCheckEvery = 100 * time.Millisecond
	sshCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestFakeSSH$", "--"}, args...)...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := New("test", providers.Builtins())
	d.ctx = ctx
	t.Cleanup(func() { cancel(); d.stopRemotes() })

	waitFor := func(what string, ok func(control.RemoteInfo) bool) control.RemoteInfo {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if rs := d.Status().Remotes; len(rs) == 1 && ok(rs[0]) {
				return rs[0]
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("remote never %s: %+v", what, d.Status().Remotes)
		return control.RemoteInfo{}
	}
	masters := func() []int {
		b, _ := os.ReadFile(logPath)
		var pids []int
		for _, line := range strings.Split(string(b), "\n") {
			if pid, ok := strings.CutPrefix(line, "master "); ok {
				n, _ := strconv.Atoi(pid)
				pids = append(pids, n)
			}
		}
		return pids
	}
	alive := func(pid int) bool { return syscall.Kill(pid, 0) == nil }

	if err := d.AddRemote(control.RemoteRequest{Target: "devbox"}); err != nil {
		t.Fatal(err)
	}
	r := waitFor("connected with a forward", func(r control.RemoteInfo) bool {
		return r.State == control.RemoteConnected && r.Ports["acme/orders"] > 0
	})
	if r.Ports["acme/orders"] != state.PortBase() {
		t.Errorf("forwarded on %d, want the first port of this daemon's range %d", r.Ports["acme/orders"], state.PortBase())
	}
	if b, _ := os.ReadFile(logPath); !strings.Contains(string(b), fmt.Sprintf("forward 127.0.0.1:%d:127.0.0.1:6100", state.PortBase())) {
		t.Errorf("no datasource forward in:\n%s", b)
	}

	// A dropped connection comes back.
	first := masters()[0]
	_ = syscall.Kill(first, syscall.SIGKILL)
	waitFor("reconnected", func(r control.RemoteInfo) bool {
		return r.State == control.RemoteConnected && len(masters()) == 2
	})

	if err := d.RemoveRemote(control.RemoteRequest{Target: "devbox"}); err != nil {
		t.Fatal(err)
	}
	if ports := d.snapshot().RemotePorts["devbox"]; ports != nil {
		t.Errorf("ports kept after remove: %v", ports)
	}
	for _, pid := range masters() {
		if alive(pid) {
			t.Errorf("ssh %d outlived its remote", pid)
		}
	}

	// Shutdown waits for every ssh connection.
	if err := d.AddRemote(control.RemoteRequest{Target: "devbox"}); err != nil {
		t.Fatal(err)
	}
	waitFor("connected again", func(r control.RemoteInfo) bool { return r.State == control.RemoteConnected })
	cancel()
	d.stopRemotes()
	for _, pid := range masters() {
		if alive(pid) {
			t.Errorf("ssh %d outlived the daemon", pid)
		}
	}
}
