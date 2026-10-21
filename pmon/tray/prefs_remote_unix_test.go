//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// fakeSSH plays ssh for the local daemon: the shared connection, a forward as a symlink to the remote socket,
// and a remote shell whose socket listing holds FAKE_REMOTE_SOCK.
const fakeSSH = `#!/bin/sh
prev=; ctl=; spec=; last=
for a; do
  [ "$prev" = -S ] && ctl=$a
  [ "$prev" = -L ] && spec=$a
  prev=$a; last=$a
done
case " $* " in
*" -M "*) : > "$ctl"; exec sleep 3600 ;;
*" check "*) [ -e "$ctl" ] || exit 255; exit 0 ;;
*" forward "*) case ${spec%%:*} in *.sock) ln -s "${spec#*:}" "${spec%%:*}" ;; esac; exit 0 ;;
*" cancel "*) exit 0 ;;
esac
case $last in *pmon-*.sock*) echo "$FAKE_REMOTE_SOCK" ;; esac
`

// remoteDaemon starts a second real daemon, with its own state and ports, for the local one to reach as devbox.
func remoteDaemon(t *testing.T) string {
	t.Helper()
	env := append(os.Environ(), "PMON_CONFIG_DIR="+t.TempDir(), fmt.Sprintf("PMON_PORT_BASE=%d", freeBase(t)))
	run := func(args ...string) string {
		cmd := exec.Command(os.Getenv("PMON_BINARY"), args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pmon %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("start")
	t.Cleanup(func() { run("stop") })
	return run("socket-path")
}

func TestSettingsManageARemotesServers(t *testing.T) {
	realDaemon(t)
	yes(t)
	t.Setenv("FAKE_REMOTE_SOCK", remoteDaemon(t))
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(fakeSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx := context.Background()
	p := &prefs{ctx: ctx, signingIn: map[string]bool{}, changed: func() {}}
	h := p.handlers()
	call := func(name string, args ...any) any {
		t.Helper()
		var raw []json.RawMessage
		for _, a := range args {
			b, _ := json.Marshal(a)
			raw = append(raw, b)
		}
		res, err := h[name](raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return res
	}
	local, err := control.EnsureDaemon(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.AddRemote(ctx, "devbox"); err != nil {
		t.Fatal(err)
	}
	remote := func() prefsRemote {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			st := p.state()
			if len(st.Remotes) == 1 && st.Remotes[0].Servers != nil {
				return st.Remotes[0]
			}
			if time.Now().After(deadline) {
				t.Fatalf("devbox never listed its servers: %+v", st.Remotes)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if r := remote(); len(r.Servers) != 0 {
		t.Fatalf("a new remote daemon has servers: %+v", r.Servers)
	}

	if e := call("setServer", "acme", "https://pm.acme.example", "devbox"); e != "" {
		t.Fatalf("add on devbox: %v", e)
	}
	if r := remote(); len(r.Servers) != 1 || r.Servers[0].Name != "acme" {
		t.Fatalf("devbox servers after add: %+v", r.Servers)
	}
	if st := p.state(); len(st.Servers) != 0 {
		t.Fatalf("the server was added to this machine's daemon: %+v", st.Servers)
	}
	if e := call("setServer", "acme", "https://pm2.acme.example", "devbox"); e != "" {
		t.Fatalf("change address on devbox: %v", e)
	}
	if r := remote(); !strings.Contains(r.Servers[0].URL, "pm2.acme.example") {
		t.Errorf("devbox address after change = %q", r.Servers[0].URL)
	}
	if e := call("removeServer", "acme", "devbox"); e != "" {
		t.Fatalf("remove on devbox: %v", e)
	}
	if r := remote(); len(r.Servers) != 0 {
		t.Fatalf("devbox servers after remove: %+v", r.Servers)
	}
	if e := call("setServer", "acme", "https://pm.acme.example", "elsewhere"); !strings.Contains(fmt.Sprint(e), "not connected") {
		t.Errorf("a server call to an unknown remote = %v", e)
	}
}
