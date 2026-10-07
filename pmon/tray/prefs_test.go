package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// realDaemon points this process at a freshly built pmon with its own state directory and ports, so the
// Preferences logic runs against the actual control socket.
func realDaemon(t *testing.T) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pmon")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = ".." // pmon's own module, so its go.sum resolves its dependencies
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build pmon: %v\n%s", err, out)
	}
	t.Setenv("PMON_BINARY", bin)
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	t.Setenv("PMON_PORT_BASE", fmt.Sprint(freeBase(t)))
	t.Cleanup(func() { _ = control.StopDaemon(context.Background()) })
}

func freeBase(t *testing.T) int {
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		base := l.Addr().(*net.TCPAddr).Port
		l.Close()
		ok := true
		for p := base; p < base+8 && ok; p++ {
			if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err != nil {
				ok = false
			} else {
				l.Close()
			}
		}
		if ok && base+8 < 65535 {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func TestPreferencesManageServers(t *testing.T) {
	realDaemon(t)
	p := &prefs{ctx: context.Background(), signingIn: map[string]bool{}, changed: func() {}}

	if st := p.state(); st.Running || len(st.Servers) != 0 {
		t.Fatalf("before anything: %+v", st)
	}
	if err := p.setServer("acme", "https://pm.acme.example"); err != "" {
		t.Fatalf("add: %s", err)
	}
	st := p.state()
	if !st.Running || len(st.Servers) != 1 || st.Servers[0].Name != "acme" || st.Servers[0].SignedIn {
		t.Fatalf("after add: %+v", st)
	}
	if err := p.setServer("acme", "https://pm2.acme.example"); err != "" {
		t.Fatalf("change address: %s", err)
	}
	if got := p.state().Servers[0].URL; !strings.Contains(got, "pm2.acme.example") {
		t.Errorf("address after change = %q", got)
	}
	if err := p.setServer("Not Valid", "https://x.example"); !strings.Contains(err, "invalid server name") {
		t.Errorf("an invalid name was not refused with the daemon's reason: %q", err)
	}
	if err := p.removeServer("acme"); err != "" {
		t.Fatalf("remove: %s", err)
	}
	if st := p.state(); len(st.Servers) != 0 {
		t.Fatalf("after remove: %+v", st)
	}
}

// The page reaches Go only through named calls with JSON arguments; drive them as the page does.
func TestSettingsCallsByName(t *testing.T) {
	realDaemon(t)
	p := &prefs{ctx: context.Background(), signingIn: map[string]bool{}, changed: func() {}}
	h := p.handlers()
	call := func(name string, args ...any) any {
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
	if e := call("setServer", "acme", "https://pm.acme.example"); e != "" {
		t.Fatalf("setServer: %v", e)
	}
	st := call("state").(prefsState)
	if !st.Running || len(st.Servers) != 1 || st.Servers[0].Name != "acme" || st.Servers[0].SignedIn {
		t.Fatalf("state after setServer: %+v", st)
	}
	if _, err := h["setServer"]([]json.RawMessage{[]byte(`"acme"`)}); err == nil {
		t.Error("setServer with one argument did not fail")
	}
	if e := call("removeServer", "acme"); e != "" {
		t.Fatalf("removeServer: %v", e)
	}
	if st := call("state").(prefsState); len(st.Servers) != 0 {
		t.Fatalf("state after removeServer: %+v", st)
	}
}
