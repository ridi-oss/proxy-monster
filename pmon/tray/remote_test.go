package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

func withRemote(state control.RemoteState) *control.Status {
	s := twoServers()
	s.Remotes = []control.RemoteInfo{{Target: "devbox", State: state, Socket: "/tmp/x.sock", Forwards: []control.Forward{{Server: "acme", Datasource: "orders", Port: 47100}}}}
	return s
}

func TestRemoteStatesInTheMenu(t *testing.T) {
	for state, want := range map[control.RemoteState]string{
		control.RemoteConnecting: "devbox — connecting…",
		control.RemoteDown:       "devbox — not connected",
		control.RemoteNoPmon:     "devbox — pmon not found",
		control.RemoteNoDaemon:   "devbox — not running",
	} {
		e := find(buildMenu(withRemote(state), view{now: now}), "remote:devbox")
		if e == nil || e.title != want {
			t.Errorf("%s: %+v, want %q", state, e, want)
		}
	}
	for _, state := range []control.RemoteState{control.RemoteConnecting, control.RemoteDown} {
		e := find(buildMenu(withRemote(state), view{now: now}), "remote:devbox#reconnect")
		if e == nil || e.act == nil || e.act.op != opReconnect || e.act.remote != "devbox" {
			t.Errorf("%s reconnect = %+v", state, e)
		}
	}
	start := find(buildMenu(withRemote(control.RemoteNoDaemon), view{now: now}), "remote:devbox#start")
	if start == nil || start.act == nil || start.act.op != opStart || start.act.remote != "devbox" {
		t.Errorf("no-daemon start = %+v", start)
	}
}

func TestConnectedRemoteServersUseForwardedPorts(t *testing.T) {
	remote := twoServers()
	remote.LocalPassword = "remote-pw"
	v := view{now: now, remotes: map[string]*control.Status{"devbox": remote}}
	m := buildMenu(withRemote(control.RemoteConnected), v)
	copyURL := find(m, "r:devbox|ds:acme/orders#url")
	if copyURL == nil || !strings.Contains(copyURL.act.payload, "127.0.0.1:47100") || !strings.Contains(copyURL.act.payload, "remote-pw") {
		t.Fatalf("remote copy = %+v", copyURL)
	}
	if find(m, "ds:acme/orders#url") == nil || find(m, "r:devbox|ds:acme/orders#url") == find(m, "ds:acme/orders#url") {
		t.Error("the local and remote rows share a key")
	}
	if e := find(m, "r:devbox|ds:acme/analytics"); e == nil || !e.disabled || !strings.Contains(e.title, "not forwarded") {
		t.Errorf("unforwarded remote datasource = %+v", e)
	}
	if e := find(m, "r:devbox|signin:acme"); e == nil || e.act.remote != "devbox" {
		t.Errorf("remote sign-in = %+v", e)
	}
	v.signingIn = map[string]bool{"r:devbox|acme": true}
	m = buildMenu(withRemote(control.RemoteConnected), v)
	if e := find(m, "r:devbox|signin:acme"); e == nil || !e.disabled {
		t.Errorf("remote signing in = %+v", e)
	}
	if e := find(m, "signin:acme"); e == nil || e.disabled {
		t.Errorf("the local server shows the remote's sign-in: %+v", e)
	}
}

func TestIconCountsRemoteServers(t *testing.T) {
	local := withRemote(control.RemoteConnected)
	local.Servers = []control.ServerInfo{{Name: "acme", LoggedIn: true, ReauthRequired: true}}
	v := view{now: now, remotes: map[string]*control.Status{"devbox": {Servers: []control.ServerInfo{signedIn("acme", 9*time.Hour)}}}}
	if got := iconFor(local, v); got != iconSignedIn {
		t.Errorf("icon %v, want signed in from the remote", got)
	}
	local.Remotes[0].State = control.RemoteDown
	if got := iconFor(local, v); got != iconEnded {
		t.Errorf("icon %v: a remote that is down has no servers to count", got)
	}
}

func TestRemoteDropNotifiesOnce(t *testing.T) {
	var got []string
	prev := notify
	notify = func(title, body string) { got = append(got, title+" | "+body) }
	t.Cleanup(func() { notify = prev })
	a := &app{}
	status := func(state control.RemoteState, err string) *control.Status {
		return &control.Status{Remotes: []control.RemoteInfo{{Target: "devbox", State: state, Error: err}}}
	}
	a.noticeRemoteDrops(status(control.RemoteConnecting, ""))
	a.noticeRemoteDrops(status(control.RemoteConnected, ""))
	a.noticeRemoteDrops(status(control.RemoteDown, "Connection reset by peer"))
	a.noticeRemoteDrops(status(control.RemoteConnecting, ""))
	a.noticeRemoteDrops(status(control.RemoteDown, "Connection refused"))
	if len(got) != 1 || got[0] != "devbox disconnected | Connection reset by peer" {
		t.Errorf("notifications %q, want one for the drop", got)
	}
}
