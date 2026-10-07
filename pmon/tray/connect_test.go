package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

func TestParseConnectLink(t *testing.T) {
	for _, tc := range []struct {
		raw, name, url, err string
	}{
		{raw: "pmon://connect?name=acme&url=https://pm.acme.example", name: "acme", url: "https://pm.acme.example"},
		{raw: "pmon://connect?url=https://pm.acme.example/", name: "pm", url: "https://pm.acme.example"},
		{raw: "pmon://connect?name=Acme&url=https%3A%2F%2Fpm.acme.example%2Fpm", name: "acme", url: "https://pm.acme.example/pm"},
		{raw: "pmon://connect?name=local&url=http://localhost:8090", name: "local", url: "http://localhost:8090"},
		{raw: "pmon://connect?name=local&url=http://127.0.0.1:8090", name: "local", url: "http://127.0.0.1:8090"},
		{raw: "pmon://connect?name=evil&url=http://pm.acme.example", err: "https"},
		{raw: "pmon://connect?name=evil&url=file:///etc/passwd", err: "valid server address"},
		{raw: "pmon://connect?name=evil&url=https://user:pw@pm.acme.example", err: "valid server address"},
		{raw: "pmon://connect?name=evil", err: "valid server address"},
		{raw: "pmon://login?name=acme&url=https://pm.acme.example", err: "not a Proxy Monster connect link"},
		{raw: "https://connect?url=https://pm.acme.example", err: "not a Proxy Monster connect link"},
	} {
		got, err := parseConnectLink(tc.raw)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.raw, err, tc.err)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.raw, err)
		case got.name != tc.name || got.url != tc.url:
			t.Errorf("%s: got %+v, want name %q url %q", tc.raw, got, tc.name, tc.url)
		}
	}
}

// A pmon:// link changes nothing until the user confirms: not even starting the daemon.
func TestAConnectLinkWaitsForConfirmation(t *testing.T) {
	realDaemon(t)
	quiet(t)
	var asked []string
	answer := false
	confirm = func(title, _, _ string) bool { asked = append(asked, title); return answer }
	t.Cleanup(func() { confirm = confirmDialog })
	a := newApp(context.Background())

	a.openConnectLink("pmon://connect?name=acme&url=https://pm.acme.example")
	if len(asked) != 1 {
		t.Fatalf("asked %v, want one confirmation", asked)
	}
	if _, err := control.Connect(context.Background()); err == nil {
		t.Fatal("a canceled link started the daemon")
	}

	answer = true
	a.openConnectLink("pmon://connect?name=acme&url=https://pm.acme.example")
	client, err := control.Connect(context.Background())
	if err != nil {
		t.Fatal("a confirmed link did not start the daemon")
	}
	s, _ := client.Status(context.Background())
	if srv := s.Server("acme"); srv == nil || !strings.Contains(srv.ControlPlane, "pm.acme.example") {
		t.Fatalf("a confirmed link did not add acme: %+v", s.Servers)
	}

	// The same server again, still signed out: it asks again rather than starting a sign-in unprompted.
	asked, answer = nil, false
	a.openConnectLink("pmon://connect?name=acme&url=https://pm.acme.example")
	if len(asked) != 1 || asked[0] != "Sign in to acme?" {
		t.Errorf("same server again asked %v", asked)
	}
}

func quiet(t *testing.T) {
	prev := notify
	notify = func(string, string) {}
	t.Cleanup(func() { notify = prev })
}

// A login past its sign-in window still reads LoggedIn until the daemon tries to renew it; the console link must
// start a fresh sign-in for it, not report it connected.
func TestAConnectLinkSignsInAgainWhenTheSignInEnded(t *testing.T) {
	ended := control.ServerInfo{Name: "ridi", ControlPlane: "https://pm.ridi.example", LoggedIn: true,
		SessionExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}
	if !signInEnded(ended, time.Now()) {
		t.Fatal("a login past its window does not read as ended")
	}
}
