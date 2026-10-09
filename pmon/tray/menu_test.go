package main

import (
	"bytes"
	"encoding/json"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

var now = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

func signedIn(name string, left time.Duration) control.ServerInfo {
	return control.ServerInfo{Name: name, Principal: "dana@" + name + ".example", LoggedIn: true,
		SessionExpiresAt: now.Add(left).Format(time.RFC3339)}
}

func twoServers() *control.Status {
	return &control.Status{
		LoggedIn: true, LocalPassword: "pw",
		Servers: []control.ServerInfo{signedIn("acme", 9*time.Hour), signedIn("staging", 3*time.Hour)},
		Datasources: []control.Datasource{
			{Server: "acme", Name: "orders", Engine: "mysql", DbName: "orders", LocalPort: 6100, Brokered: true},
			{Server: "acme", Name: "analytics", Engine: "postgres", DbName: "analytics", LocalPort: 6101, Brokered: true},
			{Server: "staging", Name: "orders", Engine: "mysql", DbName: "orders_stg", LocalPort: 6102, Brokered: true},
			{Server: "staging", Name: "legacy", Engine: "mysql", Brokered: false, Reason: "no proxy address"},
		},
	}
}

func find(es []entry, key string) *entry {
	for i := range es {
		if es[i].key == key {
			return &es[i]
		}
		if e := find(es[i].children, key); e != nil {
			return e
		}
	}
	return nil
}

func walk(es []entry, f func(entry)) {
	for _, e := range es {
		f(e)
		walk(e.children, f)
	}
}

// What a Copy item shows and what it copies must describe the same datasource: a mismatch hands the user
// another datasource's credentials. Two servers each have an "orders", which only the server tells apart.
func TestEveryCopyItemCopiesItsOwnDatasource(t *testing.T) {
	s := twoServers()
	menu := buildMenu(s, view{now: now})
	copies := 0
	for _, ds := range s.Datasources {
		if !ds.Brokered {
			continue
		}
		srv := s.Server(ds.Server)
		for _, f := range conn.SupportedFormats(ds.Engine) {
			e := find(menu, "ds:"+ds.Server+"/"+ds.Name+"#"+string(f))
			if e == nil {
				t.Fatalf("no Copy %s item for %s/%s", f, ds.Server, ds.Name)
			}
			want := conn.StringWithOptions(f, driver.Target{Name: ds.Name, Engine: ds.Engine, DbName: ds.DbName,
				Port: ds.LocalPort, User: srv.Principal, Password: s.LocalPassword}, driver.Options{})
			if e.act == nil || e.act.payload != want || e.act.server != ds.Server {
				t.Errorf("%s/%s %s copies %+v, want %q", ds.Server, ds.Name, f, e.act, want)
			}
			copies++
		}
	}
	if copies == 0 {
		t.Fatal("compared nothing")
	}
}

func TestEveryFormatIsOffered(t *testing.T) {
	menu := buildMenu(twoServers(), view{now: now})
	row := find(menu, "ds:acme/orders")
	if got, want := len(row.children), len(conn.SupportedFormats("mysql")); got != want {
		t.Fatalf("orders offers %d formats, want all %d", got, want)
	}
}

func TestAnUnbrokeredDatasourceCopiesNothing(t *testing.T) {
	row := find(buildMenu(twoServers(), view{now: now}), "ds:staging/legacy")
	if !row.disabled || len(row.children) != 0 || row.act != nil {
		t.Fatalf("legacy row = %+v, want a disabled row with no Copy items", row)
	}
	if !strings.Contains(row.title, "no proxy address") {
		t.Errorf("title %q does not say why", row.title)
	}
}

func TestASignedOutServerShowsOnlySignIn(t *testing.T) {
	s := twoServers()
	s.Servers[1] = control.ServerInfo{Name: "staging"}
	srv := find(buildMenu(s, view{now: now}), "srv:staging")
	if srv.title != "staging — signed out" {
		t.Errorf("title = %q", srv.title)
	}
	if len(srv.children) != 1 || srv.children[0].act == nil || srv.children[0].act.op != opSignIn || srv.children[0].act.server != "staging" {
		t.Fatalf("children = %+v, want one Sign In for staging", srv.children)
	}
}

func TestSigningInDisablesThatServersSignIn(t *testing.T) {
	menu := buildMenu(twoServers(), view{now: now, signingIn: map[string]bool{"acme": true}})
	if e := find(menu, "signin:acme"); !e.disabled || e.act != nil {
		t.Errorf("acme sign-in during its flow = %+v", e)
	}
	if e := find(menu, "signin:staging"); e.disabled {
		t.Error("staging's sign-in is disabled by acme's flow")
	}
}

func TestIconState(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *control.Status
		v    view
		want iconState
	}{
		{"no daemon", nil, view{now: now}, iconIdle},
		{"no servers", &control.Status{}, view{now: now}, iconIdle},
		{"all signed in", twoServers(), view{now: now}, iconSignedIn},
		{"one ending", &control.Status{LoggedIn: true, Servers: []control.ServerInfo{signedIn("acme", 9*time.Hour), signedIn("b", 20*time.Minute)}}, view{now: now}, iconExpiring},
		{"one signed out", &control.Status{LoggedIn: true, Servers: []control.ServerInfo{signedIn("acme", 9*time.Hour), {Name: "b"}}}, view{now: now}, iconSignedOut},
		{"renewal refused", &control.Status{LoggedIn: true, Servers: []control.ServerInfo{{Name: "acme", LoggedIn: true, ReauthRequired: true}}}, view{now: now}, iconSignedOut},
		{"signing in", twoServers(), view{now: now, signingIn: map[string]bool{"acme": true}}, iconBusy},
	} {
		if got := iconFor(tc.s, tc.v); got != tc.want {
			t.Errorf("%s: icon %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The time left changes every minute and must update the open menu in place; a new datasource must rebuild it.
func TestShapeIgnoresTitlesButNotRows(t *testing.T) {
	s := twoServers()
	before := shapeOf(buildMenu(s, view{now: now}))
	if after := shapeOf(buildMenu(s, view{now: now.Add(time.Hour)})); after != before {
		t.Error("the passing of time changed the menu's shape")
	}
	s.Datasources = append(s.Datasources, control.Datasource{Server: "acme", Name: "zeta", Engine: "mysql", LocalPort: 6110, Brokered: true})
	if after := shapeOf(buildMenu(s, view{now: now})); after == before {
		t.Error("a new datasource did not change the menu's shape")
	}
}

func TestHeaders(t *testing.T) {
	if e := find(buildMenu(nil, view{}), "start"); e == nil || e.act.op != opStart {
		t.Error("no Start item without a daemon")
	}
	if e := find(buildMenu(&control.Status{}, view{}), "header"); e == nil || e.title != "Not connected to a server" {
		t.Errorf("header with no servers = %+v", e)
	}
}

// Decoded from a real released daemon's /status: a login with no servers.
func TestAReleasedDaemonAsksForARestart(t *testing.T) {
	var s control.Status
	raw := `{"principal":"you@example.com","controlPlane":"http://cp","loggedIn":true,"expiresAt":"2099-01-01T00:00:00Z","startedAt":"2026-01-01T00:00:00Z","version":"0.1.5","localPassword":"pw","datasources":[{"name":"acme","engine":"mysql","localPort":6100,"brokered":true}]}`
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	menu := buildMenu(&s, view{now: now})
	if e := find(menu, "restart"); e == nil {
		t.Fatal("no Restart item for an outdated daemon")
	}
	walk(menu, func(e entry) {
		if e.act != nil && e.act.op == opCopy {
			t.Errorf("an outdated daemon's menu offers a copy: %+v", e.act)
		}
	})
}

// A datasource name may hold the shape's own separators; two different menus must still have different shapes,
// or the in-place update would apply one menu to the other's items.
func TestShapeCannotBeForgedByAName(t *testing.T) {
	one := twoServers()
	one.Datasources = []control.Datasource{{Server: "acme", Name: "a,ds:acme/b", Engine: "mysql", Reason: "x"}}
	two := twoServers()
	two.Datasources = []control.Datasource{{Server: "acme", Name: "a", Engine: "mysql", Reason: "x"}, {Server: "acme", Name: "b", Engine: "mysql", Reason: "x"}}
	if shapeOf(buildMenu(one, view{now: now})) == shapeOf(buildMenu(two, view{now: now})) {
		t.Fatal("one datasource and two datasources produced the same shape")
	}
}

func TestTwoSignInsAtOnceKeepBothBusy(t *testing.T) {
	menu := buildMenu(twoServers(), view{now: now, signingIn: map[string]bool{"acme": true, "staging": true}})
	for _, srv := range []string{"acme", "staging"} {
		if e := find(menu, "signin:"+srv); !e.disabled {
			t.Errorf("%s sign-in is clickable while its flow is open", srv)
		}
	}
}

// A failed refresh with a list already on hand says the list is stale; with no list it says why.
func TestDiscoveryErrorWording(t *testing.T) {
	s := twoServers()
	s.Servers[0].LastDiscoveryError = "Get \"https://pm.acme.example/api/datasources\": context deadline exceeded"
	if e := find(buildMenu(s, view{now: now}), "discovery:acme"); e == nil || !strings.Contains(e.title, "showing the last list") {
		t.Errorf("with datasources: %+v", e)
	}
	s.Datasources = nil
	if e := find(buildMenu(s, view{now: now}), "discovery:acme"); e == nil || !strings.Contains(e.title, "context deadline") {
		t.Errorf("without datasources: %+v", e)
	}
}

// A daemon from a different pmon build is flagged with a restart, and the servers stay usable below it.
func TestADifferentDaemonVersionOffersRestart(t *testing.T) {
	s := twoServers()
	s.Version = "0.1.7+aaaaaaaaaaaa"
	menu := buildMenu(s, view{now: now, pmonVersion: "0.1.8+bbbbbbbbbbbb"})
	if e := find(menu, "restart"); e == nil || e.act.op != opRestart {
		t.Fatal("no restart for a daemon of another version")
	}
	if find(menu, "srv:acme") == nil {
		t.Error("the servers disappeared behind the restart notice")
	}
	if find(buildMenu(s, view{now: now, pmonVersion: s.Version}), "restart") != nil {
		t.Error("a restart offered for the same version")
	}
	if find(buildMenu(s, view{now: now}), "restart") != nil {
		t.Error("a restart offered when the bundled version is unknown")
	}
}

// Past its sign-in window a login still brokers until the wire token expires, but it must read as needing a
// sign-in: AI apps get no token from it.
func TestASignInPastItsWindowReadsAsEnded(t *testing.T) {
	s := &control.Status{LoggedIn: true, Servers: []control.ServerInfo{{Name: "ridi", Principal: "dana@ridi.example", LoggedIn: true,
		SessionExpiresAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Hour).Format(time.RFC3339)}}}
	menu := buildMenu(s, view{now: now})
	if e := find(menu, "srv:ridi"); e.title != "ridi — sign-in ended" {
		t.Errorf("title = %q", e.title)
	}
	if e := find(menu, "signin:ridi"); e.disabled || e.title != "Sign In Again…" {
		t.Errorf("sign-in item = %+v", e)
	}
	if got := iconFor(s, view{now: now}); got != iconSignedOut {
		t.Errorf("icon = %v, want signed out", got)
	}
}

func TestToICOWrapsThePNG(t *testing.T) {
	ico := toICO(recolor(trayIcon, color.NRGBA{R: 255, G: 255, B: 255}))
	if !bytes.Equal(ico[:6], []byte{0, 0, 1, 0, 1, 0}) || ico[6] != 32 || ico[7] != 32 {
		t.Fatalf("header % x", ico[:8])
	}
	img, err := png.Decode(bytes.NewReader(ico[22:]))
	if err != nil {
		t.Fatal(err)
	}
	if r, g, b, _ := img.At(16, 16).RGBA(); r>>8 != 255 || g>>8 != 255 || b>>8 != 255 {
		t.Errorf("the recolored shield is not white at its center")
	}
}

func TestAIEntryShapes(t *testing.T) {
	ai := []aiState{{id: "claude-desktop", name: "Claude Desktop", connected: map[string]bool{"acme": true}}}
	one := buildMenu(twoServersWith("acme"), view{now: now, ai: ai})
	if e := find(one, "ai:claude-desktop"); e == nil || !e.checkbox || !e.checked || e.act.connect {
		t.Fatalf("one server: %+v", e)
	}
	two := buildMenu(twoServers(), view{now: now, ai: ai})
	if e := find(two, "ai:claude-desktop:staging"); e == nil || e.checked || !e.act.connect || e.act.server != "staging" {
		t.Fatalf("two servers, staging: %+v", e)
	}
	if find(buildMenu(twoServers(), view{now: now}), "ai") != nil {
		t.Error("an AI section with no AI apps installed")
	}
}

func twoServersWith(name string) *control.Status {
	s := twoServers()
	s.Servers = s.Servers[:1]
	s.Servers[0].Name = name
	return s
}
