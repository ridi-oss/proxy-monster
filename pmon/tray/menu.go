package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// endingSoon is how close to a sign-in's end the icon and the notification start warning.
const endingSoon = 30 * time.Minute

type op int

const (
	opSignIn op = iota + 1
	opSignOut
	opCopy
	opStart
	opRestart
	opLoginItem
	opQuit
	opAIApp
	opPrefs
	opAddServer
	opCheckUpdates
	opInstallUpdate
)

// action is what a click does. Copy actions carry their payload, so a row's label and what it copies are built
// together from one datasource and cannot drift apart.
type action struct {
	op      op
	server  string
	label   string
	payload string
	app     string // opAIApp: which app
	connect bool   // opAIApp: add (true) or remove (false)
}

// entry is one menu row. key identifies the row across renders: two menus with the same keys in the same order
// have the same shape and are updated in place instead of rebuilt.
type entry struct {
	key      string
	title    string
	disabled bool
	checkbox bool
	checked  bool
	sep      bool
	act      *action
	children []entry
}

// view is what the menu shows besides the daemon's status.
type view struct {
	now           time.Time
	signingIn     map[string]bool // servers whose browser sign-in is open
	loginItemOn   bool
	loginItemShow bool
	ai            []aiState
	// pmonVersion is the bundled pmon's build; a daemon reporting another one was started by a different pmon.
	pmonVersion string
	// updates is whether this build updates itself; pendingUpdate is a downloaded update waiting to install.
	updates       bool
	pendingUpdate string
}

// aiState is one installed AI app and which servers it already runs `pmon mcp` for.
type aiState struct {
	id, name  string
	connected map[string]bool
}

func header(title string) entry { return entry{key: "header", title: title, disabled: true} }

func separator(key string) entry { return entry{key: key, sep: true} }

// buildMenu turns one daemon status into the whole menu. A nil status means no daemon is reachable.
func buildMenu(s *control.Status, v view) []entry {
	var m []entry
	switch {
	case s == nil:
		m = append(m, header(T("menu.notRunning")), separator("sep-start"),
			entry{key: "start", title: T("menu.start"), act: &action{op: opStart}})
	case s.Outdated():
		m = append(m, header(T("menu.outOfDate")), separator("sep-restart"),
			entry{key: "restart", title: T("menu.restart"), act: &action{op: opRestart}})
	case v.pmonVersion != "" && s.Version != v.pmonVersion:
		// An AI app's `pmon mcp` is this bundle's pmon, and it can need routes an older daemon lacks.
		m = append(m, header(T("menu.differentVersion")), separator("sep-restart"),
			entry{key: "restart", title: T("menu.restart"), act: &action{op: opRestart}}, separator("sep-stale"))
		for _, srv := range s.Servers {
			m = append(m, serverEntry(s, srv, v))
		}
	case len(s.Servers) == 0:
		m = append(m, header(T("menu.noServer")), separator("sep-add"),
			entry{key: "addserver", title: T("menu.connectServer"), act: &action{op: opAddServer}})
	default:
		for _, srv := range s.Servers {
			m = append(m, serverEntry(s, srv, v))
		}
		if e, ok := aiEntry(s, v); ok {
			m = append(m, separator("sep-ai"), e)
		}
		if n := s.TotalLiveConns(); n > 0 {
			m = append(m, entry{key: "conns", title: Tn("menu.openConns", n), disabled: true})
		}
	}
	m = append(m, separator("sep-tail"))
	if v.loginItemShow {
		m = append(m, entry{key: "loginitem", title: T("menu.openAtLogin"), checkbox: true, checked: v.loginItemOn, act: &action{op: opLoginItem}})
	}
	switch {
	case v.pendingUpdate != "":
		m = append(m, entry{key: "update-install", title: T("menu.installUpdate", "version", v.pendingUpdate), act: &action{op: opInstallUpdate}})
	case v.updates:
		m = append(m, entry{key: "update-check", title: T("menu.checkUpdates"), act: &action{op: opCheckUpdates}})
	}
	m = append(m, entry{key: "prefs", title: T("menu.settings"), act: &action{op: opPrefs}})
	return append(m, entry{key: "quit", title: T("menu.quit"), act: &action{op: opQuit}})
}

// aiEntry lists each installed AI app with a checkmark per server it already uses. With one server the app
// itself is the checkbox; with more, each app opens a list of servers.
func aiEntry(s *control.Status, v view) (entry, bool) {
	if len(v.ai) == 0 {
		return entry{}, false
	}
	e := entry{key: "ai", title: T("menu.aiApps")}
	for _, app := range v.ai {
		item := func(key, title, server string) entry {
			on := app.connected[server]
			return entry{key: key, title: title, checkbox: true, checked: on,
				act: &action{op: opAIApp, app: app.id, server: server, label: app.name, connect: !on}}
		}
		if len(s.Servers) == 1 {
			e.children = append(e.children, item("ai:"+app.id, app.name, s.Servers[0].Name))
			continue
		}
		sub := entry{key: "ai:" + app.id, title: app.name}
		for _, srv := range s.Servers {
			sub.children = append(sub.children, item("ai:"+app.id+":"+srv.Name, srv.Name, srv.Name))
		}
		e.children = append(e.children, sub)
	}
	return e, true
}

func serverEntry(s *control.Status, srv control.ServerInfo, v view) entry {
	e := entry{key: "srv:" + srv.Name, title: serverTitle(srv, v)}
	signIn := entry{key: "signin:" + srv.Name, title: T("menu.signIn"), act: &action{op: opSignIn, server: srv.Name}}
	switch {
	case v.signingIn[srv.Name]:
		signIn = entry{key: "signin:" + srv.Name, title: T("menu.signingIn"), disabled: true}
	case srv.LoggedIn:
		signIn.title = T("menu.signInAgain")
	}
	e.children = append(e.children, signIn)
	if srv.LoggedIn {
		e.children = append(e.children, entry{key: "signout:" + srv.Name, title: T("menu.signOut"), act: &action{op: opSignOut, server: srv.Name}})
	}
	if !srv.LoggedIn {
		return e
	}
	var rows []entry
	for _, ds := range s.Datasources {
		if ds.Server == srv.Name {
			rows = append(rows, datasourceEntry(s, srv, ds))
		}
	}
	if srv.LastDiscoveryError != "" {
		// The daemon keeps the last list it got, so an error with rows means the list is stale, not missing.
		title := T("menu.refreshFailed")
		if len(rows) == 0 {
			title = T("menu.listFailed", "error", shorten(srv.LastDiscoveryError, 70))
		}
		e.children = append(e.children, entry{key: "discovery:" + srv.Name, title: title, disabled: true})
	}
	if len(rows) > 0 {
		e.children = append(e.children, separator("sep-ds:"+srv.Name))
		e.children = append(e.children, rows...)
	}
	return e
}

func datasourceEntry(s *control.Status, srv control.ServerInfo, ds control.Datasource) entry {
	key := "ds:" + srv.Name + "/" + ds.Name
	if !ds.Brokered {
		return entry{key: key, title: fmt.Sprintf("%s — %s", ds.Name, ds.Reason), disabled: true}
	}
	title := ds.Name
	if ds.LiveConns > 0 {
		title += "  ·  " + T("menu.dsOpen", "count", strconv.Itoa(ds.LiveConns))
	}
	e := entry{key: key, title: title}
	target := driver.Target{
		Name:           ds.Name,
		ConnectionInfo: ds.ConnectionInfo.Clone(),
		Engine:         ds.Engine,
		DbName:         ds.DbName,
		Port:           ds.LocalPort,
		User:           srv.Principal,
		Password:       s.LocalPassword,
	}
	for _, f := range conn.SupportedFormats(ds.Engine) {
		payload := conn.StringWithOptions(f, target, driver.Options{})
		if payload == "" {
			continue
		}
		label := formatLabel(f)
		e.children = append(e.children, entry{
			key:   key + "#" + string(f),
			title: T("menu.copy", "format", label),
			act:   &action{op: opCopy, server: srv.Name, label: ds.Name + " " + label, payload: payload},
		})
	}
	if len(e.children) == 0 {
		e.disabled = true
	}
	return e
}

func formatLabel(f driver.Format) string {
	if _, ok := catalogs["en"]["format."+string(f)]; ok {
		return T("format." + string(f))
	}
	return strings.ToUpper(string(f))
}

// signInEnd is when a server's sign-in stops working: the session window closing ends renewal and MCP tokens,
// even though the last wire token may outlive it.
func signInEnd(srv control.ServerInfo) (time.Time, bool) {
	for _, ts := range []string{srv.SessionExpiresAt, srv.ExpiresAt} {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// signInEnded reports a login whose sign-in window has closed. Brokered connections keep working until the
// wire token expires, but nothing renews it and AI apps get no new MCP token, so the user must sign in again.
func signInEnded(srv control.ServerInfo, now time.Time) bool {
	if !srv.LoggedIn {
		return false
	}
	if srv.ReauthRequired {
		return true
	}
	end, ok := signInEnd(srv)
	return ok && !end.After(now)
}

func serverTitle(srv control.ServerInfo, v view) string {
	switch {
	case v.signingIn[srv.Name]:
		return T("server.signingIn", "name", srv.Name)
	case !srv.LoggedIn:
		return T("server.signedOut", "name", srv.Name)
	case signInEnded(srv, v.now):
		return T("server.ended", "name", srv.Name)
	}
	who := srv.Principal
	if who == "" {
		who = T("n.signedIn")
	}
	if end, ok := signInEnd(srv); ok {
		return T("server.signedInLeft", "name", srv.Name, "who", who, "left", timeLeft(end.Sub(v.now)))
	}
	return T("server.signedIn", "name", srv.Name, "who", who)
}

func timeLeft(d time.Duration) string {
	switch {
	case d <= 0:
		return T("time.ended")
	case d < time.Hour:
		return T("time.minLeft", "m", strconv.Itoa(max(1, int(d.Minutes()))))
	default:
		return T("time.hoursLeft", "h", strconv.Itoa(int(d.Hours())), "m", strconv.Itoa(int(d.Minutes())%60))
	}
}

// iconFor is the menu-bar icon's state: the most urgent thing across all servers.
func iconFor(s *control.Status, v view) iconState {
	if len(v.signingIn) > 0 {
		return iconBusy
	}
	if s == nil || s.Outdated() || len(s.Servers) == 0 {
		return iconIdle
	}
	state := iconSignedIn
	for _, srv := range s.Servers {
		if !srv.LoggedIn || signInEnded(srv, v.now) {
			return iconSignedOut
		}
		if end, ok := signInEnd(srv); ok && end.Sub(v.now) < endingSoon {
			state = iconExpiring
		}
	}
	return state
}

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
