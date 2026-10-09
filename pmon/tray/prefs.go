package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/aiapps"
)

// The Preferences window runs as its own process (`pmontray --preferences`): the systray owns the menu-bar
// process's main thread, and a window needs one too. It is one more peer on the control socket, like the CLI.

// prefsServer is one server card in the Servers pane.
type prefsServer struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	SignedIn    bool   `json:"signedIn"`
	Busy        bool   `json:"busy"`
	Ending      bool   `json:"ending"`
	Ended       bool   `json:"ended"`
	TokenEndsAt string `json:"tokenEndsAt"`
	Account     string `json:"account"`
	EndsAt      string `json:"endsAt"`
	Left        string `json:"left"`
	Datasources int    `json:"datasources"`
}

type prefsVersions struct {
	App    string `json:"app"`
	Pmon   string `json:"pmon"`
	Daemon string `json:"daemon"`
}

type prefsState struct {
	Language       string        `json:"language"` // the setting: "system", "en" or "ko"
	Lang           string        `json:"lang"`     // the language in use
	Theme          string        `json:"theme"`
	Running        bool          `json:"running"`
	Servers        []prefsServer `json:"servers"`
	LoginItemOn    bool          `json:"loginItemOn"`
	LoginItemShown bool          `json:"loginItemShown"`
	Versions       prefsVersions `json:"versions"`
	Updates        prefsUpdates  `json:"updates"`
}

// prefsUpdates is the Updates setting; Shown is false in a build without an updater.
type prefsUpdates struct {
	Shown  bool `json:"shown"`
	Auto   bool `json:"auto"`
	Forced bool `json:"forced"`
}

// prefsAIApp is one installed AI app and which servers it already runs `pmon mcp` for.
type prefsAIApp struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	After     string          `json:"after"`
	Connected map[string]bool `json:"connected"`
}

// prefs is the logic behind the window, kept apart from the web view so it can be tested.
type prefs struct {
	ctx         context.Context
	changed     func()
	pmonVersion string
	// window is the native window, so a theme change also restyles its title bar; nil in tests.
	window unsafe.Pointer
	// retitle sets the window title in the current language; nil in tests.
	retitle   func()
	mu        sync.Mutex
	signingIn map[string]bool
	// aiMu runs one AI-app read or change at a time: each is several CLI calls on the same config files.
	aiMu sync.Mutex
}

func (p *prefs) busy(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signingIn[name]
}

func (p *prefs) setBusy(name string, on bool) {
	p.mu.Lock()
	p.signingIn[name] = on
	p.mu.Unlock()
	p.changed()
}

func (p *prefs) state() prefsState {
	on, shown := loginItem()
	language := prefString(prefLanguage)
	if _, ok := catalogs[language]; !ok {
		language = "system"
	}
	st := prefsState{Language: language, Lang: lang(), Theme: theme(), LoginItemOn: on, LoginItemShown: shown, Servers: []prefsServer{},
		Versions: prefsVersions{App: version, Pmon: p.pmonVersion}}
	st.Updates.Shown = updatesConfigured()
	st.Updates.Auto, st.Updates.Forced = autoUpdates()
	client, err := control.Connect(p.ctx)
	if err != nil {
		return st
	}
	s, err := client.Status(p.ctx)
	if err != nil {
		return st
	}
	st.Running = true
	st.Versions.Daemon = s.Version
	now := time.Now()
	for _, srv := range s.Servers {
		row := prefsServer{Name: srv.Name, URL: srv.ControlPlane, Account: srv.Principal,
			Ended: signInEnded(srv, now), Busy: p.busy(srv.Name)}
		row.SignedIn = srv.LoggedIn && !row.Ended
		if end, ok := signInEnd(srv); ok && srv.LoggedIn {
			row.EndsAt = clockLabel(end, now)
			row.Left = timeLeft(end.Sub(now))
			row.Ending = row.SignedIn && end.Sub(now) < endingSoon
		}
		if t, err := time.Parse(time.RFC3339, srv.ExpiresAt); err == nil && row.Ended && t.After(now) {
			row.TokenEndsAt = clockLabel(t, now)
		}
		for _, ds := range s.Datasources {
			if ds.Server == srv.Name {
				row.Datasources++
			}
		}
		st.Servers = append(st.Servers, row)
	}
	sort.Slice(st.Servers, func(i, j int) bool { return st.Servers[i].Name < st.Servers[j].Name })
	return st
}

// clockLabel names a time the way the window shows it: "Today 14:16", "Tomorrow 09:40", or a date.
func clockLabel(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	sameDay := func(a, b time.Time) bool { return a.Year() == b.Year() && a.YearDay() == b.YearDay() }
	clock := t.Format("15:04")
	switch {
	case sameDay(t, now):
		return T("time.today", "time", clock)
	case sameDay(t, now.AddDate(0, 0, 1)):
		return T("time.tomorrow", "time", clock)
	}
	return T("time.date", "month", strconv.Itoa(int(t.Month())), "monthName", t.Format("Jan"), "day", strconv.Itoa(t.Day()), "time", clock)
}

// aiState reads which servers each installed AI app uses. It runs the apps' CLIs, so the page asks for it
// separately and shows a placeholder meanwhile.
func (p *prefs) aiState() []prefsAIApp {
	p.aiMu.Lock()
	defer p.aiMu.Unlock()
	st := p.state()
	out := []prefsAIApp{}
	setup := aiSetup()
	for _, app := range aiapps.Apps() {
		if !app.Installed() {
			continue
		}
		row := prefsAIApp{ID: app.ID, Name: app.Name, After: T("ai.after." + app.ID), Connected: map[string]bool{}}
		for _, srv := range st.Servers {
			row.Connected[srv.Name] = app.Connected(setup, srv.Name)
		}
		out = append(out, row)
	}
	return out
}

func (p *prefs) aiToggle(id, server string, on bool) any {
	p.aiMu.Lock()
	defer p.aiMu.Unlock()
	for _, app := range aiapps.Apps() {
		if app.ID != id {
			continue
		}
		change := app.Remove
		if on {
			change = app.Add
		}
		err := change(aiSetup(), server)
		switch {
		case errors.Is(err, aiapps.ErrDeclined):
			return nil
		case err != nil:
			return aiErrorText(err)
		}
		return ""
	}
	return "unknown app " + id
}

func (p *prefs) openLink(u string) string { return errText(openURL(u)) }

func (p *prefs) setLanguage(l string) string {
	if _, ok := catalogs[l]; !ok && l != "system" {
		return "unknown language " + l
	}
	setPrefString(prefLanguage, l)
	if p.retitle != nil {
		p.retitle()
	}
	return ""
}

func (p *prefs) setTheme(t string) string {
	if t != "system" && t != "light" && t != "dark" {
		return "unknown theme " + t
	}
	setPrefString(prefTheme, t)
	if p.window != nil {
		applyTheme(p.window, t)
	}
	return ""
}

// handlers are the calls the page makes, by name, each with its JSON-encoded arguments.
func (p *prefs) handlers() map[string]func(args []json.RawMessage) (any, error) {
	str := func(args []json.RawMessage, i int) (string, error) {
		var v string
		if i >= len(args) {
			return "", fmt.Errorf("missing argument %d", i)
		}
		return v, json.Unmarshal(args[i], &v)
	}
	one := func(f func(string) any) func([]json.RawMessage) (any, error) {
		return func(args []json.RawMessage) (any, error) {
			a, err := str(args, 0)
			if err != nil {
				return nil, err
			}
			return f(a), nil
		}
	}
	return map[string]func([]json.RawMessage) (any, error){
		"state":        func([]json.RawMessage) (any, error) { return p.state(), nil },
		"aiState":      func([]json.RawMessage) (any, error) { return p.aiState(), nil },
		"start":        func([]json.RawMessage) (any, error) { return p.start(), nil },
		"restart":      func([]json.RawMessage) (any, error) { return p.restart(), nil },
		"signIn":       one(func(n string) any { return p.signIn(n) }),
		"signOut":      one(p.signOut),
		"removeServer": one(p.removeServer),
		"openLink":     one(func(u string) any { return p.openLink(u) }),
		"setLanguage":  one(func(l string) any { return p.setLanguage(l) }),
		"setTheme":     one(func(t string) any { return p.setTheme(t) }),
		"setServer": func(args []json.RawMessage) (any, error) {
			name, err := str(args, 0)
			if err != nil {
				return nil, err
			}
			url, err := str(args, 1)
			if err != nil {
				return nil, err
			}
			return p.setServer(name, url), nil
		},
		"setOpenAtLogin": func(args []json.RawMessage) (any, error) {
			var on bool
			if len(args) < 1 || json.Unmarshal(args[0], &on) != nil {
				return nil, errors.New("setOpenAtLogin takes a boolean")
			}
			return p.setOpenAtLogin(on), nil
		},
		"checkUpdates": func([]json.RawMessage) (any, error) { return p.checkUpdates(), nil },
		"setAutoUpdates": func(args []json.RawMessage) (any, error) {
			var on bool
			if len(args) < 1 || json.Unmarshal(args[0], &on) != nil {
				return nil, errors.New("setAutoUpdates takes a boolean")
			}
			return p.setAutoUpdates(on), nil
		},
		"aiToggle": func(args []json.RawMessage) (any, error) {
			id, err := str(args, 0)
			if err != nil {
				return nil, err
			}
			server, err := str(args, 1)
			if err != nil {
				return nil, err
			}
			var on bool
			if len(args) < 3 || json.Unmarshal(args[2], &on) != nil {
				return nil, errors.New("aiToggle takes a boolean")
			}
			return p.aiToggle(id, server, on), nil
		},
	}
}

// errText is what a binding returns to the page: empty on success, otherwise a sentence to show.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// setServer adds a server, or changes an existing one's address (which signs it out).
// A handler's result tells the page what happened: "" is success, a string is an error, nil means the user
// declined a confirmation (the page shows nothing), and a warning is success with something to point out.
type warning struct {
	Warn string `json:"warn"`
}

// notEnded is the warning for a login the server could not end, which stays valid until it expires.
func notEnded(server string) any { return warning{T("n.signedOutLocalBody", "server", server)} }

// setServer adds a server, or changes an existing one's address (which signs it out).
func (p *prefs) setServer(name, url string) any {
	client, err := control.EnsureDaemon(p.ctx)
	if err != nil {
		return errText(err)
	}
	res, err := client.SetServer(p.ctx, control.SetServerRequest{Name: name, ControlPlane: url})
	if err == nil && res.NotEndedOnServer {
		return notEnded(name)
	}
	return errText(err)
}

func (p *prefs) removeServer(name string) any {
	client, err := control.Connect(p.ctx)
	if err != nil {
		return errText(err)
	}
	body := T("confirm.removeBody")
	if n := liveConns(p.ctx, name); n > 0 {
		body += "\n" + Tn("confirm.conns", n)
	}
	if !confirm(T("confirm.remove", "name", name), body, T("confirm.removeButton")) {
		return nil
	}
	notEndedOn, err := client.UnsetServer(p.ctx, control.UnsetServerRequest{Name: name})
	if err == nil && len(notEndedOn) > 0 {
		return notEnded(name)
	}
	return errText(err)
}

// signIn starts the browser sign-in and returns at once; the window follows it through state().
func (p *prefs) signIn(name string) string {
	if p.busy(name) {
		return ""
	}
	client, err := control.EnsureDaemon(p.ctx)
	if err != nil {
		return errText(err)
	}
	p.setBusy(name, true)
	go func() {
		err := signInFlow(p.ctx, client, name)
		p.setBusy(name, false)
		if err != nil && !errors.Is(err, context.Canceled) {
			notify(T("n.signInFailed"), err.Error())
		}
	}()
	return ""
}

func (p *prefs) signOut(name string) any {
	client, err := control.Connect(p.ctx)
	if err != nil {
		return errText(err)
	}
	if !confirmDrop(p.ctx, "signOut", name) {
		return nil
	}
	notEndedOn, err := client.Logout(p.ctx, control.LogoutRequest{Server: name})
	if err == nil && len(notEndedOn) > 0 {
		return notEnded(name)
	}
	return errText(err)
}

// restart replaces a daemon of another version with the bundled pmon's.
func (p *prefs) restart() any {
	if !confirmDrop(p.ctx, "restart", "") {
		return nil
	}
	if err := control.StopDaemon(p.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		return errText(err)
	}
	_, err := control.EnsureDaemon(p.ctx)
	return errText(err)
}

func (p *prefs) setOpenAtLogin(on bool) string {
	setPrefBool(openAtLoginDecided, true)
	return errText(setLoginItem(on))
}

// setAutoUpdates writes the setting the menu-bar process's updater follows (update.go).
func (p *prefs) setAutoUpdates(on bool) string {
	if _, forced := autoUpdates(); forced {
		return T("s.general.updatesManaged")
	}
	setPrefBool(prefAutoUpdates, on)
	return ""
}

// checkUpdates asks the menu-bar process, which runs the updater and reads this process's stdout, to check now.
func (p *prefs) checkUpdates() string {
	_, err := fmt.Fprintln(toMenuBar, "check-updates")
	return errText(err)
}

// toMenuBar is this process's stdout, which the menu-bar process reads; replaceable in tests.
var toMenuBar io.Writer = os.Stdout

func (p *prefs) start() string {
	_, err := control.EnsureDaemon(p.ctx)
	return errText(err)
}

// bundledPmonVersion is the version the bundled pmon reports, or "" when it cannot be run (a `go run` build).
func bundledPmonVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := noConsole(exec.CommandContext(ctx, bundledPmon(), "--version")).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
