package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
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
	Running        bool          `json:"running"`
	Servers        []prefsServer `json:"servers"`
	LoginItemOn    bool          `json:"loginItemOn"`
	LoginItemShown bool          `json:"loginItemShown"`
	Versions       prefsVersions `json:"versions"`
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
	mu          sync.Mutex
	signingIn   map[string]bool
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
	st := prefsState{LoginItemOn: on, LoginItemShown: shown, Servers: []prefsServer{},
		Versions: prefsVersions{App: version, Pmon: p.pmonVersion}}
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
	day := func(x time.Time) time.Time { return time.Date(x.Year(), x.Month(), x.Day(), 0, 0, 0, 0, x.Location()) }
	switch day(t).Sub(day(now)) {
	case 0:
		return "Today " + t.Format("15:04")
	case 24 * time.Hour:
		return "Tomorrow " + t.Format("15:04")
	}
	return t.Format("Jan 2 15:04")
}

// aiState reads which servers each installed AI app uses. It runs the apps' CLIs, so the page asks for it
// separately and shows a placeholder meanwhile.
func (p *prefs) aiState() []prefsAIApp {
	st := p.state()
	out := []prefsAIApp{}
	pmon := bundledPmon()
	for _, app := range aiApps() {
		if !app.installed() {
			continue
		}
		row := prefsAIApp{ID: app.id, Name: app.name, After: app.after, Connected: map[string]bool{}}
		for _, srv := range st.Servers {
			row.Connected[srv.Name] = app.connected(mcpEntryName(srv.Name), pmon, srv.Name)
		}
		out = append(out, row)
	}
	return out
}

func (p *prefs) aiToggle(id, server string, on bool) string {
	for _, app := range aiApps() {
		if app.id != id {
			continue
		}
		if on {
			return errText(app.add(mcpEntryName(server), bundledPmon(), server))
		}
		return errText(app.remove(mcpEntryName(server), bundledPmon(), server))
	}
	return "unknown app " + id
}

func (p *prefs) openLink(u string) string { return errText(openURL(u)) }

// handlers are the calls the page makes, by name, each with its JSON-encoded arguments.
func (p *prefs) handlers() map[string]func(args []json.RawMessage) (any, error) {
	str := func(args []json.RawMessage, i int) (string, error) {
		var v string
		if i >= len(args) {
			return "", fmt.Errorf("missing argument %d", i)
		}
		return v, json.Unmarshal(args[i], &v)
	}
	one := func(f func(string) string) func([]json.RawMessage) (any, error) {
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
		"signIn":       one(p.signIn),
		"signOut":      one(p.signOut),
		"removeServer": one(p.removeServer),
		"openLink":     one(p.openLink),
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
func (p *prefs) setServer(name, url string) string {
	client, err := control.EnsureDaemon(p.ctx)
	if err != nil {
		return errText(err)
	}
	_, err = client.SetServer(p.ctx, control.SetServerRequest{Name: name, ControlPlane: url})
	return errText(err)
}

// errCanceled is what a binding returns when the user declined a confirmation: the page shows nothing.
const errCanceled = ""

func (p *prefs) removeServer(name string) string {
	client, err := control.Connect(p.ctx)
	if err != nil {
		return errText(err)
	}
	if !confirmDrop(p.ctx, "Remove "+name, name) {
		return errCanceled
	}
	_, err = client.UnsetServer(p.ctx, control.UnsetServerRequest{Name: name})
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
			notify("Sign-in failed", err.Error())
		}
	}()
	return ""
}

func (p *prefs) signOut(name string) string {
	client, err := control.Connect(p.ctx)
	if err != nil {
		return errText(err)
	}
	if !confirmDrop(p.ctx, "Sign Out", name) {
		return errCanceled
	}
	_, err = client.Logout(p.ctx, control.LogoutRequest{Server: name})
	return errText(err)
}

func (p *prefs) setOpenAtLogin(on bool) string {
	setPrefBool(openAtLoginDecided, true)
	return errText(setLoginItem(on))
}

func (p *prefs) start() string {
	_, err := control.EnsureDaemon(p.ctx)
	return errText(err)
}

// bundledPmonVersion is the version the bundled pmon reports, or "" when it cannot be run (a `go run` build).
func bundledPmonVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bundledPmon(), "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
