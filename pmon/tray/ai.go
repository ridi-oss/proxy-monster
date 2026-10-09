package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ridi-oss/proxy-monster/pmon/internal/aiapps"
)

// bundledPmon is the pmon shipped beside this executable: an AI app launches it directly, so it must be a path
// that survives the app being updated in place.
func bundledPmon() string {
	exe, err := os.Executable()
	if err != nil {
		return "pmon"
	}
	return filepath.Join(filepath.Dir(exe), pmonName)
}

func aiSetup() aiapps.Setup {
	return aiapps.Setup{Pmon: bundledPmon(), Confirm: func() bool {
		return confirm(T("confirm.claudeRestart"), T("confirm.claudeRestartBody"), T("confirm.restartButton"))
	}}
}

// aiErrorText is an AI-app change's error in this app's language.
func aiErrorText(err error) string {
	var entry *aiapps.EntryError
	var missing *aiapps.NotInstalledError
	switch {
	case errors.As(err, &entry) && entry.Taken:
		return T("ai.taken", "app", entry.App, "entry", entry.Entry)
	case errors.As(err, &entry):
		return T("ai.notOurs", "app", entry.App, "entry", entry.Entry)
	case errors.As(err, &missing):
		return T("ai.notInstalled", "app", missing.App)
	}
	return err.Error()
}

// refreshAI re-reads which servers each installed AI app uses, when forced or when the set of servers changed,
// and redraws the menu if anything differs.
func (a *app) refreshAI(force bool) {
	a.mu.Lock()
	s := a.status
	a.mu.Unlock()
	var servers []string
	if s != nil {
		for _, srv := range s.Servers {
			servers = append(servers, srv.Name)
		}
	}
	key := fmt.Sprint(servers)
	if force {
		a.aiMu.Lock()
	} else if !a.aiMu.TryLock() {
		return
	}
	defer a.aiMu.Unlock()
	a.mu.Lock()
	same := a.aiServers == key && a.ai != nil
	a.mu.Unlock()
	if same && !force {
		return
	}
	setup := aiSetup()
	var states []aiState
	for _, app := range aiapps.Apps() {
		if !app.Installed() {
			continue
		}
		st := aiState{id: app.ID, name: app.Name, connected: map[string]bool{}}
		for _, server := range servers {
			st.connected[server] = app.Connected(setup, server)
		}
		states = append(states, st)
	}
	a.mu.Lock()
	changed := fmt.Sprint(states) != fmt.Sprint(a.ai) || a.ai == nil
	a.ai, a.aiServers = states, key
	if a.ai == nil {
		a.ai = []aiState{}
	}
	a.mu.Unlock()
	if changed {
		a.renderMu.Lock()
		a.redraw()
		a.renderMu.Unlock()
	}
}

func (a *app) doAIApp(act action) {
	var app *aiapps.App
	for _, candidate := range aiapps.Apps() {
		if candidate.ID == act.app {
			app = &candidate
		}
	}
	if app == nil {
		return
	}
	// One AI-app change or read at a time: each is several CLI calls on the same config files.
	a.aiMu.Lock()
	defer func() {
		a.aiMu.Unlock()
		a.refreshAI(true)
	}()
	if act.connect {
		if err := app.Add(aiSetup(), act.server); errors.Is(err, aiapps.ErrDeclined) {
			return
		} else if err != nil {
			notify(T("n.aiAddFailed", "server", act.server, "app", app.Name), aiErrorText(err))
		} else {
			notify(T("n.aiAdded", "server", act.server, "app", app.Name), T("ai.after."+app.ID))
		}
	} else if err := app.Remove(aiSetup(), act.server); errors.Is(err, aiapps.ErrDeclined) {
		return
	} else if err != nil {
		notify(T("n.aiRemoveFailed", "server", act.server, "app", app.Name), aiErrorText(err))
	} else {
		notify(T("n.aiRemoved", "server", act.server, "app", app.Name), "")
	}
}
