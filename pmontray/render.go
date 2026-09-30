package main

import (
	"fmt"
	"time"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// menuItem wrappers for the FIXED items, nil-safe for the same reason as the row ones: render() must be
// exercisable in a test, so the shipped function is what is verified rather than a parallel copy.
func setTitleOf(m *systray.MenuItem, title string) {
	if m != nil {
		m.SetTitle(title)
	}
}

func showItem(m *systray.MenuItem) {
	if m != nil {
		m.Show()
	}
}

func hideItem(m *systray.MenuItem) {
	if m != nil {
		m.Hide()
	}
}

func enableItem(m *systray.MenuItem) {
	if m != nil {
		m.Enable()
	}
}

// render mirrors one daemon state into the menu. A nil status means no daemon is reachable, which is a normal
// state to display — never a stale last-known one, since a menu bar claiming "connected" after the daemon died
// is worse than one that says nothing.
//
// Only ever updates or hides existing items: systray cannot remove an item, so a menu rebuilt per update would
// accumulate rows forever.
func (a *app) render(s *control.Status) {
	// One render at a time, start to finish. render is reachable from the event watcher AND from every action
	// goroutine (via refresh), and it assigns a LABEL and a CONNECTION STRING to each row in separate steps —
	// so two interleaved renders could leave a row displaying one datasource while its click copied another
	// one's credentials. Guarding only the status field would not prevent that.
	a.renderMu.Lock()
	defer a.renderMu.Unlock()

	a.mu.Lock()
	a.status = s
	a.mu.Unlock()

	switch {
	case s == nil:
		a.renderStopped()
	case s.Outdated():
		// A daemon from before multi-server support reports a login but no servers.
		a.renderIdle(s)
		setTitleOf(a.mHeader, "daemon is outdated — restart it")
	case !s.LoggedIn:
		a.renderIdle(s)
	default:
		a.renderLoggedIn(s)
	}
}

func (a *app) renderStopped() {
	if a.mHeader != nil {
		systray.SetTooltip("proxy-monster — daemon not running")
	}
	setTitleOf(a.mHeader, "daemon not running")
	hideItem(a.mDetail)
	a.hideDatasourcesFrom(0)

	setTitleOf(a.mLogin, "Log in…") // starts the daemon on the way
	enableItem(a.mLogin)
	hideItem(a.mLogout)
	showItem(a.mStart)
	enableItem(a.mStart)
	hideItem(a.mRestart)
	hideItem(a.mStop)
}

func (a *app) renderIdle(s *control.Status) {
	if a.mHeader != nil {
		systray.SetTooltip("proxy-monster — not logged in")
	}
	setTitleOf(a.mHeader, "not logged in")
	setTitleOf(a.mDetail, fmt.Sprintf("daemon running since %s", clockOf(s.StartedAt)))
	showItem(a.mDetail)
	a.hideDatasourcesFrom(0)

	setTitleOf(a.mLogin, "Log in…")
	enableItem(a.mLogin)
	hideItem(a.mLogout)
	hideItem(a.mStart)
	showItem(a.mRestart)
	showItem(a.mStop)
}

func (a *app) renderLoggedIn(s *control.Status) {
	servers := s.LoggedInServers()
	who := servers[0].Principal
	if len(servers) > 1 {
		who = fmt.Sprintf("%d servers", len(servers))
	}
	if stale := reauthServer(s); stale != nil {
		if a.mHeader != nil {
			systray.SetTooltip("proxy-monster — re-authentication required")
		}
		setTitleOf(a.mHeader, fmt.Sprintf("%s — session expired", stale.Name))
	} else {
		if a.mHeader != nil {
			systray.SetTooltip(fmt.Sprintf("proxy-monster — %s", who))
		}
		setTitleOf(a.mHeader, fmt.Sprintf("%s — %s", who, expiryText(earliestExpiry(servers))))
	}
	setTitleOf(a.mLogin, loginTitle(s))
	enableItem(a.mLogin)
	showItem(a.mLogout)
	hideItem(a.mStart)
	showItem(a.mRestart)
	showItem(a.mStop)

	// A discovery failure is surfaced rather than left to look like "you have no datasources".
	if discoveryFailing(s) {
		setTitleOf(a.mDetail, "discovery failing — check the control plane")
		showItem(a.mDetail)
	} else if n := s.TotalLiveConns(); n > 0 {
		setTitleOf(a.mDetail, fmt.Sprintf("%d active connection(s)", n))
		showItem(a.mDetail)
	} else {
		hideItem(a.mDetail)
	}

	a.applyRows(s)
}

// applyRows assigns the datasource rows for one status: label + copy-payload per row, the overflow notice when
// the set does not fit, and the tail cleared. Split from renderLoggedIn so a test can drive the REAL logic (menu
// items are nil-safe via dsItem.setItem) instead of a reimplementation that could not detect this code changing.
func (a *app) applyRows(s *control.Status) {
	// The row pool is fixed (systray cannot remove items), so a set larger than the pool has to stop somewhere —
	// with the LAST row spent saying so, rather than silently showing a partial list the user reads as complete.
	// The reserve costs a row, so it is only taken when the set genuinely does not fit: with exactly as many
	// datasources as rows every one is shown, and the cutoff accounts for the row the notice occupies.
	shown := len(s.Datasources)
	overflowing := shown > len(a.dsItems)
	if overflowing {
		shown = len(a.dsItems) - 1
	}

	prefix := len(s.Servers) > 1
	used := 0
	for _, ds := range s.Datasources {
		if used >= shown {
			break
		}
		row := a.dsItems[used]
		name := ds.Name
		if prefix {
			name = ds.Server + "  ·  " + ds.Name
		}
		principal := ""
		if srv := s.Server(ds.Server); srv != nil {
			principal = srv.Principal
		}
		if ds.Brokered {
			label := fmt.Sprintf("%s  ·  127.0.0.1:%d", name, ds.LocalPort)
			if ds.LiveConns > 0 {
				label += fmt.Sprintf("  (%d)", ds.LiveConns)
			}
			row.set(ds.Name, conn.String(driver.URL, driver.Target{
				Engine:   ds.Engine,
				DbName:   ds.DbName,
				Port:     ds.LocalPort,
				User:     principal,
				Password: s.LocalPassword,
			}))
			row.setTitle(label)
			row.enable()
		} else {
			row.set(ds.Name, "")
			row.setTitle(fmt.Sprintf("%s  ·  %s", name, ds.Reason))
			row.disable()
		}
		row.show()
		used++
	}
	if overflowing {
		last := a.dsItems[len(a.dsItems)-1]
		last.set("", "") // no payload: the notice must not be clickable
		last.setTitle(fmt.Sprintf("… and %d more — use `pmon status`", len(s.Datasources)-used))
		last.disable()
		last.show()
		a.hideDatasourcesFrom2(used, len(a.dsItems)-1)
		return
	}
	a.hideDatasourcesFrom(used)
}

// hideDatasourcesFrom2 hides rows in [from, to), leaving the reserved overflow row beyond it untouched.
func (a *app) hideDatasourcesFrom2(from, to int) {
	for i := from; i < to && i < len(a.dsItems); i++ {
		a.dsItems[i].set("", "")
		a.dsItems[i].hide()
	}
}

// hideDatasourcesFrom hides every row at or after i, so a shrinking datasource set leaves no stale entries.
func (a *app) hideDatasourcesFrom(i int) {
	for ; i < len(a.dsItems); i++ {
		a.dsItems[i].set("", "")
		a.dsItems[i].hide()
	}
}

// The wrappers below keep the row logic runnable with no menu item attached (a test), so the production code
// itself is what gets exercised rather than a copy of it.
func (d *dsItem) setTitle(title string) {
	d.title = title
	if d.item != nil {
		d.item.SetTitle(title)
	}
}

func (d *dsItem) enable() {
	if d.item != nil {
		d.item.Enable()
	}
}

func (d *dsItem) disable() {
	if d.item != nil {
		d.item.Disable()
	}
}

func (d *dsItem) show() {
	if d.item != nil {
		d.item.Show()
	}
}

func (d *dsItem) hide() {
	if d.item != nil {
		d.item.Hide()
	}
}

func (d *dsItem) set(name, connString string) {
	d.mu.Lock()
	d.name, d.connString = name, connString
	d.mu.Unlock()
}

// reauthServer is the first logged-in server whose renewal was refused, or nil.
func reauthServer(s *control.Status) *control.ServerInfo {
	for _, srv := range s.LoggedInServers() {
		if srv.ReauthRequired {
			return &srv
		}
	}
	return nil
}

func discoveryFailing(s *control.Status) bool {
	for _, srv := range s.LoggedInServers() {
		if srv.LastDiscoveryError != "" {
			return true
		}
	}
	return false
}

func earliestExpiry(servers []control.ServerInfo) string {
	earliest := ""
	for _, srv := range servers {
		if earliest == "" || (srv.ExpiresAt != "" && srv.ExpiresAt < earliest) {
			earliest = srv.ExpiresAt
		}
	}
	return earliest
}

// loginTarget is the server the Log in item acts on: the first that needs a login, else "default" if it
// exists, else the first server.
func loginTarget(s *control.Status) string {
	if s == nil || len(s.Servers) == 0 {
		return "default"
	}
	if stale := reauthServer(s); stale != nil {
		return stale.Name
	}
	for _, srv := range s.Servers {
		if !srv.LoggedIn {
			return srv.Name
		}
	}
	if s.Server("default") != nil {
		return "default"
	}
	return s.Servers[0].Name
}

func loginTitle(s *control.Status) string {
	target := loginTarget(s)
	if srv := s.Server(target); srv != nil && srv.LoggedIn {
		return "Re-authenticate…"
	}
	if len(s.Servers) > 1 {
		return fmt.Sprintf("Log in to %s…", target)
	}
	return "Log in…"
}

// expiryText renders how long the wire token has left, which is the fact that decides whether a saved
// connection is about to start failing.
func expiryText(ts string) string {
	if ts == "" {
		return "expiry unknown"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "expiry unknown"
	}
	d := time.Until(t)
	switch {
	case d <= 0:
		return "token EXPIRED"
	case d < time.Hour:
		return fmt.Sprintf("%dm left", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%dm left", int(d.Hours()), int(d.Minutes())%60)
	}
}

func clockOf(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "an unknown time"
	}
	return t.Local().Format("15:04")
}
