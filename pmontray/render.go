package main

import (
	"fmt"
	"time"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// menuItem wrappers for the FIXED items, nil-safe for the same reason as the row ones: render() must be
// exercisable in a test, so the shipped function is what is verified rather than a parallel copy.
var setTitleOf = func(m *systray.MenuItem, title string) {
	if m != nil {
		m.SetTitle(title)
	}
}

var showItem = func(m *systray.MenuItem) {
	if m != nil {
		m.Show()
	}
}

var hideItem = func(m *systray.MenuItem) {
	if m != nil {
		m.Hide()
	}
}

var enableItem = func(m *systray.MenuItem) {
	if m != nil {
		m.Enable()
	}
}

// render mirrors one daemon state into the menu. A nil status means the daemon is stopped.
func (a *app) render(s *control.Status) {
	a.renderState(s, false)
}

func (a *app) renderUnreachable() {
	a.renderState(nil, true)
}

// Only ever updates or hides existing items: systray cannot remove an item, so a menu rebuilt per update would
// accumulate rows forever.
func (a *app) renderState(s *control.Status, unreachable bool) {
	// One render at a time, start to finish. render is reachable from the event watcher AND from every action
	// goroutine (via refresh), and it assigns a LABEL and a CONNECTION STRING to each row in separate steps —
	// so two interleaved renders could leave a row displaying one datasource while its click copied another
	// one's credentials. Guarding only the status field would not prevent that.
	a.renderMu.Lock()
	defer a.renderMu.Unlock()

	a.mu.Lock()
	a.status = s
	a.unreachable = unreachable
	a.mu.Unlock()

	switch {
	case unreachable:
		a.renderUnreachableState()
	case s == nil:
		a.renderStopped()
	case !s.LoggedIn:
		a.renderIdle(s)
	default:
		a.renderLoggedIn(s)
	}
}

func (a *app) renderUnreachableState() {
	if a.mHeader != nil {
		systray.SetTooltip("proxy-monster — daemon needs restart")
	}
	setTitleOf(a.mHeader, "daemon needs restart")
	setTitleOf(a.mDetail, "control socket unreachable")
	showItem(a.mDetail)
	a.hideDatasourcesFrom(0)

	hideItem(a.mLogin)
	hideItem(a.mLogout)
	hideItem(a.mStart)
	showItem(a.mRestart)
	enableItem(a.mRestart)
	showItem(a.mStop)
	enableItem(a.mStop)
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
	expiry := expiryText(s.ExpiresAt)
	if s.ReauthRequired {
		if a.mHeader != nil {
			systray.SetTooltip("proxy-monster — re-authentication required")
		}
		setTitleOf(a.mHeader, fmt.Sprintf("%s — session expired", s.Principal))
		setTitleOf(a.mLogin, "Re-authenticate…")
	} else {
		if a.mHeader != nil {
			systray.SetTooltip(fmt.Sprintf("proxy-monster — %s", s.Principal))
		}
		setTitleOf(a.mHeader, fmt.Sprintf("%s — %s", s.Principal, expiry))
		setTitleOf(a.mLogin, "Re-authenticate…")
	}
	enableItem(a.mLogin)
	showItem(a.mLogout)
	hideItem(a.mStart)
	showItem(a.mRestart)
	showItem(a.mStop)

	// A discovery failure is surfaced rather than left to look like "you have no datasources".
	if s.LastDiscoveryError != "" {
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

	used := 0
	for _, ds := range s.Datasources {
		if used >= shown {
			break
		}
		row := a.dsItems[used]
		if ds.Brokered {
			label := fmt.Sprintf("%s  ·  127.0.0.1:%d", ds.Name, ds.LocalPort)
			if ds.LiveConns > 0 {
				label += fmt.Sprintf("  (%d)", ds.LiveConns)
			}
			row.set(ds.Name, conn.String(conn.URL, conn.Target{
				Engine:   ds.Engine,
				DbName:   ds.DbName,
				Port:     ds.LocalPort,
				User:     s.Principal,
				Password: s.LocalPassword,
			}))
			row.setTitle(label)
			row.enable()
		} else {
			row.set(ds.Name, "")
			row.setTitle(fmt.Sprintf("%s  ·  %s", ds.Name, ds.Reason))
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
