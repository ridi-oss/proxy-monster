package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/singleinstance"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

func acquireDaemonLock(t *testing.T) *singleinstance.Daemon {
	t.Helper()
	if _, err := state.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	instance, err := state.DaemonInstance()
	if err != nil {
		t.Fatalf("DaemonInstance: %v", err)
	}
	lock, acquired, err := instance.Acquire(context.Background())
	if err != nil || !acquired {
		t.Fatalf("Acquire = %t, %v; want true, nil", acquired, err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return lock
}

// The menu-item plumbing is macOS-only, so these tests exercise the row-assignment model directly: what a row
// DISPLAYS and what it COPIES must always describe the same datasource. That pairing is the security-relevant
// part — a mismatch hands a user another datasource's credentials.

// newTestApp builds an app with the row pool but no systray, so row bookkeeping can be tested off-screen.
func newTestApp(rows int) *app {
	a := &app{ctx: context.Background()}
	for range rows {
		a.dsItems = append(a.dsItems, &dsItem{})
	}
	return a
}

func statusWith(names ...string) *control.Status {
	s := &control.Status{Principal: "you@example.com", LoggedIn: true, LocalPassword: "pw"}
	for i, n := range names {
		s.Datasources = append(s.Datasources, control.Datasource{
			Name: n, Engine: "mysql", DbName: n + "_db", LocalPort: 6100 + i, Brokered: true,
		})
	}
	return s
}

type statusBackend struct {
	status control.Status
}

func (backend statusBackend) Status() control.Status {
	return backend.status
}

func (statusBackend) Login(context.Context, control.LoginRequest, func(control.LoginEvent)) error {
	return nil
}

func (statusBackend) Logout() error {
	return nil
}

func (statusBackend) Reload() {}

func (statusBackend) Subscribe() (<-chan control.Event, func()) {
	return nil, func() {}
}

func (statusBackend) Shutdown() {}

func TestUnreachableDaemonShowsRecoveryActions(t *testing.T) {
	originalSetTitle := setTitleOf
	originalShow := showItem
	originalHide := hideItem
	originalEnable := enableItem
	t.Cleanup(func() {
		setTitleOf = originalSetTitle
		showItem = originalShow
		hideItem = originalHide
		enableItem = originalEnable
	})

	a := newTestApp(2)
	a.mDetail = new(systray.MenuItem)
	a.mLogin = new(systray.MenuItem)
	a.mLogout = new(systray.MenuItem)
	a.mStart = new(systray.MenuItem)
	a.mRestart = new(systray.MenuItem)
	a.mStop = new(systray.MenuItem)

	titles := make(map[*systray.MenuItem]string)
	visible := map[*systray.MenuItem]bool{
		a.mLogin: true, a.mLogout: true, a.mStart: true,
	}
	enabled := make(map[*systray.MenuItem]bool)
	setTitleOf = func(item *systray.MenuItem, title string) {
		if item != nil {
			titles[item] = title
		}
	}
	showItem = func(item *systray.MenuItem) { visible[item] = true }
	hideItem = func(item *systray.MenuItem) { visible[item] = false }
	enableItem = func(item *systray.MenuItem) { enabled[item] = true }

	a.renderUnreachable()

	if titles[a.mDetail] != "control socket unreachable" || !visible[a.mDetail] {
		t.Errorf("detail = %q visible=%t", titles[a.mDetail], visible[a.mDetail])
	}
	for name, item := range map[string]*systray.MenuItem{
		"login": a.mLogin, "logout": a.mLogout, "start": a.mStart,
	} {
		if visible[item] {
			t.Errorf("%s action is visible while the daemon needs restart", name)
		}
	}
	for name, item := range map[string]*systray.MenuItem{"restart": a.mRestart, "stop": a.mStop} {
		if !visible[item] || !enabled[item] {
			t.Errorf("%s action visible=%t enabled=%t", name, visible[item], enabled[item])
		}
	}
}

func TestRecoveredStatesShowLoginAfterUnreachable(t *testing.T) {
	originalSetTitle := setTitleOf
	originalShow := showItem
	originalHide := hideItem
	originalEnable := enableItem
	t.Cleanup(func() {
		setTitleOf = originalSetTitle
		showItem = originalShow
		hideItem = originalHide
		enableItem = originalEnable
	})

	a := newTestApp(1)
	a.mLogin = new(systray.MenuItem)
	visible := true
	setTitleOf = func(*systray.MenuItem, string) {}
	showItem = func(item *systray.MenuItem) {
		if item == a.mLogin {
			visible = true
		}
	}
	hideItem = func(item *systray.MenuItem) {
		if item == a.mLogin {
			visible = false
		}
	}
	enableItem = func(*systray.MenuItem) {}

	states := map[string]*control.Status{
		"stopped":   nil,
		"idle":      {},
		"logged-in": {LoggedIn: true, Principal: "you@example.com"},
	}
	for name, status := range states {
		t.Run(name, func(t *testing.T) {
			a.renderUnreachable()
			if visible {
				t.Fatal("Login is visible in the unreachable state")
			}
			a.render(status)
			if !visible {
				t.Fatal("Login stayed hidden after recovery")
			}
		})
	}
}

func TestUnreachableDaemonIsDistinctFromStopped(t *testing.T) {
	a := newTestApp(2)
	a.render(statusWith("acme"))
	a.renderUnreachable()

	a.mu.Lock()
	unreachable, status := a.unreachable, a.status
	a.mu.Unlock()
	if !unreachable || status != nil {
		t.Fatalf("unreachable render stored unreachable=%t status=%v", unreachable, status)
	}
	if a.dsItems[0].name != "" || a.dsItems[0].connString != "" {
		t.Errorf("unreachable render retained datasource state: %+v", a.dsItems[0])
	}

	a.render(nil)
	a.mu.Lock()
	unreachable = a.unreachable
	a.mu.Unlock()
	if unreachable {
		t.Error("stopped render retained the unreachable state")
	}
}

func TestControlErrorsRenderStoppedOnlyWhenDaemonIsKnownAbsent(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	a := newTestApp(1)
	a.renderControlError(errors.New("could not inspect daemon lock"))

	a.mu.Lock()
	unreachable := a.unreachable
	a.mu.Unlock()
	if !unreachable {
		t.Error("an unknown daemon-state error rendered as stopped")
	}

	a.renderControlError(control.ErrDaemonNotRunning)
	a.mu.Lock()
	unreachable = a.unreachable
	a.mu.Unlock()
	if unreachable {
		t.Error("ErrDaemonNotRunning rendered as unreachable")
	}
}

func TestDisconnectRendersStoppedOnlyAfterPidLockReleased(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	lock := acquireDaemonLock(t)

	a := newTestApp(1)
	a.render(statusWith("acme"))
	a.renderAfterDisconnect(false)

	a.mu.Lock()
	unreachable := a.unreachable
	a.mu.Unlock()
	if !unreachable {
		t.Error("a disconnected daemon holding the pid lock rendered as stopped")
	}

	a.render(statusWith("acme"))
	a.renderControlError(control.ErrDaemonNotRunning)
	a.mu.Lock()
	unreachable = a.unreachable
	a.mu.Unlock()
	if !unreachable {
		t.Error("a dial failure with the pid lock held rendered as stopped")
	}

	if err := lock.Close(); err != nil {
		t.Fatalf("release daemon lock: %v", err)
	}
	a.renderControlError(control.ErrDaemonNotRunning)

	a.mu.Lock()
	unreachable, status := a.unreachable, a.status
	a.mu.Unlock()
	if unreachable || status != nil {
		t.Errorf("released daemon rendered unreachable=%t status=%v; want stopped", unreachable, status)
	}
}

func TestDisconnectKeepsHealthyReplacementVisible(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	acquireDaemonLock(t)
	replacement := statusWith("replacement")
	server, err := control.Listen(statusBackend{status: *replacement})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		server.Close()
		<-done
	})

	a := newTestApp(1)
	a.render(statusWith("old"))
	a.renderAfterDisconnect(false)

	a.mu.Lock()
	unreachable, status := a.unreachable, a.status
	a.mu.Unlock()
	if unreachable || status == nil || len(status.Datasources) != 1 || status.Datasources[0].Name != "replacement" {
		t.Errorf("healthy replacement rendered unreachable=%t status=%v", unreachable, status)
	}
}

func TestShutdownDisconnectWaitsForPidLockRelease(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	lock := acquireDaemonLock(t)

	a := newTestApp(1)
	a.render(statusWith("acme"))
	done := make(chan struct{})
	go func() {
		a.renderAfterDisconnect(true)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("shutdown disconnect rendered before the pid lock was released")
	case <-time.After(50 * time.Millisecond):
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release daemon lock: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown disconnect did not render after the pid lock was released")
	}

	a.mu.Lock()
	unreachable, status := a.unreachable, a.status
	a.mu.Unlock()
	if unreachable || status != nil {
		t.Errorf("clean shutdown rendered unreachable=%t status=%v; want stopped", unreachable, status)
	}
}

// TestConcurrentRendersNeverLeaveAMixedPool is the invariant serializing renders exists for. render is reachable
// from the event watcher AND from every action goroutine, and it walks the row pool writing the new set then
// clearing the tail. Unserialized, two renders interleave so one clears the tail before the other has written
// it — leaving a pool like [zulu yankee delta echo], a datasource list that never existed on any daemon. The
// user would then see, and be able to copy credentials for, a set that is not the real state.
func TestConcurrentRendersNeverLeaveAMixedPool(t *testing.T) {
	a := newTestApp(8)
	setA := statusWith("alpha", "bravo", "charlie", "delta", "echo")
	setB := statusWith("zulu", "yankee")

	for attempt := range 4000 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); a.render(setA) }()
		go func() { defer wg.Done(); a.render(setB) }()
		wg.Wait()

		var names []string
		for _, row := range a.dsItems {
			row.mu.Lock()
			name, conn := row.name, row.connString
			row.mu.Unlock()
			if name == "" {
				continue
			}
			names = append(names, name)
			// Each row must also carry ITS OWN datasource's payload, never a neighbour's credentials.
			if conn != "" && !strings.Contains(conn, name+"_db") {
				t.Fatalf("row labeled %q carries a connection string for another datasource: %q", name, conn)
			}
		}
		// The settled pool must be exactly one of the two real sets.
		isA := len(names) == 5 && names[0] == "alpha"
		isB := len(names) == 2 && names[0] == "zulu"
		if !isA && !isB {
			t.Fatalf("attempt %d left a pool that never existed on any daemon: %v", attempt, names)
		}
	}
}

// TestUnbrokeredRowCarriesNoPayload: a row for a datasource that is not brokered (Postgres, no advertised
// address) must be un-clickable rather than copying an empty or bogus string.
func TestUnbrokeredRowCarriesNoPayload(t *testing.T) {
	a := newTestApp(4)
	s := &control.Status{Principal: "you@example.com", LoggedIn: true, LocalPassword: "pw"}
	s.Datasources = []control.Datasource{
		{Name: "pg", Engine: "postgres", Brokered: false, Reason: "postgres brokering not yet supported"},
	}
	a.applyRows(s)

	if a.dsItems[0].name != "pg" {
		t.Fatalf("row 0 = %q, want pg", a.dsItems[0].name)
	}
	if a.dsItems[0].connString != "" {
		t.Errorf("unbrokered row carries a payload %q; a click must copy nothing", a.dsItems[0].connString)
	}
}

// TestOverflowSpendsTheLastRowOnANotice: the pool is fixed, so a larger set must stop somewhere — with the last
// row spent saying how many are hidden, never silently truncated into a list that reads as complete. The count
// must add up: rows shown + "and N more" == the real total.
func TestOverflowSpendsTheLastRowOnANotice(t *testing.T) {
	a := newTestApp(4)
	a.applyRows(statusWith("a", "b", "c", "d", "e", "f"))

	// Rows 0..2 carry datasources; row 3 is the notice, with no payload so a click copies nothing.
	var named []string
	for i := range 3 {
		if n := a.dsItems[i].name; n != "" {
			named = append(named, n)
		}
	}
	if len(named) != 3 || named[0] != "a" || named[2] != "c" {
		t.Errorf("rows = %v, want the first three datasources", named)
	}
	notice := a.dsItems[3]
	if notice.name != "" || notice.connString != "" {
		t.Errorf("the overflow notice carries a payload (name=%q conn=%q); it must not be clickable",
			notice.name, notice.connString)
	}

	// Exactly as many datasources as rows: every one is shown, no row spent on a notice.
	b := newTestApp(4)
	b.applyRows(statusWith("a", "b", "c", "d"))
	for i, want := range []string{"a", "b", "c", "d"} {
		if got := b.dsItems[i].name; got != want {
			t.Errorf("row %d = %q, want %q (a set that fits must not lose a row to the notice)", i, got, want)
		}
	}
}
