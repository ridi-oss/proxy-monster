package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// reconnectDelay is how long to wait before re-subscribing after the event stream drops. The stream ending is
// the normal signal that the daemon stopped, so this is a poll for "did it come back", not an error path.
const reconnectDelay = 2 * time.Second

// maxDatasourceItems bounds how many datasource rows the menu preallocates. Menu items cannot be removed once
// added (only hidden), so the set is built once and reused as state changes — a menu that grew per update would
// leak items on every refresh.
const maxDatasourceItems = 24

// app is the tray's whole runtime. It owns the menu items and mirrors daemon state into them; it never holds
// state the daemon does not have.
type app struct {
	ctx    context.Context
	cancel context.CancelFunc

	// renderMu serializes whole renders. A row's label and its copy-payload are set in separate steps, so
	// interleaved renders could pair one datasource's label with another's connection string.
	renderMu sync.Mutex

	// actionBusy serializes the lifecycle actions, so a double-click cannot run two conflicting changes at once.
	// A try-lock rather than a blocking mutex: an action that cannot run should say so and return, never queue
	// behind a long one (a device-auth flow runs for minutes) and leave the menu unresponsive.
	actionBusy sync.Mutex
	actionHeld bool

	mu          sync.Mutex
	status      *control.Status
	unreachable bool
	// dsItems are the reusable datasource rows, in a fixed order established at startup.
	dsItems []*dsItem

	// Fixed menu items.
	mHeader  *systray.MenuItem
	mDetail  *systray.MenuItem
	mLogin   *systray.MenuItem
	mLogout  *systray.MenuItem
	mStart   *systray.MenuItem
	mRestart *systray.MenuItem
	mStop    *systray.MenuItem
	mQuit    *systray.MenuItem

	errMu  sync.Mutex
	err    error
	exited bool
}

// dsItem is one datasource row: clicking it copies that datasource's connection string.
type dsItem struct {
	item *systray.MenuItem
	mu   sync.Mutex
	name string
	// connString is what a click copies; empty when the row is not currently a brokered datasource.
	connString string
}

func newApp(ctx context.Context) *app {
	ctx, cancel := context.WithCancel(ctx)
	return &app{ctx: ctx, cancel: cancel}
}

// tryLockAction claims the lifecycle lock without blocking, reporting whether it was free.
func (a *app) tryLockAction() bool {
	a.actionBusy.Lock()
	defer a.actionBusy.Unlock()
	if a.actionHeld {
		return false
	}
	a.actionHeld = true
	return true
}

func (a *app) unlockAction() {
	a.actionBusy.Lock()
	a.actionHeld = false
	a.actionBusy.Unlock()
}

func (a *app) setErr(err error) {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if a.err == nil {
		a.err = err
	}
}

func (a *app) exitErr() error {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.err
}

// onReady builds the menu once and starts the watcher. Menu items are created here and only ever updated or
// hidden afterwards, because systray cannot remove an item.
func (a *app) onReady() {
	systray.SetTemplateIcon(trayIcon, trayIcon)
	systray.SetTooltip("proxy-monster")

	a.mHeader = systray.AddMenuItem("connecting…", "")
	a.mHeader.Disable()
	a.mDetail = systray.AddMenuItem("", "")
	a.mDetail.Disable()
	a.mDetail.Hide()

	systray.AddSeparator()
	a.dsItems = make([]*dsItem, 0, maxDatasourceItems)
	for range maxDatasourceItems {
		item := systray.AddMenuItem("", "Copy this datasource's connection string")
		item.Hide()
		d := &dsItem{item: item}
		a.dsItems = append(a.dsItems, d)
		go a.watchCopy(d)
	}

	systray.AddSeparator()
	a.mLogin = systray.AddMenuItem("Log in…", "Authenticate in your browser")
	a.mLogout = systray.AddMenuItem("Log out", "Clear credentials and close the brokers")
	a.mStart = systray.AddMenuItem("Start daemon", "Start the pmon daemon")
	a.mRestart = systray.AddMenuItem("Restart daemon", "Restart the pmon daemon")
	a.mStop = systray.AddMenuItem("Stop daemon", "Stop the pmon daemon")
	systray.AddSeparator()
	a.mQuit = systray.AddMenuItem("Quit", "Stop the daemon and quit")

	go a.watchClicks()
	go a.watchDaemon()
}

func (a *app) onExit() {
	a.errMu.Lock()
	a.exited = true
	a.errMu.Unlock()
	a.cancel()
}

// watchClicks dispatches the fixed menu items. Each action is the same control-API call the CLI makes.
func (a *app) watchClicks() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.mLogin.ClickedCh:
			go a.doLogin()
		case <-a.mLogout.ClickedCh:
			go a.doLogout()
		case <-a.mStart.ClickedCh:
			go a.doStart()
		case <-a.mRestart.ClickedCh:
			go a.doRestart()
		case <-a.mStop.ClickedCh:
			go a.doStop()
		case <-a.mQuit.ClickedCh:
			go a.doQuit()
		}
	}
}

// watchCopy handles clicks on one datasource row.
func (a *app) watchCopy(d *dsItem) {
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-d.item.ClickedCh:
			d.mu.Lock()
			name, conn := d.name, d.connString
			d.mu.Unlock()
			if conn == "" {
				continue
			}
			if err := copyToClipboard(conn); err != nil {
				notify("proxy-monster", fmt.Sprintf("could not copy %s: %v", name, err))
				continue
			}
			notify("proxy-monster", fmt.Sprintf("copied the %s connection string", name))
		}
	}
}

// watchDaemon keeps the menu in sync with the daemon, and is also how the tray learns the daemon is gone.
//
// It deliberately does NOT start a daemon. A tray launching at login must not force one up — that is an
// explicit action (Start / Log in), symmetric with the CLI.
func (a *app) watchDaemon() {
	for {
		if err := a.ctx.Err(); err != nil {
			return
		}
		client, err := control.Connect(a.ctx)
		if err != nil {
			a.renderControlError(err)
			if !a.sleep(reconnectDelay) {
				return
			}
			continue
		}
		// The stream's first event is the current status, so the menu is correct as soon as it opens.
		shuttingDown := false
		streamErr := client.Events(a.ctx, func(ev control.Event) {
			switch ev.Kind {
			case "status":
				if ev.Status != nil {
					a.render(ev.Status)
				}
			case "reauth":
				a.refresh(client)
				notify("proxy-monster", "your session expired — log in again from the menu")
			case "shutdown":
				shuttingDown = true
			default:
				a.refresh(client)
			}
		})
		switch {
		case a.ctx.Err() != nil:
			return
		case shuttingDown:
			a.renderAfterDisconnect(true)
		case streamErr != nil && !errors.Is(streamErr, context.Canceled):
			a.renderControlError(streamErr)
		default:
			a.renderAfterDisconnect(false)
		}
		if !a.sleep(reconnectDelay) {
			return
		}
	}
}

// refresh re-reads /status, for an event whose payload does not carry it.
func (a *app) refresh(client *control.Client) {
	s, err := client.Status(a.ctx)
	if err != nil {
		a.renderControlError(err)
		return
	}
	a.render(s)
}

func (a *app) renderAfterDisconnect(shuttingDown bool) {
	deadline := time.Now()
	if shuttingDown {
		deadline = deadline.Add(reconnectDelay)
	}
	for {
		if a.ctx.Err() != nil {
			return
		}
		running, err := daemonIsRunning(a.ctx)
		if err != nil {
			a.renderUnreachable()
			return
		}
		if !running {
			a.render(nil)
			return
		}
		if !shuttingDown || time.Now().After(deadline) {
			if a.renderConnectedDaemon() {
				return
			}
			a.renderUnreachable()
			return
		}
		if !a.sleep(25 * time.Millisecond) {
			return
		}
	}
}

func (a *app) renderConnectedDaemon() bool {
	client, err := control.Connect(a.ctx)
	if err != nil {
		return false
	}
	status, err := client.Status(a.ctx)
	if err != nil {
		return false
	}
	a.render(status)
	return true
}

func (a *app) renderControlError(err error) {
	if errors.Is(err, control.ErrDaemonNotRunning) {
		a.renderAfterDisconnect(false)
		return
	}
	a.renderUnreachable()
}

// sleep waits d, returning false if the app is shutting down.
func (a *app) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-a.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
