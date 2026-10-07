package main

import (
	"errors"
	"fmt"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// The tray's actions. Each is the SAME control-API call `pmon` makes — no privileged path, no tray-only
// behavior — so the two front ends cannot diverge in what they do or in what they protect.

func (a *app) run(act action) {
	switch act.op {
	case opSignIn:
		a.doSignIn(act.server)
	case opSignOut:
		a.doSignOut(act.server)
	case opCopy:
		if err := copyToClipboard(act.payload); err != nil {
			notify("Couldn't copy", err.Error())
			return
		}
		notify("Copied", "The "+act.label+" is on the clipboard.")
	case opStart:
		a.doStart()
	case opRestart:
		a.doRestart()
	case opLoginItem:
		a.toggleLoginItem()
	case opQuit:
		a.doQuit()
	}
}

func busy() { notify("Proxy Monster", "Another action is still running. Try again in a moment.") }

// doSignIn starts the daemon if needed, then asks IT to run the device-auth flow. The verification prompt is
// streamed back, so the browser opens and the user code reaches a notification rather than a terminal.
func (a *app) doSignIn(server string) {
	// Serialize only the DAEMON-START half. The device flow that follows runs for as long as the control plane's
	// device TTL (~10 min) if the user never finishes in the browser, and holding a plain mutex across it would
	// block Quit and Sign Out for that whole window — a mutex is not context-aware, so cancelling a.ctx would
	// not free it either. The daemon serializes concurrent logins itself, so nothing here needs to.
	if !a.tryLockAction() {
		busy()
		return
	}
	client, err := control.EnsureDaemon(a.ctx)
	a.unlockAction()
	if err != nil {
		notify("Couldn't start Proxy Monster", err.Error())
		return
	}
	a.setSigningIn(server, true)
	defer a.setSigningIn(server, false)
	err = client.Login(a.ctx, control.LoginRequest{Server: server}, func(ev control.LoginEvent) {
		switch ev.Kind {
		case "prompt":
			code := ""
			if ev.UserCode != "" {
				code = " The code is " + ev.UserCode + "."
			}
			if openURL(ev.VerificationURIComplete) == nil {
				notify("Sign in to "+server, "Finish in your browser."+code)
			} else if copyToClipboard(ev.VerificationURI) == nil {
				notify("Sign in to "+server, "The sign-in link is on the clipboard. Open it in your browser."+code)
			} else {
				notify("Sign in to "+server, "Open "+ev.VerificationURI+" in your browser."+code)
			}
		case "done":
			notify("Signed in", fmt.Sprintf("Signed in to %s as %s.", server, ev.Principal))
		}
	})
	if err != nil {
		notify("Sign-in failed", err.Error())
		return
	}
	openAtLoginOnce()
	a.refresh(client)
}

func (a *app) doSignOut(server string) {
	if !a.tryLockAction() {
		busy()
		return
	}
	defer a.unlockAction()

	client, err := control.Connect(a.ctx)
	if err != nil {
		a.render(nil)
		return
	}
	// Signing out closes the brokers, which drops live sessions — the same warning the CLI gives.
	if !a.confirmDroppingConns("Sign Out", server) {
		return
	}
	notEnded, err := client.Logout(a.ctx, control.LogoutRequest{Server: server})
	if err != nil {
		notify("Sign-out failed", err.Error())
		return
	}
	if len(notEnded) > 0 {
		notify("Signed out on this Mac", fmt.Sprintf("The server could not end the %s sign-in. It ends on its own when it expires.", server))
	}
	a.refresh(client)
}

func (a *app) doStart() {
	if !a.tryLockAction() {
		busy()
		return
	}
	defer a.unlockAction()

	if _, err := control.Connect(a.ctx); err == nil {
		return // already running; the watcher will have rendered it
	}
	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify("Couldn't start Proxy Monster", err.Error())
		return
	}
	a.refresh(client)
}

func (a *app) doRestart() {
	if !a.tryLockAction() {
		busy()
		return
	}
	defer a.unlockAction()

	if !a.confirmDroppingConns("Restart", "") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		notify("Couldn't restart", err.Error())
		return
	}
	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify("Couldn't restart", err.Error())
		a.render(nil)
		return
	}
	a.refresh(client)
}

func (a *app) toggleLoginItem() {
	on, _ := loginItem()
	if err := setLoginItem(!on); err != nil {
		notify("Couldn't change Open at Login", err.Error())
	}
	setPrefBool(openAtLoginDecided, true)
	a.renderMu.Lock()
	a.redraw()
	a.renderMu.Unlock()
}

// doQuit stops the daemon and exits — quitting the menu bar is an explicit stop, the peer of `pmon stop`.
// Closing the menu is not: that is a non-event, matching a CLI command simply returning.
func (a *app) doQuit() {
	// Quit is NOT gated on the action lock: quitting must always work, even while another action is mid-flight,
	// or a wedged menu becomes unquittable.
	if !a.confirmDroppingConns("Quit", "") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		// Quitting is meant to stop the daemon; if that failed the daemon is still brokering. A menu-bar app has
		// no stderr to read, so say so where the user will see it — otherwise the menu vanishes and a daemon
		// keeps running with no indication.
		a.setErr(fmt.Errorf("could not stop the daemon: %w", err))
		notify("Proxy Monster is still running", fmt.Sprintf("%v. Stop it with `pmon stop`.", err))
	}
	systray.Quit()
}

// confirmDroppingConns asks before an action that would cut live database sessions, on one server or (with
// server empty) all of them. The daemon is shared — the CLI may have started it, another window may be
// mid-query — so the honest guard is telling the user what breaks, exactly as `pmon stop` does.
// It asks the DAEMON for the count rather than trusting the last render: the cached status can be stale, and a
// stale nil would silently skip the dialog and drop someone's in-flight query. Only a daemon that is genuinely
// unreachable — nothing to disturb — proceeds without asking.
func (a *app) confirmDroppingConns(verb, server string) bool {
	client, err := control.Connect(a.ctx)
	if err != nil {
		return true
	}
	s, err := client.Status(a.ctx)
	if err != nil {
		return true
	}
	n := 0
	for _, ds := range s.Datasources {
		if server == "" || ds.Server == server {
			n += ds.LiveConns
		}
	}
	if n == 0 {
		return true
	}
	return confirmDialog(verb+"?", fmt.Sprintf("%s will be closed.", plural(n, "open database connection")), verb)
}
