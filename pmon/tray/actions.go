package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

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
			notify(T("n.copyFailed"), err.Error())
			return
		}
		notify(T("n.copied"), T("n.copiedBody", "label", act.label))
	case opStart:
		a.doStart()
	case opRestart:
		a.doRestart()
	case opLoginItem:
		a.toggleLoginItem()
	case opQuit:
		a.doQuit()
	case opAIApp:
		a.doAIApp(act)
	case opPrefs:
		a.openPreferences(false)
	case opAddServer:
		a.openPreferences(true)
	}
}

func busy() { notify("Proxy Monster", T("n.busy")) }

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
		notify(T("n.startFailed"), err.Error())
		return
	}
	a.setSigningIn(server, true)
	defer a.setSigningIn(server, false)
	if err := signInFlow(a.ctx, client, server); err != nil {
		notify(T("n.signInFailed"), err.Error())
		return
	}
	a.refresh(client)
}

// signInFlow runs one server's device sign-in: the browser opens the prefilled verification page, and the
// outcome arrives as a notification. Shared by the menu and the Settings window.
func signInFlow(ctx context.Context, client *control.Client, server string) error {
	return client.Login(ctx, control.LoginRequest{Server: server}, func(ev control.LoginEvent) {
		switch ev.Kind {
		case "prompt":
			code := ""
			if ev.UserCode != "" {
				code = T("n.signInCode", "code", ev.UserCode)
			}
			title := T("n.signInTo", "server", server)
			// The daemon may run on another host than this menu bar, so a link that fails to open here goes to
			// the clipboard, where the user can reach it.
			if openURL(ev.VerificationURIComplete) == nil {
				notify(title, T("n.signInBrowser")+code)
			} else if copyToClipboard(ev.VerificationURI) == nil {
				notify(title, T("n.signInClipboard")+code)
			} else {
				notify(title, T("n.signInOpen", "url", ev.VerificationURI)+code)
			}
		case "done":
			notify(T("n.signedIn"), T("n.signedInBody", "server", server, "principal", ev.Principal))
			openAtLoginOnce()
		}
	})
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
	if !a.confirmDroppingConns("signOut", server) {
		return
	}
	notEnded, err := client.Logout(a.ctx, control.LogoutRequest{Server: server})
	if err != nil {
		notify(T("n.signOutFailed"), err.Error())
		return
	}
	if len(notEnded) > 0 {
		notify(T("n.signedOutLocal"), T("n.signedOutLocalBody", "server", server))
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
		notify(T("n.startFailed"), err.Error())
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

	if !a.confirmDroppingConns("restart", "") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		notify(T("n.restartFailed"), err.Error())
		return
	}
	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify(T("n.restartFailed"), err.Error())
		a.render(nil)
		return
	}
	a.refresh(client)
}

func (a *app) toggleLoginItem() {
	on, _ := loginItem()
	if err := setLoginItem(!on); err != nil {
		notify(T("n.loginItemFailed"), err.Error())
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
	if !a.confirmDroppingConns("quit", "") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		// Quitting is meant to stop the daemon; if that failed the daemon is still brokering. A menu-bar app has
		// no stderr to read, so say so where the user will see it — otherwise the menu vanishes and a daemon
		// keeps running with no indication.
		a.setErr(fmt.Errorf("could not stop the daemon: %w", err))
		notify(T("n.stillRunning"), T("n.stillRunningBody", "error", err.Error()))
	}
	systray.Quit()
}

// confirmDroppingConns asks before an action that would cut live database sessions, on one server or (with
// server empty) all of them. The daemon is shared — the CLI may have started it, another window may be
// mid-query — so the honest guard is telling the user what breaks, exactly as `pmon stop` does.
// It asks the DAEMON for the count rather than trusting the last render: the cached status can be stale, and a
// stale nil would silently skip the dialog and drop someone's in-flight query. Only a daemon that is genuinely
// unreachable — nothing to disturb — proceeds without asking.
func (a *app) confirmDroppingConns(kind, server string) bool { return confirmDrop(a.ctx, kind, server) }

// confirmDrop's kind is "signOut", "restart", "quit" or "remove"; it picks the dialog's title and button.
func confirmDrop(ctx context.Context, kind, server string) bool {
	client, err := control.Connect(ctx)
	if err != nil {
		return true
	}
	s, err := client.Status(ctx)
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
	return confirm(T("confirm."+kind, "name", server), Tn("confirm.conns", n), T("confirm."+kind+"Button"))
}

// openPreferences opens the Settings window, or brings the open one to the front.
func (a *app) openPreferences(add bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.prefsPid != 0 {
		activatePid(a.prefsPid)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		notify(T("n.settingsFailed"), err.Error())
		return
	}
	args := []string{"--preferences"}
	if add {
		args = append(args, "--add")
	}
	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		notify(T("n.settingsFailed"), err.Error())
		return
	}
	a.prefsPid = cmd.Process.Pid
	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		a.prefsPid = 0
		a.mu.Unlock()
	}()
}
