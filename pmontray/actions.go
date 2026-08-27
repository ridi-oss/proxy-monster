package main

import (
	"context"
	"errors"
	"fmt"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

var (
	connectForConfirmation       = control.Connect
	statusForConfirmation        = (*control.Client).Status
	daemonRunningForConfirmation = daemonIsRunning
	confirmConnectionDrop        = confirmDialog
)

func daemonIsRunning(ctx context.Context) (bool, error) {
	instance, err := state.DaemonInstance()
	if err != nil {
		return false, err
	}
	return instance.Client().Running(ctx)
}

// The tray's actions. Each is the SAME control-API call `pmon` makes — no privileged path, no tray-only
// behavior — so the two front ends cannot diverge in what they do or in what they protect.

// doLogin starts the daemon if needed, then asks IT to run the device-auth flow. The verification prompt is
// streamed back, so the browser opens and the user code reaches a notification rather than a terminal.
func (a *app) doLogin() {
	// Serialize only the DAEMON-START half. The device flow that follows runs for as long as the control plane's
	// device TTL (~10 min) if the user never finishes in the browser, and holding a plain mutex across it would
	// block Quit, Stop, Restart and Logout for that whole window — a mutex is not context-aware, so cancelling
	// a.ctx would not free it either. The daemon serializes concurrent logins itself, so nothing here needs to.
	if !a.tryLockAction() {
		notify("proxy-monster", "another action is still in progress")
		return
	}
	client, err := control.EnsureDaemon(a.ctx)
	a.unlockAction()
	if err != nil {
		a.renderControlError(err)
		notify("proxy-monster", fmt.Sprintf("could not start the daemon: %v", err))
		return
	}
	err = client.Login(a.ctx, control.LoginRequest{}, func(ev control.LoginEvent) {
		switch ev.Kind {
		case "prompt":
			// The DAEMON runs the flow, and it may be on a different host than this menu bar (remote over a
			// tailnet) — so a browser it "opened" is on that host and useless here. Always put the URL somewhere
			// the user can actually reach: the clipboard, since a notification cannot be copied from. Treat
			// ev.Opened as a hint for the wording only, never as proof the user has the page.
			copied := copyToClipboard(ev.VerificationURI) == nil
			switch {
			case copied && ev.UserCode != "":
				notify("proxy-monster", fmt.Sprintf("sign-in URL copied — open it and enter %s", ev.UserCode))
			case copied:
				notify("proxy-monster", "sign-in URL copied — open it to finish logging in")
			case ev.UserCode != "":
				notify("proxy-monster", fmt.Sprintf("open %s and enter %s", ev.VerificationURI, ev.UserCode))
			default:
				notify("proxy-monster", fmt.Sprintf("open %s to finish logging in", ev.VerificationURI))
			}
		case "done":
			notify("proxy-monster", fmt.Sprintf("signed in as %s", ev.Principal))
		}
	})
	if err != nil {
		notify("proxy-monster", fmt.Sprintf("login failed: %v", err))
		return
	}
	a.refresh(client)
}

func (a *app) doLogout() {
	if !a.tryLockAction() {
		notify("proxy-monster", "another action is still in progress")
		return
	}
	defer a.unlockAction()

	client, err := control.Connect(a.ctx)
	if errors.Is(err, control.ErrDaemonUnreachable) {
		a.renderUnreachable()
		notify("proxy-monster", "the daemon control socket is unreachable — restart it before logging out")
		return
	}
	if errors.Is(err, control.ErrDaemonNotRunning) {
		a.render(nil)
		return
	}
	if err != nil {
		a.renderControlError(err)
		notify("proxy-monster", fmt.Sprintf("could not read the daemon status: %v", err))
		return
	}
	// Logging out closes the brokers, which drops live sessions — the same warning the CLI gives.
	if !a.confirmDroppingConns("Log out") {
		return
	}
	if err := client.Logout(a.ctx); err != nil {
		notify("proxy-monster", fmt.Sprintf("logout failed: %v", err))
		return
	}
	a.refresh(client)
}

func (a *app) doStart() {
	if !a.tryLockAction() {
		notify("proxy-monster", "another action is still in progress")
		return
	}
	defer a.unlockAction()

	if _, err := control.Connect(a.ctx); err == nil {
		return // already running; the watcher will have rendered it
	}
	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		a.renderControlError(err)
		notify("proxy-monster", fmt.Sprintf("could not start the daemon: %v", err))
		return
	}
	a.refresh(client)
}

func (a *app) doRestart() {
	if !a.tryLockAction() {
		notify("proxy-monster", "another action is still in progress")
		return
	}
	defer a.unlockAction()

	if !a.confirmDroppingConns("Restart") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil &&
		!errors.Is(err, control.ErrDaemonNotRunning) &&
		!errors.Is(err, control.ErrDaemonReplaced) {
		a.renderControlError(err)
		notify("proxy-monster", fmt.Sprintf("could not stop the daemon: %v", err))
		return
	}
	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify("proxy-monster", fmt.Sprintf("could not restart the daemon: %v", err))
		a.renderControlError(err)
		return
	}
	a.refresh(client)
}

func (a *app) doStop() {
	if !a.tryLockAction() {
		notify("proxy-monster", "another action is still in progress")
		return
	}
	defer a.unlockAction()

	if !a.confirmDroppingConns("Stop") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		a.renderControlError(err)
		notify("proxy-monster", fmt.Sprintf("could not stop the daemon: %v", err))
		return
	}
	a.render(nil)
}

// doQuit stops the daemon and exits — quitting the menu bar is an explicit stop, the peer of `pmon stop`.
// Closing the menu is not: that is a non-event, matching a CLI command simply returning.
func (a *app) doQuit() {
	// Quit is NOT gated on the action lock: quitting must always work, even while another action is mid-flight,
	// or a wedged menu becomes unquittable.
	if !a.confirmDroppingConns("Quit") {
		return
	}
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		// The tray has no visible stderr, so report a daemon left running before it exits.
		a.setErr(fmt.Errorf("could not stop the daemon: %w", err))
		notify("proxy-monster", fmt.Sprintf("quitting, but the daemon is still running: %v — stop it with `pmon stop`", err))
	}
	systray.Quit()
}

// confirmDroppingConns reads live status before warning because the tray's cached status may be stale.
func (a *app) confirmDroppingConns(action string) bool {
	client, err := connectForConfirmation(a.ctx)
	if errors.Is(err, control.ErrDaemonNotRunning) {
		return true
	}
	if err != nil {
		return confirmConnectionDrop(
			fmt.Sprintf("%s proxy-monster?", action),
			"The daemon status cannot be read, so active database connections cannot be checked.",
			action,
		)
	}
	s, err := statusForConfirmation(client, a.ctx)
	if errors.Is(err, control.ErrDaemonNotRunning) {
		running, runningErr := daemonRunningForConfirmation(a.ctx)
		if runningErr == nil && !running {
			return true
		}
	}
	if err != nil {
		return confirmConnectionDrop(
			fmt.Sprintf("%s proxy-monster?", action),
			"The daemon status cannot be read, so active database connections cannot be checked.",
			action,
		)
	}
	n := s.TotalLiveConns()
	if n == 0 {
		return true
	}
	return confirmConnectionDrop(
		fmt.Sprintf("%s proxy-monster?", action),
		fmt.Sprintf("%d active database connection(s) will be dropped.", n),
		action,
	)
}
