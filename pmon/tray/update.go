package main

import (
	"errors"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// restartAfterUpdate marks that the app relaunched from an update, so the daemon the old build started is
// replaced by the new build's pmon.
const restartAfterUpdate = "restartDaemonAfterUpdate"

// updaterCanQuit and onUpdaterQuit are how an updater that runs its own installer (WinSparkle) asks to quit the
// app; Sparkle on macOS installs in place and uses neither.
var (
	updaterCanQuit func() bool
	onUpdaterQuit  func()
)

// installUpdate and autoInstall are replaceable in tests.
var (
	installUpdate = installHeldUpdate
	autoInstall   = func() bool { on, _ := autoUpdates(); return on }
)

// startUpdates starts the updater in release builds.
func (a *app) startUpdates() {
	// Set before the updater starts, which can call them at once.
	onUpdateReady = a.updateReady
	updaterCanQuit = a.canQuitForInstall
	onUpdaterQuit = a.quitForUpdate
	if !startUpdater() {
		return
	}
	a.mu.Lock()
	a.updates = true
	a.mu.Unlock()
	go func() {
		auto, _ := autoUpdates()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-a.appearance:
				// The Settings window writes the setting; the updater reschedules only when told.
				if on, _ := autoUpdates(); on != auto {
					auto = on
					setAutoUpdatesNow(on)
				}
			}
		}
	}()
}

func (a *app) updateReady(version string, interactive bool) {
	a.mu.Lock()
	a.pendingUpdate = version
	a.mu.Unlock()
	a.renderMu.Lock()
	a.redraw()
	a.renderMu.Unlock()
	if interactive {
		a.doInstallUpdate()
		return
	}
	a.installWhenIdle()
}

// installWhenIdle installs a held update while automatic updates are on and nothing would be interrupted: no
// database connection, and no sign-in here or in the Settings window. A `pmon login` in a terminal is not
// visible to the app.
func (a *app) installWhenIdle() {
	a.mu.Lock()
	pending := a.pendingUpdate != ""
	a.mu.Unlock()
	if !autoInstall() || !pending || !a.idle() || !a.tryLockAction() {
		return
	}
	defer a.unlockAction()
	a.install()
}

// doInstallUpdate is the menu's Install Update, which asks first when it would drop connections.
func (a *app) doInstallUpdate() {
	if !a.tryLockAction() {
		busy()
		return
	}
	defer a.unlockAction()
	if !a.confirmDroppingConns("update", "") {
		return
	}
	a.install()
}

// idle reports that an update would interrupt nothing: no database connection, and no sign-in here or in the
// Settings window.
func (a *app) idle() bool {
	a.mu.Lock()
	busy := len(a.signingIn) > 0 || a.prefsPid != 0
	a.mu.Unlock()
	return !busy && liveConns(a.ctx, "") == 0
}

// canQuitForInstall is whether an installer may replace the app now: no database connection and no sign-in
// here. The Settings window is closed by the quit, so it does not hold the install back.
func (a *app) canQuitForInstall() bool {
	a.mu.Lock()
	busy := len(a.signingIn) > 0
	a.mu.Unlock()
	return !busy && liveConns(a.ctx, "") == 0
}

// quitForUpdate quits for an installer that replaces the files in place (WinSparkle's MSI). The daemon stops
// too: Windows cannot replace a running pmon.exe. The relaunched app starts a new one when it is needed.
func (a *app) quitForUpdate() {
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		a.setErr(err)
	}
	a.mu.Lock()
	a.tellPrefs("quit")
	a.mu.Unlock()
	systray.Quit()
}

// quitForInstall is the installer asking the app to quit (Windows): it confirms before dropping connections,
// then quits as for an update.
func (a *app) quitForInstall() bool {
	if !confirmDrop(a.ctx, "update", "") {
		return false
	}
	a.quitForUpdate()
	return true
}

func (a *app) install() {
	setPrefBool(restartAfterUpdate, true)
	a.mu.Lock()
	a.tellPrefs("quit")
	a.mu.Unlock()
	installUpdate()
}

// finishUpdate restarts a daemon left by the build before an update, unless that would drop connections; the
// menu then offers the restart instead.
func (a *app) finishUpdate() {
	if !prefBool(restartAfterUpdate) {
		return
	}
	setPrefBool(restartAfterUpdate, false)
	client, err := control.Connect(a.ctx)
	if err != nil {
		return
	}
	s, err := client.Status(a.ctx)
	if err != nil || a.pmonVersion == "" || s.Version == a.pmonVersion || s.TotalLiveConns() > 0 {
		return
	}
	if !a.tryLockAction() {
		return
	}
	defer a.unlockAction()
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		return
	}
	if client, err := control.EnsureDaemon(a.ctx); err == nil {
		a.refresh(client)
	}
}
