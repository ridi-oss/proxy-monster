package main

import (
	"errors"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// restartAfterUpdate marks that the app relaunched from an update, so the daemon the old build started is
// replaced by the new build's pmon.
const restartAfterUpdate = "restartDaemonAfterUpdate"

// installUpdate and autoInstall are replaceable in tests.
var (
	installUpdate = installHeldUpdate
	autoInstall   = func() bool { on, _ := autoUpdates(); return on }
)

// startUpdates starts the updater in release builds.
func (a *app) startUpdates() {
	if !startUpdater() {
		return
	}
	a.mu.Lock()
	a.updates = true
	a.mu.Unlock()
	onUpdateReady = a.updateReady
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
	ready := a.pendingUpdate != "" && len(a.signingIn) == 0 && a.prefsPid == 0
	a.mu.Unlock()
	if !autoInstall() || !ready || liveConns(a.ctx, "") > 0 || !a.tryLockAction() {
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
