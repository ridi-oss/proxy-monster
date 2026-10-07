package main

/*
#include <stdbool.h>
#include "updater_darwin.h"
*/
import "C"

// onUpdateReady receives the version of an update held for installUpdate; interactive is the user's Install
// and Relaunch in Sparkle's window rather than a background download.
var onUpdateReady func(version string, interactive bool)

//export goUpdateReady
func goUpdateReady(v *C.char, interactive C.bool) {
	if f := onUpdateReady; f != nil {
		go f(C.GoString(v), bool(interactive))
	}
}

func updatesConfigured() bool { return bool(C.pm_updates_configured()) }

// autoUpdates reports whether updates are checked for and downloaded on their own, and whether the
// organization has fixed that setting.
func autoUpdates() (on, forced bool) { return bool(C.pm_updates_auto()), bool(C.pm_updates_forced()) }

func startUpdater() bool { return bool(C.pm_updater_start()) }

func checkForUpdates() { C.pm_updater_check() }

func setAutoUpdatesNow(on bool) { C.pm_updater_set_auto(C.bool(on)) }

func installHeldUpdate() { C.pm_updater_install() }
