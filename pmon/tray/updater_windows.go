package main

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// feedURL and sparklePublicKey are stamped into release builds (-ldflags -X); without them there is no updater.
var feedURL, sparklePublicKey string

const policyKey = `Software\Policies\RIDI\Proxy Monster Desktop`

// winSparkle is WinSparkle.dll beside the executable, by full path so no other directory can supply it.
var winSparkle = func() *windows.LazyDLL {
	exe, err := os.Executable()
	if err != nil {
		return windows.NewLazyDLL("")
	}
	return windows.NewLazyDLL(filepath.Join(filepath.Dir(exe), "WinSparkle.dll"))
}()

func sparkle(name string) *windows.LazyProc { return winSparkle.NewProc(name) }

var onUpdateReady func(version string, interactive bool)

func updatesConfigured() bool { return feedURL != "" && winSparkle.Load() == nil }

// autoUpdates is the Settings switch, on unless turned off; a machine policy value AutoUpdate fixes it.
func autoUpdates() (on, forced bool) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("AutoUpdate"); err == nil {
			return v != 0, true
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, prefsKey, registry.QUERY_VALUE)
	if err != nil {
		return true, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(prefAutoUpdates)
	return err != nil || v != 0, false
}

func startUpdater() bool {
	if !updatesConfigured() {
		return false
	}
	url, _ := windows.BytePtrFromString(feedURL)
	key, _ := windows.BytePtrFromString(sparklePublicKey)
	if r, _, _ := sparkle("win_sparkle_set_eddsa_public_key").Call(uintptr(unsafe.Pointer(key))); r == 0 {
		return false
	}
	sparkle("win_sparkle_set_appcast_url").Call(uintptr(unsafe.Pointer(url)))
	company, _ := windows.UTF16PtrFromString("RIDI")
	app, _ := windows.UTF16PtrFromString("Proxy Monster Desktop")
	ver, _ := windows.UTF16PtrFromString(version)
	sparkle("win_sparkle_set_app_details").Call(uintptr(unsafe.Pointer(company)), uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(ver)))
	sparkle("win_sparkle_set_can_shutdown_callback").Call(windows.NewCallbackCDecl(func() uintptr {
		if f := updaterCanQuit; f != nil && f() {
			return 1
		}
		return 0
	}))
	sparkle("win_sparkle_set_shutdown_request_callback").Call(windows.NewCallbackCDecl(func() uintptr {
		if f := onUpdaterQuit; f != nil {
			go f()
		}
		return 0
	}))
	on, _ := autoUpdates()
	setAutoUpdatesNow(on)
	return true
}

// checking is whether WinSparkle was started with automatic checks on: it creates its periodic checker only
// in win_sparkle_init, so turning them on later restarts it.
var checking, started bool

func stopUpdater() {
	if started {
		sparkle("win_sparkle_cleanup").Call()
		started = false
	}
}

func checkForUpdates() { sparkle("win_sparkle_check_update_with_ui").Call() }

func setAutoUpdatesNow(on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	sparkle("win_sparkle_set_automatic_check_for_updates").Call(v)
	if !started || (on && !checking) {
		stopUpdater()
		sparkle("win_sparkle_init").Call()
		started, checking = true, on
	}
}

// installHeldUpdate has nothing to do: WinSparkle runs the installer itself once the app agrees to quit.
func installHeldUpdate() {}
