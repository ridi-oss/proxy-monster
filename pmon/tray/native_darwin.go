package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework AppKit -framework Foundation -framework UserNotifications -framework ServiceManagement
#include <stdlib.h>
#include "native_darwin.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// onNotificationClick receives the key a clicked notification was posted with.
var onNotificationClick func(key string)

//export goNotificationClicked
func goNotificationClicked(key *C.char) {
	if f := onNotificationClick; f != nil {
		go f(C.GoString(key))
	}
}

var nativeNotifications = bool(C.pm_notifications_init())

// postNative shows a notification through the system, attributed to this app. It reports false when the
// process is not a bundled app, which has no notification identity.
func postNative(id, title, body, key string) bool {
	if !nativeNotifications {
		return false
	}
	cs := []*C.char{C.CString(id), C.CString(title), C.CString(body), C.CString(key)}
	defer func() {
		for _, s := range cs {
			C.free(unsafe.Pointer(s))
		}
	}()
	return bool(C.pm_notify(cs[0], cs[1], cs[2], cs[3]))
}

// loginItem reports whether the app opens at login, and whether this macOS and build can change it.
func loginItem() (on, supported bool) {
	switch C.pm_login_item_status() {
	case C.PM_LOGIN_ON:
		return true, true
	case C.PM_LOGIN_OFF:
		return false, true
	}
	return false, false
}

func setLoginItem(on bool) error {
	if msg := C.pm_set_login_item(C.bool(on)); msg != nil {
		defer C.free(unsafe.Pointer(msg))
		return errors.New(C.GoString(msg))
	}
	return nil
}

func activatePid(pid int) { C.pm_activate_pid(C.int(pid)) }

func prefBool(key string) bool {
	k := C.CString(key)
	defer C.free(unsafe.Pointer(k))
	return bool(C.pm_pref_bool(k))
}

func setPrefBool(key string, v bool) {
	k := C.CString(key)
	defer C.free(unsafe.Pointer(k))
	C.pm_set_pref_bool(k, C.bool(v))
}
