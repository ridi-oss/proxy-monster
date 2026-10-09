package main

import (
	"errors"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// confirmDialogTimeout bounds how long a confirmation waits for an answer. Its caller holds the action lock, so
// an indefinitely-open dialog would wedge every other lifecycle action.
const confirmDialogTimeout = 60 * time.Second

var confirm = confirmDialog

var notify = func(title, message string) { notifyAction("", title, message, "") }

const pmonName = "pmon.exe"

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	messageBoxTimeout = user32.NewProc("MessageBoxTimeoutW")
	openClipboard     = user32.NewProc("OpenClipboard")
	closeClipboard    = user32.NewProc("CloseClipboard")
	emptyClipboard    = user32.NewProc("EmptyClipboard")
	setClipboardData  = user32.NewProc("SetClipboardData")
	globalAlloc       = kernel32.NewProc("GlobalAlloc")
	globalLock        = kernel32.NewProc("GlobalLock")
	globalUnlock      = kernel32.NewProc("GlobalUnlock")
	globalFree        = kernel32.NewProc("GlobalFree")
	moveMemory        = kernel32.NewProc("RtlMoveMemory")
)

const (
	mbOKCancel     = 0x1
	mbIconWarning  = 0x30
	mbDefButton2   = 0x100
	mbTopmost      = 0x40000
	mbSetForegound = 0x10000
	idOK           = 1
	cfUnicodeText  = 13
	gmemMoveable   = 0x2
)

// notifyAction posts a notification. Windows toasts arrive with the installer, which registers the app's
// identity; until then this is a no-op and the menu is the display.
func notifyAction(id, title, message, key string) { postNative(id, title, message, key) }

// openURL opens an http(s) link in the default browser.
func openURL(u string) error {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return errors.New("not a web link: " + u)
	}
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(u), nil, nil, windows.SW_SHOWNORMAL)
}

// confirmDialog asks an OK/Cancel question with Cancel as the default, and fails CLOSED: a dialog that cannot be
// shown, or is left unanswered until the timeout, is a no. Windows names the buttons; confirmLabel is unused.
func confirmDialog(title, message, _ string) bool {
	r, _, _ := messageBoxTimeout.Call(0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(message))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))),
		mbOKCancel|mbIconWarning|mbDefButton2|mbTopmost|mbSetForegound, 0, uintptr(confirmDialogTimeout.Milliseconds()))
	return r == idOK
}

// copyToClipboard puts s on the clipboard as Unicode text.
func copyToClipboard(s string) error {
	text := utf16.Encode([]rune(s + "\x00"))
	if r, _, err := openClipboard.Call(0); r == 0 {
		return err
	}
	defer closeClipboard.Call()
	if r, _, err := emptyClipboard.Call(); r == 0 {
		return err
	}
	h, _, err := globalAlloc.Call(gmemMoveable, uintptr(len(text)*2))
	if h == 0 {
		return err
	}
	p, _, err := globalLock.Call(h)
	if p == 0 {
		globalFree.Call(h)
		return err
	}
	moveMemory.Call(p, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)*2))
	globalUnlock.Call(h)
	// The clipboard owns the memory once this succeeds.
	if r, _, err := setClipboardData.Call(cfUnicodeText, h); r == 0 {
		globalFree.Call(h)
		return err
	}
	return nil
}

// platformKeySuffix picks the Windows wording of a message (i18n.go).
const platformKeySuffix = "windows"

// noConsole keeps pmon.exe, which this app runs, from opening a console window.
func noConsole(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}
