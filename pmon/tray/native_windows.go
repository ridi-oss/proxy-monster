package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// appID is the AppUserModelID toasts are shown under; registerToastIdentity gives it the app's name and icon.
const appID = "RIDI.ProxyMonsterDesktop"

const (
	prefsKey   = `Software\RIDI\Proxy Monster Desktop`
	runKey     = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue   = "Proxy Monster Desktop"
	schemeKey  = `Software\Classes\pmon`
	toastShell = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml((New-Object IO.StreamReader([Console]::OpenStandardInput(), [Text.Encoding]::UTF8)).ReadToEnd())
$t = [Windows.UI.Notifications.ToastNotification]::new($x)
$t.Tag = $env:PM_TOAST_TAG
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:PM_TOAST_APP).Show($t)`
)

var onNotificationClick func(key string)

// postNative shows a toast. Clicking it opens pmon://notification?key=…, which reaches this process the way
// any pmon:// link does. The text goes in as UTF-8 XML on stdin, never into the script; the script reads the
// bytes as UTF-8, since [Console]::In decodes with the console code page (CP949 on Korean Windows).
func postNative(id, title, body, key string) bool {
	launch := "pmon://notification?" + url.Values{"key": {key}, "token": {toastToken}}.Encode()
	xml := fmt.Sprintf(`<toast activationType="protocol" launch="%s"><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text></binding></visual></toast>`,
		xmlEscape(launch), xmlEscape(title), xmlEscape(body))
	sum := sha256.Sum256([]byte(id))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", toastShell)
	// Windows takes the first of duplicate names, so these come before the inherited environment.
	cmd.Env = append([]string{"PM_TOAST_APP=" + appID, "PM_TOAST_TAG=" + hex.EncodeToString(sum[:8])}, os.Environ()...)
	cmd.Stdin = strings.NewReader(xml)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if cmd.Start() != nil {
		return false
	}
	go func() { _ = cmd.Wait() }()
	return true
}

// toastToken is in every toast's click link and nowhere else, so a pmon://notification link that a web page or
// another program makes up is ignored.
var toastToken = func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}()

func xmlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func loginItem() (on, supported bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, true
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil, true
}

func setLoginItem(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runValue, `"`+exe+`"`)
}

// activatePid lets the Settings process take the foreground; it raises its own window when told to show.
func activatePid(pid int) { _, _, _ = allowSetForegroundWindow.Call(uintptr(pid)) }

var allowSetForegroundWindow = windows.NewLazySystemDLL("user32.dll").NewProc("AllowSetForegroundWindow")

func prefString(key string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, prefsKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(key)
	return v
}

func setPrefString(key, value string) {
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, prefsKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue(key, value)
		k.Close()
	}
}

func prefBool(key string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, prefsKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(key)
	return err == nil && v != 0
}

func setPrefBool(key string, v bool) {
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, prefsKey, registry.SET_VALUE); err == nil {
		n := uint32(0)
		if v {
			n = 1
		}
		_ = k.SetDWordValue(key, n)
		k.Close()
	}
}

func preferredLanguages() []string {
	langs, _ := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	return langs
}

// applyTheme has nothing to do: the notification-area menu follows Windows' own theme.
func applyTheme(unsafe.Pointer, string) {}

// handOffSocket is where the running app listens for links and "show" from a second launch, in the user's
// local (never roaming) app data. A forwarded connect link is confirmed before anything changes, as one opened
// directly is.
func handOffSocket() (string, error) {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Proxy Monster Desktop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "tray.sock"), nil
}

// instanceMutexName is per session, so each signed-in user runs their own app.
const instanceMutexName = `Local\RIDI.ProxyMonsterDesktop`

// instanceMutex is held by the running app for its lifetime; whoever creates it first is that app.
var instanceMutex windows.Handle

// handedOff makes this process the app, or else passes its argument (a pmon:// link, or nothing for "show") to
// the app already running and reports true, in which case this process exits. Windows starts a new process for
// every link.
func handedOff() bool {
	name, _ := windows.UTF16PtrFromString(instanceMutexName)
	h, err := windows.CreateMutex(nil, true, name)
	if err == nil {
		instanceMutex = h
		return false
	}
	if h != 0 {
		windows.CloseHandle(h)
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false
	}
	msg := "show"
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "pmon://") {
		msg = os.Args[1]
	}
	// The running app may still be starting its listener.
	for range 20 {
		if sendToRunning(msg) == nil {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return true
}

func sendToRunning(msg string) error {
	p, err := handOffSocket()
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", p, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintln(conn, msg)
	return err
}

// listenForLinks registers the pmon:// scheme for this user, accepts links handed off by later launches, and
// handles a link this process was launched with.
func listenForLinks() {
	registerScheme()
	registerToastIdentity()
	putOnPath()
	if p, err := handOffSocket(); err == nil {
		_ = os.Remove(p) // left by a crash; this process holds the instance mutex
		if ln, err := net.Listen("unix", p); err == nil {
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
						line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString('\n')
						if err != nil {
							return
						}
						if line = strings.TrimSpace(line); line == quitForInstall {
							// Room for the confirmation, which gives up after confirmDialogTimeout.
							_ = conn.SetDeadline(time.Now().Add(confirmDialogTimeout + 30*time.Second))
							answer := "declined"
							if f := onQuitForInstall; f != nil && f() {
								answer = "ok"
							}
							_, _ = fmt.Fprintln(conn, answer)
							return
						}
						openLink(line)
					}()
				}
			}()
		}
	}
	if len(os.Args) > 1 {
		go openLink(os.Args[1])
	}
}

// quitForInstall is what the installer's --quit-for-install sends the running app.
const quitForInstall = "quit-for-install"

// onQuitForInstall quits the app and its daemon for the installer, reporting false when the user declined.
var onQuitForInstall func() bool

// runQuitForInstall is `pmontray --quit-for-install`, which the MSI runs before it replaces or removes the
// files: Windows cannot replace a running pmontray.exe or pmon.exe. It asks the running app to quit, or with
// none running stops the daemon itself, asking first when that drops connections. Exit status 1 stops the install.
func runQuitForInstall() int {
	if p, err := handOffSocket(); err == nil {
		if conn, err := net.DialTimeout("unix", p, 2*time.Second); err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(confirmDialogTimeout + time.Minute))
			if _, err := fmt.Fprintln(conn, quitForInstall); err == nil {
				answer, _ := bufio.NewReader(conn).ReadString('\n')
				if strings.TrimSpace(answer) != "ok" {
					return 1
				}
				waitForInstanceExit()
				return 0
			}
		}
	}
	ctx := context.Background()
	if !confirmDrop(ctx, "update", "") {
		return 1
	}
	if err := control.StopDaemon(ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		return 1
	}
	return 0
}

// waitForInstanceExit waits, up to half a minute, for the running app to release the instance mutex.
func waitForInstanceExit() {
	name, _ := windows.UTF16PtrFromString(instanceMutexName)
	for range 60 {
		h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
		if err != nil {
			return
		}
		windows.CloseHandle(h)
		time.Sleep(500 * time.Millisecond)
	}
}

// onShow is what a second launch without a link does: open Settings.
var onShow func()

func openLink(raw string) {
	if raw == "show" {
		if f := onShow; f != nil {
			f()
		}
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "pmon" {
		return
	}
	switch u.Host {
	case "notification":
		q := u.Query()
		if f := onNotificationClick; f != nil && subtle.ConstantTimeCompare([]byte(q.Get("token")), []byte(toastToken)) == 1 {
			f(q.Get("key"))
		}
	case "connect":
		if f := onConnectLink; f != nil {
			f(raw)
		}
	}
}

//go:embed app-icon.png
var appIconPNG []byte

// registerToastIdentity registers appID for this user, which is what lets an unpackaged app show toasts under
// its own name and icon, with or without the installer's Start menu shortcut.
func registerToastIdentity() {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Proxy Monster Desktop")
	icon := filepath.Join(dir, "icon.png")
	if err := os.MkdirAll(dir, 0o700); err == nil {
		_ = os.WriteFile(icon, appIconPNG, 0o600)
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\AppUserModelId\`+appID, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue("DisplayName", "Proxy Monster Desktop")
	_ = k.SetStringValue("IconUri", icon)
}

// pathEntryPref is the PATH entry putOnPath added, so a copy that moved replaces it rather than piling up.
const pathEntryPref = "PathEntry"

// putOnPath puts the folder holding pmon.exe on this user's PATH, as the installer does, so a copy run from
// anywhere gives a terminal `pmon`.
func putOnPath() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	k, err := registry.OpenKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	current, _, err := k.GetStringValue("Path")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return
	}
	updated := withPathEntry(current, dir, prefString(pathEntryPref))
	if updated != current && k.SetExpandStringValue("Path", updated) == nil {
		broadcastEnvironmentChange()
	}
	setPrefString(pathEntryPref, dir)
}

// withPathEntry is a PATH value with dir in it once, without old (where this app used to be). Entries match
// regardless of case and a trailing backslash, which the installer's entry has.
func withPathEntry(current, dir, old string) string {
	same := func(a, b string) bool { return strings.EqualFold(strings.TrimRight(a, `\`), strings.TrimRight(b, `\`)) }
	var entries []string
	present := false
	for _, e := range strings.Split(current, ";") {
		switch {
		case e == "":
		case same(e, dir):
			if !present {
				entries = append(entries, e)
			}
			present = true
		case old != "" && same(e, old):
		default:
			entries = append(entries, e)
		}
	}
	if !present {
		entries = append(entries, dir)
	}
	return strings.Join(entries, ";")
}

// broadcastEnvironmentChange tells Explorer, and so new terminals, that the user's environment changed.
func broadcastEnvironmentChange() {
	env, _ := windows.UTF16PtrFromString("Environment")
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001a, 0x0002
	var result uintptr
	_, _, _ = sendMessageTimeout.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 2000, uintptr(unsafe.Pointer(&result)))
}

var sendMessageTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

func registerScheme() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	set := func(path, name, value string) {
		if k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE); err == nil {
			_ = k.SetStringValue(name, value)
			k.Close()
		}
	}
	set(schemeKey, "", "URL:Proxy Monster")
	set(schemeKey, "URL Protocol", "")
	set(schemeKey+`\shell\open\command`, "", `"`+exe+`" "%1"`)
}

// Libraries load from System32 only, or by full path: go-webview2 asks for WebView2Loader.dll by name first
// (and falls back to its own copy), and a DLL of that name planted on the search path must not be the one used.
func init() { _ = windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32) }
