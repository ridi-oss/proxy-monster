package main

import (
	"os"
	"path/filepath"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// newWebView opens a WebView2 window. Its browser profile lives in the user's local app data: beside the
// executable is not writable for an installed app.
func newWebView(title string, width, height int) webView {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(os.Getenv("LOCALAPPDATA"), "Proxy Monster Desktop", "WebView2"),
		WindowOptions: webview2.WindowOptions{
			Title: title, Width: uint(width), Height: uint(height), Center: true,
			IconId: 1, // the app icon winres/winres.json embeds
		},
	})
	if w == nil {
		return nil
	}
	return w
}

// webViewMissing says what to install when WebView2 could not start, which on Windows 10 is usually a missing
// runtime, and offers the download.
func webViewMissing() {
	if confirm(T("s.title"), T("s.webviewMissing"), "") {
		_ = openURL("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
	}
}

var (
	setForegroundWindow = windows.NewLazySystemDLL("user32.dll").NewProc("SetForegroundWindow")
	showWindow          = windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
)

// raiseWindow restores and brings the window forward; the menu-bar process allowed it (activatePid).
func raiseWindow(w unsafe.Pointer) {
	_, _, _ = showWindow.Call(uintptr(w), windows.SW_RESTORE)
	_, _, _ = setForegroundWindow.Call(uintptr(w))
}
