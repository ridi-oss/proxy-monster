package main

import (
	"unsafe"

	webview "github.com/webview/webview_go"
)

func newWebView(title string, width, height int) webView {
	w := webview.New(false)
	w.SetTitle(title)
	w.SetSize(width, height, webview.HintNone)
	return w
}

// raiseWindow has nothing to do: the menu-bar process activates this one (activatePid).
func raiseWindow(unsafe.Pointer) {}

// webViewMissing cannot happen: WebKit is part of macOS.
func webViewMissing() {}
