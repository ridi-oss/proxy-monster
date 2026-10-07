//go:build darwin || windows

package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	webview "github.com/webview/webview_go"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

//go:embed prefs.html
var prefsHTML string

//go:embed fonts/geist.woff2
var geistFont []byte

//go:embed fonts/geist-mono.woff2
var geistMonoFont []byte

// fontCSS embeds the console's typefaces: the window has no network, so they ship inside the app.
func fontCSS() string {
	face := func(family string, data []byte, weight string) string {
		return fmt.Sprintf("@font-face { font-family: %q; src: url(data:font/woff2;base64,%s) format(\"woff2\"); font-weight: %s; font-display: block; }\n",
			family, base64.StdEncoding.EncodeToString(data), weight)
	}
	return face("Geist", geistFont, "100 900") + face("Geist Mono", geistMonoFont, "100 900")
}

// runPreferences shows the Settings window until it is closed. The page calls Go through pmCall, which
// answers asynchronously: a binding runs on the UI thread, and several calls (an AI app's CLI, a sign-out
// confirmation) take seconds.
func runPreferences(add bool) {
	ctx, cancel := context.WithCancel(context.Background())
	w := webview.New(false)
	w.SetTitle("Proxy Monster Settings")
	w.SetSize(800, 560, webview.HintNone)

	// Background goroutines reach the page through eval; once the window closes, closed stops them from
	// dispatching into a web view that is about to be destroyed.
	var mu sync.Mutex
	closed := false
	eval := func(js string) {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			w.Dispatch(func() { w.Eval(js) })
		}
	}
	refresh := func() { eval("window.pmRefresh && window.pmRefresh()") }
	p := &prefs{ctx: ctx, signingIn: map[string]bool{}, changed: refresh, pmonVersion: bundledPmonVersion()}
	handlers := p.handlers()

	if err := w.Bind("pmCall", func(id, name, args string) {
		go func() {
			var result any
			var raw []json.RawMessage
			h, ok := handlers[name]
			switch {
			case !ok:
				result = "unknown call " + name
			case json.Unmarshal([]byte(args), &raw) != nil:
				result = "bad arguments for " + name
			default:
				res, err := h(raw)
				if err != nil {
					res = err.Error()
				}
				result = res
			}
			b, _ := json.Marshal(result)
			idJSON, _ := json.Marshal(id)
			eval(fmt.Sprintf("window.__pmDone(%s, %s)", idJSON, b))
		}()
	}); err != nil {
		panic(err)
	}
	if add {
		w.Init("window.pmStartWithAdd = true;")
	}
	w.SetHtml(strings.Replace(prefsHTML, "/*FONTS*/", fontCSS(), 1))
	go watchForPrefs(ctx, refresh)
	w.Run()

	mu.Lock()
	closed = true
	mu.Unlock()
	cancel()
	w.Destroy()
}

// watchForPrefs tells the page to refresh on every daemon event, and every 30 seconds for the time left.
func watchForPrefs(ctx context.Context, refresh func()) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	for ctx.Err() == nil {
		if client, err := control.Connect(ctx); err == nil {
			_ = client.Events(ctx, func(control.Event) { refresh() })
			refresh()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}
