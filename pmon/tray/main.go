// Command pmontray is proxy-monster's macOS menu-bar app: a second front end over the pmon daemon's control
// socket, PEER to the CLI rather than its owner. Both can start and stop the daemon, both render the same
// state, and neither is privileged — so anything done here is equally doable with `pmon`, and vice versa.
//
// It holds no state of its own. Every fact shown comes from the daemon's /status, and every action is a call
// on the same control API `pmon` uses, so the two front ends cannot drift.
//
// Its own module because a systray needs cgo and must own the main thread; keeping it out of pmon leaves that
// a pure-Go static binary.
package main

import (
	"context"
	"fmt"
	"os"

	"fyne.io/systray"
)

// version is stamped by build-app.sh via -ldflags.
var version = "dev"

func main() {
	// A menu-bar app has no terminal, so this is only for `pmontray --version` from a shell.
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println("pmontray", version)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := newApp(ctx)
	// systray.Run takes over the main thread (a macOS UI requirement) and calls onReady on it.
	systray.Run(app.onReady, app.onExit)
	if err := app.exitErr(); err != nil {
		fmt.Fprintln(os.Stderr, "pmontray:", err)
		os.Exit(1)
	}
}
