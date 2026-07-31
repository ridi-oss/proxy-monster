package main

import (
	"context"
	"fmt"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
)

// loginCmd authenticates through the daemon's control socket: the DAEMON runs the device-auth flow and streams
// its steps back, so the CLI and the menu-bar app share one implementation and two concurrent logins cannot
// race into two device flows. It starts the daemon if none is running, and the brokers open as soon as the
// login lands — there is no separate step to begin serving.
type loginCmd struct {
	URL string `help:"Control-plane base URL (saved; reused by later logins that omit it)."`
	TTL int    `default:"43200" help:"Requested token lifetime in seconds (default 12h; the server clamps it)."`
}

func (c *loginCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}

	req := control.LoginRequest{ControlPlane: c.URL, TTLSeconds: c.TTL}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = login.DefaultTTL
	}

	// A daemon reporting no version opens its own browser. Asked here rather than in the prompt
	// callback, which the poll loop waits on.
	daemonOpensItsOwn := false
	if s, err := client.Status(ctx); err == nil && s.Version == "" {
		daemonOpensItsOwn = true
	}
	if err := client.Login(ctx, req, func(ev control.LoginEvent) {
		switch ev.Kind {
		case "prompt":
			if !daemonOpensItsOwn && ev.VerificationURIComplete != "" {
				_ = openBrowser(ev.VerificationURIComplete)
			}
			fmt.Printf("\nTo finish logging in, open this URL in your browser:\n\n    %s\n", ev.VerificationURI)
			if ev.UserCode != "" {
				fmt.Printf("\nand enter this code when asked: %s\n", ev.UserCode)
			}
			fmt.Println("\nWaiting for you to finish logging in…")
		case "done":
			fmt.Printf("logged in as %s — token expires %s\n", ev.Principal, ev.ExpiresAt)
		}
	}); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	fmt.Printf("%d datasource(s) brokered — `pmon status` for the list, `pmon show <datasource>` for a connection string\n",
		brokeredCount(s))
	return nil
}
