package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// loginCmd authenticates through the daemon's control socket: the DAEMON runs the device-auth flow and streams
// its steps back, so the CLI and the menu-bar app share one implementation and two concurrent logins cannot
// race into two device flows. It starts the daemon if none is running, and the brokers open as soon as the
// login lands — there is no separate step to begin serving.
type loginCmd struct {
	Server string  `arg:"" optional:"" default:"default" help:"Server to log in to."`
	URL    string  `help:"Set the server's control-plane URL first (as 'pmon server set' does)."`
	TTL    int     `default:"43200" help:"Requested token lifetime in seconds (default 12h; the server clamps it)."`
	Scopes *string `help:"Comma-separated scopes to grant instead of the default mcp:read,mcp:query. Available: mcp:read, mcp:query, mcp:approvals:write, mcp:datasources:write, mcp:policies:write, mcp:identity:write, mcp:tokens."`
}

// parseScopes splits a --scopes value. Absent means the server's default; present but empty is an error.
func parseScopes(raw *string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	var out []string
	for _, s := range strings.Split(*raw, ",") {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--scopes needs at least one scope, e.g. --scopes mcp:read,mcp:query")
	}
	return out, nil
}

func (c *loginCmd) Run() error {
	scopes, err := parseScopes(c.Scopes)
	if err != nil {
		return err
	}
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}

	req := control.LoginRequest{Server: c.Server, ControlPlane: c.URL, TTLSeconds: c.TTL, Scopes: scopes}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = login.DefaultTTL
	}

	// A daemon reporting no version opens its own browser. Asked here rather than in the prompt
	// callback, which the poll loop waits on.
	daemonOpensItsOwn := false
	if s, err := client.Status(ctx); err == nil {
		if err := requireCurrentDaemon(s); err != nil {
			return err
		}
		daemonOpensItsOwn = s.Version == ""
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
			if len(ev.Scopes) > 0 {
				fmt.Printf("scopes: %s\n", strings.Join(ev.Scopes, " "))
			}
			if ev.ElevatedUntil != "" {
				fmt.Printf("%s expire %s\n", strings.Join(elevatedScopes(ev.Scopes), " "), expiryLine(ev.ElevatedUntil))
			}
			if ev.ReplacedNotEndedOnServer {
				fmt.Fprintf(os.Stderr, "warning: could not end the previous %q login on the server; it stays valid there until its TTL ends\n", cmp.Or(c.Server, state.DefaultServer))
			}
		}
	}); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	fmt.Printf("%d datasource(s) brokered from %q — `pmon status` for the list, `%s` for a connection string\n",
		brokeredCount(s, c.Server), c.Server, showHint(c.Server))
	return nil
}
