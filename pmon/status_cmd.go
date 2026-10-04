package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// statusCmd shows the daemon's state. Every datasource fact comes from the DAEMON's live listener set, not
// from the sticky port map on disk — a revoked datasource keeps its port assignment but stops being brokered,
// so reading the config would over-report.
type statusCmd struct{}

func (statusCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		fmt.Println("daemon:    not running (run `pmon start`, or `pmon login` to start it and log in)")
		return nil
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	if err := requireCurrentDaemon(s); err != nil {
		return err
	}
	warnOtherDaemons()

	if s.LoggedIn {
		fmt.Printf("daemon:    running since %s\n", humanTime(s.StartedAt))
	} else {
		fmt.Println("daemon:    running, idle")
	}
	if len(s.Servers) == 0 {
		fmt.Println("servers:   none (run `pmon login --url <control-plane-url>`)")
		return nil
	}
	for _, srv := range s.Servers {
		fmt.Printf("\nserver:    %s  %s\n", srv.Name, srv.ControlPlane)
		if !srv.LoggedIn {
			fmt.Printf("login:     not logged in (run `%s`)\n", loginHint(srv.Name))
			continue
		}
		fmt.Printf("principal: %s\n", srv.Principal)
		fmt.Printf("token:     %s\n", expiryLine(srv.ExpiresAt))
		if srv.SessionExpiresAt != "" {
			fmt.Printf("session:   %s\n", expiryLine(srv.SessionExpiresAt))
		}
		if len(srv.Scopes) > 0 {
			fmt.Printf("scopes:    %s\n", strings.Join(srv.Scopes, " "))
		}
		if srv.ElevatedUntil != "" {
			fmt.Printf("elevated:  %s\n", elevatedLine(srv, time.Now()))
		}
		if srv.ReauthRequired {
			fmt.Printf("reauth:    REQUIRED — the session window closed; run `%s`\n", loginHint(srv.Name))
		}
		if srv.LastDiscoveryError != "" {
			fmt.Printf("discovery: FAILING — %s\n", srv.LastDiscoveryError)
		}
	}

	if !s.LoggedIn {
		return nil
	}
	if len(s.Datasources) == 0 {
		fmt.Println("\nno datasources yet (none advertised a proxy address, or none are granted to you)")
		return nil
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tDATASOURCE\tENGINE\tLOCAL\tCONNS\tPROXY")
	for _, ds := range s.Datasources {
		local, proxy := "—", ds.AdvertiseAddr
		if ds.Brokered {
			local = fmt.Sprintf("127.0.0.1:%d", ds.LocalPort)
			// Three distinct states, not two: verified against the advertised chain, TLS verified against the
			// client's own trust store (the proxy published nothing), or no TLS at all.
			switch {
			case ds.TLSVerified:
				proxy += " (TLS verified)"
			case ds.WireTLS:
				proxy += " (TLS, system trust)"
			default:
				proxy += " (no TLS)"
			}
		} else {
			proxy = "(" + ds.Reason + ")"
		}
		conns := "—"
		if ds.Brokered {
			conns = fmt.Sprintf("%d", ds.LiveConns)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", ds.Server, ds.Name, ds.Engine, local, conns, proxy)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Println("\n`pmon show [server] <datasource>` for a connection string")
	return nil
}

// defaultScopes is what a login grants without --scopes.
var defaultScopes = []string{"mcp:read", "mcp:query"}

func elevatedScopes(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if !slices.Contains(defaultScopes, s) {
			out = append(out, s)
		}
	}
	return out
}

// elevatedLine says when a login's elevated scopes expire, or that they have and how to get them back.
func elevatedLine(srv control.ServerInfo, now time.Time) string {
	extra := strings.Join(elevatedScopes(srv.Scopes), " ")
	until, err := time.Parse(time.RFC3339, srv.ElevatedUntil)
	if err != nil || until.After(now) {
		return fmt.Sprintf("%s until %s", extra, expiryLine(srv.ElevatedUntil))
	}
	return fmt.Sprintf("%s EXPIRED at %s — run `%s --scopes %s` to get them back",
		extra, until.Local().Format("2006-01-02 15:04"), loginHint(srv.Name), strings.Join(srv.Scopes, ","))
}

// expiryLine formats an RFC3339 timestamp as an absolute time plus how long is left, so "is this about to
// break?" is answerable at a glance.
func expiryLine(ts string) string {
	if ts == "" {
		return "(unknown)"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Until(t)
	if d <= 0 {
		return fmt.Sprintf("%s (EXPIRED)", t.Local().Format("2006-01-02 15:04"))
	}
	return fmt.Sprintf("%s (in %s)", t.Local().Format("2006-01-02 15:04"), roundDuration(d))
}

func humanTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return fmt.Sprintf("%s (%s ago)", t.Local().Format("15:04"), roundDuration(time.Since(t)))
}

// roundDuration trims a duration to a readable scale — hours and minutes, not nanoseconds.
func roundDuration(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	default:
		return d.Round(time.Second)
	}
}
