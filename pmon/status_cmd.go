package main

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	if errors.Is(err, control.ErrDaemonUnreachable) {
		fmt.Println("daemon:    running, control socket unreachable (run `pmon restart`)")
		return nil
	}
	if errors.Is(err, control.ErrDaemonNotRunning) {
		fmt.Println("daemon:    not running (run `pmon start`, or `pmon login` to start it and log in)")
		return nil
	}
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	warnOtherDaemons()

	if !s.LoggedIn {
		fmt.Println("daemon:    running, idle")
		fmt.Println("login:     not logged in (run `pmon login`)")
		return nil
	}

	fmt.Printf("daemon:    running since %s\n", humanTime(s.StartedAt))
	fmt.Printf("principal: %s\n", s.Principal)
	fmt.Printf("cp:        %s\n", s.ControlPlane)
	fmt.Printf("token:     %s\n", expiryLine(s.ExpiresAt))
	if s.SessionExpiresAt != "" {
		fmt.Printf("session:   %s\n", expiryLine(s.SessionExpiresAt))
	}
	if s.ReauthRequired {
		fmt.Println("reauth:    REQUIRED — the session window closed; run `pmon login`")
	}
	if s.LastDiscoveryError != "" {
		fmt.Printf("discovery: FAILING — %s\n", s.LastDiscoveryError)
	}

	if len(s.Datasources) == 0 {
		fmt.Println("\nno datasources yet (none advertised a proxy address, or none are granted to you)")
		return nil
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DATASOURCE\tENGINE\tLOCAL\tCONNS\tPROXY")
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ds.Name, ds.Engine, local, conns, proxy)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Println("\n`pmon show <datasource>` for a connection string")
	return nil
}

// expiryLine renders an RFC3339 timestamp as an absolute time plus how long is left, so "is this about to
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
