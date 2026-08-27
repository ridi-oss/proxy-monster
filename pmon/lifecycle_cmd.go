package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// startCmd starts the daemon if none is running. Symmetric with the menu-bar app's Start: both call the same
// [control.EnsureDaemon], so start-if-needed has one implementation.
type startCmd struct{}

func (startCmd) Run() error {
	ctx := context.Background()
	if _, err := control.Connect(ctx); err == nil {
		fmt.Println("the daemon is already running")
		return nil
	}
	c, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !s.LoggedIn {
		fmt.Println("daemon started — not logged in yet; run `pmon login`")
		return nil
	}
	fmt.Printf("daemon started — logged in as %s, %d datasource(s) brokered\n", s.Principal, brokeredCount(s))
	return nil
}

// stopCmd stops the daemon. It warns before dropping live connections: the daemon is a shared resource and
// either peer can stop it, so the honest guard is telling the user what they are about to break rather than
// tracking who started it.
type stopCmd struct {
	Force bool `short:"f" help:"Stop without asking, even with connections open."`
}

func daemonMayBeRunning(ctx context.Context) bool {
	instance, err := state.DaemonInstance()
	if err != nil {
		return true
	}
	running, err := instance.Client().Running(ctx)
	return err != nil || running
}

func (c *stopCmd) Run() error {
	ctx := context.Background()
	shouldStop := true
	if !c.Force {
		client, err := control.Connect(ctx)
		if err == nil {
			s, statusErr := client.Status(ctx)
			if statusErr != nil {
				if errors.Is(statusErr, control.ErrDaemonNotRunning) && !daemonMayBeRunning(ctx) {
					shouldStop = false
				} else if !confirm("the daemon status cannot be read, so its connections cannot be checked. Stop anyway?") {
					fmt.Println("left the daemon running")
					return nil
				}
			} else if n := s.TotalLiveConns(); n > 0 {
				if !confirm(fmt.Sprintf("%d active connection(s) will be dropped. Stop anyway?", n)) {
					fmt.Println("left the daemon running")
					return nil
				}
			}
		} else if errors.Is(err, control.ErrDaemonNotRunning) {
			shouldStop = false
		} else if !confirm("the daemon status cannot be read, so its connections cannot be checked. Stop anyway?") {
			fmt.Println("left the daemon running")
			return nil
		}
	}
	if !shouldStop {
		fmt.Println("the daemon is not running")
		return nil
	}
	if err := control.StopDaemon(ctx); err != nil {
		if errors.Is(err, control.ErrDaemonNotRunning) {
			fmt.Println("the daemon is not running")
			return nil
		}
		return err
	}
	fmt.Println("daemon stopped")
	return nil
}

// restartCmd stops a running daemon and starts a fresh one.
type restartCmd struct {
	Force bool `short:"f" help:"Restart without asking, even with connections open."`
}

func (c *restartCmd) Run() error {
	ctx := context.Background()
	shouldStop := true
	if !c.Force {
		client, err := control.Connect(ctx)
		if err == nil {
			s, statusErr := client.Status(ctx)
			if statusErr != nil {
				if errors.Is(statusErr, control.ErrDaemonNotRunning) && !daemonMayBeRunning(ctx) {
					shouldStop = false
				} else if !confirm("the daemon status cannot be read, so its connections cannot be checked. Restart anyway?") {
					fmt.Println("left the daemon running")
					return nil
				}
			} else if n := s.TotalLiveConns(); n > 0 {
				if !confirm(fmt.Sprintf("%d active connection(s) will be dropped. Restart anyway?", n)) {
					fmt.Println("left the daemon running")
					return nil
				}
			}
		} else if errors.Is(err, control.ErrDaemonNotRunning) {
			shouldStop = false
		} else if !confirm("the daemon status cannot be read, so its connections cannot be checked. Restart anyway?") {
			fmt.Println("left the daemon running")
			return nil
		}
	}
	if shouldStop {
		if err := control.StopDaemon(ctx); err != nil &&
			!errors.Is(err, control.ErrDaemonNotRunning) &&
			!errors.Is(err, control.ErrDaemonReplaced) {
			return err
		}
	}
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if !s.LoggedIn {
		fmt.Println("daemon restarted — not logged in; run `pmon login`")
		return nil
	}
	fmt.Printf("daemon restarted — logged in as %s, %d datasource(s) brokered\n", s.Principal, brokeredCount(s))
	return nil
}

// logoutCmd clears the credentials and closes the brokers, leaving the daemon up and idle.
type logoutCmd struct{}

func (logoutCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if errors.Is(err, control.ErrDaemonNotRunning) {
		fmt.Println("the daemon is not running — nothing to log out of")
		return nil
	}
	if err != nil {
		return err
	}
	if err := client.Logout(ctx); err != nil {
		return err
	}
	fmt.Println("logged out — the brokers are closed and the daemon is idle")
	return nil
}

// stdinIsTerminal reports whether stdin is a character device, i.e. someone is there to answer. Done with a
// mode check rather than an isatty dependency: pmon stays a pure-Go binary with no library it does not need.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func brokeredCount(s *control.Status) int {
	n := 0
	for _, ds := range s.Datasources {
		if ds.Brokered {
			n++
		}
	}
	return n
}

// confirm asks a yes/no question. With no terminal (a script, a hook) it answers NO, so an unattended run
// never silently drops someone's connections — `--force` is the explicit way through.
func confirm(question string) bool {
	if !stdinIsTerminal() {
		fmt.Fprintf(os.Stderr, "%s (no terminal to ask; refusing — pass --force)\n", question)
		return false
	}
	fmt.Printf("%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
