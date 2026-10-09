package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/aiapps"
)

// register adds or removes `pmon mcp <server>` in the AI apps on this machine.
func (c *mcpCmd) register(ctx context.Context) error {
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	servers, err := c.targetServers(ctx, s)
	if err != nil {
		return err
	}
	apps, err := c.targetApps()
	if err != nil {
		return err
	}
	pmon, err := pmonPath()
	if err != nil {
		return err
	}
	setup := aiapps.Setup{Pmon: pmon, Confirm: confirmClaudeRestart}
	failed := 0
	for _, app := range apps {
		err := app.Batch(setup, func(setup aiapps.Setup) error {
			for _, srv := range servers {
				if !c.Install {
					switch removed, err := app.Remove(setup, srv.Name); {
					case err != nil:
						failed++
						fmt.Fprintf(os.Stderr, "%s: %s: %v\n", app.Name, srv.Name, err)
					case removed:
						fmt.Printf("%s: removed pmon mcp %s\n", app.Name, srv.Name)
					default:
						fmt.Printf("%s: no pmon mcp %s to remove\n", app.Name, srv.Name)
					}
					continue
				}
				switch entry, replaced, err := app.Add(setup, srv); {
				case err != nil:
					failed++
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", app.Name, srv.Name, err)
				case len(replaced) > 0:
					fmt.Printf("%s: added %s, replacing %s\n", app.Name, entry, strings.Join(replaced, ", "))
				default:
					fmt.Printf("%s: added %s\n", app.Name, entry)
				}
			}
			return nil
		})
		switch {
		case errors.Is(err, aiapps.ErrDeclined):
			failed += len(servers)
			fmt.Fprintf(os.Stderr, "%s: not changed, since it was not restarted; quit it and run this again\n", app.Name)
		case err != nil:
			failed += len(servers)
			fmt.Fprintf(os.Stderr, "%s: %v\n", app.Name, err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d changes failed", failed, len(apps)*len(servers))
	}
	if c.Install {
		fmt.Println("New sessions of these apps can use it; a running Claude Desktop picks it up when reopened.")
	}
	return nil
}

// targetServers is every configured server by default. --install takes only configured ones, named as each
// server advertises; --uninstall also takes a server since deleted, whose entries would otherwise stay behind.
func (c *mcpCmd) targetServers(ctx context.Context, s *control.Status) ([]aiapps.Server, error) {
	var known []string
	urls := map[string]string{}
	for _, srv := range s.Servers {
		known = append(known, srv.Name)
		urls[srv.Name] = srv.ControlPlane
	}
	names := c.Servers
	if len(names) == 0 {
		if len(known) == 0 {
			return nil, errors.New("no servers — add one with `pmon server set --url <control-plane-url>`")
		}
		names = known
	}
	var servers []aiapps.Server
	for _, name := range names {
		url, ok := urls[name]
		switch {
		case c.Install && !ok:
			return nil, fmt.Errorf("unknown server %q (known: %s)", name, strings.Join(known, ", "))
		case c.Install:
			servers = append(servers, aiapps.Lookup(ctx, name, url))
		default:
			servers = append(servers, aiapps.Server{Name: name})
		}
	}
	return servers, nil
}

// targetApps is every installed AI app by default; an app named with --app must be installed.
func (c *mcpCmd) targetApps() ([]aiapps.App, error) {
	all := aiapps.Apps()
	var ids []string
	for _, app := range all {
		ids = append(ids, app.ID)
	}
	for _, id := range c.App {
		if !slices.Contains(ids, id) {
			return nil, fmt.Errorf("unknown app %q (known: %s)", id, strings.Join(ids, ", "))
		}
	}
	var apps []aiapps.App
	for _, app := range all {
		named := slices.Contains(c.App, app.ID)
		if len(c.App) > 0 && !named {
			continue
		}
		if !app.Installed() {
			if named {
				return nil, &aiapps.NotInstalledError{App: app.Name}
			}
			continue
		}
		apps = append(apps, app)
	}
	if len(apps) == 0 {
		return nil, errors.New("no AI app found on this machine (Claude Desktop, Claude Code, Codex)")
	}
	return apps, nil
}

// pmonPath is the pmon an AI app should launch: the pmon on PATH when it is this binary, because a package
// manager's link outlives the versioned path it points at.
func pmonPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := exec.LookPath("pmon"); err == nil {
		if abs, err := filepath.Abs(p); err == nil && sameFile(abs, exe) {
			return abs, nil
		}
	}
	return exe, nil
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// confirmClaudeRestart asks on the terminal before Claude Desktop for Windows is restarted around an edit; with
// no terminal to ask on, the answer is no.
func confirmClaudeRestart() bool {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Fprint(os.Stderr, "Claude Desktop restarts to pick up the change; a message you have not sent in it is lost. Restart it now? [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
