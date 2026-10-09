// Package aiapps registers `pmon mcp <server>` as a local MCP server in the AI apps that run one: Claude
// Desktop, Claude Code and Codex. The pmon CLI and Proxy Monster Desktop both use it.
package aiapps

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Setup is what an edit needs from its caller.
type Setup struct {
	// Pmon is the pmon an AI app launches: a path that survives pmon being updated in place.
	Pmon string
	// Confirm asks before Claude Desktop for Windows is closed and reopened around an edit; nil declines.
	Confirm func() bool
}

// ErrDeclined is a change the user declined when asked to confirm it.
var ErrDeclined = errors.New("declined")

// NotInstalledError is a change to an app whose CLI is not installed.
type NotInstalledError struct{ App string }

func (e *NotInstalledError) Error() string { return e.App + " is not installed." }

// EntryError is an entry with pmon's name that pmon did not add: Taken when adding, otherwise when removing.
type EntryError struct {
	App, Entry string
	Taken      bool
}

func (e *EntryError) Error() string {
	if e.Taken {
		return fmt.Sprintf("%s already has an MCP server named %s that pmon did not add. Rename or remove it in %s first.", e.App, e.Entry, e.App)
	}
	return fmt.Sprintf("The %s entry %s is not pmon's, so it was left alone.", e.App, e.Entry)
}

// Server is a pmon server: its name and its control-plane URL.
type Server struct{ Name, URL string }

// App is an app that can run `pmon mcp <server>` as a local MCP server.
type App struct {
	ID, Name  string
	installed func() bool
	connected func(s Setup, entry, server string) bool
	add       func(s Setup, entry string, srv Server) ([]string, error)
	remove    func(s Setup, entry, server string) (bool, error) // only an entry that is pmon's
}

func (a App) Installed() bool { return a.installed() }

// Connected reports whether the app runs this setup's pmon for server, reaching the daemon in use.
func (a App) Connected(s Setup, server string) bool { return a.connected(s, EntryName(server), server) }

// Add registers `pmon mcp <server>`, replacing the app's other entries for the same server: its https
// endpoint, or pmon's relay under another name. It returns the names it replaced.
func (a App) Add(s Setup, srv Server) ([]string, error) { return a.add(s, EntryName(srv.Name), srv) }

// Remove removes pmon's entry for server, reporting whether there was one.
func (a App) Remove(s Setup, server string) (bool, error) {
	return a.remove(s, EntryName(server), server)
}

// Apps is every app this package knows, installed or not.
func Apps() []App {
	return []App{
		claudeDesktop(),
		cliOrConfig(cliApp("claude-code", "Claude Code", "claude", []string{"--scope", "user"}, claudeCodeConfig()), claudeCodeConfig()),
		cliOrConfig(cliApp("codex", "Codex", "codex", nil, codexConfig()), codexConfig()),
	}
}

// cliOrConfig uses the app's CLI when it is installed, else its config file: the desktop apps have the file
// without the CLI.
func cliOrConfig(cli App, file configFile) App {
	if cli.installed() || !file.exists() {
		return cli
	}
	return configApp(cli.ID, cli.Name, file)
}

// EntryName is the name a server is registered under in an AI app's MCP settings.
func EntryName(server string) string {
	if server == "default" {
		return "proxy-monster"
	}
	return "proxy-monster-" + server
}

// --- Claude Desktop: claude_desktop_config.json ---

type mcpCommand struct {
	Type    string            `json:"type,omitempty"` // "stdio" in ~/.claude.json
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// DaemonEnv is the environment that selects which pmon daemon is in use. An AI app starts `pmon mcp` with its
// own environment, so a caller pointed at a non-default daemon passes the same settings along; otherwise the
// entry would reach a different daemon, one without this server.
func DaemonEnv() map[string]string {
	env := map[string]string{}
	for _, k := range []string{"PMON_CONFIG_DIR", "PMON_PORT_BASE"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	return env
}

func claudeDesktop() App {
	return App{
		ID: "claude-desktop", Name: "Claude Desktop",
		installed: func() bool {
			if claudeDesktopInstalled() {
				return true
			}
			_, err := os.Stat(filepath.Dir(claudeDesktopConfig()))
			return err == nil
		},
		connected: func(s Setup, entry, server string) bool {
			servers, _, err := readDesktopServers(claudeDesktopConfig())
			if err != nil {
				return false
			}
			var c mcpCommand
			return json.Unmarshal(servers[entry], &c) == nil && ours(c.Command, c.Args, c.Env, s.Pmon, server)
		},
		add: func(s Setup, entry string, srv Server) ([]string, error) {
			raw, err := json.Marshal(mcpCommand{Command: s.Pmon, Args: []string{"mcp", srv.Name}, Env: DaemonEnv()})
			if err != nil {
				return nil, err
			}
			var taken error
			var replaced []string
			err = withClaudeDesktopClosed(s.Confirm, func() error {
				return editDesktopServers(claudeDesktopConfig(), func(m map[string]json.RawMessage) {
					replaced = nil
					if prev, ok := m[entry]; ok && !replaceable(decodeEntry(prev), srv) {
						taken = &EntryError{App: "Claude Desktop", Entry: entry, Taken: true}
						return
					}
					for name, other := range m {
						if name != entry && replaceable(decodeEntry(other), srv) {
							delete(m, name)
							replaced = append(replaced, name)
						}
					}
					m[entry] = raw
				})
			})
			if err := cmp.Or(taken, err); err != nil {
				return nil, err
			}
			slices.Sort(replaced)
			return replaced, nil
		},
		remove: func(s Setup, entry, server string) (bool, error) {
			removed := false
			err := withClaudeDesktopClosed(s.Confirm, func() error {
				return editDesktopServers(claudeDesktopConfig(), func(m map[string]json.RawMessage) {
					var c mcpCommand
					removed = json.Unmarshal(m[entry], &c) == nil && ownCommand(c.Command, c.Args, server)
					if removed {
						delete(m, entry)
					}
				})
			})
			return removed && err == nil, err
		},
	}
}

// readDesktopServers returns the config's mcpServers and every other top-level key untouched, so an edit
// rewrites only the one entry it means to.
func readDesktopServers(path string) (servers, top map[string]json.RawMessage, err error) {
	top = map[string]json.RawMessage{}
	servers = map[string]json.RawMessage{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return servers, top, nil
	}
	if err != nil {
		return nil, nil, err
	}
	// Windows editors such as Notepad save JSON with a byte-order mark, which Claude Desktop accepts.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &top); err != nil || top == nil {
			return nil, nil, fmt.Errorf("%s is not a JSON object", path)
		}
	}
	if raw, ok := top["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil || servers == nil {
			return nil, nil, fmt.Errorf("mcpServers in %s is not an object", path)
		}
	}
	return servers, top, nil
}

// desktopMu serializes this process's own edits; the content check in writeDesktopConfig covers Claude Desktop's.
var desktopMu sync.Mutex

func editDesktopServers(path string, edit func(map[string]json.RawMessage)) error {
	desktopMu.Lock()
	defer desktopMu.Unlock()
	for range 3 {
		before, _ := os.ReadFile(path)
		servers, top, err := readDesktopServers(path)
		if err != nil {
			return err
		}
		edit(servers)
		ok, err := writeDesktopConfig(path, before, servers, top)
		if err != nil || ok {
			return err
		}
	}
	return fmt.Errorf("%s keeps changing; try again", path)
}

// writeDesktopConfig replaces the file only if it still holds before, so an edit made meanwhile by Claude
// Desktop or by hand is not overwritten. It reports false when the file changed.
func writeDesktopConfig(path string, before []byte, servers, top map[string]json.RawMessage) (bool, error) {
	raw, err := json.Marshal(servers)
	if err != nil {
		return false, err
	}
	top["mcpServers"] = raw
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".claude_desktop_config-*.json")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, before) {
		return false, nil
	}
	return true, os.Rename(tmp.Name(), path)
}

// --- Claude Code and Codex: their own `mcp add/get/remove` commands ---

// ownCommand reports whether a registered command is `pmon mcp <server>`, whichever pmon runs it: the CLI
// and Proxy Monster Desktop register different copies, and either may replace or remove the other's entry.
func ownCommand(command string, args []string, server string) bool {
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(command, `\`, "/")))
	if name != "pmon" && name != "pmon.exe" || len(args) == 0 || args[0] != "mcp" {
		return false
	}
	return len(args) == 2 && args[1] == server || len(args) == 1 && server == "default"
}

// entry is any MCP server entry in an AI app's config: a command it runs, or a URL it connects to.
type entry struct {
	URL     string   `json:"url" toml:"url"`
	Command string   `json:"command" toml:"command"`
	Args    []string `json:"args" toml:"args"`
}

func decodeEntry(raw json.RawMessage) entry {
	var e entry
	_ = json.Unmarshal(raw, &e)
	return e
}

// replaceable reports whether pmon's entry for srv may take e's place: e reaches srv's MCP endpoint over
// https, which pmon's relay replaces with the pmon login, or e is pmon's relay for srv already.
func replaceable(e entry, srv Server) bool {
	if e.URL != "" {
		return srv.URL != "" && sameEndpoint(e.URL, strings.TrimRight(srv.URL, "/")+"/mcp")
	}
	return ownCommand(e.Command, e.Args, srv.Name)
}

// sameEndpoint compares two URLs as an HTTP client would reach them: scheme and host in any case, a default
// port spelled out or not, and a trailing slash or not.
func sameEndpoint(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	norm := func(u *url.URL) string {
		scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
		if scheme == "https" && port == "443" || scheme == "http" && port == "80" {
			port = ""
		}
		return scheme + "://" + host + ":" + port + strings.TrimRight(u.EscapedPath(), "/") + "?" + u.RawQuery
	}
	return norm(ua) == norm(ub)
}

// ours reports whether the entry is pmon's, runs a pmon that exists, and reaches the daemon in use, which is
// what "connected" means: an entry written for another PMON_CONFIG_DIR would reach a different login.
func ours(command string, args []string, env map[string]string, pmon, server string) bool {
	if !ownCommand(command, args, server) || !maps.Equal(env, DaemonEnv()) {
		return false
	}
	if command == pmon {
		return true
	}
	fi, err := os.Stat(command)
	return err == nil && !fi.IsDir()
}

// parseClaudeGet reads the command, args and environment from `claude mcp get` output. Args are space-joined
// there, which is unambiguous for `mcp <server>` because a server name has no spaces.
func parseClaudeGet(out string) (string, []string, map[string]string) {
	var command string
	var args []string
	env := map[string]string{}
	inEnv := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case inEnv && strings.HasPrefix(line, "    ") && strings.Contains(trimmed, "="):
			k, v, _ := strings.Cut(trimmed, "=")
			env[k] = v
			continue
		case trimmed == "Environment:":
			inEnv = true
			continue
		}
		inEnv = false
		if v, ok := strings.CutPrefix(trimmed, "Command: "); ok {
			command = v
		} else if v, ok := strings.CutPrefix(trimmed, "Args: "); ok {
			args = strings.Fields(v)
		}
	}
	return command, args, env
}

func parseCodexGet(out string) (string, []string, map[string]string) {
	var got struct {
		Transport struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"transport"`
	}
	if json.Unmarshal([]byte(out), &got) != nil {
		return "", nil, nil
	}
	if got.Transport.Env == nil {
		got.Transport.Env = map[string]string{}
	}
	return got.Transport.Command, got.Transport.Args, got.Transport.Env
}

func cliApp(id, name, bin string, scope []string, file configFile) App {
	envFlag := "-e"
	if bin == "codex" {
		envFlag = "--env"
	}
	run := func(args ...string) (string, error) {
		path := findTool(bin)
		if path == "" {
			return "", &NotInstalledError{App: name}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := noConsole(exec.CommandContext(ctx, path, args...)).CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args[:2], " "), err, bytes.TrimSpace(out))
		}
		return string(out), nil
	}
	// lookup reports whether entry exists, and whether it is pmon's. A failed `get` (missing entry or a broken
	// CLI alike) reads as absent, so nothing is ever removed or replaced on its strength.
	lookup := func(s Setup, entry, server string) (exists, own, current bool) {
		get := []string{"mcp", "get", entry}
		parse := parseClaudeGet
		if bin == "codex" {
			get, parse = append(get, "--json"), parseCodexGet
		}
		out, err := run(get...)
		if err != nil {
			return false, false, false
		}
		command, args, env := parse(out)
		return true, ownCommand(command, args, server), ours(command, args, env, s.Pmon, server)
	}
	return App{
		ID: id, Name: name,
		installed: func() bool { return findTool(bin) != "" },
		connected: func(s Setup, entry, server string) bool {
			_, _, current := lookup(s, entry, server)
			return current
		},
		add: func(s Setup, entry string, srv Server) ([]string, error) {
			// The CLI lists no entries, so the others come from its config file; one it cannot read replaces none.
			others, _ := file.list()
			exists, own, _ := lookup(s, entry, srv.Name)
			if mine, ok := others[entry]; exists && !own && !(ok && replaceable(mine, srv)) {
				return nil, &EntryError{App: name, Entry: entry, Taken: true}
			}
			if exists {
				if _, err := run(append([]string{"mcp", "remove", entry}, scope...)...); err != nil {
					return nil, err
				}
			}
			add := append([]string{"mcp", "add"}, scope...)
			for k, v := range DaemonEnv() {
				add = append(add, envFlag, k+"="+v)
			}
			if _, err := run(append(add, entry, "--", s.Pmon, "mcp", srv.Name)...); err != nil {
				return nil, err
			}
			var replaced []string
			for _, other := range replaceableNames(others, entry, srv) {
				if _, err := run(append([]string{"mcp", "remove", other}, scope...)...); err != nil {
					return replaced, err
				}
				replaced = append(replaced, other)
			}
			return replaced, nil
		},
		remove: func(s Setup, entry, server string) (bool, error) {
			exists, own, _ := lookup(s, entry, server)
			switch {
			case !exists:
				return false, nil
			case !own:
				return false, &EntryError{App: name, Entry: entry}
			}
			_, err := run(append([]string{"mcp", "remove", entry}, scope...)...)
			return err == nil, err
		},
	}
}

// replaceableNames are the entries other than entry that pmon's entry for srv replaces, in a stable order.
func replaceableNames(entries map[string]entry, entry string, srv Server) []string {
	var names []string
	for name, e := range entries {
		if name != entry && replaceable(e, srv) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// findTool looks a command up where installers put it, then on PATH.
func findTool(name string) string {
	for _, dir := range toolDirs() {
		for _, n := range toolNames(name) {
			p := filepath.Join(dir, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() && isRunnable(fi) {
				return p
			}
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}
