package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// aiApp is an app that can run `pmon mcp <server>` as a local MCP server.
type aiApp struct {
	id   string
	name string
	// after tells the user what to do once the server is added.
	after string
	// installed, connected, add and remove act on the app's own configuration.
	installed func() bool
	connected func(entry, pmon, server string) bool
	add       func(entry, pmon, server string) error
	remove    func(entry, pmon, server string) error // only an entry that is this app's
}

func aiApps() []aiApp {
	return []aiApp{claudeDesktop(), cliApp("claude-code", "Claude Code", "claude", T("ai.after.claude-code"),
		[]string{"--scope", "user"}), cliApp("codex", "Codex", "codex", T("ai.after.codex"), nil)}
}

// mcpEntryName is the name a server is registered under in an AI app's MCP settings.
func mcpEntryName(server string) string {
	if server == "default" {
		return "proxy-monster"
	}
	return "proxy-monster-" + server
}

// bundledPmon is the pmon shipped beside this executable: an AI app launches it directly, so it must be a path
// that survives the app being updated in place.
func bundledPmon() string {
	exe, err := os.Executable()
	if err != nil {
		return "pmon"
	}
	return filepath.Join(filepath.Dir(exe), "pmon")
}

// --- Claude Desktop: claude_desktop_config.json ---

func claudeDesktopConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
}

type mcpCommand struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// daemonEnv is the environment that selects which pmon daemon this app uses. An AI app starts `pmon mcp` with
// its own environment, so a tray pointed at a non-default daemon passes the same settings along; otherwise the
// entry would reach a different daemon, one without this server.
func daemonEnv() map[string]string {
	env := map[string]string{}
	for _, k := range []string{"PMON_CONFIG_DIR", "PMON_PORT_BASE"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	return env
}

func claudeDesktop() aiApp {
	return aiApp{
		id: "claude-desktop", name: "Claude Desktop", after: T("ai.after.claude-desktop"),
		installed: func() bool {
			if _, err := os.Stat("/Applications/Claude.app"); err == nil {
				return true
			}
			_, err := os.Stat(filepath.Dir(claudeDesktopConfig()))
			return err == nil
		},
		connected: func(entry, pmon, server string) bool {
			servers, _, err := readDesktopServers(claudeDesktopConfig())
			if err != nil {
				return false
			}
			var c mcpCommand
			return json.Unmarshal(servers[entry], &c) == nil && ours(c.Command, c.Args, pmon, server) &&
				maps.Equal(c.Env, daemonEnv())
		},
		add: func(entry, pmon, server string) error {
			raw, err := json.Marshal(mcpCommand{Command: pmon, Args: []string{"mcp", server}, Env: daemonEnv()})
			if err != nil {
				return err
			}
			var taken error
			err = editDesktopServers(claudeDesktopConfig(), func(m map[string]json.RawMessage) {
				var c mcpCommand
				if prev, ok := m[entry]; ok && (json.Unmarshal(prev, &c) != nil || c.Command != pmon) {
					taken = errors.New(T("ai.taken", "app", "Claude Desktop", "entry", entry))
					return
				}
				m[entry] = raw
			})
			return cmp.Or(taken, err)
		},
		remove: func(entry, pmon, server string) error {
			return editDesktopServers(claudeDesktopConfig(), func(m map[string]json.RawMessage) {
				var c mcpCommand
				if json.Unmarshal(m[entry], &c) == nil && ours(c.Command, c.Args, pmon, server) {
					delete(m, entry)
				}
			})
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

// desktopMu serializes this app's own edits; the content check in writeIfUnchanged covers Claude Desktop's.
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

// ours reports whether a registered command is this app's `pmon mcp <server>`.
func ours(command string, args []string, pmon, server string) bool {
	return command == pmon && len(args) == 2 && args[0] == "mcp" && args[1] == server
}

// parseClaudeGet reads the command and args from `claude mcp get` output. Args are space-joined there, which
// is unambiguous for `mcp <server>` because a server name has no spaces.
func parseClaudeGet(out string) (string, []string) {
	var command string
	var args []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Command: "); ok {
			command = v
		} else if v, ok := strings.CutPrefix(line, "Args: "); ok {
			args = strings.Fields(v)
		}
	}
	return command, args
}

func parseCodexGet(out string) (string, []string) {
	var got struct {
		Transport struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"transport"`
	}
	if json.Unmarshal([]byte(out), &got) != nil {
		return "", nil
	}
	return got.Transport.Command, got.Transport.Args
}

func cliApp(id, name, bin, after string, scope []string) aiApp {
	envFlag := "-e"
	if bin == "codex" {
		envFlag = "--env"
	}
	run := func(args ...string) (string, error) {
		path := findTool(bin)
		if path == "" {
			return "", errors.New(T("ai.notInstalled", "app", name))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args[:2], " "), err, bytes.TrimSpace(out))
		}
		return string(out), nil
	}
	// lookup reports whether entry exists, and whether it is this app's.
	lookup := func(entry, pmon, server string) (exists, mine bool) {
		get := []string{"mcp", "get", entry}
		parse := parseClaudeGet
		if bin == "codex" {
			get, parse = append(get, "--json"), parseCodexGet
		}
		out, err := run(get...)
		if err != nil {
			return false, false
		}
		command, args := parse(out)
		return true, ours(command, args, pmon, server)
	}
	return aiApp{
		id: id, name: name, after: after,
		installed: func() bool { return findTool(bin) != "" },
		connected: func(entry, pmon, server string) bool {
			_, mine := lookup(entry, pmon, server)
			return mine
		},
		add: func(entry, pmon, server string) error {
			exists, mine := lookup(entry, pmon, server)
			if exists && !mine {
				return errors.New(T("ai.taken", "app", name, "entry", entry))
			}
			if exists {
				if _, err := run(append([]string{"mcp", "remove", entry}, scope...)...); err != nil {
					return err
				}
			}
			add := append([]string{"mcp", "add"}, scope...)
			for k, v := range daemonEnv() {
				add = append(add, envFlag, k+"="+v)
			}
			_, err := run(append(add, entry, "--", pmon, "mcp", server)...)
			return err
		},
		remove: func(entry, pmon, server string) error {
			if exists, mine := lookup(entry, pmon, server); exists && !mine {
				return errors.New(T("ai.notOurs", "app", name, "entry", entry))
			}
			_, err := run(append([]string{"mcp", "remove", entry}, scope...)...)
			return err
		},
	}
}

// findTool looks a command up where installers put it. An app opened from Finder gets a minimal PATH without
// ~/.local/bin or Homebrew, so PATH alone would miss both.
func findTool(name string) string {
	home, _ := os.UserHomeDir()
	for _, dir := range []string{filepath.Join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".npm-global", "bin")} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// refreshAI re-reads which servers each installed AI app uses, when forced or when the set of servers changed,
// and redraws the menu if anything differs.
func (a *app) refreshAI(force bool) {
	a.mu.Lock()
	s := a.status
	a.mu.Unlock()
	var servers []string
	if s != nil {
		for _, srv := range s.Servers {
			servers = append(servers, srv.Name)
		}
	}
	key := fmt.Sprint(servers)
	if force {
		a.aiMu.Lock()
	} else if !a.aiMu.TryLock() {
		return
	}
	defer a.aiMu.Unlock()
	a.mu.Lock()
	same := a.aiServers == key && a.ai != nil
	a.mu.Unlock()
	if same && !force {
		return
	}
	pmon := bundledPmon()
	var states []aiState
	for _, app := range aiApps() {
		if !app.installed() {
			continue
		}
		st := aiState{id: app.id, name: app.name, connected: map[string]bool{}}
		for _, server := range servers {
			st.connected[server] = app.connected(mcpEntryName(server), pmon, server)
		}
		states = append(states, st)
	}
	a.mu.Lock()
	changed := fmt.Sprint(states) != fmt.Sprint(a.ai) || a.ai == nil
	a.ai, a.aiServers = states, key
	if a.ai == nil {
		a.ai = []aiState{}
	}
	a.mu.Unlock()
	if changed {
		a.renderMu.Lock()
		a.redraw()
		a.renderMu.Unlock()
	}
}

func (a *app) doAIApp(act action) {
	var app *aiApp
	for _, candidate := range aiApps() {
		if candidate.id == act.app {
			app = &candidate
		}
	}
	if app == nil {
		return
	}
	entry := mcpEntryName(act.server)
	if act.connect {
		if err := app.add(entry, bundledPmon(), act.server); err != nil {
			notify(T("n.aiAddFailed", "server", act.server, "app", app.name), err.Error())
		} else {
			notify(T("n.aiAdded", "server", act.server, "app", app.name), app.after)
		}
	} else if err := app.remove(entry, bundledPmon(), act.server); err != nil {
		notify(T("n.aiRemoveFailed", "server", act.server, "app", app.name), err.Error())
	} else {
		notify(T("n.aiRemoved", "server", act.server, "app", app.name), "")
	}
	a.refreshAI(true)
}
