package aiapps

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// An AI app's own config file, edited directly when its CLI is not installed: the Claude and Codex desktop apps
// on Windows read the same files their CLIs write, but ship no CLI.
type configFile struct {
	exists func() bool
	list   func() (map[string]entry, error)
	read   func(entry string) (cmd mcpCommand, found bool, err error)
	write  func(entry string, cmd mcpCommand) error
	delete func(entry string) error
}

func userHome() string { h, _ := os.UserHomeDir(); return h }

// claudeCodeConfig is where `claude mcp add --scope user` keeps its servers: .claude.json in CLAUDE_CONFIG_DIR,
// or in the home directory.
func claudeCodeConfig() configFile {
	path := claudeCodePath
	return configFile{
		exists: func() bool { _, err := os.Stat(path()); return err == nil },
		list: func() (map[string]entry, error) {
			servers, _, err := readDesktopServers(path())
			if err != nil {
				return nil, err
			}
			entries := map[string]entry{}
			for name, raw := range servers {
				entries[name] = decodeEntry(raw)
			}
			return entries, nil
		},
		read: func(entry string) (mcpCommand, bool, error) {
			servers, _, err := readDesktopServers(path())
			if err != nil {
				return mcpCommand{}, false, err
			}
			var c mcpCommand
			raw, ok := servers[entry]
			if !ok {
				return c, false, nil
			}
			return c, true, json.Unmarshal(raw, &c)
		},
		write: func(entry string, cmd mcpCommand) error {
			cmd.Type = "stdio"
			raw, err := json.Marshal(cmd)
			if err != nil {
				return err
			}
			return editDesktopServers(path(), func(m map[string]json.RawMessage) { m[entry] = raw })
		},
		delete: func(entry string) error {
			return editDesktopServers(path(), func(m map[string]json.RawMessage) { delete(m, entry) })
		},
	}
}

func claudeCodePath() string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, ".claude.json")
	}
	return filepath.Join(userHome(), ".claude.json")
}

// codexConfig is config.toml in CODEX_HOME, or in ~/.codex. It is read with a TOML parser but edited as text,
// one [mcp_servers.<entry>] table at a time, so the rest of the file keeps its formatting and comments.
func codexConfig() configFile {
	path := func() string {
		if dir := os.Getenv("CODEX_HOME"); dir != "" {
			return filepath.Join(dir, "config.toml")
		}
		return filepath.Join(userHome(), ".codex", "config.toml")
	}
	return configFile{
		exists: func() bool { _, err := os.Stat(path()); return err == nil },
		list: func() (map[string]entry, error) {
			servers, err := readCodexServers(path())
			if err != nil {
				return nil, err
			}
			entries := map[string]entry{}
			for name, s := range servers {
				entries[name] = entry{URL: s.URL, Command: s.Command, Args: s.Args}
			}
			return entries, nil
		},
		read: func(entry string) (mcpCommand, bool, error) {
			servers, err := readCodexServers(path())
			if err != nil {
				return mcpCommand{}, false, err
			}
			s, ok := servers[entry]
			return mcpCommand{Command: s.Command, Args: s.Args, Env: s.Env}, ok, nil
		},
		write: func(entry string, cmd mcpCommand) error {
			return editText(path(), func(text string) string {
				return strings.TrimRight(withoutTOMLTable(text, entry), "\n") + "\n\n" + codexTable(entry, cmd)
			})
		},
		delete: func(entry string) error {
			return editText(path(), func(text string) string { return withoutTOMLTable(text, entry) })
		},
	}
}

type codexServer struct {
	URL     string            `toml:"url"`
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
}

func readCodexServers(path string) (map[string]codexServer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]codexServer `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc.MCPServers, nil
}

// codexTable is the TOML for one server, as `codex mcp add` would describe it.
func codexTable(entry string, cmd mcpCommand) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[mcp_servers.%s]\ncommand = %s\nargs = [", tomlKey(entry), tomlString(cmd.Command))
	for i, a := range cmd.Args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(tomlString(a))
	}
	b.WriteString("]\n")
	if len(cmd.Env) > 0 {
		keys := make([]string, 0, len(cmd.Env))
		for k := range cmd.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("env = { ")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s = %s", k, tomlString(cmd.Env[k]))
		}
		b.WriteString(" }\n")
	}
	return b.String()
}

// tomlString quotes s as a TOML basic string; its escapes are JSON's, which strconv.Quote does not always produce.
func tomlString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// tomlKey is entry as one TOML key: quoted unless it is a bare key, since a dot would otherwise split it.
func tomlKey(entry string) string {
	if bareKey.MatchString(entry) {
		return entry
	}
	return tomlString(entry)
}

var tomlHeader = regexp.MustCompile(`^\s*\[\[?(.+?)\]\]?\s*(#.*)?$`)

// tomlKeyPath splits a table header's dotted key into its keys, unquoting each; ok is false when it is not one.
func tomlKeyPath(header string) (keys []string, ok bool) {
	rest := strings.TrimSpace(header)
	for {
		var k string
		switch {
		case strings.HasPrefix(rest, `"`):
			end := 1
			for end < len(rest) && (rest[end] != '"' || rest[end-1] == '\\') {
				end++
			}
			if end == len(rest) || json.Unmarshal([]byte(rest[:end+1]), &k) != nil {
				return nil, false
			}
			rest = rest[end+1:]
		case strings.HasPrefix(rest, "'"):
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				return nil, false
			}
			k, rest = rest[1:end+1], rest[end+2:]
		default:
			end := strings.IndexAny(rest, ". \t")
			if end < 0 {
				end = len(rest)
			}
			k, rest = rest[:end], rest[end:]
			if !bareKey.MatchString(k) {
				return nil, false
			}
		}
		keys = append(keys, k)
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return keys, true
		}
		if rest[0] != '.' {
			return nil, false
		}
		rest = strings.TrimSpace(rest[1:])
	}
}

// withoutTOMLTable removes the [mcp_servers.<entry>] table and its sub-tables (such as .env) from text.
func withoutTOMLTable(text, entry string) string {
	var out []string
	skipping := false
	for _, line := range strings.SplitAfter(text, "\n") {
		if m := tomlHeader.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
			keys, ok := tomlKeyPath(m[1])
			skipping = ok && len(keys) >= 2 && keys[0] == "mcp_servers" && keys[1] == entry
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.Join(out, "")
}

// editText rewrites a file through edit, keeping its permissions; it creates the file when missing.
func editText(path string, edit func(string) string) error {
	before, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	after := edit(string(bytes.TrimPrefix(before, []byte("\xef\xbb\xbf"))))
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(after); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// configApp is an AI app whose CLI is missing but whose config file is present.
func configApp(id, name string, file configFile) App {
	return App{
		ID: id, Name: name,
		installed: file.exists,
		connected: func(s Setup, entry, server string) bool {
			c, found, err := file.read(entry)
			return err == nil && found && ours(c.Command, c.Args, envOrEmpty(c.Env), s.Pmon, server)
		},
		add: func(s Setup, entry string, srv Server) ([]string, error) {
			others, err := file.list()
			if err != nil {
				return nil, err
			}
			if mine, ok := others[entry]; ok && !replaceable(mine, srv) {
				return nil, &EntryError{App: name, Entry: entry, Taken: true}
			}
			if err := file.write(entry, mcpCommand{Command: s.Pmon, Args: []string{"mcp", srv.Name}, Env: DaemonEnv()}); err != nil {
				return nil, err
			}
			var replaced []string
			for _, other := range replaceableNames(others, entry, srv) {
				if err := file.delete(other); err != nil {
					return replaced, err
				}
				replaced = append(replaced, other)
			}
			return replaced, nil
		},
		remove: func(s Setup, entry, server string) (bool, error) {
			entries, err := file.list()
			if err != nil {
				return false, err
			}
			mine, found := entries[entry]
			if found && (mine.URL != "" || !ownCommand(mine.Command, mine.Args, server)) {
				return false, &EntryError{App: name, Entry: entry}
			}
			names := relayNames(entries, entry, server)
			if found {
				names = append([]string{entry}, names...)
			}
			for i, n := range names {
				if err := file.delete(n); err != nil {
					return i > 0, err
				}
			}
			return len(names) > 0, nil
		},
	}
}

func envOrEmpty(env map[string]string) map[string]string {
	if env == nil {
		return map[string]string{}
	}
	return env
}
