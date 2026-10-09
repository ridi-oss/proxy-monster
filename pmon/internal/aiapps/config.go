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
	read   func(entry string) (cmd mcpCommand, found bool, err error)
	write  func(entry string, cmd mcpCommand) error
	delete func(entry string) error
}

func userHome() string { h, _ := os.UserHomeDir(); return h }

// claudeCodeConfig is ~/.claude.json, where `claude mcp add --scope user` keeps its servers.
func claudeCodeConfig() configFile {
	path := func() string { return filepath.Join(userHome(), ".claude.json") }
	return configFile{
		exists: func() bool { _, err := os.Stat(path()); return err == nil },
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

// codexConfig is ~/.codex/config.toml. It is read with a TOML parser but edited as text, one
// [mcp_servers.<entry>] table at a time, so the rest of the file keeps its formatting and comments.
func codexConfig() configFile {
	path := func() string { return filepath.Join(userHome(), ".codex", "config.toml") }
	return configFile{
		exists: func() bool { _, err := os.Stat(path()); return err == nil },
		read: func(entry string) (mcpCommand, bool, error) {
			data, err := os.ReadFile(path())
			if errors.Is(err, os.ErrNotExist) {
				return mcpCommand{}, false, nil
			}
			if err != nil {
				return mcpCommand{}, false, err
			}
			var doc struct {
				MCPServers map[string]struct {
					Command string            `toml:"command"`
					Args    []string          `toml:"args"`
					Env     map[string]string `toml:"env"`
				} `toml:"mcp_servers"`
			}
			if err := toml.Unmarshal(data, &doc); err != nil {
				return mcpCommand{}, false, fmt.Errorf("%s: %w", path(), err)
			}
			s, ok := doc.MCPServers[entry]
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

// codexTable is the TOML for one server, as `codex mcp add` would describe it.
func codexTable(entry string, cmd mcpCommand) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[mcp_servers.%s]\ncommand = %s\nargs = [", entry, tomlString(cmd.Command))
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

var tomlHeader = regexp.MustCompile(`^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$`)

// withoutTOMLTable removes the [mcp_servers.<entry>] table and its sub-tables (such as .env) from text.
func withoutTOMLTable(text, entry string) string {
	key := func(h string) string { return strings.ReplaceAll(strings.ReplaceAll(h, `"`, ""), " ", "") }
	own := "mcp_servers." + entry
	var out []string
	skipping := false
	for _, line := range strings.SplitAfter(text, "\n") {
		if m := tomlHeader.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
			k := key(m[1])
			skipping = k == own || strings.HasPrefix(k, own+".")
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
		add: func(s Setup, entry, server string) error {
			c, found, err := file.read(entry)
			if err != nil {
				return err
			}
			if found && !ownCommand(c.Command, c.Args, server) {
				return &EntryError{App: name, Entry: entry, Taken: true}
			}
			return file.write(entry, mcpCommand{Command: s.Pmon, Args: []string{"mcp", server}, Env: DaemonEnv()})
		},
		remove: func(s Setup, entry, server string) error {
			c, found, err := file.read(entry)
			switch {
			case err != nil:
				return err
			case !found:
				return nil
			case !ownCommand(c.Command, c.Args, server):
				return &EntryError{App: name, Entry: entry}
			}
			return file.delete(entry)
		},
	}
}

func envOrEmpty(env map[string]string) map[string]string {
	if env == nil {
		return map[string]string{}
	}
	return env
}
