//go:build !windows

package aiapps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCLI installs a CLI that logs its arguments and fails the subcommands in fail, where findTool looks first.
func fakeCLI(t *testing.T, name string, fail ...string) (log string) {
	t.Helper()
	dir := filepath.Join(userHome(), ".local", "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log = filepath.Join(t.TempDir(), "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\ncase \" " + strings.Join(fail, " ") + " \" in *\" $2 \"*) exit 1;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return log
}

// When claude fails to add pmon's entry, the https entry it removed to make room is put back.
func TestClaudeAddFailurePutsTheOldEntryBack(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("PATH", "/usr/bin:/bin")
	prev := `{"type":"http","url":"https://pm.example.com/mcp"}`
	if err := os.WriteFile(claudeCodePath(), []byte(`{"mcpServers":{"pmon-acme":`+prev+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	log := fakeCLI(t, "claude", "add")
	app := cliApp("claude-code", "Claude Code", "claude", []string{"--scope", "user"}, claudeCodeConfig())
	if _, err := app.Add(Setup{Pmon: "/pmon"}, acme); err == nil {
		t.Fatal("the add failed, but Add reported success")
	}
	data, _ := os.ReadFile(log)
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "mcp remove pmon-acme") ||
		calls[2] != "mcp add-json pmon-acme "+prev+" --scope user" {
		t.Errorf("claude was run as:\n%s", data)
	}
}

// When putting the old entry back fails too, the error says so: the app has neither entry.
func TestClaudeFailedPutBackIsReported(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("PATH", "/usr/bin:/bin")
	if err := os.WriteFile(claudeCodePath(), []byte(`{"mcpServers":{"pmon-acme":{"type":"http","url":"https://pm.example.com/mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeCLI(t, "claude", "add", "add-json")
	app := cliApp("claude-code", "Claude Code", "claude", []string{"--scope", "user"}, claudeCodeConfig())
	if _, err := app.Add(Setup{Pmon: "/pmon"}, acme); err == nil || !strings.Contains(err.Error(), "putting the previous pmon-acme back also failed") {
		t.Errorf("err = %v", err)
	}
}
