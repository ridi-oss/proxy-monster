package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// claudeDesktopDir is where Claude Desktop keeps its config under a test's HOME.
func claudeDesktopDir(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	}
	return filepath.Join(home, ".config", "Claude")
}

func TestMCPInstallRegistersEveryServer(t *testing.T) {
	// Built before HOME moves: go build would fill the temporary HOME with read-only module files.
	e := newEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	dir := claudeDesktopDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cp := mcpFakeCP(t)
	e.mustRun(t, "server", "set", "hr", "--url", cp.URL)
	e.mustRun(t, "server", "set", "ops", "--url", cp.URL)

	if out, err := e.run("mcp", "--app", "claude-desktop"); err == nil || !strings.Contains(out, "--app goes with --install") {
		t.Errorf("--app without --install: err=%v\n%s", err, out)
	}
	if out, err := e.run("mcp", "hr", "ops"); err == nil || !strings.Contains(out, "the relay takes one server") {
		t.Errorf("two servers without --install: err=%v\n%s", err, out)
	}
	if out, err := e.run("mcp", "--install", "--app", "claude-desktop", "nope"); err == nil || !strings.Contains(out, `unknown server "nope"`) {
		t.Errorf("an unknown server: err=%v\n%s", err, out)
	}

	seed := `{"mcpServers":{"pm-hr":{"url":"` + cp.URL + `/mcp"},"keep":{"command":"npx","args":[]}}}`
	if err := os.WriteFile(filepath.Join(dir, "claude_desktop_config.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := e.mustRun(t, "mcp", "--install", "--app", "claude-desktop"); !strings.Contains(out, "added proxy-monster-hr, replacing pm-hr") {
		t.Errorf("install output does not report the replaced https entry:\n%s", out)
	}
	servers := readDesktopServers(t, dir)
	if servers["pm-hr"] != nil || servers["keep"] == nil {
		t.Errorf("after install: %v", servers)
	}
	for _, entry := range []string{"proxy-monster-hr", "proxy-monster-ops"} {
		var c struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		}
		if err := json.Unmarshal(servers[entry], &c); err != nil {
			t.Fatalf("%s: %v in %v", entry, err, servers)
		}
		if !sameFile(c.Command, e.bin) || c.Args[0] != "mcp" || c.Env["PMON_CONFIG_DIR"] != e.stateDir {
			t.Errorf("%s = %+v, want this pmon reaching this daemon", entry, c)
		}
	}

	e.mustRun(t, "mcp", "--uninstall", "--app", "claude-desktop", "hr")
	if servers := readDesktopServers(t, dir); servers["proxy-monster-hr"] != nil || servers["proxy-monster-ops"] == nil {
		t.Errorf("after uninstalling hr: %v", servers)
	}
	if out := e.mustRun(t, "mcp", "--uninstall", "--app", "claude-desktop", "hr"); !strings.Contains(out, "no proxy-monster-hr to remove") {
		t.Errorf("uninstalling hr again:\n%s", out)
	}
}

func readDesktopServers(t *testing.T, dir string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "claude_desktop_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.MCPServers
}
