package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if out := e.mustRun(t, "mcp", "--install", "--app", "claude-desktop"); !strings.Contains(out, "added pmon-hr, replacing pm-hr") {
		t.Errorf("install output does not report the replaced https entry:\n%s", out)
	}
	servers := readDesktopServers(t, dir)
	if servers["pm-hr"] != nil || servers["keep"] == nil {
		t.Errorf("after install: %v", servers)
	}
	for entry, server := range map[string]string{"pmon-hr": "hr", "pmon-ops": "ops"} {
		var c struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		}
		if err := json.Unmarshal(servers[entry], &c); err != nil {
			t.Fatalf("%s: %v in %v", entry, err, servers)
		}
		if !sameFile(c.Command, e.bin) || strings.Join(c.Args, " ") != "mcp "+server || c.Env["PMON_CONFIG_DIR"] != e.stateDir {
			t.Errorf("%s = %+v, want this pmon reaching this daemon", entry, c)
		}
	}

	e.mustRun(t, "mcp", "--uninstall", "--app", "claude-desktop", "hr")
	if servers := readDesktopServers(t, dir); servers["pmon-hr"] != nil || servers["pmon-ops"] == nil {
		t.Errorf("after uninstalling hr: %v", servers)
	}
	if out := e.mustRun(t, "mcp", "--uninstall", "--app", "claude-desktop", "hr"); !strings.Contains(out, "no pmon mcp hr to remove") {
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

// The entry is named after the pmon server, and replaces the https entry for the MCP URL the server advertises.
func TestMCPInstallUsesTheAdvertisedMCPURL(t *testing.T) {
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
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/instance" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"name":"hr-pmon","version":"0.1.31","mcpUrl":"http://` + r.Host + `/custom-mcp","installName":"pmon-hr-pmon"}`))
	}))
	t.Cleanup(cp.Close)
	seed := `{"mcpServers":{"hr-https":{"url":"` + cp.URL + `/custom-mcp"},"other-https":{"url":"https://other.example.com/mcp"}}}`
	if err := os.WriteFile(filepath.Join(dir, "claude_desktop_config.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustRun(t, "server", "set", "hr", "--url", cp.URL)
	if out := e.mustRun(t, "mcp", "--install", "--app", "claude-desktop"); !strings.Contains(out, "added pmon-hr, replacing hr-https") {
		t.Errorf("install output:\n%s", out)
	}
	if out := e.mustRun(t, "mcp", "--uninstall", "--app", "claude-desktop"); !strings.Contains(out, "removed pmon mcp hr") {
		t.Errorf("uninstall output:\n%s", out)
	}
	if servers := readDesktopServers(t, dir); len(servers) != 1 || servers["other-https"] == nil {
		t.Errorf("after uninstall: %v", servers)
	}
}

// A renamed server keeps its login, port and default, and its AI-app entries move with it.
func TestServerRenameMovesEverything(t *testing.T) {
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
	cp := fakeCP(t, []map[string]any{{"name": "acme-mysql", "engine": "mysql", "dbName": "app", "advertiseAddr": dummyProxy(t)}})
	e.mustRun(t, "login", "--url", cp.URL, "dev")
	e.mustRun(t, "mcp", "--install", "--app", "claude-desktop")
	// An https entry for the server, added after the install: a rename moves pmon's entry without replacing it.
	cfg := filepath.Join(dir, "claude_desktop_config.json")
	installed := readDesktopServers(t, dir)
	installed["dev-https"] = json.RawMessage(`{"url":"` + cp.URL + `/mcp"}`)
	data, _ := json.Marshal(map[string]any{"mcpServers": installed})
	if err := os.WriteFile(cfg, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before := e.mustRun(t, "show", "acme-mysql")

	if out, err := e.run("server", "rename", "dev"); err == nil || !strings.Contains(out, "does not advertise a name") {
		t.Errorf("rename to an unadvertised name: %v\n%s", err, out)
	}
	out := e.mustRun(t, "server", "rename", "dev", "staging")
	if !strings.Contains(out, `server "dev" renamed to "staging"`) || !strings.Contains(out, "Claude Desktop: now runs pmon mcp staging as pmon-staging") {
		t.Errorf("rename output:\n%s", out)
	}
	if got := strings.TrimSpace(e.mustRun(t, "server", "default")); got != "staging" {
		t.Errorf("default after rename = %q", got)
	}
	if after := e.mustRun(t, "show", "acme-mysql"); after != before {
		t.Errorf("connection string changed across the rename:\n%s\n%s", before, after)
	}
	servers := readDesktopServers(t, dir)
	var c struct {
		Args []string `json:"args"`
	}
	if _, old := servers["pmon-dev"]; old || servers["dev-https"] == nil || json.Unmarshal(servers["pmon-staging"], &c) != nil || strings.Join(c.Args, " ") != "mcp staging" {
		t.Errorf("Claude Desktop entries after rename: %v", servers)
	}
}
