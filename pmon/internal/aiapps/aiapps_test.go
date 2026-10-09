package aiapps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// setHome points every per-user directory the AI apps use at dir: HOME on macOS, the profile and app-data
// directories on Windows.
func setHome(t *testing.T, dir string) {
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(dir, "AppData", "Local"))
}

// Adding and removing proxy-monster must leave every other setting in Claude Desktop's config untouched.
func TestClaudeDesktopEditKeepsOtherSettings(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	path := claudeDesktopConfig()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	orig := `{"globalShortcut":"Alt+Space","mcpServers":{"other":{"command":"npx","args":["x"],"env":{"K":"V"}}}}`
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	app := claudeDesktop()
	pmon := "/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon"

	if app.connected(Setup{Pmon: pmon}, "proxy-monster-acme", "acme") {
		t.Fatal("connected before adding")
	}
	if err := app.add(Setup{Pmon: pmon}, "proxy-monster-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	if !app.connected(Setup{Pmon: pmon}, "proxy-monster-acme", "acme") {
		t.Fatal("not connected after adding")
	}
	if app.connected(Setup{Pmon: "/elsewhere/pmon"}, "proxy-monster-acme", "acme") {
		t.Error("an entry for another pmon reads as connected")
	}

	var got struct {
		GlobalShortcut string                     `json:"globalShortcut"`
		MCPServers     map[string]json.RawMessage `json:"mcpServers"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var other bytes.Buffer
	_ = json.Compact(&other, got.MCPServers["other"])
	if got.GlobalShortcut != "Alt+Space" || other.String() != `{"command":"npx","args":["x"],"env":{"K":"V"}}` {
		t.Errorf("other settings changed: %s", data)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want the original 0640", fi.Mode().Perm())
	}

	if err := app.remove(Setup{Pmon: pmon}, "proxy-monster-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	var after map[string]map[string]json.RawMessage
	_ = json.Unmarshal(data, &after)
	if _, ok := after["mcpServers"]["proxy-monster-acme"]; ok || len(after["mcpServers"]) != 1 {
		t.Errorf("after remove: %s", data)
	}
}

func TestClaudeDesktopAddCreatesTheConfig(t *testing.T) {
	setHome(t, t.TempDir())
	if err := claudeDesktop().add(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default"); err != nil {
		t.Fatal(err)
	}
	if !claudeDesktop().connected(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default") {
		t.Fatal("not connected after creating the config")
	}
}

// A config Claude Desktop cannot parse either must not be overwritten with one that drops its contents.
func TestClaudeDesktopRefusesABrokenConfig(t *testing.T) {
	setHome(t, t.TempDir())
	path := claudeDesktopConfig()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(`{"mcpServers": {`), 0o600)
	if err := claudeDesktop().add(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default"); err == nil {
		t.Fatal("added to an unparseable config")
	}
	if data, _ := os.ReadFile(path); string(data) != `{"mcpServers": {` {
		t.Errorf("the broken config was rewritten: %s", data)
	}
}

// JSON null is valid JSON but not a config; it must be refused, not crash the app.
func TestClaudeDesktopRefusesNull(t *testing.T) {
	for _, body := range []string{`null`, `{"mcpServers":null}`} {
		setHome(t, t.TempDir())
		path := claudeDesktopConfig()
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = os.WriteFile(path, []byte(body), 0o600)
		if err := claudeDesktop().add(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default"); err == nil {
			t.Errorf("%s: added to a config that is not an object", body)
		}
	}
}

func TestClaudeDesktopConcurrentAddsKeepEveryEntry(t *testing.T) {
	setHome(t, t.TempDir())
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := claudeDesktop().add(Setup{Pmon: "/p/pmon"}, fmt.Sprintf("e%d", i), fmt.Sprintf("s%d", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	servers, _, err := readDesktopServers(claudeDesktopConfig())
	if err != nil || len(servers) != 20 {
		t.Fatalf("%d entries after 20 concurrent adds (err %v)", len(servers), err)
	}
}

// An entry with the same name that something else added is neither shown as connected, overwritten, nor removed.
func TestClaudeDesktopLeavesAForeignEntryAlone(t *testing.T) {
	setHome(t, t.TempDir())
	path := claudeDesktopConfig()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	foreign := `{"mcpServers":{"proxy-monster":{"command":"/usr/bin/false","args":[]}}}`
	_ = os.WriteFile(path, []byte(foreign), 0o600)
	app := claudeDesktop()
	if app.connected(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default") {
		t.Error("a foreign entry reads as connected")
	}
	if err := app.add(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default"); err == nil {
		t.Error("add overwrote a foreign entry")
	}
	if err := app.remove(Setup{Pmon: "/p/pmon"}, "proxy-monster", "default"); err != nil {
		t.Fatal(err)
	}
	servers, _, _ := readDesktopServers(path)
	if _, ok := servers["proxy-monster"]; !ok {
		t.Error("remove deleted a foreign entry")
	}
}

func TestCLIGetParsing(t *testing.T) {
	pmon := "/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon"
	claude := "proxy-monster-acme:\n  Scope: User config (available in all your projects)\n  Type: stdio\n  Command: " + pmon + "\n  Args: mcp acme\n  Environment:\n"
	if c, a, e := parseClaudeGet(claude); !ours(c, a, e, pmon, "acme") {
		t.Errorf("claude output parsed as %q %q", c, a)
	}
	codex := `{"name":"proxy-monster-acme","transport":{"type":"stdio","command":"` + pmon + `","args":["mcp","acme"]}}`
	if c, a, e := parseCodexGet(codex); !ours(c, a, e, pmon, "acme") {
		t.Errorf("codex output parsed as %q %q", c, a)
	}
	if c, a, e := parseCodexGet(`{"transport":{"command":"/usr/bin/false","args":[]}}`); ours(c, a, e, pmon, "acme") {
		t.Error("a foreign codex entry reads as ours")
	}
}

// A tray using a non-default daemon hands its settings to the entry, so the AI app reaches the same daemon.
func TestClaudeDesktopEntryCarriesTheDaemonSettings(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("PMON_CONFIG_DIR", "/tmp/pmd-test")
	t.Setenv("PMON_PORT_BASE", "46500")
	if err := claudeDesktop().add(Setup{Pmon: "/p/pmon"}, "proxy-monster-ridi", "ridi"); err != nil {
		t.Fatal(err)
	}
	servers, _, _ := readDesktopServers(claudeDesktopConfig())
	var c mcpCommand
	_ = json.Unmarshal(servers["proxy-monster-ridi"], &c)
	if c.Env["PMON_CONFIG_DIR"] != "/tmp/pmd-test" || c.Env["PMON_PORT_BASE"] != "46500" {
		t.Errorf("entry env = %v", c.Env)
	}
	if !claudeDesktop().connected(Setup{Pmon: "/p/pmon"}, "proxy-monster-ridi", "ridi") {
		t.Error("an entry with env does not read as connected")
	}
	// An entry written for another daemon reads as not connected, so a click rewrites it.
	t.Setenv("PMON_CONFIG_DIR", "")
	t.Setenv("PMON_PORT_BASE", "")
	if claudeDesktop().connected(Setup{Pmon: "/p/pmon"}, "proxy-monster-ridi", "ridi") {
		t.Error("an entry for another daemon reads as connected")
	}
}

// An entry this app wrote for another daemon (another PMON_CONFIG_DIR) is its own to replace, but not connected.
func TestCLIEntryForAnotherDaemonIsNotConnected(t *testing.T) {
	pmon := "/p/pmon"
	claude := "x:\n  Command: /p/pmon\n  Args: mcp acme\n  Environment:\n    PMON_CONFIG_DIR=/tmp/a\n    PMON_PORT_BASE=46500\n\nTo remove this server, run: claude mcp remove x -s user\n"
	c, a, e := parseClaudeGet(claude)
	if e["PMON_CONFIG_DIR"] != "/tmp/a" || e["PMON_PORT_BASE"] != "46500" {
		t.Fatalf("env = %v", e)
	}
	if ours(c, a, e, pmon, "acme") {
		t.Error("an entry for /tmp/a reads as connected to the default daemon")
	}
	if !ownCommand(c, a, "acme") {
		t.Error("this app's own entry is not recognized as its own")
	}
	t.Setenv("PMON_CONFIG_DIR", "/tmp/a")
	t.Setenv("PMON_PORT_BASE", "46500")
	if !ours(c, a, e, pmon, "acme") {
		t.Error("an entry for the daemon in use does not read as connected")
	}
}

func TestClaudeDesktopConfigWithAByteOrderMark(t *testing.T) {
	setHome(t, t.TempDir())
	path := claudeDesktopConfig()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\xef\xbb\xbf{\"globalShortcut\":\"Alt+Space\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := claudeDesktop().add(Setup{Pmon: "/pmon"}, "proxy-monster-acme", "acme"); err != nil {
		t.Fatalf("add on a config with a BOM: %v", err)
	}
	data, _ := os.ReadFile(path)
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) || !bytes.Contains(data, []byte("Alt+Space")) || !bytes.Contains(data, []byte("proxy-monster-acme")) {
		t.Errorf("config after add: %s", data)
	}
}

// The CLI and Proxy Monster Desktop register different copies of pmon; each treats the other's entry as pmon's.
func TestAnotherPmonsEntryIsPmons(t *testing.T) {
	setHome(t, t.TempDir())
	other := filepath.Join(t.TempDir(), "pmon")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := claudeDesktop()
	if err := app.Add(Setup{Pmon: other}, "acme"); err != nil {
		t.Fatal(err)
	}
	bundled := Setup{Pmon: "/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon"}
	if !app.Connected(bundled, "acme") {
		t.Error("an entry for another pmon that exists does not read as connected")
	}
	if err := app.Add(bundled, "acme"); err != nil {
		t.Fatalf("replacing another pmon's entry: %v", err)
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if !app.Connected(bundled, "acme") {
		t.Error("the replaced entry does not run the bundled pmon")
	}
	if err := app.Add(Setup{Pmon: other}, "acme"); err != nil {
		t.Fatal(err)
	}
	if app.Connected(bundled, "acme") {
		t.Error("an entry for a pmon that no longer exists reads as connected")
	}
	if err := app.Remove(bundled, "acme"); err != nil {
		t.Fatal(err)
	}
	if servers, _, _ := readDesktopServers(claudeDesktopConfig()); len(servers) != 0 {
		t.Errorf("remove left %v", servers)
	}
}
