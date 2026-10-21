package aiapps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const codexBefore = `# my settings
model = "gpt-5"

[desktop]
followUpQueueMode = "steer"

[mcp_servers."proxy-monster-acme"]
command = "/old/pmon"
args = ["mcp", "acme"]

[mcp_servers."proxy-monster-acme".env]
PMON_PORT_BASE = "6100"

[mcp_servers.other]
command = "npx" # someone else's
args = ["x"]
`

func writeCodex(t *testing.T, body string) string {
	t.Helper()
	setHome(t, t.TempDir())
	p := filepath.Join(userHome(), ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodexConfigEditsOnlyItsOwnTable(t *testing.T) {
	p := writeCodex(t, codexBefore)
	app := configApp("codex", "Codex", codexConfig())
	pmon := "/old/pmon"
	if _, _, err := app.add(Setup{Pmon: pmon}, Server{Name: "acme", entry: "proxy-monster-acme"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	got := string(data)
	for _, keep := range []string{"# my settings\nmodel = \"gpt-5\"\n", "[desktop]\nfollowUpQueueMode = \"steer\"\n", "[mcp_servers.other]\ncommand = \"npx\" # someone else's\n"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q:\n%s", keep, got)
		}
	}
	if strings.Count(got, "proxy-monster-acme") != 1 || strings.Contains(got, `PMON_PORT_BASE = "6100"`) {
		t.Errorf("the old entry and its env table were not replaced:\n%s", got)
	}
	c, found, err := codexConfig().read("proxy-monster-acme")
	if err != nil || !found || c.Command != pmon || strings.Join(c.Args, " ") != "mcp acme" {
		t.Errorf("read back %+v %v %v", c, found, err)
	}
	if _, err := app.remove(Setup{Pmon: pmon}, "acme"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if strings.Contains(string(data), "proxy-monster-acme") || !strings.Contains(string(data), "[mcp_servers.other]") {
		t.Errorf("after remove:\n%s", data)
	}
}

// A name held by another app's entry gets a suffix; the entry itself is never replaced or removed.
func TestCodexConfigKeepsAnotherAppsEntry(t *testing.T) {
	writeCodex(t, "[mcp_servers.proxy-monster-acme]\ncommand = \"npx\"\nargs = [\"x\"]\n")
	app := configApp("codex", "Codex", codexConfig())
	if name, _, err := app.add(Setup{Pmon: "/pmon"}, Server{Name: "acme", entry: "proxy-monster-acme"}); err != nil || name != "proxy-monster-acme-2" {
		t.Errorf("add: name %q, err %v", name, err)
	}
	if removed, err := app.remove(Setup{Pmon: "/pmon"}, "acme"); err != nil || !removed {
		t.Errorf("remove: removed %v, err %v", removed, err)
	}
	if _, found, _ := codexConfig().read("proxy-monster-acme"); !found {
		t.Error("removed an entry Proxy Monster did not add")
	}
}

func TestCodexTableQuotesWindowsPaths(t *testing.T) {
	writeCodex(t, "")
	cmd := mcpCommand{Command: `C:\Users\dana\AppData\Local\Programs\Proxy Monster Desktop\pmon.exe`, Args: []string{"mcp", "acme"},
		Env: map[string]string{"PMON_CONFIG_DIR": `C:\x "y"`}}
	if err := codexConfig().write("proxy-monster-acme", cmd); err != nil {
		t.Fatal(err)
	}
	c, found, err := codexConfig().read("proxy-monster-acme")
	if err != nil || !found || c.Command != cmd.Command || c.Env["PMON_CONFIG_DIR"] != `C:\x "y"` {
		t.Errorf("round trip %+v %v %v", c, found, err)
	}
}

func TestClaudeCodeConfigKeepsOtherKeys(t *testing.T) {
	setHome(t, t.TempDir())
	p := filepath.Join(userHome(), ".claude.json")
	if err := os.WriteFile(p, []byte(`{"userID":"u1","mcpServers":{"other":{"type":"stdio","command":"npx","args":["x"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	app := configApp("claude-code", "Claude Code", claudeCodeConfig())
	if _, _, err := app.add(Setup{Pmon: "/pmon"}, Server{Name: "acme", entry: "proxy-monster-acme"}); err != nil {
		t.Fatal(err)
	}
	if !app.connected(Setup{Pmon: "/pmon"}, "acme") {
		t.Error("not connected after add")
	}
	var got struct {
		UserID     string                     `json:"userID"`
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	data, _ := os.ReadFile(p)
	var ours mcpCommand
	if json.Unmarshal(data, &got) != nil || got.UserID != "u1" || got.MCPServers["other"] == nil ||
		json.Unmarshal(got.MCPServers["proxy-monster-acme"], &ours) != nil || ours.Type != "stdio" {
		t.Errorf("config after add: %s", data)
	}
	if _, err := app.remove(Setup{Pmon: "/pmon"}, "acme"); err != nil || app.connected(Setup{Pmon: "/pmon"}, "acme") {
		t.Errorf("remove: %v", err)
	}
}

// A dot inside a quoted key is part of the name: pm.prod is its own server, not a sub-table of pm.
func TestCodexDottedNames(t *testing.T) {
	p := writeCodex(t, "[mcp_servers.pm]\nurl = \"https://pm.example.com/mcp\"\n\n[mcp_servers.\"pm.prod\"]\ncommand = \"npx\"\nargs = []\n\n[ mcp_servers . 'pm' . env ]\nA = \"1\"\n")
	if err := codexConfig().delete("pm"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), `[mcp_servers."pm.prod"]`) || strings.Contains(string(data), "url =") || strings.Contains(string(data), "A = ") {
		t.Errorf("deleting pm:\n%s", data)
	}
	cmd := mcpCommand{Command: "/pmon", Args: []string{"mcp", "acme.prod"}}
	if err := codexConfig().write("pmon-acme.prod", cmd); err != nil {
		t.Fatal(err)
	}
	if c, found, err := codexConfig().read("pmon-acme.prod"); err != nil || !found || c.Command != "/pmon" {
		t.Errorf("read back %+v %v %v", c, found, err)
	}
	if err := codexConfig().delete("pmon-acme.prod"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := codexConfig().read("pmon-acme.prod"); found {
		t.Error("pmon-acme.prod is still there after delete")
	}
	if _, found, _ := codexConfig().read("pm.prod"); !found {
		t.Error("pm.prod was deleted")
	}
}

func TestTOMLKeyPath(t *testing.T) {
	for header, want := range map[string]string{
		`mcp_servers.pm`:            "mcp_servers|pm",
		` mcp_servers . "pm.prod" `: "mcp_servers|pm.prod",
		`mcp_servers.'a b'.env`:     "mcp_servers|a b|env",
		`mcp_servers."x\"y"`:        `mcp_servers|x"y`,
	} {
		keys, ok := tomlKeyPath(header)
		if !ok || strings.Join(keys, "|") != want {
			t.Errorf("tomlKeyPath(%q) = %q %v, want %q", header, keys, ok, want)
		}
	}
}
