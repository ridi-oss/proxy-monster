package main

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
	app := configApp("codex", "Codex", "", codexConfig())
	pmon := "/old/pmon"
	if err := app.add("proxy-monster-acme", pmon, "acme"); err != nil {
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
	if err := app.remove("proxy-monster-acme", pmon, "acme"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if strings.Contains(string(data), "proxy-monster-acme") || !strings.Contains(string(data), "[mcp_servers.other]") {
		t.Errorf("after remove:\n%s", data)
	}
}

func TestCodexConfigRefusesAnotherServersEntry(t *testing.T) {
	writeCodex(t, "[mcp_servers.proxy-monster-acme]\ncommand = \"npx\"\nargs = [\"x\"]\n")
	app := configApp("codex", "Codex", "", codexConfig())
	if err := app.add("proxy-monster-acme", "/pmon", "acme"); err == nil {
		t.Error("replaced an entry Proxy Monster did not add")
	}
	if err := app.remove("proxy-monster-acme", "/pmon", "acme"); err == nil {
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
	app := configApp("claude-code", "Claude Code", "", claudeCodeConfig())
	if err := app.add("proxy-monster-acme", "/pmon", "acme"); err != nil {
		t.Fatal(err)
	}
	if !app.connected("proxy-monster-acme", "/pmon", "acme") {
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
	if err := app.remove("proxy-monster-acme", "/pmon", "acme"); err != nil || app.connected("proxy-monster-acme", "/pmon", "acme") {
		t.Errorf("remove: %v", err)
	}
}
