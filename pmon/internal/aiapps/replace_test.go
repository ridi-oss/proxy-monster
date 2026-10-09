package aiapps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var acme = Server{Name: "acme", MCPURL: "https://pm.example.com/mcp"}

func TestSameEndpoint(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://pm.example.com/mcp", "https://pm.example.com/mcp", true},
		{"HTTPS://PM.example.com:443/mcp/", "https://pm.example.com/mcp", true},
		{"http://pm.example.com:80/mcp", "http://pm.example.com/mcp", true},
		{"https://pm.example.com:8443/mcp", "https://pm.example.com/mcp", false},
		{"https://pm.example.com/mcp", "http://pm.example.com/mcp", false},
		{"https://other.example.com/mcp", "https://pm.example.com/mcp", false},
		{"https://pm.example.com/other", "https://pm.example.com/mcp", false},
	} {
		if got := sameEndpoint(tc.a, tc.b); got != tc.want {
			t.Errorf("sameEndpoint(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

// Adding acme replaces its https entry and pmon's relay for it under another name, and nothing else.
func TestAddReplacesTheServersOtherEntries(t *testing.T) {
	setHome(t, t.TempDir())
	p := filepath.Join(userHome(), ".claude.json")
	body := `{"mcpServers":{
		"pm-https":{"type":"http","url":"https://PM.example.com:443/mcp/"},
		"proxy-monster-acme":{"type":"stdio","command":"/opt/homebrew/bin/pmon","args":["mcp","acme"]},
		"pmon-hr":{"type":"stdio","command":"/opt/homebrew/bin/pmon","args":["mcp","hr"]},
		"other-https":{"type":"http","url":"https://other.example.com/mcp"},
		"foreign":{"type":"stdio","command":"npx","args":["x"]}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	app := configApp("claude-code", "Claude Code", claudeCodeConfig())
	_, replaced, err := app.Add(Setup{Pmon: "/pmon"}, acme)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(replaced, []string{"pm-https", "proxy-monster-acme"}) {
		t.Errorf("replaced %v", replaced)
	}
	servers, _, _ := readDesktopServers(p)
	var names []string
	for name := range servers {
		names = append(names, name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"foreign", "other-https", "pmon-acme", "pmon-hr"}) {
		t.Errorf("entries after add: %v", names)
	}
}

// pmon's own name held by the server's https entry is replaced; held by another server's, pmon's gets a suffix.
func TestAddTakesItsNameOnlyFromTheSameServer(t *testing.T) {
	writeCodex(t, "[mcp_servers.proxy-monster-acme]\nurl = \"https://pm.example.com/mcp\"\n")
	app := configApp("codex", "Codex", codexConfig())
	if _, _, err := app.add(Setup{Pmon: "/pmon"}, Server{Name: acme.Name, MCPURL: acme.MCPURL, entry: "proxy-monster-acme"}); err != nil {
		t.Fatalf("replacing acme's https entry under pmon's name: %v", err)
	}
	if c, found, _ := codexConfig().read("proxy-monster-acme"); !found || c.Command != "/pmon" {
		t.Errorf("after add: %+v %v", c, found)
	}

	writeCodex(t, "[mcp_servers.proxy-monster-acme]\nurl = \"https://other.example.com/mcp\"\n")
	if name, _, err := app.add(Setup{Pmon: "/pmon"}, Server{Name: acme.Name, MCPURL: acme.MCPURL, entry: "proxy-monster-acme"}); err != nil || name != "proxy-monster-acme-2" {
		t.Errorf("beside another server's entry: name %q, err %v", name, err)
	}
	if _, found, _ := codexConfig().read("proxy-monster-acme"); !found {
		t.Error("another server's entry was replaced")
	}
}

// A name already held gets a suffix, and installing again reuses each server's own entry.
func TestNameCollisionsGetASuffix(t *testing.T) {
	setHome(t, t.TempDir())
	app := configApp("claude-code", "Claude Code", claudeCodeConfig())
	if err := os.WriteFile(claudeCodePath(), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dev := Server{Name: "dev", entry: "pmon-local"}
	dev2 := Server{Name: "dev2", entry: "pmon-local"}
	for round := range 2 {
		a, _, err := app.Add(Setup{Pmon: "/pmon"}, dev)
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := app.Add(Setup{Pmon: "/pmon"}, dev2)
		if err != nil || a != "pmon-local" || b != "pmon-local-2" {
			t.Errorf("round %d: %q and %q, err %v", round, a, b, err)
		}
	}
	servers, _, _ := readDesktopServers(claudeCodePath())
	if len(servers) != 2 {
		t.Errorf("entries: %v", servers)
	}
}

func TestCodexAddReplacesTheHTTPSEntry(t *testing.T) {
	p := writeCodex(t, codexBefore+"\n[mcp_servers.pm]\nurl = \"https://pm.example.com/mcp\"\n")
	app := configApp("codex", "Codex", codexConfig())
	_, replaced, err := app.add(Setup{Pmon: "/pmon"}, Server{Name: acme.Name, MCPURL: acme.MCPURL, entry: "proxy-monster-acme"})
	if err != nil || !slices.Equal(replaced, []string{"pm"}) {
		t.Fatalf("replaced %v, err %v", replaced, err)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), "[mcp_servers.pm]") || !strings.Contains(string(data), "[mcp_servers.other]") {
		t.Errorf("after add:\n%s", data)
	}
}

func TestClaudeDesktopAddReplacesPmonUnderAnotherName(t *testing.T) {
	setHome(t, t.TempDir())
	path := claudeDesktopConfig()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(`{"mcpServers":{"proxy-monster-acme":{"command":"pmon","args":["mcp","acme"]},"keep":{"command":"npx","args":[]}}}`), 0o600)
	_, replaced, err := claudeDesktop().Add(Setup{Pmon: "/p/pmon"}, acme)
	if err != nil || !slices.Equal(replaced, []string{"proxy-monster-acme"}) {
		t.Fatalf("replaced %v, err %v", replaced, err)
	}
	servers, _, _ := readDesktopServers(path)
	if _, ok := servers["proxy-monster-acme"]; ok || servers["keep"] == nil || servers["pmon-acme"] == nil {
		t.Errorf("after add: %v", servers)
	}
}

// Removing a server removes pmon's relay for it under any name, and leaves its https entry and others alone.
func TestRemoveTakesEveryRelayForTheServer(t *testing.T) {
	setHome(t, t.TempDir())
	p := filepath.Join(userHome(), ".claude.json")
	body := `{"mcpServers":{
		"pmon-acme":{"type":"stdio","command":"/pmon","args":["mcp","acme"]},
		"proxy-monster-acme":{"type":"stdio","command":"/old/pmon","args":["mcp","acme"]},
		"pm-https":{"type":"http","url":"https://pm.example.com/mcp"},
		"pmon-hr":{"type":"stdio","command":"/pmon","args":["mcp","hr"]}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	app := configApp("claude-code", "Claude Code", claudeCodeConfig())
	if removed, err := app.Remove(Setup{Pmon: "/pmon"}, "acme"); err != nil || !removed {
		t.Fatalf("removed %v, err %v", removed, err)
	}
	servers, _, _ := readDesktopServers(p)
	if len(servers) != 2 || servers["pm-https"] == nil || servers["pmon-hr"] == nil {
		t.Errorf("after remove: %v", servers)
	}
	if removed, err := app.Remove(Setup{Pmon: "/pmon"}, "acme"); err != nil || removed {
		t.Errorf("a second remove: removed %v, err %v", removed, err)
	}
}

// `pmon mcp` with no server is the default server's relay.
func TestBarePmonMCPIsTheDefaultServer(t *testing.T) {
	if !ownCommand("pmon", []string{"mcp"}, "default") || ownCommand("pmon", []string{"mcp"}, "acme") {
		t.Error("`pmon mcp` should be the default server's relay and only that")
	}
}

// With CODEX_HOME or CLAUDE_CONFIG_DIR set, the CLIs edit the config there, so pmon reads and edits that one and
// leaves the default one alone.
func TestConfigDirOverridesAreHonored(t *testing.T) {
	writeCodex(t, "[mcp_servers.keep]\nurl = \"https://pm.example.com/mcp\"\n")
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte("[mcp_servers.keep]\nurl = \"https://unrelated.example.com/mcp\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, replaced, err := configApp("codex", "Codex", codexConfig()).Add(Setup{Pmon: "/pmon"}, acme)
	if err != nil || len(replaced) != 0 {
		t.Fatalf("replaced %v, err %v: the unrelated keep in CODEX_HOME must stay", replaced, err)
	}
	if _, found, _ := codexConfig().read("keep"); !found {
		t.Error("the entry in CODEX_HOME was deleted")
	}

	claudeDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeDir)
	if !strings.HasPrefix(claudeCodePath(), claudeDir) {
		t.Error("Claude Code's config is not read from CLAUDE_CONFIG_DIR")
	}
}

// The entry name comes from the server, so pmon's relay counts as connected under any name.
func TestConnectedUnderAnyName(t *testing.T) {
	setHome(t, t.TempDir())
	if err := os.WriteFile(claudeCodePath(), []byte(`{"mcpServers":{"pmon-hr-pmon":{"type":"stdio","command":"/pmon","args":["mcp","acme"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	app := configApp("claude-code", "Claude Code", claudeCodeConfig())
	if !app.Connected(Setup{Pmon: "/pmon"}, "acme") || app.Connected(Setup{Pmon: "/pmon"}, "hr") {
		t.Error("connected should find acme's relay under its advertised name, and only acme's")
	}
}

// A pmon server name may hold a dot, which claude refuses in an entry name.
func TestFallbackEntryNameHasNoDot(t *testing.T) {
	if got := (Server{Name: "acme.prod"}).EntryName(); got != "pmon-acme-prod" {
		t.Errorf("EntryName = %q", got)
	}
}
