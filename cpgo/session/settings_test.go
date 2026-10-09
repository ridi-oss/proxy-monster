package session_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func TestElevatedScopeTTL(t *testing.T) {
	for raw, want := range map[string]int64{"": 3600, "900": 900, "5": 60} {
		t.Setenv("PM_ELEVATED_SCOPE_TTL", raw)
		s, err := session.SettingsFromEnv()
		if err != nil || s.ElevatedScopeTTL != want {
			t.Errorf("PM_ELEVATED_SCOPE_TTL=%q: %d %v, want %d", raw, s.ElevatedScopeTTL, err, want)
		}
	}
}

func TestDevicePageOrigin(t *testing.T) {
	same := session.Settings{MCPResource: "https://console.example/mcp"}
	if same.WebBase() != "https://console.example" || same.WebRedirect("/device") != "/device" {
		t.Fatalf("same origin: %s %s", same.WebBase(), same.WebRedirect("/device"))
	}
	split := session.Settings{MCPResource: "https://console.example/mcp", WebOrigin: "http://127.0.0.1:41300/"}
	if split.WebBase() != "http://127.0.0.1:41300" || split.WebRedirect("/device") != "http://127.0.0.1:41300/device" {
		t.Fatalf("split origin: %s %s", split.WebBase(), split.WebRedirect("/device"))
	}
}
