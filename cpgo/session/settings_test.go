package session_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func TestClampSeconds(t *testing.T) {
	for raw, want := range map[string]int64{"": 3600, "x": 3600, "900": 900, "5": 60, "999999": 24 * 3600} {
		if got := session.ClampSeconds(raw, 3600); got != want {
			t.Errorf("%q: %d, want %d", raw, got, want)
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
