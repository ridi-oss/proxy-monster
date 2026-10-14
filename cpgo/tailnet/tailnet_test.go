package tailnet

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tags := []string{"tag:console"}
	for _, tc := range []struct {
		name string
		c    Config
		want string
	}{
		{"off", Config{Service: "console"}, ""},
		{"federated Service", Config{Service: "svc:console", Tags: tags, ClientID: "id", Audience: "aud"}, ""},
		{"auth key on the node", Config{AuthKey: "k"}, ""},
		{"auth key Service", Config{Service: "svc:console", Tags: tags, AuthKey: "k"}, ""},
		{"service without svc:", Config{Service: "console", Tags: tags, AuthKey: "k"}, "must start with svc:"},
		{"untagged Service", Config{Service: "svc:console", AuthKey: "k"}, "PM_TAILNET_TAGS is required"},
		{"untagged federated", Config{ClientID: "id", Audience: "aud"}, "PM_TAILNET_TAGS is required"},
		{"no audience", Config{Tags: tags, ClientID: "id"}, "PM_TAILNET_AUDIENCE is required"},
	} {
		err := tc.c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestNodeName(t *testing.T) {
	if got := (Config{Hostname: "console-node"}).NodeName(); got != "console-node" {
		t.Errorf("an explicit hostname became %q", got)
	}
	t.Setenv("PM_INSTANCE_NAME", "")
	t.Setenv("PM_MCP_RESOURCE", "https://pm.example.com/mcp")
	if got := (Config{}).NodeName(); got != "pmon-pm" {
		t.Errorf("default hostname %q, want pmon-pm", got)
	}
}

// The cases of the Kotlin control plane's defaultInstanceName.
func TestInstanceName(t *testing.T) {
	for _, tc := range []struct{ name, resource, want string }{
		{"hr", "https://pm.example.com/mcp", "hr"},
		{" hr ", "", "hr"},
		{"", "https://pm.example.com/mcp", "pm"},
		{"", "https://PM_Dev.example.com:8443/mcp", "pm-dev"},
		{"", "http://127.0.0.1:8080/mcp", "local"},
		{"", "http://localhost:8080/mcp", "local"},
		{"", "http://[::1]:8080/mcp", "local"},
		{"", "", "local"},
		{"", "https://---.example.com/mcp", "local"},
		{"", "https://" + strings.Repeat("a", 39) + "-b.example.com/mcp", strings.Repeat("a", 39)},
	} {
		if got := instanceName(tc.name, tc.resource); got != tc.want {
			t.Errorf("instanceName(%q, %q) = %q, want %q", tc.name, tc.resource, got, tc.want)
		}
	}
}
