// Package tailnet puts the control plane on a tailnet: cp-go joins as a node and serves the console there
// itself, on a Tailscale Service or on the node, so no separate Tailscale task or TLS edge is needed.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"

	_ "tailscale.com/feature/identityfederation"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// Config is the PM_TAILNET_* settings. Tailnet mode is on when a login is configured.
type Config struct {
	Service  string   `env:"PM_TAILNET_SERVICE" help:"Tailscale Service to host, e.g. svc:console. Empty serves on the node itself."`
	Hostname string   `env:"PM_TAILNET_HOSTNAME" help:"Node name on the tailnet; defaults to pmon-<instance name>."`
	Tags     []string `env:"PM_TAILNET_TAGS" sep:"," help:"Tags the node advertises; a Service host or a federated login must be tagged."`
	ClientID string   `env:"PM_TAILNET_CLIENT_ID" help:"Federated identity client id for keyless login."`
	Audience string   `env:"PM_TAILNET_AUDIENCE" help:"Audience of the cloud ID token the federated identity trusts."`
	AuthKey  string   `env:"PM_TAILNET_AUTH_KEY" help:"Auth key, when not logging in by federated identity."`
}

// Enabled reports whether cp-go should join the tailnet.
func (c Config) Enabled() bool { return c.ClientID != "" || c.AuthKey != "" }

// Validate rejects a configuration that cannot join.
func (c Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	var errs []error
	if c.Service != "" && !strings.HasPrefix(c.Service, "svc:") {
		errs = append(errs, fmt.Errorf("PM_TAILNET_SERVICE must start with svc:, got %q", c.Service))
	}
	if len(c.Tags) == 0 && (c.Service != "" || c.ClientID != "") {
		errs = append(errs, errors.New("PM_TAILNET_TAGS is required to host a Service or log in by federated identity"))
	}
	if c.ClientID != "" && c.Audience == "" {
		errs = append(errs, errors.New("PM_TAILNET_AUDIENCE is required with PM_TAILNET_CLIENT_ID"))
	}
	return errors.Join(errs...)
}

// NodeName is PM_TAILNET_HOSTNAME, or pmon-<instance name>, the name the MCP server is installed under.
func (c Config) NodeName() string {
	if c.Hostname != "" {
		return c.Hostname
	}
	return "pmon-" + instanceName(os.Getenv("PM_INSTANCE_NAME"), os.Getenv("PM_MCP_RESOURCE"))
}

var notLabel = regexp.MustCompile(`[^a-z0-9]+`)

// instanceName is the Kotlin control plane's: PM_INSTANCE_NAME, or the first DNS label of the MCP resource
// host, e.g. https://pm.example.com/mcp -> pm; local for an IP or localhost.
func instanceName(name, mcpResource string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	host := ""
	if u, err := url.Parse(mcpResource); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	if host == "" || host == "localhost" || strings.Contains(host, ":") || strings.Trim(host, "0123456789.") == "" {
		return "local"
	}
	label, _, _ := strings.Cut(host, ".")
	label = strings.Trim(notLabel.ReplaceAllString(label, "-"), "-")
	if len(label) > 40 {
		label = strings.TrimRight(label[:40], "-")
	}
	if label == "" {
		return "local"
	}
	return label
}

// Join starts a node and waits until it is up. Its state lives in memory and the node is ephemeral, so each
// start logs in again and a stopped task leaves no node behind.
func Join(ctx context.Context, c Config) (*tsnet.Server, *ipnstate.Status, error) {
	s := &tsnet.Server{
		Hostname:      c.NodeName(),
		Store:         new(mem.Store),
		Ephemeral:     true,
		AdvertiseTags: c.Tags,
		ClientID:      c.ClientID,
		Audience:      c.Audience,
		AuthKey:       c.AuthKey,
		Logf:          func(string, ...any) {},
		UserLogf: func(format string, args ...any) {
			slog.Info("tailnet: " + fmt.Sprintf(format, args...))
		},
	}
	st, err := s.Up(ctx)
	if err != nil {
		_ = s.Close()
		return nil, nil, fmt.Errorf("tailnet: joining: %w", err)
	}
	return s, st, nil
}
