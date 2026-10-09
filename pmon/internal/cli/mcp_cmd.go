package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/mcpbridge"
)

// mcpCmd is a local stdio MCP server that relays to the server's `/mcp` with an MCP token the daemon mints
// from the pmon login. Stdout carries only JSON-RPC; every other message goes to stderr. With --install or
// --uninstall it instead registers that relay with the AI apps on this machine (mcp_install.go).
type mcpCmd struct {
	Install   bool     `help:"Register pmon mcp with the AI apps on this machine (Claude Desktop, Claude Code, Codex)." xor:"mode"`
	Uninstall bool     `help:"Remove pmon mcp from the AI apps on this machine." xor:"mode"`
	App       []string `help:"With --install or --uninstall, only these apps: claude-desktop, claude-code, codex (default: every installed one)."`
	Servers   []string `arg:"" optional:"" name:"server" help:"Server whose MCP endpoint to relay to (default: the default server). With --install or --uninstall, the servers to change (default: every one)."`
}

func (c *mcpCmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if c.Install || c.Uninstall {
		return c.register(ctx)
	}
	switch {
	case len(c.App) > 0:
		return errors.New("--app goes with --install or --uninstall")
	case len(c.Servers) > 1:
		return errors.New("the relay takes one server; to change several, add --install or --uninstall")
	}
	server := "" // the daemon's default server
	if len(c.Servers) == 1 {
		server = c.Servers[0]
	}
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	if s, err := client.Status(ctx); err == nil {
		warnVersionSkew(s)
	}
	bridge := &mcpbridge.Bridge{
		Tokens: func(ctx context.Context) (mcpbridge.Token, error) {
			tok, err := client.MCPToken(ctx, control.MCPTokenRequest{Server: server})
			if errors.Is(err, control.ErrUnknownRoute) {
				return mcpbridge.Token{}, fmt.Errorf("the running daemon predates `pmon mcp` — run `pmon restart`")
			}
			if err != nil {
				return mcpbridge.Token{}, err
			}
			expiresAt, err := time.Parse(time.RFC3339, tok.ExpiresAt)
			if err != nil {
				return mcpbridge.Token{}, fmt.Errorf("the daemon returned an MCP token without a valid expiry: %w", err)
			}
			return mcpbridge.Token{URL: tok.URL, Value: tok.Token, ExpiresAt: expiresAt}, nil
		},
		HTTP: &http.Client{},
		In:   os.Stdin,
		Out:  os.Stdout,
	}
	return bridge.Run(ctx)
}
