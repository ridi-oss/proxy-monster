package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/mcpbridge"
)

// mcpCmd is a local stdio MCP server that relays to the server's `/mcp` with an MCP token the daemon mints
// from the pmon login. Stdout carries only JSON-RPC; every other message goes to stderr.
type mcpCmd struct {
	Server string `arg:"" optional:"" default:"default" help:"Server whose MCP endpoint to relay to."`
}

func (c *mcpCmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	if s, err := client.Status(ctx); err == nil {
		warnVersionSkew(s)
	}
	bridge := &mcpbridge.Bridge{
		Tokens: func(ctx context.Context) (mcpbridge.Token, error) {
			tok, err := client.MCPToken(ctx, control.MCPTokenRequest{Server: c.Server})
			if err != nil {
				return mcpbridge.Token{}, err
			}
			expiresAt, _ := time.Parse(time.RFC3339, tok.ExpiresAt)
			return mcpbridge.Token{URL: tok.URL, Value: tok.Token, ExpiresAt: expiresAt}, nil
		},
		HTTP: &http.Client{},
		In:   os.Stdin,
		Out:  os.Stdout,
	}
	return bridge.Run(ctx)
}
