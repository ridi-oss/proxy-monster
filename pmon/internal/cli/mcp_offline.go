package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
)

// loginPromptWait bounds how long the login tool waits for the daemon to hand back the sign-in page.
const loginPromptWait = 30 * time.Second

// offlineTools is what `pmon mcp` offers before a login: the servers on this machine and a way to sign in.
type offlineTools struct {
	client *control.Client
	server string // "" is the daemon's default server
}

func (o *offlineTools) status(ctx context.Context) (*control.Status, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := o.client.Status(ctx)
	if err != nil {
		return nil, "", err
	}
	return s, cmp.Or(o.server, s.DefaultServer), nil
}

func (o *offlineTools) Instructions(loginErr error) string {
	var b strings.Builder
	if s, name, err := o.status(context.Background()); err == nil {
		if srv := s.Server(name); srv != nil && srv.InstanceDescription != "" {
			b.WriteString(srv.InstanceDescription + "\n\n")
		}
	}
	b.WriteString(loginErr.Error())
	b.WriteString(". Until then this server has no tools other than `login`, which opens the sign-in page in the" +
		" user's browser, and `list_servers`, which lists every proxy-monster server on this machine and what" +
		" each one holds.")
	return b.String()
}

func (o *offlineTools) Tools() []map[string]any {
	return []map[string]any{
		{
			"name": "list_servers",
			"description": "Lists the proxy-monster servers pmon knows on this machine: name, instance, description," +
				" and whether the user is signed in. Use it to pick the server that holds the data the user asks about.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			"annotations": map[string]any{"readOnlyHint": true},
		},
		{
			"name": "login",
			"description": "Opens the sign-in page for a proxy-monster server in the user's browser. The user approves" +
				" it there. This server's tools then appear here without a restart; another server's tools appear" +
				" under its own pmon MCP server.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server": map[string]any{"type": "string", "description": "A name from list_servers (default: this server)."},
				},
			},
		},
	}
}

func (o *offlineTools) Call(ctx context.Context, name string, args json.RawMessage) (string, error) {
	switch name {
	case "list_servers":
		return o.listServers(ctx)
	case "login":
		var in struct {
			Server string `json:"server"`
		}
		if len(args) > 0 {
			if err := json.Unmarshal(args, &in); err != nil {
				return "", fmt.Errorf("login: %w", err)
			}
		}
		return o.login(ctx, in.Server)
	}
	return "", fmt.Errorf("no tool %q before a login; call login first", name)
}

func (o *offlineTools) listServers(ctx context.Context) (string, error) {
	s, _, err := o.status(ctx)
	if err != nil {
		return "", err
	}
	type server struct {
		Name        string `json:"name"`
		Instance    string `json:"instance,omitempty"`
		Description string `json:"description,omitempty"`
		SignedIn    bool   `json:"signedIn"`
		Default     bool   `json:"default,omitempty"`
	}
	out := make([]server, 0, len(s.Servers))
	for _, srv := range s.Servers {
		out = append(out, server{srv.Name, srv.InstanceName, srv.InstanceDescription, srv.LoggedIn, srv.Default})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return string(b), err
}

// login starts the daemon's device sign-in and returns once the page is open; the sign-in finishes in the
// background, where the relay notices it and brings the server's tools.
func (o *offlineTools) login(ctx context.Context, server string) (string, error) {
	_, this, err := o.status(ctx)
	if err != nil {
		return "", err
	}
	server = cmp.Or(server, this)
	after := "This server's tools appear once they have signed in."
	if server != this {
		after = fmt.Sprintf("Once they have signed in, %q's tools appear under its own pmon MCP server, not this one.", server)
	}
	events := make(chan control.LoginEvent, 1)
	done := make(chan error, 1)
	go func() {
		done <- o.client.Login(context.Background(), control.LoginRequest{Server: server, TTLSeconds: login.DefaultTTL},
			func(ev control.LoginEvent) {
				if ev.Kind == "prompt" {
					select {
					case events <- ev:
					default:
					}
				}
			})
	}()
	select {
	case ev := <-events:
		opened := openBrowser(ev.VerificationURIComplete) == nil
		var b strings.Builder
		if opened {
			fmt.Fprintf(&b, "Opened the sign-in page for %q in the user's browser. Ask them to approve it there.", server)
			fmt.Fprintf(&b, " If no page appeared, they can open %s", ev.VerificationURI)
		} else {
			fmt.Fprintf(&b, "Ask the user to open %s to sign in to %q", ev.VerificationURI, server)
		}
		if ev.UserCode != "" {
			fmt.Fprintf(&b, " and enter the code %s", ev.UserCode)
		}
		b.WriteString(". " + after)
		return b.String(), nil
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("login to %q failed: %w", server, err)
		}
		return fmt.Sprintf("Signed in to %q.", server), nil
	case <-time.After(loginPromptWait):
		return "", errors.New("the pmon daemon did not start a sign-in; ask the user to run `" + self + " login " + server + "`")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
