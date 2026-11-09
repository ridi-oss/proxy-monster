package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// mcpFakeCP's `/mcp` answers initialize with JSON and tools/call with an event stream.
func mcpFakeCP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			_ = json.NewEncoder(w).Encode(map[string]any{"verificationUri": "https://idp.example/activate", "userCode": "ABCD-EFGH", "handle": "h-1", "interval": 1})
		case "/auth/device/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal": "you@example.com", "token": "pmk_tok", "renewalToken": "pmr_abc",
				"expiresAt": time.Now().Add(12 * time.Hour).Format(time.RFC3339),
			})
		case "/auth/session/logout":
			w.WriteHeader(http.StatusNoContent)
		case "/api/datasources":
			_ = json.NewEncoder(w).Encode([]any{})
		case "/auth/session/mcp-token":
			if r.Header.Get("Authorization") != "Bearer pmr_abc" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken": "pma_live", "scope": "mcp:query mcp:read",
				"expiresAt": time.Now().Add(10 * time.Minute).Format(time.RFC3339),
			})
		case "/mcp":
			if r.Header.Get("Authorization") != "Bearer pma_live" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var msg struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&msg)
			switch msg.Method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18"}}`, msg.ID)
			case "tools/call":
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n\n", msg.ID)
			default:
				w.WriteHeader(http.StatusAccepted)
			}
		case "/api/instance":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "hr", "description": "HR databases"})
		default:
			t.Errorf("unexpected control-plane path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runMCP returns stdout and stderr apart: stdout must carry only JSON-RPC.
func (e *env) runMCP(t *testing.T, input string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(e.bin, append([]string{"mcp"}, args...)...)
	cmd.Env = e.environ()
	var out, errOut bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(input), &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func TestMCPBridgeRelaysOverThePmonLogin(t *testing.T) {
	e := newEnv(t)
	cp := mcpFakeCP(t)
	e.mustRun(t, "server", "set", "hr", "--url", cp.URL)

	out, errOut, err := e.runMCP(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n", "hr")
	if err != nil || !strings.Contains(out, "not logged in to \\\"hr\\\" — run `pmon login hr`") {
		t.Fatalf("pmon mcp before login: err=%v stdout=%q stderr=%q; want it to start and name the login", err, out, errOut)
	}

	out, errOut, err = e.runMCP(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"+
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n"+
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_servers"}}`+"\n", "hr")
	if err != nil {
		t.Fatalf("pmon mcp before login: %v\nstderr: %s", err, errOut)
	}
	for _, want := range []string{`HR databases\n\nnot logged in`, `"name":"login"`, `"name":"list_servers"`, `\"description\": \"HR databases\"`, `\"signedIn\": false`} {
		if !strings.Contains(out, want) {
			t.Errorf("pmon mcp before login: stdout lacks %s:\n%s", want, out)
		}
	}

	out, errOut, err = e.runMCP(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"+
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"login"}}`+"\n", "hr")
	if err != nil || !strings.Contains(out, "https://idp.example/activate") || !strings.Contains(out, "ABCD-EFGH") {
		t.Fatalf("login tool: err=%v stdout=%q stderr=%q; want the sign-in page and code", err, out, errOut)
	}

	e.mustRun(t, "login", "hr")
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_my_permissions"}}` + "\n"
	out, errOut, err = e.runMCP(t, input, "hr")
	if err != nil {
		t.Fatalf("pmon mcp: %v\nstderr: %s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	ids := map[string]bool{}
	for _, line := range lines {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout line %q is not JSON-RPC: %v", line, err)
		}
		ids[string(m.ID)] = true
	}
	if len(lines) != 2 || !ids["1"] || !ids["2"] {
		t.Errorf("stdout = %q, want exactly the initialize and tools/call answers", out)
	}
}

// One relay started logged out signs in through its own login tool and then relays the server's tools.
func TestMCPLoginToolBringsTheServerTools(t *testing.T) {
	e := newEnv(t)
	cp := mcpFakeCP(t)
	e.mustRun(t, "server", "set", "hr", "--url", cp.URL)

	cmd := exec.Command(e.bin, "mcp", "hr")
	cmd.Env = e.environ()
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	lines := bufio.NewScanner(out)
	await := func(want string) {
		t.Helper()
		deadline := time.AfterFunc(20*time.Second, func() { _ = cmd.Process.Kill() })
		defer deadline.Stop()
		for lines.Scan() {
			if strings.Contains(lines.Text(), want) {
				return
			}
		}
		t.Fatalf("pmon mcp never wrote %s", want)
	}

	fmt.Fprintln(in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	await(`"id":1`)
	fmt.Fprintln(in, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"login"}}`)
	await("ABCD-EFGH")
	await("notifications/tools/list_changed")
	fmt.Fprintln(in, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_my_permissions"}}`)
	await(`"id":3,"result"`)
}
