package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoginScopesReachTheServerAndStatus(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var sent []any
	elevatedUntil := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			sent, _ = body["scopes"].([]any)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"verificationUri": "https://idp.example/activate", "userCode": "ABCD-EFGH", "handle": "h-1", "interval": 1})
		case "/auth/device/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal": "you@example.com", "token": "pmk_tok", "renewalToken": "pmr_abc",
				"expiresAt":     time.Now().Add(12 * time.Hour).Format(time.RFC3339),
				"scopes":        []string{"mcp:approvals:write", "mcp:query", "mcp:read"},
				"elevatedUntil": elevatedUntil,
			})
		case "/api/datasources":
			_ = json.NewEncoder(w).Encode([]any{})
		}
	}))
	t.Cleanup(cp.Close)

	out := e.mustRun(t, "login", "hr", "--url", cp.URL, "--scopes", "mcp:read,mcp:query,mcp:approvals:write")
	mu.Lock()
	got := sent
	mu.Unlock()
	if len(got) != 3 || got[0] != "mcp:read" || got[2] != "mcp:approvals:write" {
		t.Errorf("device start scopes = %v, want the --scopes list", got)
	}
	if !strings.Contains(out, "scopes: mcp:approvals:write mcp:query mcp:read") {
		t.Errorf("login output = %q, want the granted scopes", out)
	}

	status := e.mustRun(t, "status")
	if !strings.Contains(status, "scopes:    mcp:approvals:write mcp:query mcp:read") {
		t.Errorf("status = %q, want the granted scopes", status)
	}
	if !strings.Contains(status, "elevated:  mcp:approvals:write until ") {
		t.Errorf("status = %q, want when the extra scope expires", status)
	}

	if out, err := e.run("login", "hr", "--scopes", ","); err == nil || !strings.Contains(out, "at least one scope") {
		t.Errorf("empty --scopes = %q, %v; want it refused", out, err)
	}
}
