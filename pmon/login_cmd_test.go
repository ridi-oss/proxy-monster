package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

func TestParseScopes(t *testing.T) {
	if got, err := parseScopes(nil); got != nil || err != nil {
		t.Errorf("no flag = %v, %v; want nil so the server default applies", got, err)
	}
	raw := " mcp:read, mcp:approvals:write,,mcp:read "
	if got, err := parseScopes(&raw); err != nil || !slices.Equal(got, []string{"mcp:read", "mcp:approvals:write"}) {
		t.Errorf("parseScopes(%q) = %v, %v", raw, got, err)
	}
	empty := " , "
	if _, err := parseScopes(&empty); err == nil {
		t.Error("an empty --scopes must be refused, not sent as the default")
	}
}

func TestElevatedLine(t *testing.T) {
	srv := control.ServerInfo{Name: "hr", Scopes: []string{"mcp:approvals:write", "mcp:query", "mcp:read"}, ElevatedUntil: "2026-07-26T01:00:00Z"}
	before := elevatedLine(srv, time.Date(2026, 7, 26, 0, 30, 0, 0, time.UTC))
	if !strings.HasPrefix(before, "mcp:approvals:write until ") {
		t.Errorf("open window = %q", before)
	}
	after := elevatedLine(srv, time.Date(2026, 7, 26, 1, 0, 0, 0, time.UTC))
	if !strings.Contains(after, "mcp:approvals:write EXPIRED") || !strings.Contains(after, "pmon login hr --scopes mcp:approvals:write,mcp:query,mcp:read") {
		t.Errorf("closed window = %q", after)
	}
}
