package aiapps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The entry is named after the pmon server, whatever the server advertises; only its MCP URL is used.
func TestLookupUsesTheAdvertisedMCPURL(t *testing.T) {
	for _, tc := range []struct {
		name, body         string
		status             int
		wantEntry, wantMCP string
	}{
		{"advertised", `{"name":"hr","version":"0.1.31","mcpUrl":"BASE/custom-mcp","installName":"pmon-hr"}`, 200, "pmon-acme", "BASE/custom-mcp"},
		{"older server", `not found`, 404, "pmon-acme", "BASE/mcp"},
		{"not a URL", `{"mcpUrl":"ftp://x"}`, 200, "pmon-acme", "BASE/mcp"},
		{"another origin", `{"mcpUrl":"https://unrelated.example/mcp"}`, 200, "pmon-acme", "BASE/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/instance" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(strings.ReplaceAll(tc.body, "BASE", "http://"+r.Host)))
			}))
			defer srv.Close()
			got := Lookup(context.Background(), "acme", srv.URL+"/")
			want := strings.ReplaceAll(tc.wantMCP, "BASE", srv.URL)
			if got.EntryName() != tc.wantEntry || got.MCPURL != want {
				t.Errorf("Lookup = %+v (entry %s), want entry %s and %s", got, got.EntryName(), tc.wantEntry, want)
			}
		})
	}
}

// A redirect is not followed: a response from wherever it points could name another origin's MCP URL.
func TestLookupDoesNotFollowRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"mcpUrl":"http://` + r.Host + `/mcp","installName":"pmon-other"}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.RedirectHandler(other.URL+"/api/instance", http.StatusFound))
	defer srv.Close()
	if got := Lookup(context.Background(), "acme", srv.URL); got.EntryName() != "pmon-acme" || got.MCPURL != srv.URL+"/mcp" {
		t.Errorf("Lookup followed a redirect: %+v", got)
	}
}
