package oauth

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(redirects ...string) *Client {
	return &Client{ClientID: "https://client.example/client.json", ClientName: "Test MCP Client", RedirectURIs: redirects,
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"}
}

func TestValidate(t *testing.T) {
	read := []string{"mcp:read"}
	for _, ok := range []struct{ declared, requested string }{
		{"http://127.0.0.1:43110/callback", "http://127.0.0.1:43110/callback"},
		{"https://client.example/callback", "https://client.example/callback"},
		{"http://[::1]:43110/callback", "http://[::1]:43110/callback"},
		// A portless loopback declaration matches any port (RFC 8252 §7.3), as Claude Code's metadata needs.
		{"http://localhost/callback", "http://localhost:54213/callback"},
		{"http://127.0.0.1/callback", "http://127.0.0.1:1/callback"},
		{"http://localhost/callback", "http://localhost/callback"},
	} {
		if err := testClient(ok.declared).validate(ok.requested, read); err != nil {
			t.Errorf("%s for %s: %v", ok.requested, ok.declared, err)
		}
	}
	for _, bad := range []struct{ declared, requested string }{
		{"http://remote.example/callback", "http://remote.example/callback"},
		{"https://client.example/callback#fragment", "https://client.example/callback#fragment"},
		{"http://localhost/callback", "http://evil.example:54213/callback"},
		{"http://localhost/callback", "http://localhost:54213/other"},
		{"http://localhost/callback", "https://localhost:54213/callback"},
		{"http://127.0.0.1:43110/callback", "http://127.0.0.1:9999/callback"},
	} {
		if err := testClient(bad.declared).validate(bad.requested, read); err == nil {
			t.Errorf("%s for %s: accepted", bad.requested, bad.declared)
		}
	}
	c := testClient("https://client.example/callback")
	c.Scope = "mcp:read"
	if c.validate("https://client.example/callback", []string{"mcp:read", "mcp:tokens"}) == nil {
		t.Error("a scope the client did not declare was accepted")
	}
	c.TokenEndpointAuthMethod = "client_secret_basic"
	if c.validate("https://client.example/callback", read) == nil {
		t.Error("a confidential client was accepted")
	}
}

func TestResolveRefusesUnsafeClientIDs(t *testing.T) {
	ctx := context.Background()
	for _, id := range []string{
		"https://127.0.0.1/client.json", "https://user@example.com/client.json", "https://example.com/a/../client.json",
		"http://example.com/client.json", "https://example.com", "https://example.com/client.json#x",
	} {
		if _, err := (HTTPResolver{}).Resolve(ctx, id); err == nil {
			t.Errorf("%s: resolved", id)
		}
	}
}

func TestResolveChecksTheDocument(t *testing.T) {
	ctx := context.Background()
	var body, contentType string
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		if status == http.StatusFound {
			w.Header().Set("Location", "/elsewhere")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	id := srv.URL + "/client.json"
	resolve := func() (*Client, error) { return HTTPResolver{AllowSpecialUse: true, RootCAs: roots}.Resolve(ctx, id) }
	good := `{"client_id":"` + id + `","client_name":"n","redirect_uris":["http://localhost/cb"],"extra":1}`

	body, contentType = good, "application/json; charset=utf-8"
	if c, err := resolve(); err != nil || c.TokenEndpointAuthMethod != "none" || c.GrantTypes[0] != "authorization_code" {
		t.Fatalf("a good document: %+v %v", c, err)
	}
	contentType = "application/oauth-client+json"
	if _, err := resolve(); err != nil {
		t.Fatalf("a +json document: %v", err)
	}
	for name, change := range map[string]func(){
		"text/html":       func() { contentType = "text/html" },
		"too large":       func() { body = good[:len(good)-1] + `,"pad":"` + strings.Repeat("x", 5*1024) + `"}` },
		"other client_id": func() { body = strings.Replace(good, id, id+"x", 1) },
		"blank name":      func() { body = strings.Replace(good, `"n"`, `" "`, 1) },
		"no redirects":    func() { body = strings.Replace(good, `["http://localhost/cb"]`, `[]`, 1) },
		"remote http":     func() { body = strings.Replace(good, "http://localhost/cb", "http://remote.example/cb", 1) },
		"redirected":      func() { status = http.StatusFound },
		"not found":       func() { status = http.StatusNotFound },
	} {
		body, contentType, status = good, "application/json", http.StatusOK
		change()
		if _, err := resolve(); err == nil {
			t.Errorf("%s: resolved", name)
		}
	}
	body, contentType, status = good, "application/json", http.StatusOK
	if _, err := (HTTPResolver{RootCAs: roots}).Resolve(ctx, id); err == nil || !strings.Contains(err.Error(), "special-use") {
		t.Fatalf("a loopback document outside debug: %v", err)
	}
}
