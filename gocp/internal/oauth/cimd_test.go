package oauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// A11 §7 — Cimd.kt, the eight SSRF defences and RFC 8252 §7.3 redirect matching.
//
// ORACLE: 11-mcp-oauth-management.md §7 (the numbered defence list, INV-A11-25/26/27) and Cimd.kt
// itself. `OAuthRoutesDbTest` cases 3 and 4 are ported verbatim below and are marked as such; the
// rest are NEW, covering the defences the Kotlin suite never exercises — the DNS pin, the redirect
// ban, the two size checks and the content-type check all have ZERO Kotlin coverage (§9's "coverage
// gap"), and they are the whole point of the file.
// ---------------------------------------------------------------------------------------------

// testMetadata is `OAuthRoutesDbTest.metadata()` (`:464-469`).
func testMetadata() *CimdClientMetadata {
	return &CimdClientMetadata{
		ClientID:                testClientID,
		ClientName:              "Test MCP Client",
		RedirectURIs:            []string{testRedirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "",
	}
}

const (
	testClientID    = "https://client.example/client.json"
	testRedirectURI = "http://127.0.0.1:43110/callback"
)

// ---- OAuthRoutesDbTest case 3 -------------------------------------------------------------------

// Ported from `CIMD validation accepts omitted scope but rejects unsafe client identifiers`
// (OAuthRoutesDbTest.kt:165-192). Every assertion of the Kotlin case is here, plus the three
// client_id shape checks it makes through the real resolver.
// KT: OAuthRoutesDbTest.kt#CIMD validation accepts omitted scope but rejects unsafe client identifiers
func TestCimdValidationAcceptsOmittedScopeButRejectsUnsafeClientIdentifiers(t *testing.T) {
	t.Run("the declared loopback redirect and an omitted scope are accepted", func(t *testing.T) {
		if err := testMetadata().ValidateRequest(testRedirectURI, []string{"mcp:read"}); err != nil {
			t.Fatalf("want accepted, got %v", err)
		}
	})
	t.Run("an HTTPS redirect is accepted", func(t *testing.T) {
		m := testMetadata()
		m.RedirectURIs = []string{"https://client.example/callback"}
		if err := m.ValidateRequest("https://client.example/callback", []string{"mcp:read"}); err != nil {
			t.Fatalf("want accepted, got %v", err)
		}
	})
	t.Run("an IPv6 loopback redirect is accepted", func(t *testing.T) {
		m := testMetadata()
		m.RedirectURIs = []string{"http://[::1]:43110/callback"}
		if err := m.ValidateRequest("http://[::1]:43110/callback", []string{"mcp:read"}); err != nil {
			t.Fatalf("want accepted, got %v", err)
		}
	})
	t.Run("a plaintext NON-loopback redirect is rejected", func(t *testing.T) {
		m := testMetadata()
		m.RedirectURIs = []string{"http://remote.example/callback"}
		if err := m.ValidateRequest("http://remote.example/callback", []string{"mcp:read"}); err == nil {
			t.Fatal("want rejected: HTTP is only permitted for loopback")
		}
	})
	t.Run("a redirect carrying a fragment is rejected", func(t *testing.T) {
		m := testMetadata()
		m.RedirectURIs = []string{"https://client.example/callback#fragment"}
		if err := m.ValidateRequest("https://client.example/callback#fragment", []string{"mcp:read"}); err == nil {
			t.Fatal("want rejected: a fragment on a redirect_uri is never valid")
		}
	})

	// The three client_id shapes, through the REAL resolver with production checks on. All three fail
	// at step 1 or step 3, before any network call — which is itself the assertion: the resolver must
	// not dial to find out.
	resolver := &HTTPCimdResolver{
		ProductionChecks: true,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			t.Error("resolution must not be reached for a client_id that fails the shape check")
			return nil, nil
		},
	}
	for _, clientID := range []string{
		"https://user@example.com/client.json", // userinfo
		"https://example.com/a/../client.json", // dot segment
		"https://example.com",                  // no path
		"https://example.com/client.json#frag", // fragment
		"HTTPS://example.com/client.json",      // 🔒 case-SENSITIVE scheme, per java.net.URI
		"http://example.com/client.json",       // not HTTPS
	} {
		t.Run("rejects "+clientID, func(t *testing.T) {
			if _, err := resolver.Resolve(t.Context(), clientID); err == nil {
				t.Fatalf("want rejected: %s", clientID)
			}
		})
	}

	// A loopback client_id passes the SHAPE check and is then refused at step 3, so it needs the
	// resolver to actually resolve. Kept separate from the loop above for exactly that reason.
	t.Run("rejects a client_id that resolves to loopback", func(t *testing.T) {
		r := &HTTPCimdResolver{
			ProductionChecks: true,
			LookupIP: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			},
		}
		_, err := r.Resolve(t.Context(), "https://127.0.0.1/client.json")
		if err == nil || !strings.Contains(err.Error(), "special-use") {
			t.Fatalf("want a special-use rejection, got %v", err)
		}
	})
}

// ---- OAuthRoutesDbTest case 4 -------------------------------------------------------------------

// Ported from `CIMD validation matches a portless loopback redirect_uri against any request port,
// RFC 8252 section 7` (OAuthRoutesDbTest.kt:194-222), comment and all.
//
// 🔒 Regression for the real Claude Code client metadata document, which declares
// `http://localhost/callback` and `http://127.0.0.1/callback` with NO port — a native/CLI client binds
// an ephemeral port each launch, so `claude mcp login` always requests one. Exact-string matching
// rejected every real login unconditionally before this rule existed.
// KT: OAuthRoutesDbTest.kt#CIMD validation matches a portless loopback redirect_uri against any request port, RFC 8252 section 7
func TestLoopbackAwareRedirectMatchingRFC8252Section73(t *testing.T) {
	claudeCode := testMetadata()
	claudeCode.RedirectURIs = []string{"http://localhost/callback", "http://127.0.0.1/callback"}

	for _, requested := range []string{
		"http://localhost:54213/callback",
		"http://127.0.0.1:1/callback",
		"http://localhost/callback", // still matches with no port too
	} {
		if err := claudeCode.ValidateRequest(requested, []string{"mcp:read"}); err != nil {
			t.Errorf("a portless loopback declaration must match %s: %v", requested, err)
		}
	}

	// Still fail-closed: a different host, a different path, or a non-loopback/HTTPS request must NOT
	// be relaxed just because a loopback URI happens to be declared elsewhere in the list.
	for _, requested := range []string{
		"http://evil.example:54213/callback",
		"http://localhost:54213/other",
		"https://localhost:54213/callback",
	} {
		if err := claudeCode.ValidateRequest(requested, []string{"mcp:read"}); err == nil {
			t.Errorf("must NOT be relaxed: %s", requested)
		}
	}

	// A declared FIXED-port loopback URI is unaffected — still exact-match only, no relaxation beyond
	// what RFC 8252 asks for.
	if err := testMetadata().ValidateRequest("http://127.0.0.1:9999/callback", []string{"mcp:read"}); err == nil {
		t.Error("a declared fixed-port loopback URI must stay exact-match")
	}

	// The query string participates in the relaxed match, so a declared portless URI with a query
	// still pins it.
	withQuery := testMetadata()
	withQuery.RedirectURIs = []string{"http://localhost/cb?a=1"}
	if err := withQuery.ValidateRequest("http://localhost:5000/cb?a=1", []string{"mcp:read"}); err != nil {
		t.Errorf("query must be compared, not ignored: %v", err)
	}
	if err := withQuery.ValidateRequest("http://localhost:5000/cb?a=2", []string{"mcp:read"}); err == nil {
		t.Error("a differing query must not match")
	}
}

// The rest of validateRequest: response_types, grant_types, the public-client rule and the
// conditional scope rule. NEW — the Kotlin suite covers only the redirect half.
func TestValidateRequestChecksTheClientsDeclaredCapabilities(t *testing.T) {
	t.Run("a client that does not declare response_type=code is refused", func(t *testing.T) {
		m := testMetadata()
		m.ResponseTypes = []string{"token"}
		if err := m.ValidateRequest(testRedirectURI, []string{"mcp:read"}); err == nil {
			t.Fatal("want refused")
		}
	})
	t.Run("a client that does not declare authorization_code is refused", func(t *testing.T) {
		m := testMetadata()
		m.GrantTypes = []string{"refresh_token"}
		if err := m.ValidateRequest(testRedirectURI, []string{"mcp:read"}); err == nil {
			t.Fatal("want refused")
		}
	})
	// 🔒 PUBLIC CLIENTS ONLY. There is no client secret in this design, so a client asserting any
	// other auth method is asserting a capability the server does not have.
	t.Run("a confidential client is refused", func(t *testing.T) {
		m := testMetadata()
		m.TokenEndpointAuthMethod = "client_secret_basic"
		if err := m.ValidateRequest(testRedirectURI, []string{"mcp:read"}); err == nil {
			t.Fatal("want refused")
		}
	})
	t.Run("a declared scope list is enforced", func(t *testing.T) {
		m := testMetadata()
		m.Scope = "mcp:read"
		if err := m.ValidateRequest(testRedirectURI, []string{"mcp:read"}); err != nil {
			t.Fatalf("a declared scope must be accepted: %v", err)
		}
		if err := m.ValidateRequest(testRedirectURI, []string{"mcp:read", "mcp:policies:write"}); err == nil {
			t.Fatal("an undeclared scope must be refused")
		}
	})
	t.Run("an EMPTY declared scope accepts anything", func(t *testing.T) {
		m := testMetadata()
		m.Scope = "   "
		if err := m.ValidateRequest(testRedirectURI, MCPAScopes); err != nil {
			t.Fatalf("a blank scope declaration means no restriction: %v", err)
		}
	})
}

// ---- The HTTP half: the five defences with no Kotlin coverage at all ---------------------------

// cimdServer starts a TLS metadata server and returns the port it listens on. The certificate is
// httptest's own, so callers must trust it explicitly — [cimdTLSConfig].
func cimdServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return u.Port()
}

// cimdTLSConfig trusts the httptest certificate. InsecureSkipVerify rather than the server's cert
// pool because the tests deliberately request a hostname the certificate does not cover — that
// mismatch is the POINT of the pinning test, and verifying the name would mask it.
func cimdTLSConfig() *tls.Config { return &tls.Config{InsecureSkipVerify: true} } //nolint:gosec // test only

func metadataJSON(clientID string) string {
	return fmt.Sprintf(
		`{"client_id":%q,"client_name":"Test MCP Client","redirect_uris":["http://127.0.0.1:43110/callback"]}`,
		clientID)
}

// 🔒 INV-A11-25 — THE HTTP CLIENT IS DNS-PINNED TO THE VETTED ADDRESSES.
//
// The proof is deliberately not "we called a hook": the client_id names `cimd-pin-test.invalid`,
// a hostname RFC 2606 guarantees can never resolve, and the request SUCCEEDS. That is only possible
// if the dial used the vetted address list. A port that pre-checked and then called http.Get would
// fail this with a DNS error, which is exactly the regression the invariant is about.
//
// The second assertion is that resolution happens EXACTLY ONCE. A second lookup is the check/use gap:
// it is the window a rebinding answer would arrive in.
func TestTheHTTPClientIsPinnedToTheVettedAddresses(t *testing.T) {
	const host = "cimd-pin-test.invalid"
	var port string
	clientID := func() string { return "https://" + host + ":" + port + "/client.json" }

	port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(metadataJSON(clientID())))
	})

	var lookups atomic.Int32
	r := &HTTPCimdResolver{
		ProductionChecks: false, // the vetted address IS loopback; step 3 is the dev bypass
		LookupIP: func(_ context.Context, h string) ([]net.IP, error) {
			lookups.Add(1)
			if h != host {
				t.Errorf("resolved %q, want %q", h, host)
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		TLSConfig: cimdTLSConfig(),
	}

	// The premise: the system resolver cannot resolve this name, so a non-pinned client CANNOT reach
	// the server. Asserted rather than assumed.
	if _, err := net.DefaultResolver.LookupIP(t.Context(), "ip", host); err == nil {
		t.Fatalf("premise broken: %s resolves on this machine, so the pin proves nothing", host)
	}

	metadata, err := r.Resolve(t.Context(), clientID())
	if err != nil {
		t.Fatalf("a pinned dial must reach the vetted address even for an unresolvable name: %v", err)
	}
	if metadata.ClientName != "Test MCP Client" {
		t.Errorf("client_name = %q", metadata.ClientName)
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("resolved %d times, want exactly 1 — a second resolution is the rebinding window", n)
	}
}

// 🔒 INV-A11-26 — REDIRECTS ARE REFUSED. A followed redirect would re-resolve and escape the pin, so
// the 302 must surface as a failure rather than as a fetch of the redirect target.
//
// The target here is a SECOND server, so a client that followed the redirect would succeed with the
// wrong document — making a "no error" result unambiguously a pin escape rather than a fluke.
func TestRedirectsAreRefusedRatherThanFollowed(t *testing.T) {
	const host = "cimd-redirect-test.invalid"
	var port string
	clientID := func() string { return "https://" + host + ":" + port + "/client.json" }

	var followed atomic.Bool
	port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere.json" {
			followed.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadataJSON(clientID())))
			return
		}
		http.Redirect(w, r, "/elsewhere.json", http.StatusFound)
	})

	r := &HTTPCimdResolver{
		ProductionChecks: false,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		TLSConfig: cimdTLSConfig(),
	}
	if _, err := r.Resolve(t.Context(), clientID()); err == nil {
		t.Fatal("a redirect must be refused, not followed")
	}
	if followed.Load() {
		t.Error("the client followed the redirect — INV-A11-26 is broken")
	}
}

// Defence 7 — the document must be JSON. A metadata endpoint that answers `text/html` is either
// misconfigured or is not a metadata endpoint at all, and parsing it anyway is how a login page gets
// treated as a client registration.
func TestTheDocumentMustDeclareAJSONContentType(t *testing.T) {
	cases := []struct {
		contentType string
		accepted    bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/ld+json", true},
		{"APPLICATION/JSON", true},
		{"text/json", false},
		{"text/html", false},
		{"application/octet-stream", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.contentType, func(t *testing.T) {
			const host = "cimd-ct-test.invalid"
			var port string
			clientID := func() string { return "https://" + host + ":" + port + "/client.json" }
			port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
				if c.contentType != "" {
					w.Header().Set("Content-Type", c.contentType)
				} else {
					// Go adds a sniffed type for a bodied response, so an ABSENT header needs an
					// explicit empty one plus a zero-length write path.
					w.Header()["Content-Type"] = nil
				}
				_, _ = w.Write([]byte(metadataJSON(clientID())))
			})
			r := &HTTPCimdResolver{
				ProductionChecks: false,
				LookupIP: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				},
				TLSConfig: cimdTLSConfig(),
			}
			_, err := r.Resolve(t.Context(), clientID())
			if c.accepted && err != nil {
				t.Fatalf("%s must be accepted: %v", c.contentType, err)
			}
			if !c.accepted && err == nil {
				t.Fatalf("%s must be rejected", c.contentType)
			}
		})
	}
}

// 🔒 INV-A11-27 — THE SIZE CAP IS ENFORCED TWICE, and both halves are pinned separately because they
// fail in different situations:
//
//   - the Content-Length check catches a server that ANNOUNCES an oversized body, before a byte of it
//     is read. Pinned with a hijacked response whose header LIES, so only the header check can be
//     what rejects it;
//   - the read-MAX+1 check is the real bound, because Content-Length is advisory and a chunked
//     response carries none at all. Pinned with a chunked 6 KiB body.
//
// A port that kept only the first would stream an unbounded chunked document into memory.
func TestTheFiveKiBCapIsEnforcedOnContentLengthAndOnTheRead(t *testing.T) {
	newResolver := func() *HTTPCimdResolver {
		return &HTTPCimdResolver{
			ProductionChecks: false,
			LookupIP: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			},
			TLSConfig: cimdTLSConfig(),
		}
	}

	t.Run("an oversized Content-Length is refused before the body is read", func(t *testing.T) {
		const host = "cimd-cl-test.invalid"
		var port string
		port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("the test server must support hijacking")
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			// The header LIES: it announces 99999 bytes over a seven-byte body. Only the
			// Content-Length check can reject this, because the body itself is tiny.
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
				"Content-Length: 99999\r\nConnection: close\r\n\r\n{\"a\":1}")
			_ = buf.Flush()
		})
		clientID := "https://" + host + ":" + port + "/client.json"
		_, err := newResolver().Resolve(t.Context(), clientID)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("want a Content-Length rejection, got %v", err)
		}
	})

	t.Run("an oversized CHUNKED body is refused with no Content-Length at all", func(t *testing.T) {
		const host = "cimd-chunk-test.invalid"
		var port string
		var sawContentLength atomic.Bool
		port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Flushing before the body exceeds Go's buffer forces chunked encoding, so the response
			// carries NO Content-Length and only the read-MAX+1 check can bound it.
			_, _ = w.Write([]byte(`{"pad":"`))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", 6*1024)))
			_, _ = w.Write([]byte(`"}`))
			if w.Header().Get("Content-Length") != "" {
				sawContentLength.Store(true)
			}
		})
		clientID := "https://" + host + ":" + port + "/client.json"
		_, err := newResolver().Resolve(t.Context(), clientID)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("want a read-bound rejection, got %v", err)
		}
		if sawContentLength.Load() {
			t.Error("premise broken: the response carried a Content-Length, so the read check was not what rejected it")
		}
	})

	t.Run("a document just under the cap is accepted", func(t *testing.T) {
		const host = "cimd-fit-test.invalid"
		var port string
		clientID := func() string { return "https://" + host + ":" + port + "/client.json" }
		port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			body := fmt.Sprintf(
				`{"client_id":%q,"client_name":"Test MCP Client","redirect_uris":["http://127.0.0.1:43110/callback"],"pad":%q}`,
				clientID(), strings.Repeat("x", 4*1024))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		if _, err := newResolver().Resolve(t.Context(), clientID()); err != nil {
			t.Fatalf("a 4 KiB document is under the 5 KiB cap: %v", err)
		}
	})
}

// The four post-fetch document checks (Cimd.kt:66-71). The client_id equality check is the important
// one: without it, a document hosted at one URL could claim to be a client registered at another.
func TestTheFetchedDocumentIsValidatedAgainstTheClientID(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"a well-formed document",
			`{"client_id":"%[1]s","client_name":"n","redirect_uris":["http://127.0.0.1:1/cb"]}`, true},
		{"client_id must equal the URL it was fetched from",
			`{"client_id":"https://other.example/x.json","client_name":"n","redirect_uris":["http://127.0.0.1:1/cb"]}`, false},
		{"client_name must be present",
			`{"client_id":"%[1]s","redirect_uris":["http://127.0.0.1:1/cb"]}`, false},
		{"client_name must not be blank",
			`{"client_id":"%[1]s","client_name":"  ","redirect_uris":["http://127.0.0.1:1/cb"]}`, false},
		{"redirect_uris must be present",
			`{"client_id":"%[1]s","client_name":"n"}`, false},
		{"redirect_uris must not be empty",
			`{"client_id":"%[1]s","client_name":"n","redirect_uris":[]}`, false},
		{"no redirect_uri may be blank",
			`{"client_id":"%[1]s","client_name":"n","redirect_uris":["http://127.0.0.1:1/cb",""]}`, false},
		{"every redirect_uri must itself validate",
			`{"client_id":"%[1]s","client_name":"n","redirect_uris":["http://evil.example/cb"]}`, false},
		{"unknown keys are ignored",
			`{"client_id":"%[1]s","client_name":"n","redirect_uris":["http://127.0.0.1:1/cb"],"future":1}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const host = "cimd-doc-test.invalid"
			var port string
			clientID := func() string { return "https://" + host + ":" + port + "/client.json" }
			port = cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body := c.body
				if strings.Contains(body, "%[1]s") {
					body = fmt.Sprintf(body, clientID())
				}
				_, _ = w.Write([]byte(body))
			})
			r := &HTTPCimdResolver{
				ProductionChecks: false,
				LookupIP: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				},
				TLSConfig: cimdTLSConfig(),
			}
			_, err := r.Resolve(t.Context(), clientID())
			if c.ok && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("want rejected")
			}
		})
	}
}

// The four Kotlin default arguments survive an omitting document — a real CIMD file declares only the
// three required fields, so getting these wrong rejects every legitimate client.
func TestCimdDefaultsMatchTheKotlinDataClass(t *testing.T) {
	var m CimdClientMetadata
	err := m.UnmarshalJSON([]byte(`{"client_id":"x","client_name":"n","redirect_uris":["u"]}`))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(m.GrantTypes) != 1 || m.GrantTypes[0] != "authorization_code" {
		t.Errorf("grant_types default = %q, want [authorization_code]", m.GrantTypes)
	}
	if len(m.ResponseTypes) != 1 || m.ResponseTypes[0] != "code" {
		t.Errorf("response_types default = %q, want [code]", m.ResponseTypes)
	}
	if m.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method default = %q, want none", m.TokenEndpointAuthMethod)
	}
	if m.Scope != "" {
		t.Errorf("scope default = %q, want empty", m.Scope)
	}
}

// ---- The special-use blocklist ------------------------------------------------------------------

// 🔒 Defence 3, and the one place delegating to Go's stdlib would silently WIDEN what the resolver
// will fetch: Java's `isSiteLocalAddress` for IPv6 is `fec0::/10`, Go's `IP.IsPrivate` is `fc00::/7`,
// and `fec0::/10` is NOT in the 30-entry CIDR list — so `net.IP.IsPrivate` would let a deprecated
// site-local address through.
func TestIsSpecialUseCoversEveryJDKPredicateAndTheCIDRList(t *testing.T) {
	special := []string{
		// The five InetAddress predicates, v4.
		"0.0.0.0", "127.0.0.1", "127.255.255.254", "169.254.1.1",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "224.0.0.1",
		// The five InetAddress predicates, v6.
		"::", "::1", "fe80::1", "fec0::1", "ff02::1",
		// CIDR-list entries that NO InetAddress predicate covers.
		"100.64.0.1",   // RFC 6598 CGNAT
		"192.0.0.1",    // IETF protocol assignments
		"192.0.2.1",    // TEST-NET-1
		"198.18.0.1",   // benchmarking
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
		"240.0.0.1",    // reserved
		"64:ff9b::1",   // NAT64
		"2001:db8::1",  // documentation
		"2002::1",      // 6to4
		"fc00::1",      // ULA
	}
	for _, s := range special {
		if !isSpecialUse(net.ParseIP(s)) {
			t.Errorf("%s must be special-use", s)
		}
	}
	// 🔒 fec0::/10 specifically: assert the STDLIB would have missed it, so the reason for the
	// hand-written predicate is recorded in the suite and not only in a comment.
	if net.ParseIP("fec0::1").IsPrivate() {
		t.Error("premise broken: net.IP.IsPrivate now covers fec0::/10, so isSiteLocalV6 is redundant")
	}

	routable := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111", "2400:cb00::1"}
	for _, s := range routable {
		if isSpecialUse(net.ParseIP(s)) {
			t.Errorf("%s must NOT be special-use", s)
		}
	}
}

// 🔒 F18's cidr, including the width check that refuses a cross-family match. Without it,
// `::ffff:10.0.0.1/104` would match a v4 address and the blocklist would behave differently for a
// caller that passed 16-byte v4-in-v6 forms.
func TestCidrContainsRefusesACrossFamilyMatch(t *testing.T) {
	v4Block := parseCIDRs("10.0.0.0/8")[0]
	if !v4Block.contains(net.ParseIP("10.1.2.3").To4()) {
		t.Error("10.1.2.3 is inside 10.0.0.0/8")
	}
	if v4Block.contains(net.ParseIP("10.1.2.3").To16()) {
		t.Error("a 16-byte form must NOT match a 4-byte block — the width check is the family guard")
	}
	if v4Block.contains(net.ParseIP("11.1.2.3").To4()) {
		t.Error("11.1.2.3 is outside 10.0.0.0/8")
	}
	// The boundary mask, on a prefix that is not a whole number of bytes.
	cgnat := parseCIDRs("100.64.0.0/10")[0]
	for _, in := range []string{"100.64.0.0", "100.100.1.10", "100.127.255.255"} {
		if !cgnat.contains(net.ParseIP(in).To4()) {
			t.Errorf("%s is inside 100.64.0.0/10", in)
		}
	}
	for _, out := range []string{"100.63.255.255", "100.128.0.0"} {
		if cgnat.contains(net.ParseIP(out).To4()) {
			t.Errorf("%s is outside 100.64.0.0/10", out)
		}
	}
	if n := len(specialUseCIDRs); n != 30 {
		t.Errorf("the blocklist has %d entries, want the Kotlin's 30", n)
	}
}

// `productionChecks = !config.authDebug`, so a dev box CAN point at localhost metadata — and only
// step 3 is bypassed. The pin, the redirect ban and the caps stay on, which the tests above already
// exercise through ProductionChecks:false.
func TestProductionChecksGateOnlyTheSpecialUseStep(t *testing.T) {
	dev := &HTTPCimdResolver{
		ProductionChecks: false,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	// The shape check is NOT gated: a non-HTTPS client_id is refused in dev too.
	if _, err := dev.Resolve(t.Context(), "http://127.0.0.1/client.json"); err == nil {
		t.Error("the client_id shape check must apply in dev as well")
	}
}

// ValidatedRedirectURI on its own, including the loopback host rule the consent page's warning
// depends on.
func TestValidatedRedirectURIAndLoopbackHosts(t *testing.T) {
	valid := []string{
		"https://client.example/cb",
		"http://localhost/cb",
		"http://localhost:1234/cb",
		"http://127.0.0.1:43110/callback",
		"http://127.255.255.254/cb",
		"http://[::1]:43110/callback",
	}
	for _, v := range valid {
		if _, err := ValidatedRedirectURI(v); err != nil {
			t.Errorf("%s must validate: %v", v, err)
		}
	}
	invalid := []string{
		"/relative/cb",                     // not absolute
		"https:///cb",                      // no host
		"https://user@client.example/cb",   // userinfo
		"https://client.example/cb#f",      // fragment
		"http://remote.example/cb",         // plaintext, not loopback
		"http://127.0.0.1.evil.example/cb", // five labels, so not a dotted quad
		"ftp://client.example/cb",          // neither scheme
	}
	for _, v := range invalid {
		if _, err := ValidatedRedirectURI(v); err == nil {
			t.Errorf("%s must be refused", v)
		}
	}

	loopback := []string{"localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.1", "127.0.0.2", "127.255.255.254"}
	for _, h := range loopback {
		if !IsLoopbackRedirectHost(h) {
			t.Errorf("%s is loopback", h)
		}
	}
	notLoopback := []string{"example.com", "127.0.0", "127.0.0.1.2", "128.0.0.1", "127.999.0.1", ""}
	for _, h := range notLoopback {
		if IsLoopbackRedirectHost(h) {
			t.Errorf("%s is NOT loopback", h)
		}
	}
}
