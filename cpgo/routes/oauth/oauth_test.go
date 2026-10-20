package oauth_test

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/oauth"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

const (
	resource = "http://127.0.0.1:8080/mcp"
	redirect = "http://127.0.0.1:43110/callback"
	verifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	// challenge is the S256 of verifier.
	challenge = "7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM"
)

// fixture is a cp-go whose MCP client publishes its metadata document from a local HTTPS server.
type fixture struct {
	*routetest.Env
	clientID string
}

func setup(t *testing.T, production, autoConsent bool) fixture {
	t.Helper()
	var clientID string
	cimd := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": clientID, "client_name": "Test MCP Client", "redirect_uris": []string{redirect}})
	}))
	t.Cleanup(cimd.Close)
	clientID = cimd.URL + "/client.json"
	roots := x509.NewCertPool()
	roots.AddCert(cimd.Certificate())
	settings := dbtest.Settings()
	settings.AuthDebug = !production
	settings.OAuthDebugAutoConsent = autoConsent
	return fixture{routetest.SetupConfig(t, routetest.Config{Settings: &settings,
		Clients: oauth.HTTPResolver{AllowSpecialUse: true, RootCAs: roots}}), clientID}
}

func (f fixture) authorize(scope, state, principal string) string {
	q := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {redirect}, "scope": {scope},
		"state": {state}, "resource": {resource}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if principal != "" {
		q.Set("principal", principal)
	}
	return "/oauth/authorize?" + q.Encode()
}

func noFollow(t *testing.T, b *routetest.Browser, req *http.Request) (*http.Response, string) {
	t.Helper()
	c := &http.Client{Jar: b.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

func (f fixture) get(t *testing.T, b *routetest.Browser, path string, header ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.Srv.URL+path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return noFollow(t, b, req)
}

func (f fixture) form(t *testing.T, b *routetest.Browser, path string, v url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.Srv.URL+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return noFollow(t, b, req)
}

func location(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want a redirect", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// csrfOf is the CSRF token of b's pending request, as the consent page reads it.
func (f fixture) csrfOf(t *testing.T, b *routetest.Browser) string {
	t.Helper()
	resp, body := f.get(t, b, "/oauth/pending")
	csrf, _ := decode(t, body)["csrf"].(string)
	if resp.StatusCode != http.StatusOK || csrf == "" {
		t.Fatalf("pending request: %d %s", resp.StatusCode, body)
	}
	return csrf
}

func (f fixture) codeGrant(code, clientID string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "resource": {resource}, "code_verifier": {verifier}}
}

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return m
}

// authEvents is the outcome|decision|channel of each kind=auth row for action and resource.
func (f fixture) authEvents(t *testing.T, action, principal, resource string) []string {
	t.Helper()
	rows, err := f.St.Pool.Query(t.Context(), `SELECT outcome || '|' || decision || '|' || channel FROM audit_event
		WHERE kind = 'auth' AND action = $1 AND ($2 = '' OR principal = $2) AND ($3 = '' OR resource = $3) ORDER BY id`, action, principal, resource)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func (f fixture) consentID(t *testing.T, principal string) string {
	t.Helper()
	var id string
	if err := f.St.Pool.QueryRow(t.Context(), `SELECT id::text FROM oauth_consent WHERE principal = $1 ORDER BY id DESC LIMIT 1`, principal).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDebugCodePKCERefreshAndDiscovery(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	resp, body := f.get(t, b, "/.well-known/oauth-authorization-server")
	if resp.StatusCode != http.StatusOK || body != `{"issuer":"http://127.0.0.1:8080","authorization_endpoint":"http://127.0.0.1:8080/oauth/authorize",`+
		`"token_endpoint":"http://127.0.0.1:8080/oauth/token","revocation_endpoint":"http://127.0.0.1:8080/oauth/revoke",`+
		`"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],`+
		`"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],`+
		`"scopes_supported":["mcp:approvals:write","mcp:datasources:write","mcp:identity:write","mcp:policies:write","mcp:query","mcp:read","mcp:tokens"],`+
		`"client_id_metadata_document_supported":true}` {
		t.Fatalf("discovery: %d %s", resp.StatusCode, body)
	}

	resp, _ = f.get(t, b, f.authorize("mcp:read mcp:policies:write", "state-1", "mcp-debug@example.com"))
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("authorize headers %v", resp.Header)
	}
	loc := location(t, resp)
	if loc.Query().Get("state") != "state-1" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize went to %s", loc)
	}
	resp, body = f.form(t, b, "/oauth/token", f.codeGrant(loc.Query().Get("code"), f.clientID))
	first := decode(t, body)
	if resp.StatusCode != http.StatusOK || first["token_type"] != "Bearer" || first["expires_in"] != 600.0 ||
		first["scope"] != "mcp:policies:write mcp:read" {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first["refresh_token"].(string)},
		"client_id": {f.clientID}, "resource": {resource}}
	resp, body = f.form(t, b, "/oauth/token", refresh)
	if resp.StatusCode != http.StatusOK || decode(t, body)["refresh_token"] == first["refresh_token"] {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	resp, body = f.form(t, b, "/oauth/token", refresh)
	if resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_grant"}` {
		t.Fatalf("replay: %d %s", resp.StatusCode, body)
	}
	if n := f.Count(t, `SELECT count(*) FROM proxy_token WHERE client_id = $1 AND revoked_at IS NULL`, f.clientID); n != 0 {
		t.Fatalf("a replayed refresh token left %d tokens of its family live", n)
	}
	if got := f.authEvents(t, "auth.oauth.revoke", "unknown", ""); len(got) != 1 {
		t.Fatalf("replay revoke events %v", got)
	}
	// The debug authorization and the console share one session.
	if resp, _ := f.get(t, b, "/oauth/consents"); resp.StatusCode != http.StatusOK {
		t.Fatalf("consents after a debug authorization: %d", resp.StatusCode)
	}
}

func TestDiscoveryPutsAuthorizeOnTheConsoleOrigin(t *testing.T) {
	settings := dbtest.Settings()
	settings.WebOrigin = "http://console.example.com"
	f := fixture{Env: routetest.SetupConfig(t, routetest.Config{Settings: &settings})}
	_, body := f.get(t, f.Browser(t), "/.well-known/oauth-authorization-server")
	var got struct {
		Authorize string `json:"authorization_endpoint"`
		Token     string `json:"token_endpoint"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil ||
		got.Authorize != "http://console.example.com/oauth/authorize" || got.Token != "http://127.0.0.1:8080/oauth/token" {
		t.Fatalf("discovery: %s", body)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	for name, path := range map[string]string{
		"unknown scope":    strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), "mcp%3Aread", "mcp%3Aread+mcp%3Aadmin", 1),
		"no scope":         strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), "scope=mcp%3Aread", "scope=", 1),
		"other resource":   strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), url.QueryEscape(resource), url.QueryEscape("http://other/mcp"), 1),
		"plain challenge":  strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), "code_challenge_method=S256", "code_challenge_method=plain", 1),
		"short challenge":  strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), challenge, challenge[1:], 1),
		"blank state":      strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), "state=s", "state=+", 1),
		"no response_type": strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), "response_type=code", "response_type=token", 1),
	} {
		if resp, body := f.get(t, b, path); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	for name, path := range map[string]string{
		"unregistered redirect": strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), url.QueryEscape(redirect), url.QueryEscape("http://127.0.0.1:9999/callback"), 1),
		"unpublished client":    strings.Replace(f.authorize("mcp:read", "s", "p@example.com"), url.QueryEscape(f.clientID), url.QueryEscape(f.clientID+"x"), 1),
	} {
		if resp, body := f.get(t, b, path); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_client"}` {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	if resp, body := f.get(t, b, f.authorize("mcp:read", "s", "")); resp.StatusCode != http.StatusBadRequest || body != `{"error":"login_required"}` {
		t.Errorf("debug authorize naming no one: %d %s", resp.StatusCode, body)
	}
}

func TestConsentPage(t *testing.T) {
	f := setup(t, false, false)
	b := f.Browser(t)
	resp, _ := f.get(t, b, f.authorize("mcp:read mcp:tokens", "state-consent", "mcp-debug@example.com"))
	if loc := location(t, resp); loc.String() != "/consent" {
		t.Fatalf("authorize went to %s", loc)
	}
	csrf := f.csrfOf(t, b)
	want := `{"clientName":"Test MCP Client","clientId":"` + f.clientID + `","redirectUri":"` + redirect +
		`","loopback":true,"scopes":["mcp:read","mcp:tokens"],"csrf":"` + csrf + `"}`
	if resp, body := f.get(t, b, "/oauth/pending"); body != want || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("pending request: %v\n%s\nwant\n%s", resp.Header, body, want)
	}
	if resp, body := f.get(t, f.Browser(t), "/oauth/pending"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("pending request without the cookie: %d %s", resp.StatusCode, body)
	}

	for _, form := range []url.Values{{"decision": {"approve"}}, {"csrf": {"x"}, "decision": {"approve"}}} {
		if resp, body := f.form(t, b, "/oauth/consent", form); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
			t.Fatalf("consent with csrf %q: %d %s", form.Get("csrf"), resp.StatusCode, body)
		}
	}

	resp, _ = f.form(t, b, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"deny"}})
	if loc := location(t, resp); loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "state-consent" {
		t.Fatalf("deny went to %s", loc)
	}
	if resp, body := f.form(t, b, "/oauth/consent", url.Values{"csrf": {"x"}, "decision": {"approve"}}); resp.StatusCode != http.StatusBadRequest ||
		body != `{"error":"invalid_request"}` {
		t.Fatalf("consent after the pending request was cleared: %d %s", resp.StatusCode, body)
	}
	if n := f.Count(t, `SELECT count(*) FROM oauth_consent`); n != 0 {
		t.Fatalf("%d consents after a denial", n)
	}

	// Another principal signed in on the same browser can neither read nor approve the pending request.
	other := f.Browser(t)
	f.get(t, other, f.authorize("mcp:read", "state-other", "mcp-debug@example.com"))
	csrf = f.csrfOf(t, other)
	u, _ := url.Parse(f.Srv.URL)
	other.Jar.SetCookies(u, f.St.WebSession(t, "someone-else@example.com", session.NewKey(), "11111111-1111-4111-8111-111111111111"))
	if resp, body := f.get(t, other, "/oauth/pending"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("pending request read by another principal: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.form(t, other, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"approve"}}); resp.StatusCode != http.StatusBadRequest ||
		body != `{"error":"invalid_request"}` {
		t.Fatalf("pending request approved by another principal: %d %s", resp.StatusCode, body)
	}
	if n := f.Count(t, `SELECT count(*) FROM oauth_consent`); n != 0 {
		t.Fatalf("%d consents after another principal's approval", n)
	}
}

func TestProductionReusesTheSession(t *testing.T) {
	f := setup(t, true, false)
	b := f.Browser(t)
	u, _ := url.Parse(f.Srv.URL)
	b.Jar.SetCookies(u, f.St.WebSession(t, "mcp-user@example.com", session.NewKey(), "11111111-1111-4111-8111-111111111111"))
	resp, _ := f.get(t, b, f.authorize("mcp:read", "state-shared-session", "someone@example.com"))
	if loc := location(t, resp); loc.String() != "/consent" {
		t.Fatalf("authorize with a session went to %s", loc)
	}
	f.form(t, b, "/oauth/consent", url.Values{"csrf": {f.csrfOf(t, b)}, "decision": {"approve"}})
	if n := f.Count(t, `SELECT count(*) FROM oauth_consent WHERE principal = 'mcp-user@example.com'`); n != 1 {
		t.Fatal("outside debug, ?principal= must not choose who consents")
	}
	f.Exec(t, `UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT' WHERE principal = 'mcp-user@example.com'`)
	resp, _ = f.get(t, b, f.authorize("mcp:read", "state-ended-session", ""))
	if loc := location(t, resp); loc.String() != "/auth/oidc/login?return_to=%2Foauth%2Fresume" {
		t.Fatalf("authorize after the session ended went to %s", loc)
	}
}

func TestProductionCancelAtTheIdP(t *testing.T) {
	f := setup(t, true, true)
	b := f.Browser(t)
	resp, _ := f.get(t, b, f.authorize("mcp:read", "state-shared-oidc", ""))
	if loc := location(t, resp); loc.String() != "/auth/oidc/login?return_to=%2Foauth%2Fresume" {
		t.Fatalf("authorize went to %s", loc)
	}
	if resp, body := f.get(t, b, "/oauth/resume?error=login_required"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("resume with another error: %d %s", resp.StatusCode, body)
	}
	resp, _ = f.get(t, b, "/oauth/resume?error=access_denied")
	if loc := location(t, resp); loc.String() != redirect+"?error=access_denied&state=state-shared-oidc" {
		t.Fatalf("cancel went to %s", loc)
	}
	if resp, _ := f.get(t, b, "/oauth/resume?error=access_denied"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a second cancel: %d", resp.StatusCode)
	}
}

func TestProductionResumeAndConsent(t *testing.T) {
	f := setup(t, true, true)
	b := f.Browser(t)
	f.get(t, b, f.authorize("mcp:identity:write", "state-resumed", ""))
	if resp, body := f.get(t, b, "/oauth/resume"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("resume before logging in: %d %s", resp.StatusCode, body)
	}
	u, _ := url.Parse(f.Srv.URL)
	b.Jar.SetCookies(u, f.St.WebSession(t, "resume-user@example.com", session.NewKey(), "11111111-1111-4111-8111-111111111111"))
	resp, _ := f.get(t, b, "/oauth/resume")
	if loc := location(t, resp); loc.String() != "/consent" {
		t.Fatalf("resume went to %s", loc)
	}
	resp, _ = f.form(t, b, "/oauth/consent", url.Values{"csrf": {f.csrfOf(t, b)}, "decision": {"approve"}})
	loc := location(t, resp)
	if loc.Query().Get("code") == "" || loc.Query().Get("state") != "state-resumed" {
		t.Fatalf("approve went to %s", loc)
	}
	// The consent stands, so the next authorization skips the page.
	resp, _ = f.get(t, b, f.authorize("mcp:identity:write", "state-again", ""))
	if loc := location(t, resp); loc.Query().Get("code") == "" || loc.Query().Get("state") != "state-again" {
		t.Fatalf("a consented authorization went to %s", loc)
	}
	if resp, body := f.get(t, b, "/oauth/resume"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("an issued code left a pending request behind: %d %s", resp.StatusCode, body)
	}
}

func TestDebugAuthorizeKeepsTheSimulatedAddress(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	liveIP := func(principal string) string {
		var ip *string
		_ = f.St.Pool.QueryRow(t.Context(), `SELECT debug_requester_ip FROM principal_session
			WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL ORDER BY id DESC LIMIT 1`, principal).Scan(&ip)
		if ip == nil {
			return ""
		}
		return *ip
	}
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"ip-owner@example.com","requesterIp":"100.100.1.10"}`, http.StatusOK, "")
	if resp, _ := f.get(t, b, f.authorize("mcp:read", "state-ip", "ip-owner@example.com")); resp.StatusCode != http.StatusFound ||
		liveIP("ip-owner@example.com") != "100.100.1.10" {
		t.Fatalf("same principal: %d, address %q", resp.StatusCode, liveIP("ip-owner@example.com"))
	}
	if resp, _ := f.get(t, b, f.authorize("mcp:read", "state-ip", "ip-other@example.com")); resp.StatusCode != http.StatusFound ||
		liveIP("ip-other@example.com") != "" {
		t.Fatalf("another principal: %d, address %q", resp.StatusCode, liveIP("ip-other@example.com"))
	}
	// The consent is recorded from the session the request arrived with, as Kotlin does.
	if n := f.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.oauth.consent' AND client_addr = '100.100.1.10'`); n != 2 {
		t.Fatalf("%d consent rows from the simulated address, want 2", n)
	}

	// A browser whose device cookie is gone keeps the session the authorization mints.
	lost := f.Browser(t)
	lost.DebugLogin("ip-lost@example.com")
	u, _ := url.Parse(f.Srv.URL)
	lost.Jar.SetCookies(u, []*http.Cookie{{Name: "pm_did", Value: "", Path: "/", MaxAge: -1}})
	if resp, _ := f.get(t, lost, f.authorize("mcp:read", "state-lost", "ip-lost@example.com")); resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize without a device cookie: %d", resp.StatusCode)
	}
	if resp, body := f.get(t, lost, "/oauth/consents"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the minted session did not survive: %d %s", resp.StatusCode, body)
	}
}

func TestEachGrantAndRevokeWritesOneAuthEvent(t *testing.T) {
	f := setup(t, false, false)
	b := f.Browser(t)
	principal := "oauth-audit@example.com"
	f.get(t, b, f.authorize("mcp:read", "state-audit", principal))
	if got := f.authEvents(t, "auth.oauth.consent", principal, ""); len(got) != 0 {
		t.Fatalf("consent events before approving: %v", got)
	}
	resp, _ := f.form(t, b, "/oauth/consent", url.Values{"csrf": {f.csrfOf(t, b)}, "decision": {"approve"}})
	code := location(t, resp).Query().Get("code")
	consentID := f.consentID(t, principal)
	ok := []string{"SUCCESS|ALLOW|oauth"}
	if got := f.authEvents(t, "auth.oauth.consent", principal, `Consent::"`+consentID+`"`); strings.Join(got, ",") != strings.Join(ok, ",") {
		t.Fatalf("consent events %v", got)
	}
	var summary string
	_ = f.St.Pool.QueryRow(t.Context(), `SELECT statement FROM audit_event WHERE action = 'auth.oauth.consent'`).Scan(&summary)
	if summary != "OAuth consent granted to client "+f.clientID+" for mcp:read" {
		t.Fatalf("consent summary %q", summary)
	}

	_, body := f.form(t, b, "/oauth/token", f.codeGrant(code, f.clientID))
	access := decode(t, body)["access_token"].(string)
	client := `Client::"` + f.clientID + `"`
	if got := f.authEvents(t, "auth.oauth.token", "unknown", client); strings.Join(got, ",") != strings.Join(ok, ",") {
		t.Fatalf("token grant events %v", got)
	}
	if n := f.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.oauth.token' AND detail = 'grant_type=authorization_code'
		AND statement = 'OAuth token granted to client ' || $1`, f.clientID); n != 1 {
		t.Fatalf("token grant row: %d", n)
	}
	var tokenID string
	_ = f.St.Pool.QueryRow(t.Context(), `SELECT id::text FROM proxy_token WHERE token_hash = $1`, session.TokenHash(access)).Scan(&tokenID)
	revoked := `Token::"` + tokenID + `"`
	revoke := func(token string) {
		if resp, body := f.form(t, b, "/oauth/revoke", url.Values{"token": {token}}); resp.StatusCode != http.StatusOK || body != `{}` {
			t.Fatalf("revoke: %d %s", resp.StatusCode, body)
		}
	}
	revoke("pma_bogus")
	if got := f.authEvents(t, "auth.oauth.revoke", "", ""); len(got) != 0 {
		t.Fatalf("an unknown token's revoke recorded %v", got)
	}
	revoke(access)
	revoke(access)
	if got := f.authEvents(t, "auth.oauth.revoke", "unknown", revoked); strings.Join(got, ",") != strings.Join(ok, ",") {
		t.Fatalf("token revoke events %v", got)
	}

	resp, body = f.get(t, b, "/oauth/consents")
	list := decode(t, body)
	consents := list["consents"].([]any)
	if resp.StatusCode != http.StatusOK || len(consents) != 1 || consents[0].(map[string]any)["clientId"] != f.clientID {
		t.Fatalf("consents: %d %s", resp.StatusCode, body)
	}
	csrf := list["csrfToken"].(string)
	del := func(id, csrf string) (int, string) {
		req, _ := http.NewRequest(http.MethodDelete, f.Srv.URL+"/oauth/consents/"+id, nil)
		req.Header.Set("X-PM-CSRF", csrf)
		resp, body := noFollow(t, b, req)
		return resp.StatusCode, body
	}
	if status, body := del(consentID, "wrong"); status != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("wrong csrf: %d %s", status, body)
	}
	if status, body := del("x", csrf); status != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("bad id: %d %s", status, body)
	}
	if status, _ := del(consentID, csrf); status != http.StatusNoContent {
		t.Fatalf("revoke consent: %d", status)
	}
	if status, body := del(consentID, csrf); status != http.StatusNotFound || body != `{"error":"invalid_request"}` {
		t.Fatalf("repeat revoke consent: %d %s", status, body)
	}
	if got := f.authEvents(t, "auth.oauth.revoke", principal, `Consent::"`+consentID+`"`); strings.Join(got, ",") != strings.Join(ok, ",") {
		t.Fatalf("consent revoke events %v", got)
	}
	if n := f.Count(t, `SELECT count(*) FROM proxy_token WHERE consent_id = $1::bigint AND revoked_at IS NULL`, consentID); n != 0 {
		t.Fatalf("%d live tokens under a revoked consent", n)
	}
	if n := f.Count(t, `SELECT count(*) FROM audit_event WHERE statement LIKE '%' || $1 || '%' OR detail LIKE '%' || $1 || '%' OR resource LIKE '%' || $1 || '%'`, access); n != 0 {
		t.Fatalf("the access token reached the audit trail %d times", n)
	}
	anon := f.Browser(t)
	if resp, body := f.get(t, anon, "/oauth/consents"); resp.StatusCode != http.StatusUnauthorized || body != `{"error":"login_required"}` {
		t.Fatalf("consents without a session: %d %s", resp.StatusCode, body)
	}
	routetest.VerifyChain(t, f.Env)
}

func TestAutoConsentWritesOneConsentEvent(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	principal := "oauth-auto-consent@example.com"
	resp, _ := f.get(t, b, f.authorize("mcp:read", "state-auto-consent", principal))
	if location(t, resp).Query().Get("code") == "" {
		t.Fatal("no code")
	}
	if resp, body := f.get(t, b, "/oauth/resume"); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
		t.Fatalf("an issued code left a pending request behind: %d %s", resp.StatusCode, body)
	}
	f.get(t, b, f.authorize("mcp:read", "state-auto-consent", principal))
	if got := f.authEvents(t, "auth.oauth.consent", principal, `Consent::"`+f.consentID(t, principal)+`"`); strings.Join(got, ",") != "SUCCESS|ALLOW|oauth" {
		t.Fatalf("consent events %v", got)
	}
	routetest.VerifyChain(t, f.Env)
}

func TestARejectedGrantAuditLeavesTheCodeUnused(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	resp, _ := f.get(t, b, f.authorize("mcp:read", "state-token-rollback", "oauth-token-rollback@example.com"))
	code := location(t, resp).Query().Get("code")
	f.Exec(t, `CREATE FUNCTION pm_test_reject_auth_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced auth audit failure'; END $$ LANGUAGE plpgsql`)
	f.Exec(t, `CREATE TRIGGER pm_test_reject_auth_audit BEFORE INSERT ON audit_event FOR EACH ROW
		WHEN (NEW.kind = 'auth' AND NEW.action = 'auth.oauth.token') EXECUTE FUNCTION pm_test_reject_auth_audit()`)
	if resp, body := f.form(t, b, "/oauth/token", f.codeGrant(code, f.clientID)); resp.StatusCode != http.StatusInternalServerError || body != `{"error":"server_error"}` {
		t.Fatalf("grant with a rejected audit: %d %s", resp.StatusCode, body)
	}
	if n := f.Count(t, `SELECT count(*) FROM oauth_authorization_code WHERE code_hash = $1 AND used_at IS NULL`, session.TokenHash(code)); n != 1 {
		t.Fatal("a rejected grant audit consumed the code")
	}
	if n := f.Count(t, `SELECT count(*) FROM proxy_token WHERE client_id = $1`, f.clientID); n != 0 {
		t.Fatalf("a rejected grant audit minted %d tokens", n)
	}
	f.Exec(t, `DROP TRIGGER pm_test_reject_auth_audit ON audit_event`)
	if resp, body := f.form(t, b, "/oauth/token", f.codeGrant(code, f.clientID)); resp.StatusCode != http.StatusOK {
		t.Fatalf("retry: %d %s", resp.StatusCode, body)
	}
	routetest.VerifyChain(t, f.Env)
}

func TestTokenRejects(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	long := "https://client.example/" + strings.Repeat("a", 300)
	if resp, body := f.form(t, b, "/oauth/token", f.codeGrant("pmc_never-issued", long)); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_grant"}` {
		t.Fatalf("unknown code: %d %s", resp.StatusCode, body)
	}
	if n := f.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.oauth.token' AND outcome = 'FAILURE' AND resource = $1`,
		`Client::"`+long[:200]+`"`); n != 1 {
		t.Fatal("the denied grant did not record the client_id cut to 200 characters")
	}
	if n := f.Count(t, `SELECT count(*) FROM audit_event WHERE resource LIKE '%' || $1 || '%'`, strings.Repeat("a", 220)); n != 0 {
		t.Fatal("the whole client_id reached the audit trail")
	}
	for name, form := range map[string]url.Values{
		"no verifier": {"grant_type": {"authorization_code"}, "code": {"c"}, "client_id": {"x"}, "redirect_uri": {redirect}, "resource": {resource}},
		"no refresh":  {"grant_type": {"refresh_token"}, "client_id": {"x"}, "resource": {resource}},
	} {
		if resp, body := f.form(t, b, "/oauth/token", form); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	if resp, body := f.form(t, b, "/oauth/token", url.Values{"grant_type": {"password"}}); resp.StatusCode != http.StatusBadRequest || body != `{"error":"unsupported_grant_type"}` {
		t.Errorf("password grant: %d %s", resp.StatusCode, body)
	}

	resp, _ := f.get(t, b, f.authorize("mcp:read", "s", "p@example.com"))
	code := location(t, resp).Query().Get("code")
	wrong := f.codeGrant(code, f.clientID)
	wrong.Set("code_verifier", strings.Repeat("w", 43))
	if resp, body := f.form(t, b, "/oauth/token", wrong); resp.StatusCode != http.StatusBadRequest || body != `{"error":"invalid_grant"}` {
		t.Fatalf("wrong verifier: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.form(t, b, "/oauth/token", f.codeGrant(code, f.clientID)); resp.StatusCode != http.StatusOK {
		t.Fatalf("a wrong verifier used up the code: %d", resp.StatusCode)
	}
	if resp, _ := f.form(t, b, "/oauth/token", f.codeGrant(code, f.clientID)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a code redeemed twice: %d", resp.StatusCode)
	}
	routetest.VerifyChain(t, f.Env)
}

func TestARepeatedConsentWritesOneEvent(t *testing.T) {
	f := setup(t, false, false)
	b := f.Browser(t)
	principal := "oauth-double-consent@example.com"
	u, _ := url.Parse(f.Srv.URL)
	approve := func() {
		f.get(t, b, f.authorize("mcp:read", "state-double", principal))
		csrf, cookies := f.csrfOf(t, b), b.Jar.Cookies(u)
		// Both submissions carry the pending request, as a double click does before the first answer clears it.
		for range 2 {
			b.Jar.SetCookies(u, cookies)
			if resp, body := f.form(t, b, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"approve"}}); resp.StatusCode != http.StatusFound {
				t.Fatalf("approve: %d %s", resp.StatusCode, body)
			}
		}
	}
	approve()
	approve()
	if got := f.authEvents(t, "auth.oauth.consent", principal, `Consent::"`+f.consentID(t, principal)+`"`); strings.Join(got, ",") != "SUCCESS|ALLOW|oauth" {
		t.Fatalf("consent events %v", got)
	}
	routetest.VerifyChain(t, f.Env)
}

func TestRevokingAConsentEndsThePmonLoginsThatUsedIt(t *testing.T) {
	f := setup(t, false, true)
	b := f.Browser(t)
	b.DebugLogin("pmon-user@example.com")
	f.Exec(t, `INSERT INTO principal_session (kind, principal, idle_expires_at, absolute_expires_at)
		VALUES ('DAEMON', 'pmon-user@example.com', now() + interval '1 hour', now() + interval '1 hour')`)
	f.Exec(t, `INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES ('pmon-user@example.com', 'pmon', $1, 'mcp:read')`, resource)
	f.Exec(t, `INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, principal_session_id)
		SELECT 'h', 'MCP_ACCESS', 'pmon-user@example.com', '[]'::jsonb, now() + interval '1 hour', $1, 'pmon', 'mcp:read', 'pmf_x',
		       (SELECT id FROM oauth_consent WHERE client_id = 'pmon'), (SELECT id FROM principal_session WHERE kind = 'DAEMON')`, resource)
	_, body := f.get(t, b, "/oauth/consents")
	req, _ := http.NewRequest(http.MethodDelete, f.Srv.URL+"/oauth/consents/"+f.consentID(t, "pmon-user@example.com"), nil)
	req.Header.Set("X-PM-CSRF", decode(t, body)["csrfToken"].(string))
	if resp, _ := noFollow(t, b, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if n := f.Count(t, `SELECT count(*) FROM principal_session WHERE kind = 'DAEMON' AND ended_at IS NULL`); n != 0 {
		t.Fatal("the pmon login that minted under the consent is still live")
	}
}
