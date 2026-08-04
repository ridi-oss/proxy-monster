package mcp

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
)

// ---------------------------------------------------------------------------------------------
// `McpServerDbTest.kt` — all EIGHT cases, one Go test each, in the Kotlin's order and with the
// Kotlin's names. 11-mcp-oauth-management.md §9 lists them.
//
// The extra coverage F19 asks for ("eight cases for 38 tools … most of the 38 tools have no
// individual test") is in mcp_tools_db_test.go and mcp_pipeline_db_test.go, not here — this file is
// the migration and stays recognisable next to the Kotlin.
// ---------------------------------------------------------------------------------------------

// TestResourceMetadataAndBearerFailuresAreStandardsShaped is case 1.
// KT: McpServerDbTest.kt#resource metadata and bearer failures are standards shaped
func TestResourceMetadataAndBearerFailuresAreStandardsShaped(t *testing.T) {
	f := newMcpFixture(t)

	metadata := f.get("/.well-known/oauth-protected-resource/mcp")
	if metadata.status != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200 (%s)", metadata.status, metadata.rawBody)
	}
	var body struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}
	if err := json.Unmarshal([]byte(metadata.rawBody), &body); err != nil {
		t.Fatalf("decode metadata: %v (%s)", err, metadata.rawBody)
	}
	if body.Resource != testResource {
		t.Errorf("resource = %q, want %q", body.Resource, testResource)
	}
	if len(body.AuthorizationServers) != 1 || body.AuthorizationServers[0] != "http://localhost" {
		t.Errorf("authorization_servers = %v, want [http://localhost]", body.AuthorizationServers)
	}
	// Not in the Kotlin case, but free here and it is the discovery document a client reads to learn
	// which scopes exist at all: it must be the registry's sorted set, not a hardcoded list.
	if !slices.Equal(body.ScopesSupported, SupportedScopes) {
		t.Errorf("scopes_supported = %v, want %v", body.ScopesSupported, SupportedScopes)
	}
	if !slices.Equal(body.BearerMethodsSupported, []string{"header"}) {
		t.Errorf("bearer_methods_supported = %v, want [header]", body.BearerMethodsSupported)
	}

	// The BARE well-known path serves the same document. Two routes, one body.
	if bare := f.get("/.well-known/oauth-protected-resource"); bare.rawBody != metadata.rawBody {
		t.Errorf("the two discovery routes disagree:\n %s\n %s", bare.rawBody, metadata.rawBody)
	}

	noToken := f.post(toolCall(1, "list_roles", nil))
	if noToken.status != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401 (%s)", noToken.status, noToken.rawBody)
	}
	challenge := noToken.header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="`+testMetadataURI+`"`) {
		t.Errorf("WWW-Authenticate = %q, want it to carry resource_metadata=%q", challenge, testMetadataURI)
	}
	if got := noToken.apiErrorCode(t); got != "common.invalid_token" {
		t.Errorf("no-token code = %q, want common.invalid_token", got)
	}

	foreignOrigin := f.post(toolCall(2, "list_roles", nil), header("Origin", "https://evil.example"))
	if foreignOrigin.status != http.StatusForbidden {
		t.Fatalf("foreign-origin status = %d, want 403 (%s)", foreignOrigin.status, foreignOrigin.rawBody)
	}
	if got := foreignOrigin.apiErrorCode(t); got != "mcp.invalid_origin" {
		t.Errorf("foreign-origin code = %q, want mcp.invalid_origin", got)
	}

	foreignHost := f.post(toolCall(3, "list_roles", nil), header("Host", "evil.example"))
	if foreignHost.status != http.StatusForbidden {
		t.Fatalf("foreign-host status = %d, want 403 (%s)", foreignHost.status, foreignHost.rawBody)
	}
	if got := foreignHost.apiErrorCode(t); got != "mcp.invalid_host" {
		t.Errorf("foreign-host code = %q, want mcp.invalid_host", got)
	}
}

// TestAnHttpsResourceAdmitsACleartextForwardedRequestWhoseHostCarriesNoPort is case 2 — 🔒 INV-A11-3
// and INV-A11-4's production shape.
//
// The comment is the Kotlin's: behind a TLS-terminating edge the resource is https (default 443), the
// edge forwards cleartext to the container, and the client's `Host` omits the port because it is the
// scheme default. Reaching `common.invalid_token` rather than `mcp.invalid_host` is what proves the
// authority matched.
// KT: McpServerDbTest.kt#an https resource admits a cleartext-forwarded request whose Host carries no port
func TestAnHttpsResourceAdmitsACleartextForwardedRequestWhoseHostCarriesNoPort(t *testing.T) {
	f := newMcpFixture(t, func(c *config.Config) { c.MCPResource = "https://console.example.com/mcp" })

	response := f.post(toolCall(1, "list_roles", nil), header("Host", "console.example.com"))
	if response.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", response.status, response.rawBody)
	}
	if got := response.apiErrorCode(t); got != "common.invalid_token" {
		t.Errorf("code = %q, want common.invalid_token", got)
	}

	// 🔒 INV-A12-8 — a port on the Host is IGNORED, not compared. `:443` alone would also pass an
	// implementation that compared EFFECTIVE default ports, so the case that pins the property is the
	// NON-default port against an https resource.
	for _, authority := range []string{"console.example.com:443", "console.example.com:8443"} {
		withPort := f.post(toolCall(2, "list_roles", nil), header("Host", authority))
		if withPort.status != http.StatusUnauthorized {
			t.Errorf("Host %q: status = %d, want 401 (%s)", authority, withPort.status, withPort.rawBody)
		}
	}

	foreign := f.post(toolCall(3, "list_roles", nil), header("Host", "evil.example"))
	if foreign.status != http.StatusForbidden {
		t.Fatalf("foreign status = %d, want 403", foreign.status)
	}
	if got := foreign.apiErrorCode(t); got != "mcp.invalid_host" {
		t.Errorf("foreign code = %q, want mcp.invalid_host", got)
	}
}

// TestAnIPv6LiteralResourceHostMatchesAForwardedAuthority is case 3.
//
// Java exposes an IPv6 URI host BRACKETED while a forwarded authority resolves to the bare address, so
// comparing them raw rejects every request to a valid IPv6 resource. Go's `url.Hostname()` strips the
// brackets on one side and [unbracket] strips them on the other — the same normalisation, arrived at
// from the opposite direction, which is exactly why the area doc calls it out as a trap.
//
// Only the FORWARDED path is asserted here, as in the Kotlin. The direct path diverges deliberately
// and is pinned by TestDirectHostParsesIPv6Correctly and
// TestAnIPv6LiteralResourceHostAlsoMatchesADirectHostHeader.
// KT: McpServerDbTest.kt#an IPv6 literal resource host matches a forwarded authority
func TestAnIPv6LiteralResourceHostMatchesAForwardedAuthority(t *testing.T) {
	f := newMcpFixture(t, func(c *config.Config) {
		c.MCPResource = "http://[::1]/mcp"
		// httptest's peer is 127.0.0.1, where Ktor's testApplication reports the literal "localhost".
		c.TrustedProxies = map[string]struct{}{"127.0.0.1": {}}
	})
	// The direct Host is irrelevant once a trusted edge asserts one, but it still has to be a legal
	// authority for Go's client to send.
	f.defaultHost = "localhost"

	response := f.post(toolCall(1, "list_roles", nil), header("X-Forwarded-Host", "[::1]"))
	if response.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", response.status, response.rawBody)
	}
	if got := response.apiErrorCode(t); got != "common.invalid_token" {
		t.Errorf("code = %q, want common.invalid_token", got)
	}

	foreign := f.post(toolCall(2, "list_roles", nil), header("X-Forwarded-Host", "[::2]"))
	if foreign.status != http.StatusForbidden {
		t.Fatalf("foreign status = %d, want 403 (%s)", foreign.status, foreign.rawBody)
	}
	if got := foreign.apiErrorCode(t); got != "mcp.invalid_host" {
		t.Errorf("foreign code = %q, want mcp.invalid_host", got)
	}
}

// TestAnIPv6LiteralResourceHostAlsoMatchesADirectHostHeader is 🔴 THE DELIBERATE DIVERGENCE, asserted
// as behaviour rather than left in a comment.
//
// KNOWN_LIMITATIONS.md:265-271 records that on the JVM an IPv6-literal PM_MCP_RESOURCE is reachable
// only behind a trusted edge, because Ktor's `host()` shreds `Host: [::1]` at the literal's first
// colon. That is a framework artifact whose only effect is to refuse a request the operator asked to
// be served, so [directHost] uses the same bracket-aware parse as the forwarded path. Authority is
// NOT widened: the gate still demands equality with the configured resource host, which the second
// half of this case proves.
func TestAnIPv6LiteralResourceHostAlsoMatchesADirectHostHeader(t *testing.T) {
	f := newMcpFixture(t, func(c *config.Config) { c.MCPResource = "http://[::1]/mcp" })
	f.defaultHost = "[::1]"

	response := f.post(toolCall(1, "list_roles", nil))
	if response.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — the JVM answers 403 here (%s)", response.status, response.rawBody)
	}

	foreign := f.post(toolCall(2, "list_roles", nil), header("Host", "[::2]"))
	if foreign.status != http.StatusForbidden {
		t.Fatalf("foreign status = %d, want 403: the divergence must not widen the gate", foreign.status)
	}
}

// TestToolCatalogIsCompleteLocalizedAndScopeCannotGrantAWrite is case 4 —
// 🔒 INV-A11-1 / INV-A11-2 / INV-A11-7.
// KT: McpServerDbTest.kt#tool catalog is complete localized and scope cannot grant a write
func TestToolCatalogIsCompleteLocalizedAndScopeCannotGrantAWrite(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-catalog@example.com"
	f.grantRole(principal, "system:admin")
	readToken := f.mintToken(principal, ScopeRead)

	listed := f.post(rpcRequest(1, "tools/list", map[string]any{}),
		bearer(readToken), header("Accept-Language", "ko"))
	if listed.rpc == nil {
		t.Fatalf("tools/list did not return JSON-RPC (status %d): %s", listed.status, listed.rawBody)
	}
	var tools struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Annotations *struct {
				ReadOnlyHint    bool `json:"readOnlyHint"`
				DestructiveHint bool `json:"destructiveHint"`
				IdempotentHint  bool `json:"idempotentHint"`
				OpenWorldHint   bool `json:"openWorldHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listed.rpc["result"], &tools); err != nil {
		t.Fatalf("decode tools/list: %v (%s)", err, listed.rpc["result"])
	}

	// 🔒 INV-A11-2 — the ADVERTISED set is `approvedToolNames`, the frozen reviewed artifact, not
	// whatever happens to be in Entries.
	advertised := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		advertised = append(advertised, tool.Name)
	}
	wantNames := slices.Clone(ApprovedToolNames)
	slices.Sort(wantNames)
	gotNames := slices.Clone(advertised)
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("advertised tools = %v,\nwant %v", gotNames, wantNames)
	}

	for _, tool := range tools.Tools {
		if isBlank(tool.Description) {
			t.Errorf("tool %q has a blank description", tool.Name)
		}
		if tool.Annotations == nil {
			t.Fatalf("tool %q advertises no annotations", tool.Name)
			continue
		}
		capability := ByName[tool.Name]
		if tool.Annotations.ReadOnlyHint != capability.Annotations.ReadOnlyHint {
			t.Errorf("%s readOnlyHint = %v, want %v",
				tool.Name, tool.Annotations.ReadOnlyHint, capability.Annotations.ReadOnlyHint)
		}
		if tool.Annotations.DestructiveHint != capability.Annotations.DestructiveHint {
			t.Errorf("%s destructiveHint = %v, want %v",
				tool.Name, tool.Annotations.DestructiveHint, capability.Annotations.DestructiveHint)
		}
		if want := capability.Classification == ClassificationRead; tool.Annotations.IdempotentHint != want {
			t.Errorf("%s idempotentHint = %v, want %v", tool.Name, tool.Annotations.IdempotentHint, want)
		}
		// 🔒 INV-A11-13 — TRUE FOR EXACTLY ONE TOOL.
		if want := tool.Name == "get_table_detail"; tool.Annotations.OpenWorldHint != want {
			t.Errorf("%s openWorldHint = %v, want %v", tool.Name, tool.Annotations.OpenWorldHint, want)
		}
	}

	// `Accept-Language: ko` changed what the descriptions say. 역할 is "role".
	for _, tool := range tools.Tools {
		if tool.Name != "create_role" {
			continue
		}
		if !strings.Contains(tool.Description, "역할") {
			t.Errorf("create_role's ko description = %q, want it to contain 역할", tool.Description)
		}
	}

	// 🔒 INV-A11-7 — a read scope cannot reach a write tool, whatever Cedar says. This principal IS
	// system:admin, so Cedar would allow it; the scope is what refuses.
	denied, result := f.call(readToken, "create_role", map[string]any{"name": "scope-must-not-authorize"})
	if denied.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", denied.status, denied.rawBody)
	}
	challenge := denied.header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"insufficient_scope\"", challenge)
	}
	if !strings.Contains(challenge, `scope="`+ScopePoliciesWrite+`"`) {
		t.Errorf("WWW-Authenticate = %q, want scope=%q", challenge, ScopePoliciesWrite)
	}
	if !result.isError {
		t.Error("the insufficient-scope result is not marked isError")
	}
	if got := result.errorCode(t); got != "mcp.insufficient_scope" {
		t.Fatalf("code = %q, want mcp.insufficient_scope", got)
	}
	// 🔒 INV-A11-15 — BOTH locales, inline, because an MCP client has no message catalog.
	assertBothLocalesPresent(t, result)

	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name=$1`, "scope-must-not-authorize"); n != 0 {
		t.Errorf("the refused create_role wrote %d rows", n)
	}
}

// assertBothLocalesPresent is 🔒 INV-A11-15's assertion, used by every error-shaped case.
func assertBothLocalesPresent(t testing.TB, result callResult) {
	t.Helper()
	for _, key := range []string{"message_en", "message_ko"} {
		raw, ok := result.structured[key]
		if !ok {
			t.Fatalf("%s missing from the MCP error body: %v", key, result.structured)
		}
		var message string
		if err := json.Unmarshal(raw, &message); err != nil {
			t.Fatalf("decode %s: %v", key, err)
		}
		if isBlank(message) {
			t.Errorf("%s is blank", key)
		}
	}
	var en, ko string
	_ = json.Unmarshal(result.structured["message_en"], &en)
	_ = json.Unmarshal(result.structured["message_ko"], &ko)
	if en == ko {
		t.Errorf("message_en and message_ko are the same string (%q) — one locale did not resolve", en)
	}
}

// TestMutationsAreAtomicIdempotentAuditedAndRolesAreResolvedLive is case 5 —
// 🔒 INV-A11-8 / INV-A11-10 / INV-A11-11.
// KT: McpServerDbTest.kt#mutations are atomic idempotent audited and roles are resolved live
func TestMutationsAreAtomicIdempotentAuditedAndRolesAreResolvedLive(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-mutation@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite, ScopePoliciesWrite)

	arguments := map[string]any{
		"name":           "mcp-idempotent-role",
		"description":    "created once",
		"idempotencyKey": "create-role-once",
	}

	_, first := f.call(token, "create_role", arguments)
	if first.isError {
		t.Fatalf("first create_role failed: %v", first.structured)
	}
	_, replay := f.call(token, "create_role", arguments)
	if replay.isError {
		t.Fatalf("the replay failed: %v", replay.structured)
	}
	if !sameJSON(t, first.structured["result"], replay.structured["result"]) {
		t.Errorf("the replay returned a different body:\n first  %s\n replay %s",
			first.structured["result"], replay.structured["result"])
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name=$1`, "mcp-idempotent-role"); n != 1 {
		t.Errorf("app_role rows = %d, want 1 — the replay ran the mutation again", n)
	}
	if got := f.auditOutcomes(principal, "[MCP create_role]"); !slices.Equal(got, []string{"ALLOW", "IDEMPOTENT_REPLAY"}) {
		t.Errorf("audit outcomes = %v, want [ALLOW IDEMPOTENT_REPLAY]", got)
	}
	channels := f.strings(
		`SELECT DISTINCT channel FROM audit_event WHERE principal=$1 AND statement='[MCP create_role]'`, principal)
	if !slices.Equal(channels, []string{"mcp"}) {
		t.Errorf("channels = %v, want [mcp]", channels)
	}

	// 🔒 INV-A11-11 — the SAME key with DIFFERENT arguments is a CONFLICT, never a silent replay.
	conflictArgs := map[string]any{}
	for k, v := range arguments {
		conflictArgs[k] = v
	}
	conflictArgs["description"] = "different input"
	_, conflict := f.call(token, "create_role", conflictArgs)
	if !conflict.isError {
		t.Fatal("a replay with different arguments was not an error")
	}
	if got := conflict.errorCode(t); got != "mcp.idempotency_conflict" {
		t.Errorf("code = %q, want mcp.idempotency_conflict", got)
	}

	// 🔒 INV-A11-16 — an undeclared argument is refused, and the WRITE path AUDITS the refusal.
	_, malformed := f.call(token, "create_role", map[string]any{"name": "must-not-exist", "unexpected": true})
	if !malformed.isError {
		t.Fatal("an unknown argument key was accepted")
	}
	if got := malformed.errorCode(t); got != "mcp.invalid_request" {
		t.Errorf("code = %q, want mcp.invalid_request", got)
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name=$1`, "must-not-exist"); n != 0 {
		t.Errorf("the refused call wrote %d app_role rows", n)
	}
	if got := f.strings(
		`SELECT outcome FROM audit_event WHERE principal=$1 AND statement='[MCP create_role]'
		   AND outcome='mcp.invalid_request'`, principal); !slices.Equal(got, []string{"mcp.invalid_request"}) {
		t.Errorf("invalid-request audit rows = %v, want [mcp.invalid_request]", got)
	}

	// A structurally wrong argument (an object where a string belongs) is the same refusal, and it is
	// audited against the datasource tool — which is also the case that proves `safeDatasource` names a
	// datasource only for the two classification tools without exploding on a non-string one.
	_, malformedDatasource := f.call(token, "set_column_classification", map[string]any{
		"datasource": map[string]any{"invalid": true},
		"table":      "users",
		"column":     "rrn",
		"tags":       []string{"pii"},
	})
	if !malformedDatasource.isError {
		t.Fatal("a non-string datasource was accepted")
	}
	if got := malformedDatasource.errorCode(t); got != "mcp.invalid_request" {
		t.Errorf("code = %q, want mcp.invalid_request", got)
	}
	if got := f.auditOutcomes(principal, "[MCP set_column_classification]"); !slices.Equal(got, []string{"mcp.invalid_request"}) {
		t.Errorf("set_column_classification outcomes = %v, want [mcp.invalid_request]", got)
	}

	// 🔒 INV-A11-8 — roles are resolved LIVE. The same token, valid and unexpired, stops working the
	// moment the assignment behind it is gone.
	f.unassignRole(principal, "system:admin")
	afterLoss, lost := f.call(token, "create_role",
		map[string]any{"name": "must-not-exist-after-role-loss", "idempotencyKey": "after-role-loss"})
	if afterLoss.status != http.StatusForbidden {
		t.Fatalf("status after role loss = %d, want 403 (%s)", afterLoss.status, afterLoss.rawBody)
	}
	if got := lost.errorCode(t); got != "common.forbidden" {
		t.Errorf("code = %q, want common.forbidden", got)
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name=$1`, "must-not-exist-after-role-loss"); n != 0 {
		t.Errorf("the denied call wrote %d rows", n)
	}
}

// sameJSON compares two encoded values as PARSED JSON, which is what the Kotlin's
// `assertEquals(first.structuredContent, replay.structuredContent)` does.
//
// It matters here rather than being pedantry: a replay's body comes back through JSONB, which
// re-orders object keys and re-renders numbers, so the two are equal as VALUES and unequal as BYTES.
// [MutationExecutor.priorResponse] documents the same thing from the other side.
func sameJSON(t testing.TB, a, b json.RawMessage) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("decode %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	x, _ := json.Marshal(av)
	y, _ := json.Marshal(bv)
	return string(x) == string(y)
}

// TestCedarAuthorityRemainsNarrowerThanABroadConsentScope is case 6 — 🔒 INV-A11-7's sufficiency half,
// end to end over the real Cedar engine.
// KT: McpServerDbTest.kt#Cedar authority remains narrower than a broad consent scope
func TestCedarAuthorityRemainsNarrowerThanABroadConsentScope(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-policy-only@example.com"

	f.seed.Role("mcp-policy-only")
	f.seed.CedarPolicy("mcp-policy-only",
		`permit(principal in Role::"mcp-policy-only", action == Action::"admin.policies", resource);`)
	f.grantRole(principal, "mcp-policy-only")

	// The consent carries EVERY write scope. Cedar carries one action.
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite)

	_, created := f.call(token, "create_role", map[string]any{"name": "mcp-created-by-policy-admin"})
	if created.isError {
		t.Fatalf("create_role should be permitted by admin.policies: %v", created.structured)
	}

	assigned, assignResult := f.call(token, "assign_role", map[string]any{
		"principal": principal, "roleName": "mcp-created-by-policy-admin",
	})
	if assigned.status != http.StatusForbidden {
		t.Fatalf("assign_role status = %d, want 403 (%s)", assigned.status, assigned.rawBody)
	}
	if got := assignResult.errorCode(t); got != "common.forbidden" {
		t.Errorf("assign_role code = %q, want common.forbidden", got)
	}
	if got := f.auditOutcomes(principal, "[MCP assign_role]"); !slices.Equal(got, []string{"common.forbidden"}) {
		t.Errorf("assign_role audit = %v, want [common.forbidden]", got)
	}

	// A denied READ audits too — 🔒 INV-A11-14's other half.
	listed, listResult := f.call(token, "list_users", nil)
	if listed.status != http.StatusForbidden {
		t.Fatalf("list_users status = %d, want 403 (%s)", listed.status, listed.rawBody)
	}
	if got := listResult.errorCode(t); got != "common.forbidden" {
		t.Errorf("list_users code = %q, want common.forbidden", got)
	}
	if got := f.auditOutcomes(principal, "[MCP list_users]"); !slices.Equal(got, []string{"common.forbidden"}) {
		t.Errorf("list_users audit = %v, want [common.forbidden]", got)
	}
}

// TestRepresentativeToolFamiliesDispatchWithStructuredLivenessAndAudit is case 7.
//
// The Kotlin's final assertion is `count(*) FROM audit_event WHERE principal = ? == 8`, and that
// number is the case's real content: EIGHT writes produced eight rows and the two READS at the end
// produced NONE. 🔒 INV-A11-14 stated as arithmetic.
func TestRepresentativeToolFamiliesDispatchWithStructuredLivenessAndAudit(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-tool-families@example.com"
	f.grantRole(principal, "system:admin")
	f.seedDatasource("mcp-family-datasource")
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite, ScopePoliciesWrite, ScopeIdentityWrite)

	writes := []struct {
		tool string
		args map[string]any
	}{
		{"create_user", map[string]any{"principal": "mcp-managed-user@example.com"}},
		{"create_group", map[string]any{"name": "mcp-managed-group"}},
		{"add_group_member", map[string]any{
			"groupName": "mcp-managed-group", "principal": "mcp-managed-user@example.com"}},
		{"create_role", map[string]any{"name": "mcp-managed-role"}},
		{"assign_role", map[string]any{
			"principal": "mcp-managed-user@example.com", "roleName": "mcp-managed-role"}},
		{"create_mask_fn", map[string]any{"name": "mcp-managed-mask", "kind": "FIXED"}},
		{"create_policy", map[string]any{
			"name":     "mcp-managed-policy",
			"cedarSrc": `permit(principal in Role::"mcp-managed-role", action == Action::"admin.identity", resource);`}},
		{"set_column_classification", map[string]any{
			"datasource": "mcp-family-datasource", "schema": "public", "table": "users",
			"column": "rrn", "tags": []string{"pii"}, "maskFnName": "mcp-managed-mask"}},
	}
	for _, w := range writes {
		_, result := f.call(token, w.tool, w.args)
		if result.isError {
			t.Fatalf("%s failed: %s", w.tool, result.text)
		}
		if len(result.structured) == 0 {
			t.Fatalf("%s returned no structuredContent", w.tool)
		}
	}

	_, livenessResult := f.call(token, "get_datasource_liveness", map[string]any{"datasource": "mcp-family-datasource"})
	if livenessResult.isError {
		t.Fatalf("get_datasource_liveness failed: %s", livenessResult.text)
	}
	liveness := livenessResult.resultObject(t)
	var name string
	if err := json.Unmarshal(liveness["datasource"], &name); err != nil || name != "mcp-family-datasource" {
		t.Errorf("liveness datasource = %s, want mcp-family-datasource", liveness["datasource"])
	}
	if _, ok := liveness["attached"]; !ok {
		t.Error("liveness has no `attached` field")
	}
	// 🔒 INV-A1-4's explicitNulls=false half: an absent optional field is OMITTED, never null.
	for _, absent := range []string{"detail", "message"} {
		if _, ok := liveness[absent]; ok {
			t.Errorf("liveness carries %q; an absent optional must be omitted, not emitted", absent)
		}
	}

	_, tagsResult := f.call(token, "list_column_tags", map[string]any{"datasource": "mcp-family-datasource"})
	if tagsResult.isError {
		t.Fatalf("list_column_tags failed: %s", tagsResult.text)
	}
	var tags []struct {
		Column string `json:"column"`
	}
	if err := json.Unmarshal(tagsResult.structured["result"], &tags); err != nil {
		t.Fatalf("decode list_column_tags: %v (%s)", err, tagsResult.structured["result"])
	}
	if len(tags) != 1 || tags[0].Column != "rrn" {
		t.Errorf("column tags = %v, want exactly one for rrn", tags)
	}

	// 🔒 INV-A11-14, as arithmetic: eight WRITEs, two successful READs, EIGHT rows.
	if n := f.scalar(`SELECT count(*) FROM audit_event WHERE principal=$1`, principal); n != 8 {
		t.Errorf("audit rows = %d, want 8 — a successful READ must write none", n)
	}
}

// TestAFailedAuditInsertRollsBackItsManagementMutation is case 8 — 🔒 INV-A11-10.
//
// The trigger is the Kotlin's, verbatim in intent: a BEFORE INSERT on `audit_event` that raises for
// exactly the one statement this case makes. It fires INSIDE the mutation's transaction, which is the
// whole point — if the audit insert ran on its own connection the group would survive.
// KT: McpServerDbTest.kt#a failed audit insert rolls back its management mutation
func TestAFailedAuditInsertRollsBackItsManagementMutation(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-audit-rollback@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	f.exec(`CREATE OR REPLACE FUNCTION pm_test_fail_mcp_audit() RETURNS trigger AS $body$
	        BEGIN RAISE EXCEPTION 'forced MCP audit failure'; END
	        $body$ LANGUAGE plpgsql`)
	f.exec(`CREATE TRIGGER pm_test_fail_mcp_audit BEFORE INSERT ON audit_event
	        FOR EACH ROW WHEN (NEW.statement = '[MCP create_group]')
	        EXECUTE FUNCTION pm_test_fail_mcp_audit()`)
	t.Cleanup(func() {
		f.exec(`DROP TRIGGER IF EXISTS pm_test_fail_mcp_audit ON audit_event`)
		f.exec(`DROP FUNCTION IF EXISTS pm_test_fail_mcp_audit()`)
	})

	_, failed := f.call(token, "create_group", map[string]any{"name": "must-roll-back-with-audit"})
	if !failed.isError {
		t.Fatal("a failed audit insert did not fail the call")
	}
	if n := f.scalar(`SELECT count(*) FROM app_group WHERE name=$1`, "must-roll-back-with-audit"); n != 0 {
		t.Errorf("app_group rows = %d, want 0 — the mutation was not rolled back", n)
	}
	// The catch-all arm: a database failure is `mcp.internal_error` with no detail, because an MCP
	// client is a language model and a raw driver message is both useless and a disclosure risk.
	if got := failed.errorCode(t); got != "mcp.internal_error" {
		t.Errorf("code = %q, want mcp.internal_error", got)
	}
}
