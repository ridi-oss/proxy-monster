package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// The DB-backed harness for A11 §§2-5.
//
// `McpServerDbTest.kt` builds the WHOLE object graph — real stores, real Cedar, real audit — and
// drives it over HTTP, because every property it asserts (rollback, idempotency rows, audit outcomes,
// live role resolution) is only observable in the rows. This fixture does the same.
//
// 🔴 THE ONE SEAM THAT IS FAKED IS [TokenResolver], and it is faked because `McpTokenStore` lives in
// the Kotlin `auth/` module (14-auth.md), not this area. The Kotlin test mints a real access token
// through `OAuthAuthorizationStore`; the Go port's OAuth store is a sibling increment, so gate 3's
// input is supplied directly. What the fake must preserve is written down on [TokenResolver] itself:
// a nil identity is "no such live token", and a resolved identity has ALREADY been matched on
// resource (INV-A11-18's audience binding). Nothing below depends on how the token was minted.
// ---------------------------------------------------------------------------------------------

const (
	// testResource is the Kotlin's `RESOURCE`.
	testResource = "http://localhost/mcp"
	// testMetadataURI is the Kotlin's `METADATA_URI`.
	testMetadataURI = "http://localhost/.well-known/oauth-protected-resource/mcp"
	// testClientID is the Kotlin's `CLIENT_ID` — a CIMD URL, which is what an MCPA client id is.
	testClientID = "https://client.example/mcp.json"
)

// fakeTokens is the [TokenResolver] seam.
//
// It enforces the audience binding itself (`resource != expected ⇒ nil`) so that a test which forgot
// to point the client at the configured resource fails the same way production would, rather than
// silently authenticating.
type fakeTokens struct {
	byToken map[string]*AccessIdentity
	// calls counts resolutions, which is how INV-A11-5's "Origin is validated BEFORE authentication"
	// is proved rather than asserted: a refused cross-origin request must leave this at zero.
	calls atomic.Int64
	// err, when set, is returned instead of a lookup — the SQLException path.
	err error
}

func (f *fakeTokens) ResolveAccess(_ context.Context, token, expectedResource string) (*AccessIdentity, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	identity, ok := f.byToken[token]
	if !ok {
		return nil, nil
	}
	if identity.Resource != expectedResource {
		return nil, nil
	}
	return identity, nil
}

// attachedSet is the [management.ProxyAttachments] seam — A5's `ProxyEventsHub.attached()`, a live
// in-memory registry of which datasources have a proxy streaming events. Mutable so a case can flip a
// datasource's liveness without a proxy.
type attachedSet struct{ names map[string]struct{} }

func (a *attachedSet) Attached() map[string]struct{} { return a.names }

// fakeTableDetails is [management.TableDetails]. `get_table_detail` reaches the LIVE target database
// through the proxy — 🔒 INV-A11-13, the one tool whose `openWorldHint` is true — which is A5/A10
// plumbing this area does not own.
//
// The zero value returns (nil, nil), the Kotlin's "the datasource exists but introspection found no
// such table", which the service turns into `common.not_found{resource: table}`.
type fakeTableDetails struct {
	fetch func(ctx context.Context, name, schema, table string) (*engine.TableDetail, error)
}

func (f *fakeTableDetails) Fetch(ctx context.Context, name, schema, table string) (*engine.TableDetail, error) {
	if f.fetch == nil {
		return nil, nil
	}
	return f.fetch(ctx, name, schema, table)
}

// discardLogger keeps the suite's output readable: the pipeline logs an Error on every deliberate
// internal failure (the forced audit trigger, the forced token-store error), and those are EXPECTED
// here. Routed to t.Log so a genuinely unexpected one is still recoverable with `-v`.
func discardLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

type mcpFixture struct {
	t   *testing.T
	ctx context.Context

	db   *store.Db
	pool *pgxpool.Pool
	seed *dbtest.Seed

	cedarStore *policy.CedarPolicyStore
	auditStore *audit.Store

	tokens       *fakeTokens
	versions     *countingVersions
	attached     *attachedSet
	tableDetails *fakeTableDetails
	routes       *Routes
	server       *httptest.Server

	// defaultHost is what every request's `Host` is set to unless a case overrides it.
	//
	// 🔴 httptest's listener answers on 127.0.0.1:<random>, so Go's client would send
	// `Host: 127.0.0.1:53211` and gate 1 would refuse EVERY request — the suite would be green on 403s
	// and prove nothing. Ktor's `testApplication` has no socket and reports the authority as
	// `localhost`, which is why the Kotlin file never mentions this. Setting it here is the equivalent
	// of that, and the cases that care about the host set it themselves.
	defaultHost string
}

// newMcpFixture is the Go form of `installTestMcp`.
func newMcpFixture(t *testing.T, opts ...func(*config.Config)) *mcpFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	ctx := context.Background()

	policyStore := policy.NewPolicyStore(db.Pool)
	cedarStore := policy.NewCedarPolicyStore(db.Pool)
	userStore := identity.NewUserGroupStore(db.Pool)
	datasourceStore := datasource.NewDatasourceStore(db)
	auditStore := audit.New(db.Pool)

	roleResolver := identity.NewRoleResolver(db.Pool, userStore, noGrants{})
	cedarEngine, err := authz.NewCedarEngine(cedarStore)
	if err != nil {
		t.Fatalf("build the Cedar engine over the seeded policies: %v", err)
	}
	// 🔒 INV-A11-8 — the RoleSource resolves LIVE, from the same resolver the Authorizer calls, so a
	// role revoked mid-test is visible to Cedar on the very next call.
	az := authz.New(cedarEngine, cedarStore, authz.RoleSourceFunc(func(principal string) []string {
		roles, err := roleResolver.Resolve(ctx, principal)
		if err != nil {
			return nil
		}
		return roles
	}))

	cfg := config.Defaults()
	cfg.AuthDebug = false
	cfg.MCPResource = testResource
	cfg.TrustedProxies = map[string]struct{}{}
	for _, o := range opts {
		o(&cfg)
	}

	f := &mcpFixture{
		t: t, ctx: ctx, db: db, pool: db.Pool, seed: dbtest.NewSeed(t, db),
		cedarStore: cedarStore, auditStore: auditStore,
		tokens:       &fakeTokens{byToken: map[string]*AccessIdentity{}},
		versions:     &countingVersions{},
		attached:     &attachedSet{names: map[string]struct{}{}},
		tableDetails: &fakeTableDetails{},
	}

	routes, err := New(Options{
		Config:        cfg,
		DB:            db.Pool,
		Tokens:        f.tokens,
		Deactivations: userStore,
		Roles:         roleResolver,
		Cedar:         az,
		Audit:         auditStore,
		Policies:      f.versions,
		Services: Services{
			Datasources: management.NewDatasourceService(
				datasourceStore, f.attached, f.tableDetails),
			Policies:   management.NewPolicyService(cedarStore, policyStore),
			Identities: management.NewIdentityService(db.Pool, userStore, policyStore, nil),
			MaskFns:    policyStore,
		},
		Log: discardLogger(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.routes = routes

	f.defaultHost = routes.resourceHost

	mux := http.NewServeMux()
	routes.Register(mux)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// noGrants is [identity.AccessGrants]. A6's JIT grants are a third role source and no case here needs
// one; an empty implementation keeps the resolver honest about the two sources that ARE seeded.
type noGrants struct{}

func (noGrants) ListGrantRoles(context.Context, string, bool) ([]string, error) { return nil, nil }

// ---- HTTP driving --------------------------------------------------------------------------------

// rpcRequest is one JSON-RPC envelope, the Kotlin's `toolCall(id, name, arguments)` generalised over
// the method so `tools/list` uses the same path.
func rpcRequest(id int, method string, params any) string {
	body := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func toolCall(id int, name string, arguments map[string]any) string {
	if arguments == nil {
		arguments = map[string]any{}
	}
	return rpcRequest(id, "tools/call", map[string]any{"name": name, "arguments": arguments})
}

// httpResult is what every call below returns: the raw HTTP facts plus the decoded JSON-RPC body.
type httpResult struct {
	status  int
	header  http.Header
	rawBody string
	// rpc is the decoded JSON-RPC envelope, or nil when the body was not one (a gate rejection).
	rpc map[string]json.RawMessage
}

// post drives one request through the whole mounted pipeline.
//
// `acceptMcp`'s three headers are the Kotlin's, and all three are load-bearing: the SDK refuses a
// request whose Content-Type is not application/json or whose Accept omits either media type.
func (f *mcpFixture) post(body string, mutate ...func(*http.Request)) httpResult {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		f.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Host = f.defaultHost
	for _, m := range mutate {
		m(req)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		f.t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("read body: %v", err)
	}
	out := httpResult{status: resp.StatusCode, header: resp.Header.Clone(), rawBody: string(raw)}
	if payload := jsonRPCPayload(resp.Header.Get("Content-Type"), string(raw)); payload != "" {
		decoded := map[string]json.RawMessage{}
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			out.rpc = decoded
		}
	}
	return out
}

// get drives one of the two unauthenticated discovery routes.
func (f *mcpFixture) get(path string) httpResult {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.server.URL+path, nil)
	if err != nil {
		f.t.Fatalf("build request: %v", err)
	}
	req.Host = f.defaultHost
	resp, err := f.server.Client().Do(req)
	if err != nil {
		f.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("read body: %v", err)
	}
	out := httpResult{status: resp.StatusCode, header: resp.Header.Clone(), rawBody: string(raw)}
	decoded := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &decoded); err == nil {
		out.rpc = decoded
	}
	return out
}

// apiErrorCode reads the `code` of a gate rejection's ApiError body.
func (r httpResult) apiErrorCode(t testing.TB) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(r.rawBody), &body); err != nil {
		t.Fatalf("decode ApiError (status %d): %v (%s)", r.status, err, r.rawBody)
	}
	return body.Code
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func header(name, value string) func(*http.Request) {
	return func(r *http.Request) {
		if strings.EqualFold(name, "Host") {
			r.Host = value
			return
		}
		r.Header.Set(name, value)
	}
}

// jsonRPCPayload unwraps the transport framing.
//
// 🔴 RECORDED FRAMING DIFFERENCE. The Kotlin SDK answers a stateless POST with `application/json` —
// `McpServerDbTest` parses `response.bodyAsText()` straight into a JsonObject. The Go SDK's
// `StreamableHTTPHandler` frames the same JSON-RPC response as `text/event-stream` unless
// `StreamableHTTPOptions.JSONResponse` is set, and the port leaves it unset rather than guessing at a
// wire change: both framings are legal under the Streamable HTTP transport and every conformant
// client accepts both, but flipping it is a visible change to the response's Content-Type and belongs
// in a decision, not in a test helper. This function therefore accepts EITHER, and
// TestTheStatelessPostIsFramedAsAnEventStream pins which one the port actually emits so the choice is
// asserted somewhere rather than assumed everywhere.
func jsonRPCPayload(contentType, body string) string {
	if !strings.HasPrefix(contentType, "text/event-stream") {
		return body
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			return after
		}
	}
	return ""
}

// ---- JSON-RPC result accessors ---------------------------------------------------------------

// callResult is the decoded `result` of a `tools/call` response.
type callResult struct {
	isError    bool
	structured map[string]json.RawMessage
	text       string
}

// toolResultOf decodes a `tools/call` response, failing the test if the transport returned a
// JSON-RPC `error` instead (which would mean the handler itself failed, not the tool).
func (f *mcpFixture) toolResultOf(res httpResult) callResult {
	f.t.Helper()
	if res.rpc == nil {
		f.t.Fatalf("not a JSON-RPC body (status %d): %s", res.status, res.rawBody)
	}
	if raw, ok := res.rpc["error"]; ok {
		f.t.Fatalf("JSON-RPC error where a tool result was expected: %s", raw)
	}
	var decoded struct {
		IsError           bool                       `json:"isError"`
		StructuredContent map[string]json.RawMessage `json:"structuredContent"`
		Content           []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res.rpc["result"], &decoded); err != nil {
		f.t.Fatalf("decode tools/call result: %v (%s)", err, res.rpc["result"])
	}
	out := callResult{isError: decoded.IsError, structured: decoded.StructuredContent}
	if len(decoded.Content) > 0 {
		out.text = decoded.Content[0].Text
	}
	return out
}

// call is the common shape: POST one tool call as `principal`'s token and decode the result.
func (f *mcpFixture) call(token, name string, arguments map[string]any, mutate ...func(*http.Request)) (httpResult, callResult) {
	f.t.Helper()
	res := f.post(toolCall(nextRPCID(), name, arguments), append([]func(*http.Request){bearer(token)}, mutate...)...)
	return res, f.toolResultOf(res)
}

var rpcIDs atomic.Int64

func nextRPCID() int { return int(rpcIDs.Add(1)) }

// errorCode reads `structuredContent.code`, which every localizedError body carries and no success
// body does.
func (c callResult) errorCode(t testing.TB) string {
	t.Helper()
	raw, ok := c.structured["code"]
	if !ok {
		t.Fatalf("no `code` in structuredContent: %v", c.structured)
	}
	var code string
	if err := json.Unmarshal(raw, &code); err != nil {
		t.Fatalf("decode code: %v", err)
	}
	return code
}

// resultObject reads `structuredContent.result` as an object.
func (c callResult) resultObject(t testing.TB) map[string]json.RawMessage {
	t.Helper()
	raw, ok := c.structured["result"]
	if !ok {
		t.Fatalf("no `result` in structuredContent: %v", c.structured)
	}
	out := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode result object: %v (%s)", err, raw)
	}
	return out
}

// ---- seeding -------------------------------------------------------------------------------------

// mintToken registers a bearer for `principal` with `scopes`. The returned string is opaque, exactly
// as a real access token is.
func (f *mcpFixture) mintToken(principal string, scopes ...string) string {
	f.t.Helper()
	token := "tok-" + principal + "-" + strings.Join(scopes, "+")
	f.tokens.byToken[token] = &AccessIdentity{
		Principal: principal, ClientID: testClientID, Resource: testResource,
		Scopes: scopes, ConsentID: 1,
	}
	return token
}

// grantRole is the Kotlin's `grantRole` — a direct `principal_role` row, asserting exactly one row was
// written so a typo in the role name fails here rather than as an inexplicable deny later.
func (f *mcpFixture) grantRole(principal, roleName string) {
	f.t.Helper()
	tag, err := f.pool.Exec(f.ctx,
		`INSERT INTO principal_role(principal, role_id) SELECT $1, id FROM app_role WHERE name=$2
		 ON CONFLICT DO NOTHING`, principal, roleName)
	if err != nil {
		f.t.Fatalf("grant %s to %s: %v", roleName, principal, err)
	}
	if tag.RowsAffected() != 1 {
		f.t.Fatalf("grant %s to %s: %d rows, want 1", roleName, principal, tag.RowsAffected())
	}
}

func (f *mcpFixture) unassignRole(principal, roleName string) {
	f.t.Helper()
	tag, err := f.pool.Exec(f.ctx,
		`DELETE FROM principal_role WHERE principal=$1 AND role_id=(SELECT id FROM app_role WHERE name=$2)`,
		principal, roleName)
	if err != nil {
		f.t.Fatalf("unassign %s from %s: %v", roleName, principal, err)
	}
	if tag.RowsAffected() != 1 {
		f.t.Fatalf("unassign %s from %s: %d rows, want 1", roleName, principal, tag.RowsAffected())
	}
}

// seedDatasource is the Kotlin's `seedDatasource` — one postgres datasource with one catalog column,
// which is the minimum `browse_catalog` / `list_column_tags` / `set_column_classification` need.
func (f *mcpFixture) seedDatasource(name string) int64 {
	f.t.Helper()
	var id int64
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO datasource(name, engine, host, port, db_name, default_schemas)
		 VALUES ($1, 'postgres', '127.0.0.1', 5432, 'mcp', '["public"]'::jsonb) RETURNING id`,
		name).Scan(&id); err != nil {
		f.t.Fatalf("seed datasource %s: %v", name, err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO catalog_column
		   (datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)
		 VALUES ($1, 'public', 'users', 'rrn', 'text', 'VARCHAR', 1, true)`, id); err != nil {
		f.t.Fatalf("seed catalog column: %v", err)
	}
	return id
}

func (f *mcpFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *mcpFixture) scalar(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

func (f *mcpFixture) strings(sql string, args ...any) []string {
	f.t.Helper()
	rows, err := f.pool.Query(f.ctx, sql, args...)
	if err != nil {
		f.t.Fatalf("query %q: %v", sql, err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			f.t.Fatalf("scan %q: %v", sql, err)
		}
		out = append(out, s)
	}
	return out
}

// auditOutcomes is the exact projection `McpServerDbTest` selects on.
func (f *mcpFixture) auditOutcomes(principal, statement string) []string {
	f.t.Helper()
	return f.strings(
		`SELECT outcome FROM audit_event WHERE principal=$1 AND statement=$2 ORDER BY id`,
		principal, statement)
}
