package mcp

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §2 — `installMcp`: the interceptor, the two discovery routes, and the SDK mount.
// ---------------------------------------------------------------------------------------------

// Routes is `fun Application.installMcp(config, core, datasourceService, policyService,
// identityService)` as a [httpapi.RouteGroup].
//
// ⚠️ IT USES NONE OF THE FOUR httpapi GATES, AND THAT IS CORRECT. docs/authz-model.md:330 maps this
// prefix to "MCP access-token bearer + host/origin checks in an interceptor; metadata routes public"
// — there is no session, no cookie and no `requireApi` anywhere on `/mcp`. A reviewer grepping this
// file for `Require` and finding nothing is seeing the documented gate, not a missing one.
type Routes struct {
	config config.Config
	log    *slog.Logger

	tokens        TokenResolver
	deactivations Deactivations
	authorizer    *Authorizer
	mutations     *MutationExecutor
	audit         AuditWriter
	services      Services

	// handler is the SDK's streamable-HTTP handler, built once. The per-request work is in the
	// getServer callback it holds, not here.
	handler http.Handler

	// metadataURI is `protectedResourceMetadataUri(config.mcpResource)` — the absolute URL of
	// `/.well-known/oauth-protected-resource/mcp`, emitted in both WWW-Authenticate challenges.
	metadataURI string
	// resourceHost is the configured resource's host, UNBRACKETED, for gate 1.
	resourceHost string
	// resourceOrigin is scheme+host+port, for gate 2's strict sameOrigin.
	resourceOrigin *url.URL

	// RequesterIP is A12's `call.httpRequesterIp(config)`.
	//
	// 🔴 NIL UNTIL A12 LANDS, AND THAT IS A REAL DIVERGENCE, not a theoretical one. With no requester
	// IP: `audit_event.client_addr` is NULL on every MCP row, and the Cedar context carries no
	// `requester_ip`, so an ip-conditioned admin grant DENIES here where the Kotlin would allow.
	// Absence is fail-closed (INV-A2-8 — a policy conditioning on an absent optional attribute simply
	// does not fire), so nothing is widened; the audit gap is the part that bites.
	//
	// It is a function field rather than a config flag for the same reason httpapi.Gates.Context is:
	// A12 wires ONE implementation and both surfaces get it.
	//
	//	TODO(A12): set this to httpRequesterIp — 12-request-context.md §2. It must reuse
	//	httpapi.IsTrustedEdge, not a second copy of the trusted-edge test.
	RequesterIP func(r *http.Request) *string
}

// Options are [New]'s dependencies. Everything except Users and Log is required.
type Options struct {
	Config config.Config
	// DB is the pool the mutation executor opens its transactions on.
	DB store.Beginner
	// Tokens resolves the bearer — see [TokenResolver]. TODO(A14).
	Tokens TokenResolver
	// Deactivations is gate 3's second half. *identity.UserGroupStore.
	Deactivations Deactivations
	// Roles is INV-A11-8's live resolver. *identity.RoleResolver.
	Roles Roles
	// Cedar is the SHARED authorizer (INV-A1-1). *authz.Authz. May be nil only under AuthDebug.
	Cedar Cedar
	// Audit is *audit.Store.
	Audit AuditWriter
	// Policies is the SHARED *policy.CedarPolicyStore, for INV-A11-12's post-commit bump.
	Policies PolicyVersions
	// Services are the three management services plus the two store seams.
	Services Services
	Log      *slog.Logger
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// New is `installMcp`'s construction half.
//
// 🔒 IT CALLS [Verify] FIRST AND RETURNS ITS ERROR, which is INV-A11-1's "port it as a real startup
// check, not a comment". internal/app MUST treat a non-nil error here as FATAL — the same way it
// treats a failed migration — because the failure means the Cedar action set and the MCP tool catalog
// have drifted, and booting past that either exposes an unreviewed action or silently hides a new one.
//
// It also validates `config.mcpResource` as a URI, which the Kotlin does implicitly by constructing
// `URI(config.mcpResource)` at install time and letting a malformed value throw out of `module()`.
func New(opts Options) (*Routes, error) {
	if err := Verify(); err != nil {
		return nil, err
	}
	resource, err := url.Parse(opts.Config.MCPResource)
	if err != nil {
		return nil, err
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	services := opts.Services
	authorizer := NewAuthorizer(opts.Config.AuthDebug, opts.Roles, opts.Cedar)
	rt := &Routes{
		config:        opts.Config,
		log:           log,
		tokens:        opts.Tokens,
		deactivations: opts.Deactivations,
		authorizer:    authorizer,
		mutations:     NewMutationExecutor(opts.DB, opts.Audit, opts.Policies, authorizer),
		audit:         opts.Audit,
		services:      services,
		metadataURI:   protectedResourceMetadataURI(resource),
		// Java exposes an IPv6 URI host BRACKETED (`[::1]`) while a request authority resolves to the
		// bare address, so both sides are unbracketed before they are compared. Go's url.Hostname()
		// already strips the brackets, so this is the deliberate normalisation the area doc's
		// "Java/URI trap" note asks for rather than a no-op: url.Host would still carry them.
		resourceHost:   resource.Hostname(),
		resourceOrigin: resource,
	}
	// 🔒 INV-A11-4 — the SDK's OWN DNS-rebinding guard is DISABLED and replaced by gate 1, and its
	// cross-origin protection is left nil and replaced by gate 2. Both SDK guards read the literal
	// `Host`/`Origin` headers with rules of their own; running them alongside these gates would mean
	// two differently-shaped host checks on one path, and the SDK's is the one that rejects HTTP/2.
	rt.handler = sdk.NewStreamableHTTPHandler(rt.serverFor, &sdk.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: true,
		CrossOriginProtection:      nil,
		Logger:                     log,
	})
	return rt, nil
}

// Register mounts the three patterns `installMcp` installs.
//
// ⚠️ `/mcp` is registered WITHOUT a method, which is Ktor's interceptor scope (`path == "/mcp"`,
// every verb) rather than a `post("/mcp")`. It matters: a GET or DELETE to `/mcp` must go through the
// host/origin/bearer gates too and be answered by the SDK (405 in stateless mode), not by the mux's
// method-not-allowed.
//
// ⚠️ Neither well-known path ends in `/`, so neither creates a ServeMux subtree match or the 307
// redirect internal/httpapi's Router warns about.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", rt.resourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", rt.resourceMetadata)
	mux.Handle("/mcp", http.HandlerFunc(rt.serve))
}

// protectedResourceMetadata is `@Serializable private data class ProtectedResourceMetadata`, RFC 9728
// §2. The snake_case field names are the RFC's and are not negotiable.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// resourceMetadata serves both discovery routes, UNAUTHENTICATED — which is the point: a client that
// has just been 401'd fetches this to learn where to get a token.
//
// `authorization_servers` is `[config.mcpIssuer]`, the resource URI's own origin. It is never
// independently configured and never inferred from Host/X-Forwarded-*, which is 🔒 INV-A11-20's
// one-origin property in its discovery form: the AS a client is pointed at is the same process.
func (rt *Routes) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	body := protectedResourceMetadata{
		Resource:               rt.config.MCPResource,
		AuthorizationServers:   []string{rt.config.MCPIssuer()},
		ScopesSupported:        SupportedScopes,
		BearerMethodsSupported: []string{"header"},
	}
	if err := httpapi.RespondJSON(w, http.StatusOK, body); err != nil {
		rt.log.Error("failed to write MCP resource metadata", "path", r.URL.Path, "err", err)
	}
}

// protectedResourceMetadataURI is `private fun protectedResourceMetadataUri(resource)`:
// `URI(scheme, userInfo, host, port, "/.well-known/oauth-protected-resource/mcp", null, null)`.
//
// ⚠️ It keeps the resource's userInfo, host and PORT and replaces only the path — so an MCP resource
// on a non-default port advertises its metadata on that port. Query and fragment are dropped.
func protectedResourceMetadataURI(resource *url.URL) string {
	u := &url.URL{
		Scheme: resource.Scheme,
		User:   resource.User,
		Host:   resource.Host,
		Path:   "/.well-known/oauth-protected-resource/mcp",
	}
	return u.String()
}

// serve is the four-gate interceptor plus the SDK handler.
//
// 🔒 THE ORDER IS THE CONTRACT (A11 §2's table), and two of the four orderings are invariants in their
// own right:
//
//  1. HOST     403 mcp.invalid_host    — INV-A11-3, the DNS-rebinding defence
//  2. ORIGIN   403 mcp.invalid_origin  — INV-A11-5, BEFORE authentication
//  3. BEARER   401 + WWW-Authenticate  — common.invalid_token{kind: "MCP bearer"}
//  4. stash the RequestContext
//
// 🔒 INV-A11-5's ordering is the security property, not a performance one: a cross-origin browser
// request is refused WITHOUT its token ever being resolved, so a malicious page cannot use timing or
// error shape to probe whether a token it replayed is live.
func (rt *Routes) serve(w http.ResponseWriter, r *http.Request) {
	// ---- gate 1: host -------------------------------------------------------------------------
	//
	// 🔒 INV-A11-3 — read through the PROTOCOL-NEUTRAL authority, never the literal `Host` header.
	// Go's net/http fills r.Host from the HTTP/1.1 `Host` header AND from HTTP/2's `:authority`, which
	// is exactly what Ktor's `host()` gives and exactly why reading `r.Header.Get("Host")` here would
	// reject every HTTP/2 request (net/http does not even populate that header map entry).
	//
	// Behind a reverse proxy the authority is the PROXY's, so a trusted edge's `X-Forwarded-Host`
	// supersedes it — honored only from a peer in PM_TRUSTED_PROXIES (INV-A12-1), so a direct caller
	// cannot assert its way past this check.
	peer, peerPresent := httpapi.RequestPeer(r)
	host := resolveForwardedAuthority(
		directHost(r.Host),
		peer, peerPresent,
		httpapi.LastHeader(r, "X-Forwarded-Host"),
		rt.config.TrustedProxies,
	)
	if !strings.EqualFold(unbracket(host), rt.resourceHost) {
		rt.respondError(w, http.StatusForbidden, types.ApiError{Code: "mcp.invalid_host"})
		return
	}

	// ---- gate 2: origin -----------------------------------------------------------------------
	//
	// Only when the header is PRESENT. A non-browser client sends none, and demanding one would break
	// every CLI; a browser always sends one on a cross-origin request, which is the case this guards.
	if raw := r.Header.Get("Origin"); raw != "" {
		origin, err := url.Parse(raw)
		if err != nil || !sameOrigin(origin, rt.resourceOrigin) {
			rt.respondError(w, http.StatusForbidden, types.ApiError{Code: "mcp.invalid_origin"})
			return
		}
	}

	// ---- gate 3: bearer -----------------------------------------------------------------------
	token := bearerToken(r)
	var identity *AccessIdentity
	if token != "" {
		resolved, err := rt.tokens.ResolveAccess(r.Context(), token, rt.config.MCPResource)
		if err != nil {
			// The Kotlin's SQLException escapes the interceptor into StatusPages as a 500. Same here.
			rt.log.Error("mcp bearer resolution failed", "err", err)
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		identity = resolved
	}
	deactivated := false
	if identity != nil {
		var err error
		deactivated, err = rt.deactivations.IsDeactivated(r.Context(), identity.Principal)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
	}
	if identity == nil || deactivated {
		// 🔒 THE SAME BODY FOR BOTH. A live token belonging to a deprovisioned principal and a token
		// that never existed are indistinguishable to the caller — the `kind` param says "MCP bearer"
		// and nothing else. `mcp.principal_deactivated` exists in the bundle but is deliberately NOT
		// used here: telling a holder that their account was deprovisioned confirms the principal
		// exists.
		w.Header().Set("WWW-Authenticate",
			"Bearer resource_metadata=\""+rt.metadataURI+"\", scope=\""+ScopeRead+"\"")
		rt.respondError(w, http.StatusUnauthorized,
			types.ApiError{Code: "common.invalid_token", Params: map[string]string{"kind": "MCP bearer"}})
		return
	}

	// ---- gate 4: stash ------------------------------------------------------------------------
	rc := identity.toContext(rt.requesterIP(r))
	r = withRequestContext(r, rc)

	// The response-status override, which is how `localizedError` reaches the HTTP layer from inside a
	// tool handler — see [responseControl].
	ctl := &responseControl{header: http.Header{}}
	r = r.WithContext(withResponseControl(r.Context(), ctl))
	r = r.WithContext(withLocale(r.Context(), requestLocale(r)))
	rt.handler.ServeHTTP(&controlledWriter{ResponseWriter: w, ctl: ctl}, r)
}

// serverFor is the SDK's `getServer func(*http.Request) *Server` — 🔒 A FRESH SERVER PER REQUEST.
//
// Returning nil makes the SDK answer 400; that happens only if gate 4 did not run, which is
// unreachable through [Routes.serve].
func (rt *Routes) serverFor(r *http.Request) *sdk.Server {
	rc, ok := requestContextOf(r.Context())
	if !ok {
		rt.log.Error("mcp request reached the SDK without a request context")
		return nil
	}
	ctl, _ := responseControlOf(r.Context())
	server, err := rt.newServer(rc, localeOf(r.Context()), ctl)
	if err != nil {
		rt.log.Error("mcp server construction failed", "err", err)
		return nil
	}
	return server
}

func (rt *Routes) requesterIP(r *http.Request) *string {
	if rt.RequesterIP == nil {
		return nil
	}
	return rt.RequesterIP(r)
}

func (rt *Routes) respondError(w http.ResponseWriter, status int, e types.ApiError) {
	if err := httpapi.RespondAPIError(w, types.ErrorResponse{Status: status, Body: e}); err != nil {
		rt.log.Error("failed to write MCP error", "code", e.Code, "err", err)
	}
}

// bearerToken is
// `headers[Authorization]?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }?.substringAfter(' ')?.takeIf(String::isNotBlank)`.
//
// ⚠️ Three details are the Kotlin's and all three are observable:
//   - the scheme test is CASE-INSENSITIVE (`bearer x` works), per RFC 6750;
//   - `substringAfter(' ')` splits at the FIRST space, so `Bearer  x` yields `" x"` — wait, no: it
//     yields everything after the first space, i.e. `" x"` for a double space. A token is opaque, so
//     the extra space is carried into the hash and simply fails to match. Reproduced by splitting at
//     the first space rather than trimming.
//   - a blank remainder is treated as NO token, which is why `Authorization: Bearer ` is a 401 rather
//     than a lookup of the empty string.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return ""
	}
	i := strings.IndexByte(header, ' ')
	token := header[i+1:]
	if isBlank(token) {
		return ""
	}
	return token
}

// ---------------------------------------------------------------------------------------------
// Origin comparison — A11 §2, INV-A11-6
// ---------------------------------------------------------------------------------------------

// sameOrigin is `private fun URI.sameOrigin(other: URI)`:
//
//	scheme equalsIgnoreCase && host equalsIgnoreCase && effectivePort() == other.effectivePort() &&
//	userInfo == null && path.isNullOrEmpty() && query == null && fragment == null
//
// 🔒 INV-A11-6 — IT IS STRICT IN BOTH DIRECTIONS. Scheme, host and PORT must match, AND the Origin
// must be a bare origin: no userInfo, no path, no query, no fragment. `https://console.example.com/`
// with a trailing slash is REFUSED, which is correct — a real browser never sends one — and an
// implementation that tolerated it would also tolerate `https://console.example.com/@evil`.
//
// ⚠️ THE PORT IS ENFORCED HERE EVEN THOUGH GATE 1 IGNORES IT (INV-A12-8). That is not an
// inconsistency: gate 1 has to ignore the port because a TLS-terminating edge reaches the backend on
// its own cleartext port, while the Origin header is written by the BROWSER from the page's own URL
// and therefore always carries the real one. The two gates see different things and check what each
// can.
//
// ⚠️ The three "must be absent" tests are applied to the ORIGIN ONLY, not to `other` — the Kotlin's
// receiver/argument asymmetry. The configured resource URI DOES have a path (`/mcp`), so a symmetric
// test would reject every request. Reproduced by keeping the receiver/argument roles.
func sameOrigin(origin, resource *url.URL) bool {
	if origin == nil || resource == nil {
		return false
	}
	if !strings.EqualFold(origin.Scheme, resource.Scheme) {
		return false
	}
	if !strings.EqualFold(origin.Hostname(), resource.Hostname()) {
		return false
	}
	if effectivePort(origin) != effectivePort(resource) {
		return false
	}
	return origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

// effectivePort is `private fun URI.effectivePort()`: the explicit port, else 443 for https, else 80.
//
// ⚠️ The `else 80` arm is unconditional — a `ws://` or `ftp://` origin defaults to 80, not to its own
// scheme's default. Unreachable for a browser Origin on this surface and reproduced anyway.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// ---------------------------------------------------------------------------------------------
// `resolveForwardedAuthority` — A12's, ported here because A11 gate 1 is its only caller today
// ---------------------------------------------------------------------------------------------

// resolveForwardedAuthority is `internal fun resolveForwardedAuthority(directHost, peerAddress,
// forwardedHost, trustedProxies)` (RequesterIp.kt:148).
//
// 🔴 IT BELONGS TO A12, WHICH IS NOT PORTED. It lives here because A11 gate 1 is its only caller in
// the whole control plane, and because httpapi/trustededge.go's own `TODO(A12)` lists the four
// functions A12 owes WITHOUT this one. It REUSES [httpapi.IsTrustedEdge] rather than re-testing the
// peer, which is 🔒 INV-A12-1 — one definition of "this hop may speak for the client", and the Kotlin's
// own warning that "a second hand-rolled copy of this test is how a header ends up honored from an
// untrusted peer".
//
//	TODO(A12): hoist into internal/httpapi beside IsTrustedEdge when the rest of RequesterIp.kt lands,
//	and delete this copy. It is a FILE-PLACEMENT move, not a behaviour change.
//
// The three steps:
//  1. not a trusted edge ⇒ directHost.
//  2. RIGHTMOST `X-Forwarded-Host` entry, trimmed, non-empty — else directHost. 🔒 INV-A12-9: it falls
//     back to directHost, NOT to null, which is also the right answer for an edge that preserves the
//     client `Host` and sends no `X-Forwarded-Host`.
//  3. split a port off the LAST colon, only when it follows the last `]`, is not the final character,
//     and is all digits; then unbracket.
//
// 🔒 INV-A12-8 — HOST ONLY, NEVER A PORT. Behind a TLS-terminating edge the backend is reached on its
// own cleartext port and a client's `Host` omits the port when it is the scheme default, so a port
// comparison would reject every request in the deployment shape this exists to serve. It also buys
// nothing: an attacker who controls the host names any port. The port of a browser-facing request is
// still enforced — by [sameOrigin].
func resolveForwardedAuthority(direct string, peer string, peerPresent bool, forwardedHost *string, trustedProxies map[string]struct{}) string {
	if !httpapi.IsTrustedEdge(peer, peerPresent, trustedProxies) {
		return direct
	}
	if forwardedHost == nil {
		return direct
	}
	parts := strings.Split(*forwardedHost, ",")
	asserted := strings.TrimSpace(parts[len(parts)-1])
	if asserted == "" {
		return direct
	}
	return unbracket(stripAuthorityPort(asserted))
}

// directHost is Ktor's `call.request.host()` — the client-addressed host, without its port.
//
// 🔴 DELIBERATE, RECORDED DIVERGENCE — IPv6. Ktor's `host()` splits a direct `Host: [::1]` at the
// literal's FIRST colon and yields `[`, so on the JVM an IPv6-literal `PM_MCP_RESOURCE` is reachable
// only behind a trusted edge; that is written up in KNOWN_LIMITATIONS.md:265-271 and attributed to
// Ktor, not to proxy-monster's own code. The PORT POLICY's OMIT category is "dead code + JVM
// artifacts", and this is a framework artifact whose only effect is to refuse a legitimate request, so
// the port uses the SAME bracket-aware parse as the forwarded path instead of reimplementing the
// shred. TestAnIPv6LiteralResourceHostAlsoMatchesADirectHostHeader pins it, deliberately, as the
// behaviour that differs.
//
// Note this is NOT a widening of authority: the gate still demands equality with the CONFIGURED
// resource host. It only stops rejecting the host the operator configured.
func directHost(hostHeader string) string { return unbracket(stripAuthorityPort(hostHeader)) }

// stripAuthorityPort splits a `:port` suffix off an authority, ONLY when the colon is after the last
// `]`, is not the final character, and everything after it is digits.
//
// IPv6 note, from the Kotlin verbatim: only split at the last colon AFTER the closing bracket, or
// `[::1]` gets shredded at its first colon.
func stripAuthorityPort(authority string) string {
	lastColon := strings.LastIndexByte(authority, ':')
	if lastColon <= strings.LastIndexByte(authority, ']') {
		return authority
	}
	if lastColon == len(authority)-1 {
		return authority
	}
	for i := lastColon + 1; i < len(authority); i++ {
		if authority[i] < '0' || authority[i] > '9' {
			return authority
		}
	}
	return authority[:lastColon]
}

// unbracket is Kotlin's `removeSurrounding("[", "]")` — it strips the pair ONLY when BOTH are present.
func unbracket(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------------------------
// The HTTP response override — how `localizedError` sets a status from inside a tool handler
// ---------------------------------------------------------------------------------------------

// responseControl is the Go stand-in for Ktor's `call.response.status(...)` /
// `call.response.header(...)` being reachable from inside a tool handler.
//
// Ktor's stateless streamable-HTTP mount buffers the JSON-RPC response and writes the HTTP response
// after the handler returns, so a handler can still set the status. The Go SDK does the same —
// measured this session: a tool handler that recorded 403 + `WWW-Authenticate` through this type
// produced `status=403` with the header present and the JSON-RPC result intact in the body. Without
// that ordering, INV-A11-15's 403-for-insufficient-scope would be unreachable and `claude mcp login`'s
// RFC 9728 discovery loop would never be triggered.
//
// The mutex is not decoration: the SDK may run a tool handler on a different goroutine from the one
// that writes the response.
type responseControl struct {
	mu     sync.Mutex
	status int
	header http.Header
}

func (c *responseControl) setStatus(status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}

func (c *responseControl) setHeader(name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.header.Set(name, value)
}

func (c *responseControl) apply(w http.ResponseWriter, status int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, values := range c.header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	if c.status != 0 {
		return c.status
	}
	return status
}

// controlledWriter applies the override on the FIRST WriteHeader, then gets out of the way.
//
// It implements Flush and Unwrap because the SDK streams SSE: without Flush the transport would
// buffer, and without Unwrap an http.ResponseController-based flush would fail to find the real
// writer.
type controlledWriter struct {
	http.ResponseWriter
	ctl     *responseControl
	written bool
}

func (w *controlledWriter) WriteHeader(status int) {
	if !w.written {
		w.written = true
		status = w.ctl.apply(w.ResponseWriter, status)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *controlledWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *controlledWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *controlledWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
