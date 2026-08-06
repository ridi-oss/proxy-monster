// Package mcp is A11 §§1-5 — the MCP server: the 38-tool capability catalog, the four-gate `/mcp`
// request pipeline, the two-stage authorizer, the idempotent mutation executor and the tool dispatch
// surface.
//
// Area doc: plans/proxy-monster-go-port/11-mcp-oauth-management.md, sections 1 through 5.
// Kotlin sources: `mcp/McpServer.kt` (766 LOC) and `management/McpCapabilityRegistry.kt` (136 LOC).
//
// # What is here and what is deliberately not
//
// A11 has three co-hosted surfaces. This package is the FIRST one only:
//
//   - §§1-5 MCP server — here.
//   - §6/§7 the OAuth 2.1 authorization server and `Cimd.kt` — NOT here. `/oauth/*` and
//     `/.well-known/oauth-authorization-server` belong to a later increment; the only OAuth-adjacent
//     thing this package serves is the two unauthenticated PROTECTED-RESOURCE discovery documents,
//     which McpServer.kt itself mounts (`installMcp`'s `routing { … }` block).
//   - §8 the transport-neutral management services — internal/management, already landed. This
//     package CALLS it and re-implements none of it.
//
// # The four ordered gates are the contract (§2)
//
// [Routes.Register] mounts ONE handler on `/mcp`, and that handler is the Go form of Ktor's
// `intercept(ApplicationCallPipeline.Plugins) { if (path == "/mcp") … }`. The order is not an
// implementation detail:
//
//  1. Host — 🔒 INV-A11-3, the DNS-rebinding defence, read through the PROTOCOL-NEUTRAL authority.
//  2. Origin — 🔒 INV-A11-5, validated BEFORE authentication, so a cross-origin browser request is
//     refused without its token ever being resolved.
//  3. Bearer — resolve the MCP access token, reject a deactivated principal, 401 + WWW-Authenticate.
//  4. Stash [RequestContext] on the request context for the tool handlers.
//
// 🔒 INV-A11-4 — the SDK's OWN DNS-rebinding guard is DISABLED
// (`StreamableHTTPOptions.DisableLocalhostProtection`) and replaced by gate 1. Measured this session:
// the Go SDK's guard rejects a localhost-peer request whose `Host` header is non-localhost, reading
// the literal header exactly as the Kotlin SDK's does. Leaving it on would double-gate `/mcp` with a
// second, differently-shaped host rule. `StreamableHTTPOptions.CrossOriginProtection` is likewise nil
// — gate 2 is the Origin rule, and the SDK's would apply a different one.
//
// # How internal/app mounts this — the whole contract, in one place
//
// This package is mounted like every other area: build it once, then add it to `router.Mount(...)`'s
// list in internal/app/http.go, replacing that file's `TODO(A11): MCP, OAuth, management` line. There
// is no other edit; [Routes] implements httpapi.RouteGroup.
//
//	mcpRoutes, err := mcp.New(mcp.Options{
//	    Config: cfg, DB: c.DB.Pool,
//	    Tokens:        <TODO(A14) — the OAuth increment's McpTokenStore>,
//	    Deactivations: c.UserGroupStore,
//	    Roles:         c.RoleResolver,
//	    Cedar:         c.Authz,          // 🔒 INV-A1-1 — the SHARED one
//	    Audit:         c.AuditStore,
//	    Policies:      c.CedarPolicyStore, // its Bump is INV-A11-12's post-commit counter
//	    Services:      mcp.Services{...},  // the SAME three management services REST holds
//	    Log:           log,
//	})
//	if err != nil { /* 🔒 FATAL — see below */ }
//
// Four things about that call are not stylistic:
//
//  1. 🔒 A NON-NIL ERROR FROM [New] MUST FAIL THE BOOT, exactly as a failed migration does. [New]
//     calls [Verify] first, and a failure means the Cedar action set and the MCP tool catalog have
//     drifted — booting past it either exposes an unreviewed action or silently hides a new one
//     (INV-A11-1/2). Logging and continuing would defeat the entire mechanism.
//  2. 🔒 ONE OBJECT GRAPH (INV-A1-1). `Cedar`, `Policies` and every member of [Services] must be the
//     instances the REST surface already holds. A second CedarPolicyStore would bump a version
//     counter nobody reads; a second Authz would answer from a stale policy set.
//  3. `Tokens` is the one seam with no implementation yet — see [TokenResolver]. Until A14 lands,
//     every /mcp request 401s at gate 3, which is the correct fail-closed behaviour for a resource
//     server whose token store is absent.
//  4. `Routes.RequesterIP` is a settable field, nil until A12. While it is nil, `audit_event.
//     client_addr` is NULL on every MCP row and the Cedar context carries no `requester_ip`. See its
//     doc comment — the audit gap is the part that bites.
//
// ⚠️ SSE: App.kt deliberately does NOT install Ktor's SSE plugin because the MCP mount installs it
// (internal/app/http.go repeats the note). The Go SDK's StreamableHTTPHandler brings its own SSE
// writer for /mcp only, so A1's `/api/tasks/events` must supply its own — mounting this package does
// not give it one.
//
// # Two-stage authorization (§3)
//
// 🔒 INV-A11-7 — a scope is NECESSARY BUT NEVER SUFFICIENT. [Authorizer.Authorize] checks the OAuth
// scope first and then asks Cedar; a broad consent scope cannot widen what the PRINCIPAL may do.
// 🔒 INV-A11-8 — roles are resolved LIVE per tool call, never carried on the token.
//
// # Audit shapes differ by classification (§5)
//
// 🔒 INV-A11-14 — a successful READ writes NO audit row (only a denial does); a WRITE always writes
// one, ALLOW or replay or failure. `list_datasources` on every tool refresh would otherwise flood the
// trail.
//
// # Wire-visible strings live in resources/
//
// 🔒 INV-A11-15 — MCP errors ship BOTH locales inline (`message_en` AND `message_ko`), unlike REST,
// because an MCP client has no message catalog. The four `.properties` bundles under resources/ are
// byte-for-byte copies of the Kotlin's (D11) and `mcp_tools` text is ON THE MCP WIRE — it is the tool
// description every client displays, so editing one is a wire change.
//
// # Test posture
//
// `McpServerDbTest.kt`'s 8 cases are ported (mcp_server_db_test.go names each one), and 00-INDEX.md
// F19 says 8 cases for 38 tools is thin, so this package adds substantially more: every one of the 38
// tools is dispatched at least once, the catalog is asserted entry by entry, `verify()`'s six
// assertions each have a negative case, and canonicalJson is pinned byte-for-byte because it is a
// stored-hash compatibility contract.
package mcp
