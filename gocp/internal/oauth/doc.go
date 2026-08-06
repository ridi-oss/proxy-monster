// Package oauth is the MCP OAuth 2.1 authorization server: A11 §6's seven routes, A11 §7's
// SSRF-hardened CIMD client resolver, and A14 §4-5's two stores (`McpTokenStore`,
// `OAuthAuthorizationStore`) with the five pure functions they are built on.
//
// # Why one package for two Kotlin modules
//
// The Kotlin splits this surface across a module boundary: `auth/McpOAuth.kt` holds the stores and
// the pure functions, `control-plane/oauth/{OAuthRoutes,Cimd}.kt` holds the routes and the client
// resolver, and 14-auth.md:112-115 records that the split is what forces `OAuthAuthorizationStore`
// to hand-roll its own `inTransaction` instead of using A1's `inTx` ("`auth/` does not depend on
// `control-plane`. Using it would invert the module graph"). A Go port has one package here, so that
// particular duplication is resolved by calling [store.InTx] — the ONE collapse the area doc
// explicitly blesses. Nothing else is collapsed: F18's third CIDR implementation, F21's second
// clamp, F23's half-applied kind constants and F31's redundant round trip are all reproduced.
//
// # What lives here that the area docs assign elsewhere
//
//   - [MCPTokenStore] is 14-auth.md §4, the `/mcp` bearer gate. It is A11's MCP half that CALLS it,
//     but it is declared in `McpOAuth.kt` beside the authorization store and every one of the six
//     `McpOAuthStoreDbTest` cases asserts through it, so porting §5 without it would leave those
//     tests unwritable.
//   - `GET /.well-known/oauth-protected-resource` and `…/mcp` are `McpServer.kt:143-144`, i.e. A11
//     §2, and internal/mcp OWNS them. This package can SERVE them —
//     [Routes.ProtectedResourceMetadata] is exported and [Routes.MountProtectedResourceMetadata]
//     mounts them — because `OAuthRoutesDbTest` case 2 asserts the authorization-server document and
//     the protected-resource document agree on one origin, and that claim needs both halves. The flag
//     defaults to FALSE: registering one pattern twice on a ServeMux panics at startup.
//
// # The port's binding constraints in this area
//
//	🔒 INV-A14-4  — CanonicalScopes is a DATABASE JOIN KEY. Order, dedupe and the trim set are all
//	                load-bearing; see the golden vectors in pure_test.go.
//	🔒 INV-A14-6  — no credential is ever stored in plaintext; every write is SHA256Hex(token).
//	🔒 INV-A11-18 — `resource` must equal config.MCPResource EXACTLY at authorize and at both grants.
//	🔒 INV-A11-25 — the CIMD HTTP client is DNS-PINNED to the vetted addresses.
//	🔒 INV-A14-15 — a `return@inTransaction null` COMMITS, which is how a burnt code stays burnt.
package oauth
