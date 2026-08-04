// Package oidc is the OIDC half of the control plane's login surface: provider-agnostic discovery,
// id_token validation, the IdP-group → pm-group resolver, JIT directory provisioning, and the
// browser authorization-code flow.
//
// It merges THREE Kotlin files, because they are one feature split across a module boundary:
//
//   - `auth/Oidc.kt` (A14, 14-auth.md §6) — OidcDiscovery, IdTokenValidator, oidcHttpClient,
//     OidcGroupMapping.
//   - `auth/OidcDirectoryProvisioner.kt` (A14, 14-auth.md §6) — the JIT app_user/app_group/
//     group_member reconciler.
//   - `control-plane/Oidc.kt` (A4, 04-auth-session-tokens.md §6) — oidcRoutes (GET
//     /auth/oidc/login + /auth/oidc/callback), the three signed cookie payloads, randomOpaqueToken,
//     oidcReturnTarget and oidcFailureTarget.
//
// The three cookie CONSTANTS (`pm_oauth_state`, `pm_oauth_nonce`, `pm_device_verify`) all live in
// control-plane/Oidc.kt in the Kotlin — including the device-verify one, which internal/device
// consumes. That is why internal/device imports this package rather than the other way round: the
// dependency direction mirrors the Kotlin's.
//
// # Provider-agnostic, always
//
// Nothing here knows about Okta, Entra, Keycloak or Google. Every endpoint comes from
// ${issuer}/.well-known/openid-configuration. A port that hardcodes a provider path — or "helpfully"
// falls back to one when discovery fails — breaks the one property docs/auth-model.md names.
//
// # The three defects this package REPRODUCES, deliberately
//
//   - F24 / INV-A14-32 — a `groups` claim of the WRONG SHAPE (a bare string, or a comma-joined
//     string; real IdPs ship both) fails the list cast and silently becomes an EMPTY list. Combined
//     with INV-A14-37's full reconciliation that strips every group from every user on next login,
//     `system:admin` included. Pinned by TestValidate_F24_MalformedGroupsClaimSilentlyBecomesEmpty
//     and TestProvision_F24_MalformedShapeStripsSystemAdmin.
//   - F35 / F36 — the discovery document is cached FOREVER with no invalidation, while the JWKS is
//     re-fetched on EVERY id_token validation. Both are reproduced; neither may be "fixed".
//   - F38 — no timeout, no retry, no backoff on any outbound IdP call. [NewHTTPClient] therefore has
//     a zero Timeout, and every call takes its deadline from the caller's context.
//
// # What is NOT here
//
// The MCP OAuth authorization server (`auth/McpOAuth.kt`, 14-auth.md §3-§5) is A11's. The web
// session store, the daemon session store and `ensureDeviceCookie` are A4's — this package reaches
// them through the narrow interfaces in seams.go, never by reimplementing them.
package oidc
