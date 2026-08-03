// Package device is RFC 8628 device authorization — `pmon login`'s server half.
//
// Area doc: 04-auth-session-tokens.md §1.1, §2.1, §3.7 (`DeviceAuth.kt`). One Kotlin file, split here
// into the wire DTOs (dto.go), the store (store.go) and the four routes (routes.go).
//
// # The flow, and who holds what at each step
//
//	pmon  --POST /auth/device/start-->  CP        mints a PENDING row: a 192-bit `handle` + a
//	                                             ~40-bit human `user_code`. Nothing else.
//	human --opens {web}/device?user_code=…-->     the verification PAGE is the console's, not the CP's
//	page  --POST /auth/device/confirm-->  CP      sets the signed pm_device_verify cookie
//	page  --GET  /auth/device/authorize--> CP     requires that cookie + a live console session,
//	                                             then CAS-approves the handle
//	pmon  --POST /auth/device/poll-->     CP      202 until approved; then ONE SESSION token +
//	                                             ONE `pmr_` renewal secret, exactly once
//
// 🔒 INV-A4-4 — every `/auth/device/*` route is deliberately UNAUTHENTICATED, and that is safe only
// because of what each step holds. `start` mints nothing but a PENDING row. `poll` is authenticated
// BY the 192-bit handle and yields a token only after a browser session approved it, exactly once.
// `confirm`/`authorize` are the browser half and carry the anti-phishing cookie. There is no principal
// in any request body anywhere in this flow.
//
// 🔒 INV-A4-41 / INV-A4-44 — the IdP is reached ONLY by the browser's SSO choice (the
// authorization-code flow in internal/oidc). The pmon↔CP device flow is entirely CP-owned, so
// `pmon login` has one code path whether the user then chooses SSO or debug. Consequence: the control
// plane does NOT implement the RFC 8628 CLIENT side against the IdP at all, `device_code` is always
// NULL in practice, and `OidcDiscoveryDocument.device_authorization_endpoint` is parsed and unused.
//
// # The device-phishing gate
//
// 🔒 INV-A4-46 — `pm_device_verify` (declared in internal/oidc, because it is declared in
// control-plane/Oidc.kt in the Kotlin) is the ONLY thing binding a device login to an SSO session. It
// proves the browser actually viewed /device for a SPECIFIC user_code, so a raw
// `/auth/device/authorize?user_code=…` link mailed to a victim cannot approve a handle they never
// confirmed. It is cleared on every branch that TERMINATES an approval attempt and deliberately NOT
// cleared on the /login redirect — see [Routes.Authorize] for the full four-way analysis.
//
// # Silence is reproduced, not fixed
//
// ⚠️ F33 (index F53) — `deviceSessionRoutes` accepts a `log: Logger` and never uses it:
// `grep -n 'log\.' DeviceAuth.kt` returns nothing. The whole device-auth surface emits ZERO log lines,
// including on the security-relevant refusals (`device.unknown_or_expired_login`,
// `device.login_already_completed`, the no-confirm authorize bounce), so a device-phishing attempt is
// indistinguishable from an abandoned login in the CP logs. 04-auth-session-tokens.md splits the
// disposition: OMIT the unused parameter (an unread parameter has no observable behaviour), REPRODUCE
// the silence (adding warn lines is a behaviour change on a security surface, and a separate decision
// after cutover). This package therefore takes no logger and writes no log line. See §8 Q11.
package device
