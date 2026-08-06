package oauth

import (
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// renderConsent — OAuthRoutes.kt:350-392, the only server-rendered HTML in the control plane
// ---------------------------------------------------------------------------------------------

// The `authorization_messages_{en,ko}.properties` bundles, transcribed verbatim from
// control-plane/src/main/resources.
//
// They are maps rather than files because there is no ResourceBundle in Go and no second consumer:
// every other user-facing string in the control plane goes out as an `ApiError` CODE that web/ looks
// up (docs/l10n.md), and this page is the documented exception — it is rendered server-side for a
// browser that is mid-redirect and has no console loaded. Keeping the two locales adjacent is also
// what makes a missing key visible at review time; a properties file that silently lacks one throws
// MissingResourceException at request time instead.
var (
	consentMessagesEN = map[string]string{
		"consent.title":             "Authorize MCP client",
		"consent.client":            "Client",
		"consent.client_id":         "Client ID",
		"consent.redirect":          "Redirect destination",
		"consent.localhost_warning": "This client redirects to this computer. Verify that you started the local client before authorizing.",
		"consent.scopes":            "Requested access",
		"consent.approve":           "Authorize",
		"consent.deny":              "Deny",
	}
	consentMessagesKO = map[string]string{
		"consent.title":             "MCP 클라이언트 승인",
		"consent.client":            "클라이언트",
		"consent.client_id":         "클라이언트 ID",
		"consent.redirect":          "리디렉션 대상",
		"consent.localhost_warning": "이 클라이언트는 이 컴퓨터로 리디렉션됩니다. 승인하기 전에 로컬 클라이언트를 직접 실행했는지 확인하세요.",
		"consent.scopes":            "요청한 접근 권한",
		"consent.approve":           "승인",
		"consent.deny":              "거부",
	}
)

// localizedBundle is `private fun localizedBundle(call)` (OAuthRoutes.kt:385-389):
// `headers["Accept-Language"]?.lowercase().orEmpty()`, then `startsWith("ko")` ⇒ Korean else English.
//
// ⚠️ This is NOT RFC 7231 content negotiation — no q-values, no fallback chain, and the test is on the
// WHOLE header, so `en-US,ko;q=0.9` is English and `ko-KR,en;q=0.9` is Korean. Reproduced; a port that
// reached for a real Accept-Language parser would change which page a browser gets.
func localizedBundle(r *http.Request) map[string]string {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ko") {
		return consentMessagesKO
	}
	return consentMessagesEN
}

// escapeHTML is `private fun escapeHtml(value)` (OAuthRoutes.kt:391-392) — the five replacements, in
// the Kotlin's order. `&` MUST be first, or every subsequent entity gets double-escaped.
//
// html.EscapeString is not a substitute: it emits `&#39;` for `'` (same) but `&#34;` for `"` where
// this emits `&quot;`, and the rendered bytes are asserted on.
func escapeHTML(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, `"`, "&quot;")
	return strings.ReplaceAll(value, "'", "&#39;")
}

// renderConsent is `private suspend fun renderConsent(call, pending, clientName, clientId)`
// (OAuthRoutes.kt:350-383).
//
// 🔒 INV-A11-24 — THE PAGE DISCLOSES THE REDIRECT DESTINATION AND WARNS ON LOOPBACK. A local listener
// means any process on the user's machine could receive the code, so the destination is shown in full
// and a loopback target gets an extra paragraph. `OAuthRoutesDbTest` case 5 pins both.
//
// 🔒 The three headers are the page's whole defence, since it carries a CSRF token in a form:
//
//	Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'
//	X-Content-Type-Options: nosniff
//	Referrer-Policy: no-referrer
//
// `form-action 'self'` is what stops an injected form from posting the approval elsewhere;
// `frame-ancestors 'none'` is what stops clickjacking the Authorize button.
//
// ⚠️ It calls [ValidatedRedirectURI] and dereferences the host, so a pending cookie carrying an
// unvalidatable redirect_uri raises — reaching StatusPages as a 500 rather than an OAuth error. The
// path is unreachable in practice (the authorize route validated the same string), and the throw is
// reproduced rather than softened.
//
// The body's shape is byte-exact, including the eleven-space indent on every line after the first:
// the Kotlin's raw string opens with content on the `"""` line, so `trimIndent()` computes a common
// indent of ZERO and strips nothing.
func (rt *Routes) renderConsent(w http.ResponseWriter, r *http.Request, pending PendingAuthorization, clientName, clientID string) {
	bundle := localizedBundle(r)

	// `pending.scope.split(' ').joinToString("<br>") { escapeHtml(it) }` — note NO blank filter, so a
	// double space renders an empty line. Reproduced.
	parts := strings.Split(pending.Scope, " ")
	escaped := make([]string, 0, len(parts))
	for _, p := range parts {
		escaped = append(escaped, escapeHTML(p))
	}
	scopes := strings.Join(escaped, "<br>")

	redirect, err := ValidatedRedirectURI(pending.RedirectURI)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	loopbackWarning := ""
	if IsLoopbackRedirectHost(redirect.Hostname()) {
		loopbackWarning = "<p><strong>" + escapeHTML(bundle["consent.localhost_warning"]) + "</strong></p>"
	}

	title := escapeHTML(bundle["consent.title"])
	body := `<!doctype html><html><head><meta charset="utf-8"><title>` + title + `</title></head>` + "\n" +
		`           <body><h1>` + title + `</h1>` + "\n" +
		`           <p>` + escapeHTML(bundle["consent.client"]) + `: ` + escapeHTML(clientName) + `</p>` + "\n" +
		`           <p>` + escapeHTML(bundle["consent.client_id"]) + `: ` + escapeHTML(clientID) + `</p>` + "\n" +
		`           <p>` + escapeHTML(bundle["consent.redirect"]) + `: ` + escapeHTML(pending.RedirectURI) + `</p>` + "\n" +
		`           ` + loopbackWarning + "\n" +
		`           <p>` + escapeHTML(bundle["consent.scopes"]) + `:<br>` + scopes + `</p>` + "\n" +
		`           <form method="post" action="/oauth/consent">` + "\n" +
		`           <input type="hidden" name="csrf" value="` + escapeHTML(pending.CSRF) + `">` + "\n" +
		`           <button name="decision" value="approve">` + escapeHTML(bundle["consent.approve"]) + `</button>` + "\n" +
		`           <button name="decision" value="deny">` + escapeHTML(bundle["consent.deny"]) + `</button>` + "\n" +
		`           </form></body></html>`

	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Ktor's `respondText(text, ContentType.Text.Html)` appends the charset for a `text/*` type.
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(body)); err != nil {
		rt.logger().Error("failed to write the consent page", "err", err)
	}
}
