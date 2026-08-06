package httpapi

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	cedartypes "github.com/cedar-policy/cedar-go/types"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
)

// ---------------------------------------------------------------------------------------------
// `RequesterIp.kt`'s RESOLVER half — 12-request-context.md §2.
//
// trustededge.go ported `isTrustedEdge` early because requireScimAuth needed it, and left a TODO for
// the rest: "resolveHttpRequesterIp, stripToBareIp, unusableTrustedProxyEntries, httpRequesterIp and
// httpAuthzContext join these". These are the first three of the five, and they REUSE [IsTrustedEdge]
// as that TODO demands — RequesterIp.kt's own warning is that "a second hand-rolled copy of this test
// is how a header ends up honored from an untrusted peer".
//
// The last two — `httpRequesterIp`'s authDebug arm and `httpAuthzContext` — are at the bottom of this
// file as methods on [Gates], which is the seam every route already holds.
// ---------------------------------------------------------------------------------------------

// ResolveHTTPRequesterIP is `internal fun resolveHttpRequesterIp(peerAddress, xff, trustedProxies)`.
//
// 🔒 THE ANTI-SPOOF INVARIANT (docs/authz-context.md, "server-attested, never client-asserted"). An
// HTTP request's socket peer is trustworthy on its own — it is a fact of the TCP connection. The
// moment a load balancer sits in front, that peer is the EDGE and the real client appears only in
// `X-Forwarded-For`, which the client can also forge. So the header is honored ONLY when the peer is a
// configured [IsTrustedEdge]: spoofing requester_ip then also requires controlling the edge's socket
// address.
//
// 🔒 ONCE THE PEER IS A TRUSTED EDGE, ITS OWN ADDRESS IS NEVER THE ANSWER. A missing, blank or
// malformed rightmost XFF entry resolves to nil — requester_ip goes ABSENT and a policy conditioning
// on it fails closed (INV-A2-8) — rather than silently attributing the request to the edge. Falling
// back to the peer here is the single most tempting "fix" and it would quietly attribute every
// behind-an-edge request to the load balancer, which sits inside any plausible trusted CIDR.
//
// 🔒 THE RIGHTMOST ENTRY, not the leftmost. That is the one THIS edge appended; everything to its left
// came from an upstream hop and is not attested. Taking the leftmost is the classic XFF bug and it
// hands the client full control of the value.
//
// Never throws / never panics: every failure path is a nil.
//
// peerAddress is the bare socket peer ([RequestPeer] strips Go's port); present is Kotlin's
// nullability. xff is the raw, possibly multi-hop header value, nil when absent.
func ResolveHTTPRequesterIP(peerAddress string, present bool, xff *string, trustedProxies map[string]struct{}) *string {
	if IsTrustedEdge(peerAddress, present, trustedProxies) {
		if xff == nil || strings.TrimSpace(*xff) == "" {
			return nil
		}
		parts := strings.Split(*xff, ",")
		return validRequesterIP(StripToBareIP(strings.TrimSpace(parts[len(parts)-1]), true))
	}
	// A DIRECT client: the TCP peer IS the requester (unspoofable), and any X-Forwarded-For it sends is
	// client-forgeable and ignored entirely.
	if !present {
		return nil
	}
	return validRequesterIP(StripToBareIP(peerAddress, true))
}

// validRequesterIP is the Kotlin's local `fun validate(bare: String?)`.
//
// It is deliberately THE SAME parse [authz.AuthzContext.ToCedarMap] uses for `requester_ip`, so the
// resolver and the eventual Cedar marshalling can never disagree about what counts as well-formed —
// a stripped-but-still-bogus candidate resolves to nil HERE rather than being dropped silently later.
//
// The Kotlin calls cedar-java's `IpAddress(...)`; cedar-go's ParseIPAddr is the same layer. (This is
// L2 of [IsStorableIPLiteral]'s three stages, NOT L3: there is no charset allowlist in front of it,
// because unlike a stored `/auth/debug` value an XFF entry that happens to be a CIDR is simply a
// malformed address and Cedar's ipaddr type is welcome to accept it — nothing persists it.)
func validRequesterIP(bare *string) *string {
	if bare == nil {
		return nil
	}
	if _, err := cedartypes.ParseIPAddr(*bare); err != nil {
		return nil
	}
	return bare
}

// StripToBareIP is `private fun stripToBareIp(candidate)` — strip a bare address out of a candidate
// that may carry a port, STRICTLY.
//
// ⚠️ STRICT IS THE WHOLE POINT, and it is what separates this from [query.ParseRequesterIp]. That one
// parses Netty's always-well-formed SocketAddress.toString() and may salvage; an XFF entry is
// ATTACKER-ADJACENT, so a malformed candidate must resolve to nil rather than be truncated into a
// valid-looking IP. `[203.0.113.5` and `[203.0.113.5]junk` must not become `203.0.113.5`.
//
// The three arms, verbatim:
//
//   - `[v6]` / `[v6]:port` — a closing bracket is REQUIRED, and any suffix after `]` must be exactly
//     `:<digits>`;
//   - `host:port` (EXACTLY one colon) — the port must be all digits;
//   - anything else is a bare address (bare IPv4, or a bare IPv6 whose many colons are not a port).
//
// The result is only a CANDIDATE; [ResolveHTTPRequesterIP] still validates it through Cedar's parser.
//
// stripSlash is Kotlin's unconditional `removePrefix("/")`. It is exported as a parameter only so the
// behaviour is visible at the call site; production always passes true.
//
// Kotlin's `Char::isDigit` is Unicode-aware and this is ASCII-only. The difference is unreachable: a
// port made of ARABIC-INDIC digits would pass there, and the resulting host still has to satisfy
// Cedar's parser. Narrower is the safe direction.
func StripToBareIP(candidate string, stripSlash bool) *string {
	c := strings.TrimSpace(candidate)
	if stripSlash {
		c = strings.TrimPrefix(c, "/")
	}
	if c == "" {
		return nil
	}

	var host string
	switch {
	case strings.HasPrefix(c, "["):
		closeIdx := strings.IndexByte(c, ']')
		if closeIdx < 0 {
			return nil
		}
		suffix := c[closeIdx+1:]
		if suffix != "" && !(strings.HasPrefix(suffix, ":") && len(suffix) > 1 && allASCIIDigits(suffix[1:])) {
			return nil
		}
		host = c[1:closeIdx]
	case strings.Count(c, ":") == 1:
		colon := strings.IndexByte(c, ':')
		port := c[colon+1:]
		if port == "" || !allASCIIDigits(port) {
			return nil
		}
		host = c[:colon]
	default:
		host = c
	}

	if host == "" {
		return nil
	}
	return &host
}

func allASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// UnusableTrustedProxyEntries is `internal fun unusableTrustedProxyEntries(trustedProxies)` — the
// entries [IsTrustedEdge] could never match: not a literal address, and not a parseable CIDR block.
//
// 🔒 Its whole reason to exist is OBSERVABILITY OF A FAIL-CLOSED FAILURE. A malformed entry matches
// nothing, which is the right posture and also completely silent: the symptom is "forwarded headers
// stopped working" with nothing pointing at the typo. Config logs these at startup.
//
// ⚠️ It must WARN, never refuse to boot — a typo in one entry must not take the control plane down.
// See internal/config/doc.go's TODO(A12).
//
// A NOTE ON WHAT IT DOES NOT FLAG, because this is a real asymmetry with [IsTrustedEdge] and not an
// oversight: a non-parseable entry with no slash, such as `"localhost"`, IS reported here — yet
// IsTrustedEdge still matches it, because its literal set lookup runs BEFORE any parsing. So a
// reported entry is not necessarily dead (ScimAuthTest relies on exactly that literal). The Kotlin has
// the same asymmetry and the report is advisory, so it is reproduced rather than tightened.
//
// Returns a SORTED slice where the Kotlin returns a Set-ordered List: Go map iteration is randomised,
// and a warning whose order changes per boot is a worse warning.
func UnusableTrustedProxyEntries(trustedProxies map[string]struct{}) []string {
	out := make([]string, 0)
	for entry := range trustedProxies {
		if slash := strings.IndexByte(entry, '/'); slash >= 0 {
			addr, ok := parseIPLiteral(entry[:slash])
			if !ok {
				out = append(out, entry)
				continue
			}
			prefix, err := strconv.Atoi(strings.TrimSpace(entry[slash+1:]))
			if err != nil || prefix < 0 || prefix > len(addr)*8 {
				out = append(out, entry)
			}
			continue
		}
		if _, ok := parseIPLiteral(entry); !ok {
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}

// RequestRequesterIP is the peer/header half of `internal fun ApplicationCall.httpRequesterIp(config)`
// — read the raw socket peer and the LAST `X-Forwarded-For` header instance, then resolve.
//
// ⚠️ IT IS NOT THE WHOLE FUNCTION. The Kotlin's first act is the PM_AUTH_DEBUG arm: under authDebug a
// web session may carry a SIMULATED address chosen at debug login, which then replaces the observed
// peer for every HTTP-path decision. That arm is A1's (`/auth/debug` stores the value; see
// internal/app/authroutes.go) and DebugRequesterIpDbTest is its suite. Keeping it out of here is
// deliberate: this function has no business reading a session, and the caller that eventually becomes
// `httpAuthzContext` is where the two compose.
//
// ⚠️ INV-A12-11 — this reads the CONNECTION's peer. No forwarded-headers middleware may be installed
// (see [RequestScheme]); one would rewrite the peer before this code sees it and defeat the whole
// anti-spoof invariant.
//
// [LastHeader], not Header.Get: the LAST header instance, which is a different thing from the first
// and is what Ktor's `getAll(...).lastOrNull()` returns.
func RequestRequesterIP(r *http.Request, trustedProxies map[string]struct{}) *string {
	peer, present := RequestPeer(r)
	return ResolveHTTPRequesterIP(peer, present, LastHeader(r, "X-Forwarded-For"), trustedProxies)
}

// ---------------------------------------------------------------------------------------------
// The composition point: `httpRequesterIp` + `httpAuthzContext` (RequesterIp.kt:235-251)
// ---------------------------------------------------------------------------------------------

// HTTPRequesterIP is `internal fun ApplicationCall.httpRequesterIp(config)` — [RequestRequesterIP]
// with the PM_AUTH_DEBUG arm in front of it, which is the whole function.
//
// ⚠️ THE authDebug ARM WIDENS THE BYPASS, and that is the Kotlin's own assessment, reproduced rather
// than softened. Under `PM_AUTH_DEBUG` a web session's stored `debug_requester_ip` REPLACES the
// observed peer, and because this is the ONE resolver every HTTP-path decision reads, the simulated
// value reaches the editor, the approval routes and the admin gates identically to a real address
// instead of being special-cased per route. `authDebug` already mints any role, so against a policy
// gated on role alone this adds nothing — but against one gated on role AND network (the shipped
// `-258` PII unmask needs `system:production-pii-accessor` AND the `trusted-network` tag) the peer was
// a second, INDEPENDENT factor, and simulating it removes that. Acceptable only because
// `Config.FromEnv` refuses to start with authDebug on in a production-looking configuration, and
// because with the bypass off the stored value is never consulted.
//
// A session-lookup error yields no simulated IP rather than propagating: Kotlin's
// `webSession()?.debugRequesterIp` cannot fail this way, and failing the whole resolution would let a
// storage blip become a fail-OPEN on any policy that denies when requester_ip is PRESENT.
func (g *Gates) HTTPRequesterIP(r *http.Request) *string {
	if g.Config.AuthDebug && g.Sessions != nil {
		if row, err := g.Sessions.WebSession(r); err == nil && row != nil && row.DebugRequesterIP != nil {
			return row.DebugRequesterIP
		}
	}
	return RequestRequesterIP(r, g.Config.TrustedProxies)
}

// HTTPAuthzContext is `internal fun ApplicationCall.httpAuthzContext(config)` — the non-query
// [authz.AuthzContext] for an HTTP admin/audit/approval route, and what [Gates.authzContext] falls
// back to when no suite has overridden [Gates.Context].
//
// Only RequesterIP is populated. Channel is deliberately left UNSET: these routes have no
// query-decision channel and inventing one would be dishonest. The datasource-scoped tag derivation
// they layer on top when a datasource is in scope lives in authz's AuthorizeWithContext, not here.
//
// 🔒 INV-A2-16 is why this is a method on Gates rather than an argument threaded per route: the
// derivation lives at ONE seam, so ~35 admin call sites get `requester_ip` with no call-site churn and
// none of them can drift from it. [Gates.AuthzContext] exposes the same value to the one route that
// builds its own Cedar decision (`GET /api/me/permissions`), so the gates and that route can never
// disagree about what `requester_ip` is for a single request.
func (g *Gates) HTTPAuthzContext(r *http.Request) authz.AuthzContext {
	return authz.AuthzContext{RequesterIP: g.HTTPRequesterIP(r)}
}
