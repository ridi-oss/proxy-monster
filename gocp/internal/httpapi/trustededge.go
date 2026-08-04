package httpapi

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// `RequesterIp.kt`'s trusted-edge half — 12-request-context.md §2
//
// Ported HERE, ahead of the rest of A12, because [Gates.RequireScimAuth]'s TLS gate cannot be written
// without it and a second hand-rolled copy is precisely the drift the Kotlin's own doc warns about:
// "the ONE definition of 'this hop may speak for the client', shared by every X-Forwarded-* consumer
// so the anti-spoof invariant cannot drift between them (a second hand-rolled copy of this test is
// how a header ends up honored from an untrusted peer)" (RequesterIp.kt).
//
//	TODO(A12): resolveHttpRequesterIp, stripToBareIp, unusableTrustedProxyEntries, httpRequesterIp and
//	httpAuthzContext join these — 12-request-context.md. They must REUSE [IsTrustedEdge].
// ---------------------------------------------------------------------------------------------

// IsTrustedEdge is `internal fun isTrustedEdge(peerAddress, trustedProxies)`.
//
// 🔒 The anti-spoof invariant (docs/authz-context.md, "server-attested, never client-asserted"): an
// `X-Forwarded-*` header may speak for the client ONLY when the socket peer is a configured edge. An
// arbitrary caller cannot spoof `requester_ip` — or the SCIM transport — merely by setting a header,
// because doing so also requires controlling the trusted edge's socket address.
//
// An entry is either a literal address or a CIDR block (`10.10.0.0/16`, `2001:db8::/32`). A block is
// what a real deployment needs: an autoscaled load balancer or a Kubernetes ingress presents whichever
// pod address it happens to have, so enumerating them is impossible and the alternative is trusting
// nothing and losing every forwarded header. A block WIDENS what may speak for a client, so it must
// cover only hops you operate.
//
// A malformed entry matches nothing rather than throwing or matching everything — a typo must fail
// closed.
//
// The literal match comes FIRST, exactly as in the Kotlin: the common single-edge case costs one map
// lookup and no parsing. It also means a non-parseable entry such as `"localhost"` still matches a
// peer string of `"localhost"` — which is what ScimAuthTest cases 3-5 rely on, since Ktor's test host
// reports its peer as the literal name.
func IsTrustedEdge(peerAddress string, present bool, trustedProxies map[string]struct{}) bool {
	if !present {
		// Kotlin's `peerAddress: String?` null arm. A missing peer never passes on a header alone.
		return false
	}
	if _, ok := trustedProxies[peerAddress]; ok {
		return true
	}
	peer, ok := parseIPLiteral(peerAddress)
	if !ok {
		return false
	}
	for entry := range trustedProxies {
		if cidrContains(entry, peer) {
			return true
		}
	}
	return false
}

// parseIPLiteral is `private fun parseIp(candidate)`: parsed only through the LITERAL path, never a
// DNS lookup — which a peer address is not, and which would let a hostname entry resolve at match
// time.
//
// The character allowlist is the Kotlin's verbatim, `%` included (unlike `isStorableIpLiteral`'s,
// which excludes it): a link-local IPv6 zone id is legitimate on a socket peer.
//
// Returns the address in its NATIVE width — 4 bytes for IPv4, 16 for IPv6 — because cidrContains
// compares `block.size != peer.size` to refuse a cross-family match. net.ParseIP normalises IPv4 to a
// 16-byte v4-in-v6 form, which would silently make `::ffff:10.0.0.1/104` match a v4 peer; To4() is
// what keeps the two address spaces compared and never coerced.
func parseIPLiteral(candidate string) (net.IP, bool) {
	c := strings.TrimSpace(candidate)
	c = strings.TrimSuffix(strings.TrimPrefix(c, "["), "]")
	if c == "" {
		return nil, false
	}
	for _, r := range c {
		switch {
		case r >= '0' && r <= '9', r == '.', r == ':',
			r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '%':
		default:
			return nil, false
		}
	}
	// A zone id (`fe80::1%eth0`) is stripped before parsing; InetAddress.getByName accepts it and
	// yields the bare address, and net.ParseIP rejects the whole string.
	if i := strings.IndexByte(c, '%'); i >= 0 {
		c = c[:i]
	}
	ip := net.ParseIP(c)
	if ip == nil {
		return nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, true
	}
	return ip, true
}

// cidrContains is `private fun cidrContains(entry, peer)`: true when peer falls inside
// `address/prefixLength`. Whole bytes first, then the remaining bits of the boundary byte. A prefix
// outside `0..bits` or a family mismatch (an IPv4 peer against an IPv6 block) is not a match.
//
// Hand-rolled rather than net.ParseCIDR because the accepted set must match the Kotlin's: ParseCIDR
// rejects a non-canonical block (`10.0.0.1/8`, host bits set) that the Kotlin accepts and matches on,
// so swapping it in would silently narrow a deployment's configured trust set.
func cidrContains(entry string, peer net.IP) bool {
	slash := strings.IndexByte(entry, '/')
	if slash < 0 {
		return false
	}
	block, ok := parseIPLiteral(entry[:slash])
	if !ok || len(block) != len(peer) {
		return false
	}
	prefix, err := strconv.Atoi(strings.TrimSpace(entry[slash+1:]))
	if err != nil {
		return false
	}
	bits := len(block) * 8
	if prefix < 0 || prefix > bits {
		return false
	}
	fullBytes := prefix / 8
	for i := 0; i < fullBytes; i++ {
		if block[i] != peer[i] {
			return false
		}
	}
	remaining := prefix % 8
	if remaining == 0 {
		return true
	}
	mask := byte(0xFF << (8 - remaining))
	return block[fullBytes]&mask == peer[fullBytes]&mask
}

// ResolveScimTLS is `internal fun resolveScimTls(directScheme, peerAddress, forwardedProto,
// trustedProxies)` (Scim.kt:194).
//
// True when the request demonstrably arrived over TLS. Direct HTTPS is a fact of the connection.
// `X-Forwarded-Proto` is client-settable, so it is honored ONLY when the socket peer is a configured
// trusted edge — the same server-attested-never-client-asserted invariant [IsTrustedEdge] enforces
// for `X-Forwarded-For`. Without that gate any direct plaintext caller could assert `https` about
// itself and send the standing bearer in the clear.
//
// 🔒 A multi-hop value takes the RIGHTMOST entry — the one THIS edge appended; everything left of it
// is client-supplied. Absent, blank, or non-`https` is not TLS (fail-closed). Note the practical
// consequence of the empty default: with `PM_TRUSTED_PROXIES` unset NO peer is trusted, so a
// TLS-terminating edge must be listed there or SCIM stays 403.
//
// Both comparisons are case-insensitive, matching `String?.equals(…, ignoreCase = true)`.
func ResolveScimTLS(directScheme string, peerAddress string, peerPresent bool, forwardedProto *string, trustedProxies map[string]struct{}) bool {
	if strings.EqualFold(directScheme, "https") {
		return true
	}
	if !IsTrustedEdge(peerAddress, peerPresent, trustedProxies) {
		return false
	}
	if forwardedProto == nil {
		return false
	}
	parts := strings.Split(*forwardedProto, ",")
	asserted := strings.TrimSpace(parts[len(parts)-1])
	return strings.EqualFold(asserted, "https")
}

// RequestScheme is `request.origin.scheme` reduced to the fact it actually carries here.
//
// ⚠️ INV-A12-11 — NO forwarded-headers middleware is installed (App.kt has no `ForwardedHeaders` /
// `XForwardedHeaders`), so nothing upstream has already substituted a client-asserted value and
// `origin.scheme` really is the connection's. A Go port MUST NOT enable a framework's
// forwarded-header middleware: doing so rewrites the peer before this code sees it and silently
// defeats the whole anti-spoof invariant. This is the single easiest way to break the area.
func RequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// RequestPeer is `request.local.remoteAddress` — the RAW SOCKET PEER, and deliberately not
// `origin.remoteAddress`, which is header-influenced and therefore not the TCP-level fact the
// trusted-edge test needs.
//
// Go's r.RemoteAddr carries a port; Ktor's does not, so it is stripped. The second return is Kotlin's
// nullability: a request with no peer at all (an in-process test transport) must never pass on a
// header alone.
func RequestPeer(r *http.Request) (string, bool) {
	if r.RemoteAddr == "" {
		return "", false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port at all — take it verbatim. A literal trusted-proxy entry may well BE this string
		// (ScimAuthTest trusts the literal "localhost"), so it must not be discarded.
		return r.RemoteAddr, true
	}
	return host, true
}

// LastHeader is `request.headers.getAll(name)?.lastOrNull()` — the LAST INSTANCE of a repeated
// header, which is a different thing from its first.
//
// ⚠️ Two levels of "rightmost" are in play and only one of them lives here: this takes the last
// HEADER INSTANCE; [ResolveScimTLS] then takes the rightmost ENTRY within that instance. Go's
// Header.Get returns the FIRST instance and would be wrong for both consumers.
func LastHeader(r *http.Request, name string) *string {
	values := r.Header.Values(name)
	if len(values) == 0 {
		return nil
	}
	v := values[len(values)-1]
	return &v
}

// ---------------------------------------------------------------------------------------------
// The two-stage storable-IP check — RequesterIp.kt:200-214, 98-cedar-spike-report.md § S5 / W3
// ---------------------------------------------------------------------------------------------

// IsStorableIPLiteral is `internal fun isStorableIpLiteral(candidate, evaluatesInCedar)`
// (RequesterIp.kt:209-214) — whether a candidate can be BOTH stored and evaluated as a
// `requester_ip`. Its one production caller today is 🔒 INV-A1-7, `/auth/debug`'s 400
// `auth.invalid_requester_ip`.
//
// 🔒 THE ALLOWLIST IS NOT REDUNDANT, however strict the engine half looks. `100.100.1.0/24` is the
// literal that proves it: cedar's `ipaddr` type covers PREFIXES, because a CIDR is a legal `ip()`
// argument inside a policy, so [Authorizer]'s engine half ACCEPTS it — and it is not a legal
// requester_ip VALUE. `/` is not in the allowlist and the allowlist is the only thing separating the
// two. Drop it and an operator can store a whole /24 as their simulated source address, i.e.
// /auth/debug answers 200 where the Kotlin answers 400. internal/authz/ip_test.go asserts this
// premise from the engine side (TestEvaluatesInCedar_AcceptsACIDRLiteral) so that removing the
// allowlist breaks A2's suite as well as this one.
//
// It takes evaluatesInCedar as a FUNCTION, exactly as the Kotlin does, which is what keeps the two
// halves separable — and what lets this be tested without standing up an engine.
//
// ⚠️ Kotlin has THREE stages and Go has TWO, with the same outcome on all 16 pinned literals:
//
//	L1 charset allowlist          — reproduced verbatim below
//	L2 cedar-java `IpAddress(…)`  — a JVM REGEX, looser than the engine; it accepts a NUL-bearing
//	                                string and non-canonical IPv4 like `100.100.001.010`
//	L3 evaluatesInCedar           — the authoritative gate, which refuses what L2 let through
//
// Go's net/netip (behind cedar-go's ParseIPAddr) rejects at parse everything L2 would have let
// through, so L2 and L3 COLLAPSE into the single evaluatesInCedar call. Same verdict, different
// layer — which is why the Kotlin's layering is not evidence for the Go layering, and why the
// oracle is DebugRequesterIpDbTest.kt:156-195's literal list rather than the stage structure.
//
// ⚠️ The allowlist deliberately EXCLUDES `%`, unlike [parseIPLiteral]'s a few lines up. A link-local
// zone id is legitimate on a socket peer and is NOT storable as a Cedar value, so the two allowlists
// in this file differ on exactly one character and both are correct. `fe80::1%lo0` is 400 here and a
// valid peer there.
func IsStorableIPLiteral(candidate string, evaluatesInCedar func(string) bool) bool {
	if candidate == "" {
		return false
	}
	// `candidate.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }`.
	//
	// Kotlin's Char.isDigit() is Unicode-aware (it accepts e.g. ARABIC-INDIC DIGIT ZERO), Go's range
	// test is ASCII-only. The difference is unreachable: any non-ASCII digit that passed here would
	// then have to parse as an IP literal, and neither cedar-java's regex nor cedar-go's parser
	// accepts one. Narrower is also the safe direction for an allowlist.
	for _, r := range candidate {
		switch {
		case r >= '0' && r <= '9', r == '.', r == ':',
			r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return evaluatesInCedar(candidate)
}
