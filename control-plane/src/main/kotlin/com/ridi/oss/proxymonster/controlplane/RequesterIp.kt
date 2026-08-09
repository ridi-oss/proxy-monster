package com.ridi.oss.proxymonster.controlplane

import com.cedarpolicy.value.IpAddress
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import io.ktor.server.application.ApplicationCall
import java.net.InetAddress

/**
 * The HTTP-side counterpart of [parseRequesterIp] (docs/authz-context.md), which resolves the wire proxy's
 * client_addr. An HTTP request's SOCKET PEER is trustworthy on its own —
 * it's a fact of the TCP connection, never client-supplied — but the moment a load balancer / reverse proxy
 * sits in front of the control-plane, the socket peer is the EDGE, not the end client, and the true client
 * address only appears in a header (`X-Forwarded-For`) the CLIENT can also forge. So `X-Forwarded-For` is
 * honored ONLY when the socket peer is a configured [trustedProxies] entry (anti-spoof invariant,
 * authz-context.md "Server-attested, never client-asserted") — an arbitrary caller cannot spoof requester_ip
 * simply by setting the header, because doing so requires ALSO controlling the trusted edge's socket address.
 *
 * When trusted, the RIGHTMOST comma-separated `X-Forwarded-For` entry is taken — by X-Forwarded-For
 * convention that's the entry the trusted edge itself appended; every entry to its left was supplied by
 * whatever sits upstream of the edge (the client, or another untrusted hop) and is not attested here. Once
 * the peer is known to be a trusted edge, its OWN socket address is NEVER used as the requester_ip (the edge
 * is not the end client): a missing, blank, or malformed rightmost XFF entry resolves to `null` — the
 * attribute goes absent and a policy conditioning on it fails closed, rather than silently attributing the
 * request to the edge's own address. Never throws. The trusted-edge set is [Config.trustedProxies].
 *
 * [peerAddress] is the bare socket-peer address (already free of a port — see [ApplicationCall.httpRequesterIp]
 * for how it's obtained from Ktor). [xff] is the raw (possibly multi-hop, comma-separated) header value.
 */
/**
 * True when the socket peer is a configured trusted edge — the ONE definition of "this hop may speak for
 * the client", shared by every `X-Forwarded-*` consumer so the anti-spoof invariant cannot drift between
 * them (a second hand-rolled copy of this test is how a header ends up honored from an untrusted peer).
 *
 * An entry is either a literal address or a CIDR block (`10.10.0.0/16`, `2001:db8::/32`). A block is
 * what a real deployment needs: an autoscaled load balancer or a Kubernetes ingress presents whichever
 * pod address it happens to have, so enumerating them is impossible and the alternative is trusting
 * nothing and losing every forwarded header.
 *
 * A block widens what may speak for a client, so it must cover ONLY hops you operate — never a subnet
 * that also holds untrusted workloads, because anything inside it can then assert its own requester_ip,
 * pass the SCIM TLS gate over plaintext, and satisfy the /mcp host check. Prefer the narrowest prefix
 * that covers the edge.
 *
 * A malformed entry matches nothing rather than throwing or matching everything: a typo must fail
 * closed. [Config] logs the rejected entries at startup so a typo is visible instead of silently
 * disabling forwarding.
 */
internal fun isTrustedEdge(peerAddress: String?, trustedProxies: Set<String>): Boolean {
    if (peerAddress == null) return false
    // Literal match first: the common single-edge case costs one set lookup and no parsing.
    if (peerAddress in trustedProxies) return true
    val peer = parseIp(peerAddress) ?: return false
    return trustedProxies.any { entry -> cidrContains(entry, peer) }
}

/** Parsed only through [InetAddress.getByName]'s literal path — never a DNS lookup, which a peer
 *  address is not and which would let a hostname entry resolve at match time. */
private fun parseIp(candidate: String): ByteArray? {
    val c = candidate.trim().removeSurrounding("[", "]")
    if (c.isEmpty() || !c.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' || it == '%' }) {
        return null
    }
    return runCatching { InetAddress.getByName(c).address }.getOrNull()
}

/**
 * True when [peer] falls inside `entry` written as `address/prefixLength`. Compares whole bytes, then
 * the remaining bits of the boundary byte. A prefix outside `0..bits` or a family mismatch (an IPv4
 * peer against an IPv6 block) is not a match — the two address spaces are compared, never coerced.
 */
private fun cidrContains(entry: String, peer: ByteArray): Boolean {
    val slash = entry.indexOf('/')
    if (slash < 0) return false
    val block = parseIp(entry.substring(0, slash)) ?: return false
    if (block.size != peer.size) return false
    val prefix = entry.substring(slash + 1).trim().toIntOrNull() ?: return false
    val bits = block.size * 8
    if (prefix < 0 || prefix > bits) return false
    val fullBytes = prefix / 8
    for (i in 0 until fullBytes) if (block[i] != peer[i]) return false
    val remaining = prefix % 8
    if (remaining == 0) return true
    val mask = (0xFF shl (8 - remaining)) and 0xFF
    return (block[fullBytes].toInt() and mask) == (peer[fullBytes].toInt() and mask)
}

/**
 * The entries [isTrustedEdge] could never match: not a literal address and not a parseable CIDR block.
 * Config logs these at startup — a malformed entry fails closed, and failing closed silently is how a
 * typo turns into "forwarded headers stopped working" with nothing pointing at the cause.
 */
internal fun unusableTrustedProxyEntries(trustedProxies: Set<String>): List<String> =
    trustedProxies.filter { entry ->
        if (entry.contains('/')) {
            val slash = entry.indexOf('/')
            val addr = parseIp(entry.substring(0, slash))
            val prefix = entry.substring(slash + 1).trim().toIntOrNull()
            addr == null || prefix == null || prefix < 0 || prefix > addr.size * 8
        } else {
            parseIp(entry) == null
        }
    }

internal fun resolveHttpRequesterIp(peerAddress: String?, xff: String?, trustedProxies: Set<String>): String? {
    // The SAME cedar-java parse AuthzContext.toCedarMap uses for `requester_ip` (Authz.kt) is the ONE
    // definition of "valid IP" for the whole control-plane, so this resolver and the eventual Cedar
    // marshalling can never disagree about what counts as a well-formed address. A stripped-but-still-bogus
    // candidate resolves to null here.
    fun validate(bare: String?): String? = bare?.takeIf { runCatching { IpAddress(it) }.isSuccess }

    if (isTrustedEdge(peerAddress, trustedProxies)) {
        // The socket peer is a configured trusted edge — its OWN address is the edge, NOT the end requester, so
        // it must NEVER be used as requester_ip. The client only appears in X-Forwarded-For; take the RIGHTMOST
        // entry (the one THIS edge appended — everything to its left is client-supplied and unattested). A
        // missing, blank, or malformed rightmost entry resolves to null: requester_ip goes absent (fail-closed),
        // never the edge's own address and never a client-forgeable value.
        if (xff.isNullOrBlank()) return null
        return validate(stripToBareIp(xff.split(',').last().trim()))
    }
    // The socket peer is a DIRECT client (not a configured edge): the TCP-level peer IS the requester (a fact of
    // the connection, unspoofable), and any X-Forwarded-For it sends is client-forgeable and ignored. An
    // absent/unparseable peer resolves to null.
    return validate(stripToBareIp(peerAddress))
}

/**
 * The HOST the CLIENT addressed, for the checks that compare a request's target against a configured
 * public identity — today the `/mcp` host check (McpServer.kt).
 *
 * Host only, never a port. Behind a TLS-terminating edge the backend is reached on its own cleartext
 * port, and a client's `Host` omits the port whenever it is the scheme default, so a port comparison
 * rejects every request in the deployment shape the check exists to serve. It also buys nothing — an
 * attacker who controls the host names any port they like. (The port of a browser-facing request is
 * still enforced, by the `Origin` check's scheme+host+port comparison in McpServer.kt.)
 *
 * Direct `Host` is a fact of the request. `X-Forwarded-Host` is client-settable, so it is honored ONLY
 * when the socket peer is a configured trusted edge — [isTrustedEdge], the same
 * server-attested-never-client-asserted invariant [resolveHttpRequesterIp] enforces for
 * `X-Forwarded-For` and [resolveScimTls] for `X-Forwarded-Proto`. Without that gate the host check
 * would be bypassable by asserting a header, which is the DNS-rebinding defense it exists to provide.
 *
 * A multi-hop value takes the RIGHTMOST entry — the one THIS edge appended; everything left of it is
 * client-supplied. A port in `X-Forwarded-Host` is parsed off and discarded rather than left on the
 * host, so `cp.example.com:8443` compares as `cp.example.com`. Falls back to the direct host whenever
 * the peer is untrusted or the header is absent/blank, which is also the correct answer for an edge
 * that preserves the client `Host` and sends no `X-Forwarded-Host` at all.
 */
internal fun resolveForwardedAuthority(
    directHost: String,
    peerAddress: String?,
    forwardedHost: String?,
    trustedProxies: Set<String>,
): String {
    if (!isTrustedEdge(peerAddress, trustedProxies)) return directHost
    val asserted = forwardedHost?.split(',')?.lastOrNull()?.trim()?.takeIf { it.isNotEmpty() } ?: return directHost
    // An IPv6 literal authority is bracketed (`[::1]:443`), so only split a port off the LAST colon and
    // only when it follows the closing bracket — otherwise `[::1]` would be shredded at its first colon.
    val lastColon = asserted.lastIndexOf(':')
    val hasPort = lastColon > asserted.lastIndexOf(']') &&
        lastColon < asserted.length - 1 &&
        asserted.drop(lastColon + 1).all(Char::isDigit)
    val host = if (hasPort) asserted.take(lastColon) else asserted
    return host.removeSurrounding("[", "]")
}

/**
 * Strip a bare address out of an XFF/peer candidate that may carry a port, STRICTLY. Unlike the wire path's
 * [parseRequesterIp] (which parses Netty's always-well-formed `SocketAddress.toString()`), an XFF entry is
 * attacker-adjacent, so a malformed candidate must resolve to `null`, never be salvaged into a valid-looking IP:
 *  - `[v6]` / `[v6]:port` — a closing bracket is REQUIRED, and any suffix after `]` must be exactly `:<digits>`
 *    (so `[203.0.113.5` and `[203.0.113.5]junk` are rejected, not silently truncated to a valid IP);
 *  - `host:port` (a single colon) — the port must be all digits (so `203.0.113.5:not-a-port` is rejected,
 *    not accepted as a bare IPv4);
 *  - anything else is a bare address (bare IPv4, or bare IPv6 whose multiple colons aren't a port).
 * The result is only a CANDIDATE — [resolveHttpRequesterIp] still validates it through cedar-java's [IpAddress]
 * (the one definition of "valid IP"), so a stripped-but-still-bogus host resolves to null there.
 */
private fun stripToBareIp(candidate: String?): String? {
    val c = candidate?.trim()?.removePrefix("/")?.takeIf { it.isNotEmpty() } ?: return null
    val host = when {
        c.startsWith("[") -> {
            val close = c.indexOf(']')
            if (close < 0) return null
            val suffix = c.substring(close + 1)
            if (suffix.isNotEmpty() && !(suffix.startsWith(":") && suffix.length > 1 && suffix.drop(1).all(Char::isDigit))) {
                return null
            }
            c.substring(1, close)
        }
        c.count { it == ':' } == 1 -> {
            val port = c.substringAfter(':')
            if (port.isEmpty() || !port.all(Char::isDigit)) return null
            c.substringBefore(':')
        }
        else -> c
    }
    return host.takeIf { it.isNotEmpty() }
}

/**
 * Whether [candidate] can be stored AND evaluated by the Cedar engine.
 *
 * `IpAddress` is a Java-side regex, looser than the Rust engine that ultimately parses the value: it
 * accepts a NUL-bearing string (which Postgres then rejects at INSERT) and non-canonical IPv4 like
 * `100.100.001.010` (which the engine refuses — and an unevaluable context value fails the whole
 * authorization closed, so the request denies everywhere with nothing naming the address). Hence
 * [evaluatesInCedar], the authoritative gate; the character allowlist is only a cheap pre-filter.
 */
internal fun isStorableIpLiteral(candidate: String, evaluatesInCedar: (String) -> Boolean): Boolean {
    if (candidate.isEmpty()) return false
    if (!candidate.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }) return false
    if (runCatching { IpAddress(candidate) }.isFailure) return false
    return evaluatesInCedar(candidate)
}

/**
 * The HTTP entry point's resolved requester IP — trusted-edge-gated per
 * [resolveHttpRequesterIp]. `request.local.remoteAddress` is the raw socket peer Ktor's Netty engine reports;
 * no `ForwardedHeaders`/`XForwardedHeaders` plugin is installed (App.kt), so nothing upstream of this call
 * has already substituted a client-asserted value — the peer really is the TCP-level fact this resolver needs.
 *
 * Under [Config.authDebug] a session may instead carry a SIMULATED address chosen at debug login
 * ([debugRequesterIp]) — every browser request on a development box arrives from loopback, so a tag rule
 * keyed on a CIDR could otherwise never fire and the behavior it gates could not be exercised at all. This
 * is the ONE resolver every HTTP-path decision reads, so the simulation reaches the editor, the approval
 * routes, and the admin gates identically to a real address, rather than being special-cased per route.
 *
 * What this costs, stated precisely: `authDebug` already mints any role, so against a policy gated on role
 * alone a simulated address adds nothing. But against one gated on role AND network — the shipped `-258`
 * PII unmask needs `system:production-pii-accessor` AND the `trusted-network` tag — the peer was still a
 * second, independent factor, and simulating it removes that. So this WIDENS the bypass rather than merely
 * riding on it. It is acceptable only because `Config.fromEnv` refuses to start with `authDebug` on in a
 * production-looking configuration, and because with the bypass off the stored value is never consulted.
 */
internal fun ApplicationCall.httpRequesterIp(config: Config): String? {
    if (config.authDebug) {
        webSession()?.debugRequesterIp?.let { return it }
    }
    val peer = request.local.remoteAddress
    val xff = request.headers.getAll("X-Forwarded-For")?.lastOrNull()
    return resolveHttpRequesterIp(peer, xff, config.trustedProxies)
}

/**
 * The non-query [AuthzContext] for an HTTP admin/audit/approval route: `requesterIp` from the trusted-edge
 * resolver, plus [channel] for a route that sits on a named surface — the approve/reject/read routes pass
 * `workflow-viewer` so a policy can scope console approvals. Admin/audit routes have no channel and pass none.
 */
internal fun ApplicationCall.httpAuthzContext(config: Config, channel: Channel? = null): AuthzContext =
    AuthzContext(requesterIp = httpRequesterIp(config), channel = channel?.contextValue)
