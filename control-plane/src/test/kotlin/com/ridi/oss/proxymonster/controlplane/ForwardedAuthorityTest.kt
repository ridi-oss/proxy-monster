package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [resolveForwardedAuthority] — which host the client addressed, for the `/mcp` host check
 * (McpServer.kt). The invariant is the one [resolveHttpRequesterIp] enforces for `X-Forwarded-For` and
 * [resolveScimTls] for `X-Forwarded-Proto`: a client-settable header may speak for the request ONLY when
 * the socket peer is a configured trusted edge.
 *
 * The case that matters most is [forwardedHostFromAnUntrustedPeerIsIgnored]. The `/mcp` host check is a
 * DNS-rebinding defense — a browser page on an attacker's domain can reach a locally-bound MCP endpoint,
 * and the Host comparison is what makes that request fail. If `X-Forwarded-Host` were honored from any
 * peer, asserting one header would bypass it, so the header must buy nothing without the edge's socket
 * address behind it.
 *
 * Resolution is host-only. [aPortIsNeverPartOfTheResolvedHost] pins that: a TLS-terminating edge makes
 * the addressed port unobservable, so carrying one through only reintroduces a comparison that rejects
 * every request behind such an edge.
 */
class ForwardedAuthorityTest {
    private val edge = setOf("10.0.0.1")

    @Test
    fun `with no trusted edge the direct host is used`() {
        assertEquals("cp.example.com", resolveForwardedAuthority("cp.example.com", "203.0.113.9", null, emptySet()))
    }

    @Test
    fun `forwardedHostFromAnUntrustedPeerIsIgnored`() {
        // The security case: a direct caller asserting the expected public host must not pass a check it
        // would otherwise fail. The direct host wins, so the comparison still rejects it.
        assertEquals(
            "127.0.0.1",
            resolveForwardedAuthority(
                directHost = "127.0.0.1",
                peerAddress = "203.0.113.9",
                forwardedHost = "cp.example.com",
                trustedProxies = edge,
            ),
        )
    }

    @Test
    fun `a trusted edge's forwarded host supersedes the proxy's own authority`() {
        // The deployment this exists for: an edge (or the Next console) forwards to the control plane, so
        // the socket authority is the proxy's and only the header carries what the client addressed.
        assertEquals("cp.example.com", resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "cp.example.com", edge))
    }

    @Test
    fun `an edge that preserves the client host needs no forwarded header`() {
        // An ALB with preserve_host_header forwards the client's Host untouched and sends no
        // X-Forwarded-Host at all. The direct host is then already what the client addressed, so the
        // absent header must fall back to it rather than resolve to the socket's own name.
        assertEquals("cp.example.com", resolveForwardedAuthority("cp.example.com", "10.0.0.1", null, edge))
    }

    @Test
    fun `aPortIsNeverPartOfTheResolvedHost`() {
        // Whatever port the edge asserts, the result is the bare host: the caller compares hosts, and a
        // port left dangling on the string would fail that compare (`cp.example.com:8443` != host).
        assertEquals("cp.example.com", resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "cp.example.com:8443", edge))
        assertEquals("cp.example.com", resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "cp.example.com:443", edge))
    }

    @Test
    fun `the rightmost entry of a multi-hop forwarded host is taken`() {
        // Same convention as X-Forwarded-For: the rightmost entry is the one THIS edge appended;
        // everything left of it came from an upstream hop and is not attested.
        assertEquals(
            "cp.example.com",
            resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "evil.example.net, cp.example.com", edge),
        )
    }

    @Test
    fun `a bracketed IPv6 authority is unwrapped without being split at its own colons`() {
        // A naive split on the first colon shreds `[::1]:8443` into host `[` — so the port is only taken
        // from a colon that follows the closing bracket.
        assertEquals("::1", resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "[::1]:8443", edge))
        assertEquals("::1", resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "[::1]", edge))
    }

    @Test
    fun `a blank or non-numeric-port forwarded host falls back rather than resolving a partial authority`() {
        assertEquals(
            "127.0.0.1",
            resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "   ", edge),
            "a blank header carries nothing to honor",
        )
        // `cp.example.com:https` is not host:port — the trailing text is part of the host, so the
        // comparison fails rather than silently accepting `cp.example.com`.
        assertEquals(
            "cp.example.com:https",
            resolveForwardedAuthority("127.0.0.1", "10.0.0.1", "cp.example.com:https", edge),
        )
    }
}

/**
 * [isTrustedEdge]'s CIDR support. A block is what an autoscaled edge needs — its pod address is not
 * knowable in advance — but a block also widens what may speak for a client, so the cases that matter
 * are the ones that must NOT match: an address outside the prefix, a different address family, and a
 * malformed entry, which has to fail closed rather than match everything.
 */
class TrustedEdgeCidrTest {
    @Test
    fun `a literal entry still matches exactly and nothing else`() {
        assertTrue(isTrustedEdge("10.0.0.1", setOf("10.0.0.1")))
        assertFalse(isTrustedEdge("10.0.0.2", setOf("10.0.0.1")))
    }

    @Test
    fun `an address inside a CIDR block is trusted and one outside it is not`() {
        val edge = setOf("10.10.0.0/16")
        assertTrue(isTrustedEdge("10.10.0.1", edge))
        assertTrue(isTrustedEdge("10.10.255.254", edge), "the whole /16 is covered")
        assertFalse(isTrustedEdge("10.11.0.1", edge), "one bit outside the prefix is outside the block")
        assertFalse(isTrustedEdge("203.0.113.9", edge))
    }

    @Test
    fun `a prefix that is not byte-aligned masks the boundary byte`() {
        // /20 splits the third byte: 10.10.16.x is inside, 10.10.32.x is not. A whole-byte-only compare
        // would wrongly accept both.
        val edge = setOf("10.10.16.0/20")
        assertTrue(isTrustedEdge("10.10.16.1", edge))
        assertTrue(isTrustedEdge("10.10.31.255", edge))
        assertFalse(isTrustedEdge("10.10.32.0", edge))
        assertFalse(isTrustedEdge("10.10.15.255", edge))
    }

    @Test
    fun `IPv6 blocks work and never match across address families`() {
        assertTrue(isTrustedEdge("2001:db8::1", setOf("2001:db8::/32")))
        assertFalse(isTrustedEdge("2001:db9::1", setOf("2001:db8::/32")))
        // A v4 peer must not be coerced into a v6 block or vice versa: ::/0 is every IPv6 address, not
        // every address, and 0.0.0.0/0 is every IPv4 one.
        assertFalse(isTrustedEdge("10.0.0.1", setOf("::/0")))
        assertFalse(isTrustedEdge("2001:db8::1", setOf("0.0.0.0/0")))
    }

    @Test
    fun `a malformed entry matches nothing rather than everything`() {
        // The security case: a typo must narrow trust, never widen it. Each of these would be a disaster
        // if a lenient parser treated it as "match anything".
        for (bad in listOf("10.10.0.0/", "10.10.0.0/33", "10.10.0.0/-1", "not-an-ip/16", "/16", "10.10.0.0/abc")) {
            assertFalse(isTrustedEdge("10.10.0.1", setOf(bad)), "entry $bad must not match")
        }
        assertTrue(unusableTrustedProxyEntries(setOf("10.10.0.0/33", "nope")).size == 2)
        assertTrue(unusableTrustedProxyEntries(setOf("10.10.0.0/16", "10.0.0.1", "2001:db8::/32")).isEmpty())
    }

    @Test
    fun `a hostname entry is never resolved at match time`() {
        // Resolving would make trust depend on DNS, which an attacker may influence, and would turn a
        // config typo into a network call on every request.
        assertFalse(isTrustedEdge("10.0.0.1", setOf("localhost")))
        assertFalse(isTrustedEdge("127.0.0.1", setOf("localhost")))
    }

    @Test
    fun `an empty trusted set trusts nothing`() {
        assertFalse(isTrustedEdge("10.0.0.1", emptySet()))
        assertFalse(isTrustedEdge(null, setOf("10.10.0.0/16")))
    }
}
