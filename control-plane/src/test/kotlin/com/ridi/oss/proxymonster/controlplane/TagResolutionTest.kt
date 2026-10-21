package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.contextTagLint
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Pass-1 (docs/authz-context.md): the derived-`context.tags` two-pass mechanism, in-memory (no DB).
 * Pins that a `context.tag::<name>` rule (a) is LOADABLE though its action isn't predefined (the schema is
 * auto-augmented from the rule), (b) fires only when its condition + resource scope hold, (c) fails closed,
 * (d) once derived, feeds a consuming policy's `context.tags.contains(...)`, and (e) cannot depend on tags
 * (no recursion). Mirrors ChannelContextAuthzTest's in-memory CedarEngine pattern.
 */
class TagResolutionTest {
    private object UnusedDataSource : DataSource {
        override fun getConnection(): Connection = error("not used by this test")
        override fun getConnection(username: String?, password: String?): Connection = error("not used by this test")
        override fun getLogWriter() = error("not used by this test")
        override fun setLogWriter(out: java.io.PrintWriter?) = error("not used by this test")
        override fun setLoginTimeout(seconds: Int) = error("not used by this test")
        override fun getLoginTimeout() = error("not used by this test")
        override fun getParentLogger(): Logger = error("not used by this test")
        override fun <T : Any?> unwrap(iface: Class<T>?): T = error("not used by this test")
        override fun isWrapperFor(iface: Class<*>?): Boolean = false
    }

    private fun authz(policies: List<Pair<Long, String>>): Authz =
        Authz(CedarEngine(policies), CedarPolicyStore(UnusedDataSource), RoleSource { emptySet() })

    // A tag rule earning "trusted-network" for the tailnet CIDR — its action is NOT predefined in the bundled
    // schema; it loads only because CedarSchema auto-declares `context.tag::trusted-network` from this rule.
    private val cidrTagRule = 1L to """permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };"""

    private fun tags(authz: Authz, requesterIp: String?, datasource: String = "acme-prod"): Set<String> =
        authz.resolveContextTags(
            principal = "alice",
            parents = UserParents(emptySet()),
            datasource = datasource,
            rawContext = AuthzContext(requesterIp = requesterIp),
        )

    @Test
    fun `a tag rule loads though its action is not predefined, and fires when its condition holds`() {
        val earned = tags(authz(listOf(cidrTagRule)), requesterIp = "100.100.5.5")
        assertEquals(setOf("trusted-network"), earned)
    }

    @Test
    fun `the tag is absent when the raw signal does not match — fail closed`() {
        assertTrue(tags(authz(listOf(cidrTagRule)), requesterIp = "10.0.0.1").isEmpty())
        assertTrue(tags(authz(listOf(cidrTagRule)), requesterIp = null).isEmpty(), "absent ip -> no tag")
    }

    @Test
    fun `an empty vocabulary short-circuits to no tags`() {
        val noTagRules = listOf(2L to """permit(principal, action == Action::"datasource.connect", resource);""")
        assertTrue(tags(authz(noTagRules), requesterIp = "100.100.5.5").isEmpty())
    }

    @Test
    fun `a datasource-scoped tag rule fires only for the named datasource`() {
        val scoped = authz(
            listOf(
                1L to """permit(
                    principal, action == Action::"context.tag::trusted-network",
                    resource == Datasource::"acme-prod"
                ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
            ),
        )
        assertEquals(setOf("trusted-network"), tags(scoped, "100.100.5.5", datasource = "acme-prod"))
        assertTrue(tags(scoped, "100.100.5.5", datasource = "other").isEmpty(), "other datasource earns nothing")
    }

    @Test
    fun `a derived tag drives a consuming grant end-to-end`() {
        // The full loop: pass-1 earns the tag, pass-2's grant conditions on context.tags.contains(...).
        val az = authz(
            listOf(
                cidrTagRule,
                2L to """permit(
                    principal in Role::"analyst", action == Action::"datasource.connect",
                    resource == Datasource::"acme-prod"
                ) when { context has tags && context.tags.contains("trusted-network") };""",
            ),
        )
        val earned = az.resolveContextTags("alice", UserParents(setOf("analyst")), "acme-prod", AuthzContext(requesterIp = "100.100.5.5"))
        fun connect(t: Set<String>) = az.authorizeDatasourceAction(
            principal = "alice", parents = UserParents(setOf("analyst")), action = AuthzAction.DATASOURCE_CONNECT,
            datasource = "acme-prod", context = AuthzContext(requesterIp = "100.100.5.5", tags = t),
        )
        assertEquals(AuthzDecision.Allow, connect(earned), "the derived trusted-network tag must satisfy the grant")
        assertIs<AuthzDecision.Deny>(connect(emptySet()), "without the tag the same grant must not apply")
    }

    @Test
    fun `an unguarded tag-on-tag rule is rejected at construction — tags absent from the tag-action schema`() {
        // The generated tag-action schema omits `tags`, so reading context.tags unguarded is an unknown-attr
        // error → CedarEngine's fail-fast construction refuses it.
        val unguarded = listOf(
            1L to """permit(principal, action == Action::"context.tag::derived", resource)
                     when { context.tags.contains("other") };""",
        )
        assertFailsWith<IllegalStateException> { CedarEngine(unguarded) }
    }

    @Test
    fun `a guarded tag-on-tag rule loads but can never earn a tag — no recursion`() {
        // A `context has tags` guard validates (Cedar allows `has` on an absent attr), but pass-1 omits tags
        // from the eval context entirely, so the guard is always false → the tag can never fire off tags.
        val guardedTagOnTag = authz(
            listOf(
                1L to """permit(principal, action == Action::"context.tag::derived", resource)
                         when { context has tags && context.tags.contains("other") };""",
            ),
        )
        assertTrue(
            guardedTagOnTag.resolveContextTags("alice", UserParents(emptySet()), "acme-prod", AuthzContext(tags = setOf("other"))).isEmpty(),
            "a tag rule must not be able to earn a tag by reading context.tags",
        )
    }

    @Test
    fun `effectiveAuthzContext makes channel authoritative and discards caller-supplied tags`() {
        // The core invariant: even if a caller (or a client upstream) stuffs channel + tags into the
        // context, the Channel enum (from the token kind) must WIN and the derived tags must REPLACE — never
        // trust client input. This pins the exact overlay decideQuery relies on.
        val az = authz(listOf(cidrTagRule))
        val caller = AuthzContext(channel = "editor", tags = setOf("injected", "trusted-network"), requesterIp = "10.0.0.1")
        val eff = effectiveAuthzContext(caller, Channel.WIRE, az, "alice", UserParents(emptySet()), "acme-prod", emptyList())
        assertEquals("wire", eff.channel, "the Channel enum must override a caller-supplied channel")
        // requesterIp 10.0.0.1 is outside the rule's range -> no tag earned -> the caller's injected tags are gone.
        assertTrue(eff.tags.isEmpty(), "caller-supplied tags must be discarded, replaced by the derived set")

        // And when the raw signal DOES earn a tag, only the derived tag survives (still never the injected one).
        val eff2 = effectiveAuthzContext(
            caller.copy(requesterIp = "100.100.5.5"), Channel.WIRE, az, "alice", UserParents(emptySet()), "acme-prod", emptyList(),
        )
        assertEquals(setOf("trusted-network"), eff2.tags, "only the derived tag survives; injected is dropped")
    }

    @Test
    fun `the dangling-tag lint flags a consumer with no producer and a producer with no consumer`() {
        val consumerNoProducer = listOf(
            1L to """permit(principal, action == Action::"datasource.connect", resource)
                     when { context has tags && context.tags.contains("ghost") };""",
        )
        assertTrue(
            contextTagLint(consumerNoProducer).any { it.contains("\"ghost\"") && it.contains("no tag rule produces") },
            "a consumed-but-unproduced tag must be flagged",
        )

        // cidrTagRule produces "trusted-network" but nothing consumes it -> dead tag rule.
        assertTrue(
            contextTagLint(listOf(cidrTagRule)).any { it.contains("\"trusted-network\"") && it.contains("no policy consumes") },
            "a produced-but-unconsumed tag must be flagged",
        )

        val matched = listOf(
            cidrTagRule,
            2L to """permit(principal, action == Action::"datasource.connect", resource)
                     when { context has tags && context.tags.contains("trusted-network") };""",
        )
        assertTrue(contextTagLint(matched).isEmpty(), "a matched producer/consumer pair has no diagnostics")
    }
}
