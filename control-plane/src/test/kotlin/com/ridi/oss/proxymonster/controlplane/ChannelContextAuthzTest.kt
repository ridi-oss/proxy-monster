package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * Pin that the server-attested `context.channel` actually reaches Cedar (docs/authz-context.md)
 * and that a policy can gate a grant on it — the value is threaded through [AuthzContext.toCedarMap].
 * Absence fails closed. Also pins the empirically-verified authoring rule (the Cedar-behavior probe): an
 * OPTIONAL context attribute MUST be `has`-guarded before access or the policy fails schema validation and
 * [CedarEngine]'s fail-fast construction rejects it — which is why every channel/tag/requester_ip policy
 * must guard. No-DB, mirrors AuthzDatasourceActionTest's in-memory-CedarEngine pattern.
 */
class ChannelContextAuthzTest {
    // A datasource.connect grant that applies ONLY on the wire channel. The `context has channel` guard is
    // mandatory (channel is optional in the schema); the unguarded-policy test below proves why.
    private val wireOnlyConnect = listOf(
        1L to """permit(
            principal in Role::"wire-only",
            action == Action::"datasource.connect",
            resource in Datasource::"acme-mysql"
        ) when { context has channel && context.channel == "wire" };""",
    )

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

    private fun connect(channel: String?): AuthzDecision =
        authz(wireOnlyConnect).authorizeDatasourceAction(
            principal = "alice",
            roles = setOf("wire-only"),
            action = AuthzAction.DATASOURCE_CONNECT,
            datasource = "acme-mysql",
            context = AuthzContext(channel = channel),
        )

    @Test
    fun `a channel-conditioned grant fires only for the matching channel`() {
        assertEquals(AuthzDecision.Allow, connect("wire"), "the wire channel must satisfy the grant")
    }

    @Test
    fun `the same grant does not apply on a different channel`() {
        assertIs<AuthzDecision.Deny>(connect("editor"))
    }

    @Test
    fun `an absent channel fails the guard closed`() {
        // channel == null -> toCedarMap omits it -> `context has channel` is false -> grant does not apply.
        assertIs<AuthzDecision.Deny>(connect(null))
    }

    @Test
    fun `an unguarded optional-attr policy is rejected at engine construction`() {
        val unguarded = listOf(
            1L to """permit(principal, action == Action::"datasource.connect", resource)
                     when { context.channel == "wire" };""",
        )
        assertFailsWith<IllegalStateException> { CedarEngine(unguarded) }
    }
}
