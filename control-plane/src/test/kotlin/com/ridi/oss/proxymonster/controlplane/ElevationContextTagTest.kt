package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import java.sql.Connection
import java.util.concurrent.atomic.AtomicInteger
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * [authorizeWithContext] — the coherent non-query decision used by
 * `mayDecide` (Approvals.kt) and the ROLE access-request TASK_APPROVE sites
 * (Access.kt). It resolves the principal's roles ONCE and threads that single snapshot through BOTH pass-1
 * datasource-scoped tag derivation and pass-2 authorization (the non-query analog of decideQuery's
 * single-resolution invariant). Pins: (a) `requester_ip` reaches Cedar on every decision; (b) `context.tags`
 * is derived — via the SAME resolveContextTags pass-1 the query path uses — ONLY when a datasource is in
 * scope (tag rules are Datasource-scoped by construction, CedarEngine.kt `appliesTo { resource:
 * [Datasource] }`); (c) a null datasource derives no tags (no sentinel invented) yet still passes raw signals
 * through; (d) the two passes never disagree on roles — a JIT grant expiring between them can't earn a tag
 * the final authorization no longer sees.
 */
class ElevationContextTagTest {
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

    // A principal-agnostic tag rule: requester_ip in the documentation range earns "trusted-network".
    private val trustedNetworkTagRule = 1L to """permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };"""

    // A TASK_APPROVE permit gated ONLY on the derived tag — the consuming end of the two-pass.
    private val tagGatedApprovePermit = 2L to """permit(
        principal in Role::"reviewer", action == Action::"task.approve", resource
    ) when { context has tags && context.tags.contains("trusted-network") };"""

    private fun authz(policies: List<Pair<Long, String>>, roleSource: RoleSource): Authz =
        Authz(CedarEngine(policies), CedarPolicyStore(UnusedDataSource), roleSource)

    private fun authz(policies: List<Pair<Long, String>>, roles: Map<String, Set<String>> = emptyMap()): Authz =
        authz(policies, RoleSource { p -> roles[p] ?: emptySet() })

    private fun Authz.approve(principal: String, raw: AuthzContext, datasourceName: String?, datasourceTags: List<String> = emptyList()) =
        authorizeWithContext(
            principal, AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "requester", datasourceName = datasourceName),
            raw, datasourceName, datasourceTags,
        )

    @Test
    fun `parentsOf exposes the wired RoleSource`() {
        val az = authz(emptyList(), roles = mapOf("alice" to setOf("analyst", "approver")))
        assertEquals(setOf("analyst", "approver"), az.parentsOf("alice").roles)
        assertEquals(emptySet(), az.parentsOf("nobody").roles)
    }

    @Test
    fun `a requester_ip-derived tag gates a TASK_APPROVE elevation decision (Access-kt Approvals-kt shape)`() {
        val az = authz(listOf(trustedNetworkTagRule, tagGatedApprovePermit), roles = mapOf("approver" to setOf("reviewer")))

        assertEquals(
            AuthzDecision.Allow,
            az.approve("approver", AuthzContext(requesterIp = "100.100.5.5"), "acme-prod"),
            "requester_ip in range -> trusted-network tag -> the elevation permit fires",
        )
        assertIs<AuthzDecision.Deny>(
            az.approve("approver", AuthzContext(requesterIp = "10.0.0.1"), "acme-prod"),
            "requester_ip out of range -> no tag -> the elevation permit must not fire",
        )
    }

    @Test
    fun `a null datasource derives no tags — a tag-conditioned permit fails closed`() {
        val az = authz(listOf(trustedNetworkTagRule, tagGatedApprovePermit), roles = mapOf("approver" to setOf("reviewer")))
        // Same in-range requester_ip that earns the tag WITH a datasource in scope; with none, no tag is
        // derived (no sentinel/pseudo-datasource invented), so the tag-conditioned permit can't fire.
        assertIs<AuthzDecision.Deny>(
            az.approve("approver", AuthzContext(requesterIp = "100.100.5.5"), datasourceName = null),
            "no datasource -> no tags -> a tag-conditioned permit fails closed",
        )
    }

    @Test
    fun `a null datasource still passes requester_ip through to Cedar`() {
        // A permit conditioned DIRECTLY on requester_ip (no tag) must still fire with no datasource in scope —
        // raw signals reach Cedar; only tag DERIVATION is datasource-scoped.
        val az = authz(
            listOf(
                3L to """permit(
                    principal in Role::"reviewer", action == Action::"task.approve", resource
                ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
            ),
            roles = mapOf("approver" to setOf("reviewer")),
        )
        assertEquals(
            AuthzDecision.Allow,
            az.approve("approver", AuthzContext(requesterIp = "100.100.5.5"), datasourceName = null),
            "no datasource, but requester_ip still reaches Cedar -> a requester_ip-direct permit fires",
        )
    }

    @Test
    fun `a datasource-scoped tag rule fires only for the datasource in scope`() {
        val az = authz(
            listOf(
                1L to """permit(
                    principal, action == Action::"context.tag::trusted-network",
                    resource == Datasource::"acme-prod"
                ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
                tagGatedApprovePermit,
            ),
            roles = mapOf("approver" to setOf("reviewer")),
        )
        val raw = AuthzContext(requesterIp = "100.100.5.5")
        assertEquals(AuthzDecision.Allow, az.approve("approver", raw, "acme-prod"))
        assertIs<AuthzDecision.Deny>(az.approve("approver", raw, "other-ds"), "another datasource earns nothing")
    }

    @Test
    fun `datasourceTags reach the tag rule's Datasource entity (preset posture)`() {
        val az = authz(
            listOf(
                1L to """permit(
                    principal, action == Action::"context.tag::trusted-network", resource
                ) when { resource in Tag::"system:development" };""",
                tagGatedApprovePermit,
            ),
            roles = mapOf("approver" to setOf("reviewer")),
        )
        val raw = AuthzContext()
        assertEquals(
            AuthzDecision.Allow,
            az.approve("approver", raw, "acme-dev", datasourceTags = listOf("system:development")),
            "system:development posture -> the tag rule fires -> the elevation permit fires",
        )
        assertIs<AuthzDecision.Deny>(
            az.approve("approver", raw, "acme-prod", datasourceTags = emptyList()),
            "no system:development posture -> the tag rule never fires",
        )
    }

    @Test
    fun `tag derivation and final authorization share ONE role snapshot — no second, disagreeing resolution`() {
        // A RoleSource that returns the approver's role on the FIRST resolution and nothing after — a JIT grant
        // expiring between two resolutions. authorizeWithContext must resolve ONCE and thread that snapshot
        // through both passes; a design that re-resolved for the final authorization (building a context, then
        // separately calling authorize) would see empty roles on pass 2 and DENY. The tag rule here is
        // principal-agnostic, so pass-1 tags are role-independent — isolating the role-snapshot behavior.
        val calls = AtomicInteger(0)
        val flakyRoles = RoleSource { p -> if (p != "approver") emptySet() else if (calls.getAndIncrement() == 0) setOf("reviewer") else emptySet() }
        val az = authz(listOf(trustedNetworkTagRule, tagGatedApprovePermit), flakyRoles)

        assertEquals(
            AuthzDecision.Allow,
            az.approve("approver", AuthzContext(requesterIp = "100.100.5.5"), "acme-prod"),
            "one snapshot: the role resolved for tag derivation also decides the request (a re-resolution would deny)",
        )
        assertEquals(1, calls.get(), "authorizeWithContext must resolve the principal's roles exactly once")
    }
}
