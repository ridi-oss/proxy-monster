package com.ridi.oss.proxymonster.controlplane.authz

import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The satisfiability primitive that notification routing rests on, proven at the Cedar-decision level with an
 * in-memory policy set — no DB. The two properties that matter: an unknown attribute is marked UNKNOWN (so a
 * conditioned permit stays a maybe instead of dropping a real approver), and only the verdict is read (so an
 * undecided forbid is not mistaken for a deny). [AuthzTest] uses the same off-Docker construction.
 */
class AuthzSatisfiableTest {
    private object UnusedDataSource : DataSource {
        override fun getConnection(): Connection = error("not used")
        override fun getConnection(username: String?, password: String?): Connection = error("not used")
        override fun getLogWriter() = error("not used")
        override fun setLogWriter(out: java.io.PrintWriter?) = error("not used")
        override fun setLoginTimeout(seconds: Int) = error("not used")
        override fun getLoginTimeout() = error("not used")
        override fun getParentLogger(): Logger = error("not used")
        override fun <T : Any?> unwrap(iface: Class<T>?): T = error("not used")
        override fun isWrapperFor(iface: Class<*>?): Boolean = false
    }

    private val approve = AuthzAction.TASK_APPROVE
    private val resource = AuthzResource.ApprovalRequest(requester = "someone@example.com", datasourceName = "prod-db")

    private fun authz(vararg policies: String): Authz {
        val engine = CedarEngine(policies.mapIndexed { i, src -> (i + 1).toLong() to src })
        return Authz(engine, CedarPolicyStore(UnusedDataSource), RoleSource { emptySet() })
    }

    private fun Authz.verdict(
        roles: Set<String>,
        channel: String? = null,
        unknown: Set<String> = emptySet(),
    ) = satisfiableAs("bob@example.com", roles, approve, resource, knownChannel = channel, unknownContextKeys = unknown)

    @Test
    fun `an unconditional permit is ALLOWED regardless of the unknowns`() {
        val authz = authz("""permit(principal in Role::"approver", action == Action::"task.approve", resource);""")
        assertEquals(
            SatisfiableVerdict.ALLOWED,
            authz.verdict(setOf("approver"), unknown = setOf("requester_ip")),
            "nothing the permit reads is unknown, so it allows under every assignment",
        )
    }

    @Test
    fun `no matching permit is IMPOSSIBLE`() {
        val authz = authz("""permit(principal in Role::"approver", action == Action::"task.approve", resource);""")
        assertEquals(
            SatisfiableVerdict.IMPOSSIBLE,
            authz.verdict(setOf("some-other-role")),
            "a principal no permit covers is denied under every assignment",
        )
    }

    @Test
    fun `a permit conditioned on an UNKNOWN attribute is POSSIBLE`() {
        val authz = authz(
            """permit(principal in Role::"office-approver", action == Action::"task.approve", resource)
               when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
        )
        assertEquals(
            SatisfiableVerdict.POSSIBLE,
            authz.verdict(setOf("office-approver"), unknown = setOf("requester_ip")),
            "some address would satisfy the permit, so the approver must be told",
        )
    }

    /** The property the UNKNOWN marking exists for: omitting the attribute drops a real approver. */
    @Test
    fun `omitting the attribute the permit reads makes it IMPOSSIBLE — the bug UNKNOWN prevents`() {
        val authz = authz(
            """permit(principal in Role::"office-approver", action == Action::"task.approve", resource)
               when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
        )
        assertEquals(
            SatisfiableVerdict.IMPOSSIBLE,
            authz.verdict(setOf("office-approver"), unknown = emptySet()),
            "absent requester_ip makes `context has requester_ip` false, so the permit never fires",
        )
    }

    @Test
    fun `a known channel is supplied concretely and decides the permit`() {
        val authz = authz(
            """permit(principal in Role::"approver", action == Action::"task.approve", resource)
               when { context has channel && context.channel == "slack" };""",
        )
        assertEquals(SatisfiableVerdict.ALLOWED, authz.verdict(setOf("approver"), channel = "slack"))
        assertEquals(
            SatisfiableVerdict.IMPOSSIBLE,
            authz.verdict(setOf("approver"), channel = "editor"),
            "the permit is fully decided against a concrete channel; the wrong one denies",
        )
    }

    /** Reading only the verdict: an undecided forbid over the unknown axis is not a deny. */
    @Test
    fun `an undecided forbid does not make a permitted principal IMPOSSIBLE`() {
        val authz = authz(
            """permit(principal in Role::"approver", action == Action::"task.approve", resource);""",
            """forbid(principal, action == Action::"task.approve", resource)
               when { context has requester_ip && !context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
        )
        assertEquals(
            SatisfiableVerdict.POSSIBLE,
            authz.verdict(setOf("approver"), unknown = setOf("requester_ip")),
            "the forbid is undecided under an unknown address; treating it as a deny would skip a real approver",
        )
    }
}
