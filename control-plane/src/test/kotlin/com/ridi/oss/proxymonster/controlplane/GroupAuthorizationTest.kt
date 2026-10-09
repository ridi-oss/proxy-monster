package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class GroupAuthorizationTest {
    private fun authz(vararg policies: String): Authz {
        val policyList = policies.mapIndexed { i, policy -> (i.toLong() + 1) to policy }
        return Authz(
            CedarEngine(policyList),
            CedarPolicyStore(UnusedDataSource),
            object : RoleSource {
                override fun rolesOf(principal: String) = parentsOf(principal).roles

                override fun parentsOf(principal: String) = when (principal) {
                    "alice" -> UserParents(setOf("dba", "viewer"), setOf("system:admin"))
                    "bob" -> UserParents(emptySet(), setOf("team-a", "team-a-leads"))
                    "charlie" -> UserParents(emptySet(), setOf("team-b"))
                    else -> UserParents(emptySet())
                }
            },
        )
    }

    @Test
    fun `principal in Group permits approval`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource);""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "alice", datasourceName = "ds1", roleName = "admin"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `requester in Group permits approval`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource.requester in Group::"team-a" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "bob", datasourceName = "ds1", roleName = "admin"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `team-a-lead cannot approve team-b member`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource.requester in Group::"team-a" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "charlie", datasourceName = "ds1", roleName = "admin"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `requester in Role reads the requester's own roles`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource.requester in Role::"viewer" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "alice", datasourceName = "ds1", roleName = "admin"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `requester without the role is denied`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource.requester in Role::"viewer" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "charlie", datasourceName = "ds1", roleName = "admin"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `requester groups are not parents of the request`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource in Group::"team-a" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "bob", datasourceName = "ds1", roleName = "admin"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `requester roles are not parents of the request`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource in Role::"dba");""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "alice", datasourceName = "ds1", roleName = "admin"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `approver and executedBy carry their roles and groups`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
                when { resource has approver && resource.approver in Role::"dba" &&
                       resource has executedBy && resource.executedBy in Group::"team-b" };""",
        )
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(
                requester = "bob", datasourceName = "ds1", roleName = "admin", approver = "alice", executedBy = "charlie",
            ),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `user with no groups is unaffected by group policies`() {
        val authz = authz(
            """permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource);""",
        )
        val decision = authz.authorize(
            "alice",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "alice", datasourceName = "ds1", roleName = "admin"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `role-based approval still works with groups`() {
        val authz = authz(
            """permit(principal in Role::"dba", action == Action::"task.approve", resource);""",
        )
        val decision = authz.authorize(
            "alice",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "bob", datasourceName = "ds1", roleName = "admin"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    private object UnusedDataSource : DataSource {
        override fun getConnection() = error("unused")
        override fun getConnection(user: String?, password: String?) = error("unused")
        override fun <T> unwrap(p0: Class<T>?): T = error("unused")
        override fun isWrapperFor(p0: Class<*>?): Boolean = error("unused")
        override fun getLoginTimeout(): Int = error("unused")
        override fun setLoginTimeout(p0: Int) = error("unused")
        override fun getLogWriter() = error("unused")
        override fun setLogWriter(p0: java.io.PrintWriter?) = error("unused")
        override fun getParentLogger() = error("unused")
    }
}
