package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertIs

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GroupAuthorizationDbTest {
    private lateinit var database: DataSource
    private lateinit var core: ControlPlaneCore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_group_authorization"))
        core = ControlPlaneCore(database)
    }

    @AfterAll
    fun cleanup() {
        if (::database.isInitialized) (database as? AutoCloseable)?.close()
    }

    @Test
    fun `team lead approves only their own team's requests`() {
        val team = group("team")
        val leads = group("leads")
        val lead = user(team, leads)
        val member = user(team)
        val outsider = user(group("other"))
        policy(
            """permit(principal in Group::"${leads.name}", action == Action::"task.approve", resource)
                when { resource.requester in Group::"${team.name}" };""",
        )
        assertEquals(AuthzDecision.Allow, approve(lead, member))
        assertIs<AuthzDecision.Deny>(approve(lead, outsider))
    }

    @Test
    fun `principal in Group admits members only`() {
        val approvers = group("approvers")
        val member = user(approvers)
        val nonMember = user()
        policy("""permit(principal in Group::"${approvers.name}", action == Action::"task.approve", resource);""")
        assertEquals(AuthzDecision.Allow, approve(member, user()))
        assertIs<AuthzDecision.Deny>(approve(nonMember, user()))
    }

    @Test
    fun `requester in Role reads the requester's live roles`() {
        val approvers = group("approvers")
        val approver = user(approvers)
        val requesterRole = role()
        val requestedRole = role()
        val withRole = user()
        core.policyStore.createAssignment(RoleAssignmentInput(withRole, requesterRole.id))
        val withoutRole = user()
        policy(
            """permit(principal in Group::"${approvers.name}", action == Action::"task.approve", resource)
                when { resource.requester in Role::"${requesterRole.name}" };""",
        )
        assertEquals(AuthzDecision.Allow, approve(approver, withRole, requestedRole.name))
        assertIs<AuthzDecision.Deny>(approve(approver, withoutRole, requestedRole.name))
    }

    @Test
    fun `a user in no group keeps role-only decisions`() {
        val approverRole = role()
        val approver = user()
        core.policyStore.createAssignment(RoleAssignmentInput(approver, approverRole.id))
        policy("""permit(principal in Role::"${approverRole.name}", action == Action::"task.approve", resource);""")
        assertEquals(AuthzDecision.Allow, approve(approver, user()))
    }

    @Test
    fun `deleted groups and deactivated members grant nothing`() {
        val deleted = group("deleted")
        val active = group("active")
        val inDeleted = user(deleted)
        val deactivated = user(active)
        policy("""permit(principal in Group::"${deleted.name}", action == Action::"task.approve", resource);""")
        policy("""permit(principal in Group::"${active.name}", action == Action::"task.approve", resource);""")
        assertEquals(AuthzDecision.Allow, approve(inDeleted, user()))
        assertEquals(AuthzDecision.Allow, approve(deactivated, user()))
        core.userGroupStore.deleteGroup(deleted.id)
        core.userGroupStore.setUserActive(deactivated, false)
        assertIs<AuthzDecision.Deny>(approve(inDeleted, user()))
        assertIs<AuthzDecision.Deny>(approve(deactivated, user()))
    }

    @Test
    fun `groups resolve with or without roles and deleted ones drop out`() {
        val bare = group("bare")
        val granting = group("granting")
        val kept = role()
        val dropped = role()
        core.userGroupStore.addGroupRole(granting.id, kept.id)
        core.userGroupStore.addGroupRole(granting.id, dropped.id)
        val principal = user(bare, granting)
        assertEquals(
            UserParents(setOf(kept.name, dropped.name), setOf(bare.name, granting.name)),
            core.roleResolver.resolveParents(principal),
        )
        core.policyStore.deleteRole(dropped.id)
        assertEquals(UserParents(setOf(kept.name), setOf(bare.name, granting.name)), core.roleResolver.resolveParents(principal))
        core.userGroupStore.deleteGroup(granting.id)
        assertEquals(UserParents(emptySet(), setOf(bare.name)), core.roleResolver.resolveParents(principal))
    }

    private fun approve(approver: String, requester: String, roleName: String = "unrelated") = core.authz.authorize(
        approver,
        AuthzAction.TASK_APPROVE,
        AuthzResource.ApprovalRequest(requester = requester, datasourceName = "ds", roleName = roleName),
    )

    private fun user(vararg groups: AppGroup): String {
        val principal = "group-${UUID.randomUUID()}@example.com"
        val created = core.userGroupStore.createUser(
            AppUserInput(principal = principal), core.tokenStore, core.accessStore, PrincipalSessionStore(database, null),
        )
        groups.forEach { core.userGroupStore.addMember(it.id, created.id) }
        return principal
    }

    private fun group(prefix: String) = core.userGroupStore.createGroup(AppGroupInput("$prefix-${UUID.randomUUID()}"))

    private fun role() = core.policyStore.createRole(RoleInput("group-${UUID.randomUUID()}"))

    private fun policy(src: String) {
        core.cedarPolicyStore.create(CedarPolicyInput(name = "group-${UUID.randomUUID()}", cedarSrc = src), updatedBy = null)
    }
}
