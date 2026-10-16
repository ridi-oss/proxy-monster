package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.UserAttribute
import com.ridi.oss.proxymonster.controlplane.authz.fromClaims
import com.ridi.oss.proxymonster.controlplane.notify.RecipientResolver
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserAttributeAuthorizationDbTest {
    private lateinit var database: DataSource
    private lateinit var core: ControlPlaneCore
    private val declared = UserAttribute.parseList("manager:User,department:String,teams:Set<String>")

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_user_attributes"))
        Flyway.configure().dataSource(database).load().migrate()
        CedarSchema.declareUserAttributes(declared)
        core = ControlPlaneCore(database)
        policy(
            """permit(principal, action in [Action::"task.approve", Action::"task.read"], resource is Request)
                when { resource.requester has manager && resource.requester.manager == principal };""",
        )
    }

    @AfterAll
    fun cleanup() {
        CedarSchema.declareUserAttributes(emptyList())
        if (::database.isInitialized) (database as? AutoCloseable)?.close()
    }

    @Test
    fun `the requester's manager approves and nobody else does`() {
        val lead = login(principal())
        val other = login(principal())
        val member = login(principal(), "manager" to lead)
        assertEquals(AuthzDecision.Allow, approve(lead, member))
        assertEquals(AuthzDecision.Allow, decide(lead, member, AuthzAction.TASK_READ))
        assertIs<AuthzDecision.Deny>(approve(other, member))
        assertIs<AuthzDecision.Deny>(decide(other, member, AuthzAction.TASK_READ))
    }

    @Test
    fun `a login without the claim clears it`() {
        val lead = login(principal())
        val member = login(principal(), "manager" to lead)
        assertEquals(AuthzDecision.Allow, approve(lead, member))
        login(member)
        assertIs<AuthzDecision.Deny>(approve(lead, member))
    }

    @Test
    fun `a SCIM-owned user's attributes still follow the login`() {
        val lead = login(principal())
        val member = principal()
        core.userGroupStore.upsertScimUser("ext-${UUID.randomUUID()}", member, member, null, active = true)
        login(member, "manager" to lead)
        assertEquals(AuthzDecision.Allow, approve(lead, member))
        login(member)
        assertIs<AuthzDecision.Deny>(approve(lead, member))
    }

    @Test
    fun `a claim of the wrong type is not stored`() {
        val lead = login(principal())
        val member = login(principal(), "manager" to listOf(lead))
        assertEquals(emptyMap(), core.roleResolver.resolveParents(member).attributes)
        assertIs<AuthzDecision.Deny>(approve(lead, member))
    }

    @Test
    fun `string and set attributes reach the principal and the requester`() {
        policy(
            """permit(principal, action == Action::"task.approve", resource is Request)
                when { principal has department && resource.requester has department && resource.requester has teams &&
                       principal.department == resource.requester.department &&
                       resource.requester.teams.contains("db-review") };""",
        )
        val reviewer = login(principal(), "department" to "data")
        val inTeam = login(principal(), "department" to "data", "teams" to listOf("db-review", "backend"))
        val notInTeam = login(principal(), "department" to "data", "teams" to listOf("backend"))
        val otherDepartment = login(principal(), "department" to "web", "teams" to listOf("db-review"))
        assertEquals(AuthzDecision.Allow, approve(reviewer, inTeam))
        assertIs<AuthzDecision.Deny>(approve(reviewer, notInTeam))
        assertIs<AuthzDecision.Deny>(approve(reviewer, otherDepartment))
    }

    @Test
    fun `a deactivated requester carries no attributes`() {
        val lead = login(principal())
        val member = login(principal(), "manager" to lead)
        core.userGroupStore.setUserActive(member, false)
        assertIs<AuthzDecision.Deny>(approve(lead, member))
    }

    @Test
    fun `the manager is notified of a pending request`() {
        val lead = login(principal())
        val other = login(principal())
        val member = login(principal(), "manager" to lead)
        val resolver = RecipientResolver(core.authz, core.roleResolver) { listOf(lead, other, member) }
        val request = AccessRequest(
            id = 1, principal = member, roleName = "unrelated", datasourceName = "ds",
            requestedDurationSec = 3600, status = "PENDING", createdAt = "2026-10-13T00:00:00Z", revision = 1,
        )
        val recipients = resolver.recipientsFor(request)
        assertTrue(lead in recipients)
        assertFalse(other in recipients)
    }

    private fun approve(approver: String, requester: String) = decide(approver, requester, AuthzAction.TASK_APPROVE)

    private fun decide(principal: String, requester: String, action: AuthzAction) = core.authz.authorize(
        principal,
        action,
        AuthzResource.ApprovalRequest(requester = requester, datasourceName = "ds", roleName = "unrelated"),
    )

    private fun principal() = "attr-${UUID.randomUUID()}@example.com"

    // OIDC login is served by cp-go; this stores what its provisioning writes.
    private fun login(principal: String, vararg claims: Pair<String, Any?>): String {
        database.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO app_user (principal, email, attributes) VALUES (?, ?, ?::jsonb)
                   ON CONFLICT (principal) DO UPDATE SET attributes = EXCLUDED.attributes""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setString(2, principal)
                ps.setString(3, declared.fromClaims(claims.toMap()).toString())
                ps.executeUpdate()
            }
        }
        return principal
    }

    private fun policy(src: String) {
        core.cedarPolicyStore.create(CedarPolicyInput(name = "attr-${UUID.randomUUID()}", cedarSrc = src), updatedBy = null)
    }
}
