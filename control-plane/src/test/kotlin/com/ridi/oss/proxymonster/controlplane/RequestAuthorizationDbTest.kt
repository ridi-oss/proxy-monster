package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.grpc.Status
import io.grpc.StatusException
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestAuthorizationDbTest {
    private lateinit var database: DataSource
    private lateinit var core: ControlPlaneCore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_request_authorization"))
        Flyway.configure().dataSource(database).load().migrate()
        core = ControlPlaneCore(database)
    }

    @AfterAll
    fun cleanup() {
        if (::database.isInitialized) (database as? AutoCloseable)?.close()
    }

    @Test
    fun `missing invalid expired and revoked tokens are unauthenticated`() {
        val principal = principal()
        val expired = issue(TokenKind.USER, principal)
        database.connection.use { connection ->
            connection.prepareStatement("UPDATE proxy_token SET expires_at = now() - interval '1 second' WHERE id = ?").use {
                it.setLong(1, expired.id)
                it.executeUpdate()
            }
        }
        val revoked = issue(TokenKind.SESSION, principal)
        core.tokenStore.revoke(revoked.id, principal)
        for (token in listOf("", "invalid", expired.token, revoked.token)) {
            assertUnauthenticated(token)
        }
    }

    @Test
    fun `deprovisioning rejects a surviving token`() {
        val principal = principal()
        core.userGroupStore.createUser(
            AppUserInput(principal = principal), core.tokenStore, core.accessStore, PrincipalSessionStore(database, null),
        )
        val token = issue(TokenKind.USER, principal).token
        core.userGroupStore.setUserActive(principal, false)
        assertUnauthenticated(token)
        assertNull(resolveActiveToken(core.tokenStore, core.userGroupStore, token))
    }

    @Test
    fun `native credentials use live roles rather than token roles`() {
        val principal = principal()
        val liveRole = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, liveRole.id))
        for (kind in listOf(TokenKind.USER, TokenKind.SESSION)) {
            val token = issue(kind, principal, listOf("system:admin")).token
            core.runRequesterIps.put(tokenHash(token), "10.0.0.1")
            val resolved = core.resolveRequestIdentity(token, "198.51.100.7:45100")
            assertEquals(setOf(liveRole.name), resolved.effectiveRoles)
            assertNull(resolved.providedRoles)
            assertEquals(Channel.WIRE, resolved.channel)
            assertEquals("wire", resolved.context.channel)
            assertEquals("198.51.100.7", resolved.context.requesterIp)
            assertNull(resolved.httpRequesterIp)
        }
    }

    @Test
    fun `ordinary roles are refreshed after deletion`() {
        val principal = principal()
        val role = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        val token = issue(TokenKind.USER, principal).token
        assertEquals(setOf(role.name), core.resolveRequestIdentity(token, null).effectiveRoles)
        core.policyStore.deleteRole(role.id)
        assertEquals(emptySet(), core.resolveRequestIdentity(token, null).effectiveRoles)
    }

    @Test
    fun `task credentials use exactly provided live roles and never ordinary roles`() {
        val principal = principal()
        val own = role()
        val assumed = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, own.id))
        for (kind in listOf(TokenKind.EDITOR, TokenKind.APPROVER_EXEC)) {
            val token = issue(kind, principal, listOf(assumed.name, "missing-role")).token
            core.runRequesterIps.put(tokenHash(token), "203.0.113.8")
            val resolved = core.resolveRequestIdentity(token, "10.0.0.1:49152")
            assertEquals(setOf(assumed.name), resolved.effectiveRoles)
            assertEquals(setOf(assumed.name, "missing-role"), resolved.providedRoles)
            assertEquals(if (kind == TokenKind.EDITOR) Channel.EDITOR else Channel.WORKFLOW_EXECUTOR, resolved.channel)
            assertEquals(resolved.channel.contextValue, resolved.context.channel)
            assertEquals("203.0.113.8", resolved.context.requesterIp)
        }
    }

    @Test
    fun `deleting all task roles does not fall back to ordinary roles`() {
        val principal = principal()
        val own = role()
        val assumed = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, own.id))
        val token = issue(TokenKind.APPROVER_EXEC, principal, listOf(assumed.name)).token
        core.policyStore.deleteRole(assumed.id)
        val resolved = core.resolveRequestIdentity(token, null)
        assertEquals(emptySet(), resolved.effectiveRoles)
        assertEquals(Channel.WORKFLOW_EXECUTOR, resolved.channel)
    }

    @Test
    fun `task tokens without provided roles retain ordinary editor enforcement`() {
        val principal = principal()
        val own = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, own.id))
        for (kind in listOf(TokenKind.EDITOR, TokenKind.APPROVER_EXEC)) {
            val token = issue(kind, principal).token
            val resolved = core.resolveRequestIdentity(token, "10.0.0.1:49152")
            assertEquals(setOf(own.name), resolved.effectiveRoles)
            assertEquals(Channel.EDITOR, resolved.channel)
            assertNull(resolved.providedRoles)
            assertNull(resolved.context.requesterIp)
        }
    }

    @Test
    fun `task requester IP clearing never falls back to the proxy socket`() {
        val token = issue(TokenKind.EDITOR, principal()).token
        core.runRequesterIps.put(tokenHash(token), "203.0.113.8")
        assertEquals("203.0.113.8", core.resolveRequestIdentity(token, "10.0.0.1:49152").context.requesterIp)
        core.runRequesterIps.set(tokenHash(token), null)
        assertNull(core.resolveRequestIdentity(token, "10.0.0.1:49152").context.requesterIp)
    }

    @Test
    fun `request identity resolution allocates no connection catalog state`() {
        assertEquals(0, core.connectionCatalog.connectionCount())
        assertEquals(0, core.connectionCatalog.poolSize())
        val token = issue(TokenKind.USER, principal()).token
        repeat(3) { core.resolveRequestIdentity(token, "198.51.100.7:45100") }
        assertEquals(0, core.connectionCatalog.connectionCount())
        assertEquals(0, core.connectionCatalog.poolSize())
    }

    private fun assertUnauthenticated(token: String) {
        val failure = assertFailsWith<StatusException> { core.resolveRequestIdentity(token, null) }
        assertEquals(Status.Code.UNAUTHENTICATED, failure.status.code)
    }

    private fun principal() = "request-${UUID.randomUUID()}@example.com"

    private fun role() = core.policyStore.createRole(RoleInput("request-${UUID.randomUUID()}"))

    private fun issue(kind: TokenKind, principal: String, roles: List<String> = emptyList()) =
        core.tokenStore.issue(kind, principal, roles, null, 3600)
}
