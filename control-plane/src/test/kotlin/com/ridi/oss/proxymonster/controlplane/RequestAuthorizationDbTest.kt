package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.google.protobuf.UnknownFieldSet
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.namespaceRef
import com.ridi.oss.proxymonster.grpc.readCatalog
import com.ridi.oss.proxymonster.grpc.readTableMetadata
import com.ridi.oss.proxymonster.grpc.tableRef
import io.grpc.ManagedChannel
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestAuthorizationDbTest {
    private lateinit var database: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var channel: ManagedChannel
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_request_authorization"))
        Flyway.configure().dataSource(database).load().migrate()
        core = ControlPlaneCore(database)
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        channel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
    }

    @AfterAll
    fun cleanup() {
        if (::channel.isInitialized) channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        if (::server.isInitialized) server.shutdown()
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

    @Test
    fun `AuthorizeRequest enforces live roles and wire IP without allocating a connection`() {
        val principal = principal()
        val role = role()
        core.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        val datasource = core.datasourceStore.create(DatasourceInput("request-${UUID.randomUUID()}", engine = "mysql", dbName = "app"))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "request-${UUID.randomUUID()}",
                cedarSrc = """permit(principal in Role::"${role.name}", action == Action::"datasource.connect", resource == Datasource::"${datasource.name}")
                    when { context has channel && context.channel == "wire" && context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
            ),
            updatedBy = null,
        )
        val token = issue(TokenKind.USER, principal, listOf("system:admin")).token
        val request = RequestAuthorization.newBuilder()
            .setToken(token)
            .setDatasourceName(datasource.name)
            .setClientAddr("10.2.3.4:49152")
            .setReadCatalog(readCatalog { namespace = namespaceRef { catalog = "def"; schema = "app" } })
            .build()
        runBlocking {
            val allowed = stub.authorizeRequest(request)
            assertTrue(allowed.allowed)
            assertEquals(principal, allowed.principal)
            assertEquals(setOf(role.name), allowed.effectiveRolesList.toSet())
            val tableRequest = request.toBuilder().setReadTableMetadata(
                readTableMetadata { table = tableRef { catalog = "def"; schema = "app"; table = "users" } },
            ).build()
            assertTrue(stub.authorizeRequest(tableRequest).allowed)
            val denied = stub.authorizeRequest(request.toBuilder().setClientAddr("198.51.100.7:49152").build())
            assertFalse(denied.allowed)
            assertEquals("", denied.principal)
            val unknown = request.toBuilder().clearOperation().setUnknownFields(
                UnknownFieldSet.newBuilder().addField(99, UnknownFieldSet.Field.newBuilder().addLengthDelimited(ByteString.EMPTY).build()).build(),
            ).build()
            assertFalse(stub.authorizeRequest(unknown).allowed)
            core.policyStore.deleteRole(role.id)
            assertFalse(stub.authorizeRequest(request).allowed)
        }
        assertEquals(0, core.connectionCatalog.connectionCount())
        assertEquals(0, core.connectionCatalog.poolSize())
    }

    private fun assertUnauthenticated(token: String) {
        val failure = assertFailsWith<StatusException> { core.resolveRequestIdentity(token, null) }
        assertEquals(Status.Code.UNAUTHENTICATED, failure.status.code)
        val rpcFailure = assertFailsWith<StatusException> {
            runBlocking { stub.authorizeRequest(RequestAuthorization.newBuilder().setToken(token).build()) }
        }
        assertEquals(Status.Code.UNAUTHENTICATED, rpcFailure.status.code)
    }

    private fun principal() = "request-${UUID.randomUUID()}@example.com"

    private fun role() = core.policyStore.createRole(RoleInput("request-${UUID.randomUUID()}"))

    private fun issue(kind: TokenKind, principal: String, roles: List<String> = emptyList()) =
        core.tokenStore.issue(kind, principal, roles, null, 3600)
}
