package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.TokenKind
import com.ridi.oss.proxymonster.controlplane.effectiveCatalog

import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.systemSchemas
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ConnectionDoor
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.ridi.oss.proxymonster.grpc.openConnectionRequest
import com.ridi.oss.proxymonster.controlplane.namespaces
import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.seed
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed coverage for the decide/validate gRPC handlers (docs/datasource-registration.md), against a real
 * control-plane Postgres + [ControlPlaneCore] + a running gRPC server (gate open — the interceptor is
 * covered separately by [GrpcServerTest]). The focus is what's NEW in the gRPC path: per-query token
 * re-validation (the revocation-gap fix), datasource-by-name resolution, deactivation rechecks, and the
 * authN-vs-authZ status split. Decision *correctness* (ALLOW/MASK/lineage) is exercised directly against
 * `decideAndAudit` by SchemaThreadingDbTest's live-search-path tests, so it is not re-proven here.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcDecideHandlerDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel
    private lateinit var ds: Datasource
    private lateinit var validToken: String

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_grpc_decide"))
        core = ControlPlaneCore(dataSource)
        ds = core.datasourceStore.seed(name = "grpc-ds", engine = "postgres")
        // A principal with no roles/grants — used for the "ungranted -> deny-by-default" path.
        validToken = core.tokenStore.issue(TokenKind.USER, "grpc-user", emptyList(), name = null, ttlSeconds = 3600).token
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private suspend fun open(token: String, datasource: Datasource = ds): ByteString {
        val resolved = core.tokenStore.resolve(token)!!
        val opened = core.connectionCatalog.open(
            com.ridi.oss.proxymonster.controlplane.Binding(datasource.name, resolved.principal, resolved.kind, datasource.effectiveCatalog, datasource.engine),
            datasource.namespaces(datasource.defaultSchemas + datasource.engine.systemSchemas),
        )
        val identity = com.ridi.oss.proxymonster.grpc.wireIdentity {
            connectionId = opened.connectionId
            onOpen.addAll(opened.onOpen.map { com.ridi.oss.proxymonster.grpc.proxyCommand { refetch = it } })
        }
        var backendGeneration = 1L
        identity.onOpenList.forEach { command ->
            val schema = command.refetch.schema
            stub.pushSchemaFragment(schemaFragmentPush {
                connectionId = identity.connectionId
                datasourceName = datasource.name
                catalog = datasource.effectiveCatalog
                this.schema = schema
                contentHash = ByteString.copyFromUtf8("empty:$schema")
                this.backendGeneration = backendGeneration++
            })
        }
        return identity.connectionId
    }

    private fun statusOf(block: suspend () -> Unit): Status.Code =
        assertFailsWith<StatusException> { runBlocking { block() } }.status.code

    @Test
    fun `openConnection returns the identity for a valid token`() = runBlocking {
        val id = stub.openConnection(openConnectionRequest { token = validToken; datasourceName = ds.name })
        assertEquals("grpc-user", id.principal)
    }

    @Test
    fun `openConnection rejects an unknown token UNAUTHENTICATED`() {
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.openConnection(openConnectionRequest { token = "nope"; datasourceName = ds.name }) })
    }

    @Test
    fun `an editor-door token opens only through the editor door, a login token only through the wire door`() = runBlocking {
        val run = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "grpc-user", listOf("analyst"), null, 600)
        fun open(token: String, door: ConnectionDoor) = openConnectionRequest { this.token = token; datasourceName = ds.name; this.door = door }
        val editor = core.tokenStore.issue(TokenKind.EDITOR, "grpc-user", emptyList(), null, 600)
        val session = core.tokenStore.issue(TokenKind.SESSION, "grpc-user", emptyList(), null, 600)
        for (wrongDoor in listOf(run.token to ConnectionDoor.CONNECTION_DOOR_WIRE, editor.token to ConnectionDoor.CONNECTION_DOOR_WIRE,
            validToken to ConnectionDoor.CONNECTION_DOOR_EDITOR, session.token to ConnectionDoor.CONNECTION_DOOR_EDITOR)) {
            assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.openConnection(open(wrongDoor.first, wrongDoor.second)) }, wrongDoor.second.name)
        }
        val opened = stub.openConnection(open(run.token, ConnectionDoor.CONNECTION_DOOR_EDITOR))
        assertEquals("grpc-user", opened.principal)
        assertEquals(16, opened.connectionId.size())
    }

    @Test
    fun `openConnection rejects a revoked token UNAUTHENTICATED`() {
        val t = core.tokenStore.issue(TokenKind.USER, "revoke-user", emptyList(), null, 3600)
        assertTrue(core.tokenStore.revoke(t.id, "revoke-user"))
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.openConnection(openConnectionRequest { token = t.token; datasourceName = ds.name }) })
    }

    @Test
    fun `openConnection rejects a deactivated principal UNAUTHENTICATED`() {
        val daemon = PrincipalSessionStore(dataSource, null)
        core.userGroupStore.createUser(AppUserInput(principal = "gone-user"), core.tokenStore, core.accessStore, daemon)
        val t = core.tokenStore.issue(TokenKind.USER, "gone-user", emptyList(), null, 3600)
        core.userGroupStore.setUserActive("gone-user", false)
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.openConnection(openConnectionRequest { token = t.token; datasourceName = ds.name }) })
    }

    @Test
    fun `a decision in a schema the connection did not open with first asks for that schema`() = runBlocking {
        val connectionId = open(validToken)
        val response = stub.decide(
            decisionRequest {
                token = validToken; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog
                this.connectionId = connectionId; sql = "select 1"; searchPath.add("pr_schema")
            },
        )
        assertTrue(response.hasBeforeDecide(), "a schema outside the open catalog must be fetched before deciding")
        assertTrue("pr_schema" in response.beforeDecide.commandsList.map { it.refetch.schema }, response.toString())
    }

    @Test
    fun `decide re-validates the token per query - a token revoked mid-session is rejected`() {
        val t = core.tokenStore.issue(TokenKind.USER, "session-user", emptyList(), null, 3600)
        // Works while valid (handshake succeeds and mints the connection state).
        val connectionId = runBlocking {
            val id = stub.openConnection(openConnectionRequest { token = t.token; datasourceName = ds.name })
            id.connectionId
        }
        // Revoke mid-session; the NEXT decide must re-validate and reject — this is the revocation-gap fix.
        assertTrue(core.tokenStore.revoke(t.id, "session-user"))
        assertEquals(
            Status.Code.UNAUTHENTICATED,
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); this.connectionId = connectionId; sql = "select 1" }) },
        )
    }

    @Test
    fun `decide rejects a deactivated principal UNAUTHENTICATED (session teardown, not a policy deny)`() {
        val daemon = PrincipalSessionStore(dataSource, null)
        core.userGroupStore.createUser(AppUserInput(principal = "decide-gone"), core.tokenStore, core.accessStore, daemon)
        val t = core.tokenStore.issue(TokenKind.USER, "decide-gone", emptyList(), null, 3600)
        core.userGroupStore.setUserActive("decide-gone", false)
        // Must be UNAUTHENTICATED (authN teardown), NOT the DENY that decideQuery's internal
        // deactivation gate would otherwise produce — that split is the point of the explicit check.
        assertEquals(
            Status.Code.UNAUTHENTICATED,
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(t.token); sql = "select 1" }) },
        )
    }

    @Test
    fun `decide rejects an unknown datasource NOT_FOUND`() {
        assertEquals(
            Status.Code.NOT_FOUND,
            statusOf { stub.decide(decisionRequest { token = validToken; datasourceName = "does-not-exist"; connectionId = open(validToken); sql = "select 1" }) },
        )
    }

    @Test
    fun `decide denies an ungranted principal by default and audits the decision`() = runBlocking {
        val d = stub.decide(decisionRequest { token = validToken; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(validToken); sql = "select 1 from foo" })
        assertTrue(d.hasVerdict())
        assertEquals(EnfAction.DENY, d.verdict.decision)
        assertTrue(d.verdict.decisionId > 0, "a wire decision must be audited (decisionId > 0)")
        assertTrue("no access to datasource" in d.verdict.denyReason, "unexpected deny reason: ${d.verdict.denyReason}")
    }

    @Test
    fun `decide rejects an expired token UNAUTHENTICATED`() {
        val t = core.tokenStore.issue(TokenKind.USER, "expired-user", emptyList(), null, 3600)
        val connectionId = runBlocking { open(t.token) }
        // Min TTL is 60s, so force-expire the row directly rather than waiting it out.
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE proxy_token SET expires_at = now() - interval '1 hour' WHERE id = ?").use { ps ->
                ps.setLong(1, t.id)
                ps.executeUpdate()
            }
        }
        assertEquals(
            Status.Code.UNAUTHENTICATED,
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); this.connectionId = connectionId; sql = "select 1" }) },
        )
    }

    /**
     * The central invariant that justifies ControlPlaneCore: an HTTP-side policy edit MUST be seen by
     * the gRPC decision path. Because CedarEngine's cache invalidates only on the shared
     * CedarPolicyStore's in-memory stateVersion, a second/divergent graph would leave this green while
     * the gRPC engine served a stale PolicySet. So: warm the gRPC engine, edit policy through the same
     * core the HTTP admin routes use, and assert the next gRPC decision reflects it.
     */
    @Test
    fun `an HTTP-side policy edit is seen by the gRPC decision path`() = runBlocking {
        val tok = core.tokenStore.issue(TokenKind.USER, "cache-user", emptyList(), null, 3600).token
        // Warm the gRPC engine: ungranted -> deny at the datasource.connect gate.
        val before = stub.decide(decisionRequest { token = tok; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(tok); sql = "select 1 from t" })
        assertEquals(EnfAction.DENY, before.verdict.decision)
        assertTrue("no access to datasource" in before.verdict.denyReason, "before: ${before.verdict.denyReason}")

        // Grant datasource.connect through the SAME shared core the HTTP admin routes mutate. Adding a
        // policy bumps CedarPolicyStore.stateVersion, which must invalidate the gRPC engine's cache.
        val role = core.policyStore.createRole(RoleInput("cache-role"))
        core.policyStore.createAssignment(RoleAssignmentInput("cache-user", role.id))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "cache-connect",
                cedarSrc = """permit(principal in Role::"cache-role", action == Action::"datasource.connect", resource == Datasource::"${ds.name}");""",
            ),
            updatedBy = null,
        )

        // The next gRPC decision must reflect the edit: connect now passes, so the deny moves off the
        // connect gate to the statement-kind gate. A stale/separate cache would still report "no access to
        // datasource".
        val after = stub.decide(decisionRequest { token = tok; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(tok); sql = "select 1 from t" })
        assertEquals(EnfAction.DENY, after.verdict.decision)
        assertTrue("statement kind 'select' is not permitted" in after.verdict.denyReason, "after (expected kind-gate deny): ${after.verdict.denyReason}")
        assertTrue("no access to datasource" !in after.verdict.denyReason, "connect gate should now pass: ${after.verdict.denyReason}")
    }

    // ---- Token-kind → channel / assume-role / grant-eligibility derivation ----

    @Test
    fun `a native-wire token cannot assert roles from the token, but an approver-exec token's assume-role is honored`() = runBlocking {
        // Grant Role "elevated" datasource.connect + stmt.cat.read (so the `select 1` clears both gates). A
        // native-wire (USER) token that CARRIES "elevated" on the token must NOT get it (roles are
        // server-resolved — the principal has no such assignment); an APPROVER_EXEC token's on-token roles ARE
        // the assume-role set (execute-under-R). This pins the core "native token cannot assert privilege /
        // only ephemeral kinds carry assume-roles" invariant.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "elevated-connect",
                cedarSrc = """permit(principal in Role::"elevated", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource == Datasource::"${ds.name}");""",
            ),
            updatedBy = null,
        )
        val userTok = core.tokenStore.issue(TokenKind.USER, "native-asserter", listOf("elevated"), null, 3600).token
        val userDecision = stub.decide(decisionRequest { token = userTok; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(userTok); sql = "select 1" })
        assertEquals(EnfAction.DENY, userDecision.verdict.decision, "a native-wire token's on-token roles must be IGNORED (server-resolved)")
        assertTrue("no access to datasource" in userDecision.verdict.denyReason, "native: ${userDecision.verdict.denyReason}")

        val execTok = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "exec-asserter", listOf("elevated"), null, 3600).token
        val execDecision = stub.decide(decisionRequest { token = execTok; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(execTok); sql = "select 1" })
        assertEquals(EnfAction.ALLOW, execDecision.verdict.decision, "an approver-exec token's assume-role must decide AS that role: ${execDecision.verdict.denyReason}")
    }

    @Test
    fun `a no-R approver-exec decides at the editor channel, only a with-R token reaches workflow-executor`() = runBlocking {
        // Grant datasource.connect + stmt.cat.read (so `select 1` clears both gates) ONLY on the
        // workflow-executor channel. A with-R approver-exec (assume-role present) decides there and connects;
        // a no-R approver-exec (no assume-role) decides at the EDITOR channel, so the workflow-executor-gated
        // grant never fires → deny. Pins the no-R escalation fix.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "wfexec-only-connect",
                cedarSrc = """permit(principal, action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource == Datasource::"${ds.name}") when { context has channel && context.channel == "workflow-executor" };""",
            ),
            updatedBy = null,
        )
        val withR = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "with-r", listOf("some-role"), null, 3600).token
        val withRDecision = stub.decide(decisionRequest { token = withR; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(withR); sql = "select 1" })
        assertEquals(EnfAction.ALLOW, withRDecision.verdict.decision, "with-R approver-exec runs at workflow-executor → connect: ${withRDecision.verdict.denyReason}")

        val noR = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "no-r", emptyList(), null, 3600).token
        val noRDecision = stub.decide(decisionRequest { token = noR; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(noR); sql = "select 1" })
        assertEquals(EnfAction.DENY, noRDecision.verdict.decision, "no-R approver-exec must decide at EDITOR, not workflow-executor")
        assertTrue("no access to datasource" in noRDecision.verdict.denyReason, "no-R: ${noRDecision.verdict.denyReason}")
    }

    @Test
    fun `an editor or approver-exec token cannot open a wire session — validate rejects both ephemeral kinds`() {
        val editor = core.tokenStore.issue(TokenKind.EDITOR, "eph-editor", emptyList(), null, 3600).token
        val approverExec = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "eph-exec", emptyList(), null, 3600).token
        val user = core.tokenStore.issue(TokenKind.USER, "wire-user", emptyList(), null, 3600).token
        assertNull(core.tokenStore.validate(editor), "an EDITOR token must not pass the wire-session handshake")
        assertNull(core.tokenStore.validate(approverExec), "an APPROVER_EXEC token must not pass the wire-session handshake")
        assertNotNull(core.tokenStore.validate(user), "a USER token opens a wire session")
    }

    // ---- A decision's requester_ip is the client_addr goproxy reports, for every channel ----

    @Test
    fun `an EDITOR decision's client_addr reaches Cedar and satisfies an ip-gated permit`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-editor-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.EDITOR, "ipgate-editor-user", emptyList(), null, 3600)

        val decision = stub.decide(decisionRequest { token = issued.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(issued.token); sql = "select 1 from t"; clientAddr = "203.0.113.10" })
        assertEquals(
            EnfAction.DENY, decision.verdict.decision,
            "connect now passes via the ip-gated permit; the deny should have moved off connect to the kind gate: ${decision.verdict.denyReason}",
        )
        assertTrue("statement kind 'select' is not permitted" in decision.verdict.denyReason, "expected the connect gate to pass: ${decision.verdict.denyReason}")
    }

    @Test
    fun `an APPROVER_EXEC decision's client_addr also reaches Cedar`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-approver-exec-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "ipgate-approver-exec-user", emptyList(), null, 3600)

        val decision = stub.decide(decisionRequest { token = issued.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(issued.token); sql = "select 1 from t"; clientAddr = "203.0.113.20" })
        assertTrue("statement kind 'select' is not permitted" in decision.verdict.denyReason, "expected the connect gate to pass: ${decision.verdict.denyReason}")
    }

    @Test
    fun `an EDITOR decision with no client_addr decides with requester_ip absent`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-editor-no-addr-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.EDITOR, "ipgate-editor-no-addr", emptyList(), null, 3600)
        val decision = stub.decide(
            decisionRequest { token = issued.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(issued.token); sql = "select 1 from t" },
        )
        assertEquals(EnfAction.DENY, decision.verdict.decision)
        assertTrue("no access to datasource" in decision.verdict.denyReason, decision.verdict.denyReason)
    }

    @Test
    fun `a native-wire token DOES resolve requester_ip from client_addr (the WIRE-channel source)`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-wire-clientaddr-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.USER, "ipgate-wire-clientaddr", emptyList(), null, 3600)
        val decision = stub.decide(
            decisionRequest {
                token = issued.token; datasourceName = ds.name; currentCatalog = ds.effectiveCatalog; searchPath.add("public"); connectionId = open(issued.token)
                sql = "select 1 from t"; clientAddr = "/203.0.113.40:5432"
            },
        )
        assertTrue(
            "statement kind 'select' is not permitted" in decision.verdict.denyReason,
            "a WIRE token's client_addr must satisfy the ip-gated connect permit: ${decision.verdict.denyReason}",
        )
    }

    @Test
    fun `decide stamps the shipped default cap and denies a spent shipped rate`() = runBlocking {
        val datasource = core.datasourceStore.seed(name = "caps-grpc-ds", engine = "postgres")
        val principal = "caps-grpc-user"
        val tok = core.tokenStore.issue(TokenKind.USER, principal, emptyList(), null, 3600).token
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                "caps-grpc-read",
                """permit(principal == User::"$principal",
                          action in [Action::"datasource.connect", Action::"stmt.cat.read"],
                          resource == Datasource::"${datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val conn = open(tok, datasource)
        val verdict = stub.decide(
            decisionRequest { token = tok; datasourceName = datasource.name; currentCatalog = datasource.effectiveCatalog; searchPath.add("public"); connectionId = conn; sql = "select 42" },
        ).verdict
        assertEquals(EnfAction.ALLOW, verdict.decision, verdict.denyReason)
        assertEquals(5_000L, verdict.maxRows)
        assertEquals(50_000_000L, verdict.maxBytes)
        // The -305 rate: 100MB relayed this hour denies the next read over the wire, naming the rate.
        core.auditStore.insert(
            AuditEvent(
                principal = principal, datasource = datasource.name, statement = "select 1",
                decision = Decision.ALLOW, kind = "completion", rowsReturned = 9, bytesReturned = 100_000_000,
            ),
        )
        val spent = stub.decide(
            decisionRequest { token = tok; datasourceName = datasource.name; currentCatalog = datasource.effectiveCatalog; searchPath.add("public"); connectionId = conn; sql = "select 42" },
        ).verdict
        assertEquals(EnfAction.DENY, spent.decision)
        assertEquals("rate 100MB/1h spent", spent.denyReason)
    }
}
