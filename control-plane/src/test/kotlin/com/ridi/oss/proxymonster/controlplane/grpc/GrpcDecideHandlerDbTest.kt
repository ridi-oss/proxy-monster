package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.TokenKind

import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.systemSchemas
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.tokenHash
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import com.google.protobuf.ByteString
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
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
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_grpc_decide"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        ds = core.datasourceStore.create(
            DatasourceInput(name = "grpc-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
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
            com.ridi.oss.proxymonster.controlplane.Binding(datasource.name, resolved.principal, resolved.kind),
            datasource.defaultSchemas + datasource.engine.systemSchemas,
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
    fun `validateToken returns the identity for a valid token`() = runBlocking {
        val id = stub.validateToken(validateTokenRequest { token = validToken; datasourceName = ds.name })
        assertEquals("grpc-user", id.principal)
    }

    @Test
    fun `validateToken rejects an unknown token UNAUTHENTICATED`() {
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.validateToken(validateTokenRequest { token = "nope"; datasourceName = ds.name }) })
    }

    @Test
    fun `validateToken rejects a revoked token UNAUTHENTICATED`() {
        val t = core.tokenStore.issue(TokenKind.USER, "revoke-user", emptyList(), null, 3600)
        assertTrue(core.tokenStore.revoke(t.id, "revoke-user"))
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.validateToken(validateTokenRequest { token = t.token; datasourceName = ds.name }) })
    }

    @Test
    fun `validateToken rejects a deactivated principal UNAUTHENTICATED`() {
        val daemon = PrincipalSessionStore(dataSource, null)
        core.userGroupStore.createUser(AppUserInput(principal = "gone-user"), core.tokenStore, core.accessStore, daemon)
        val t = core.tokenStore.issue(TokenKind.USER, "gone-user", emptyList(), null, 3600)
        core.userGroupStore.setUserActive("gone-user", false)
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf { stub.validateToken(validateTokenRequest { token = t.token; datasourceName = ds.name }) })
    }

    @Test
    fun `decide re-validates the token per query - a token revoked mid-session is rejected`() {
        val t = core.tokenStore.issue(TokenKind.USER, "session-user", emptyList(), null, 3600)
        // Works while valid (handshake succeeds and mints the connection state).
        val connectionId = runBlocking {
            val id = stub.validateToken(validateTokenRequest { token = t.token; datasourceName = ds.name })
            id.connectionId
        }
        // Revoke mid-session; the NEXT decide must re-validate and reject — this is the revocation-gap fix.
        assertTrue(core.tokenStore.revoke(t.id, "session-user"))
        assertEquals(
            Status.Code.UNAUTHENTICATED,
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; this.connectionId = connectionId; sql = "select 1" }) },
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
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; connectionId = open(t.token); sql = "select 1" }) },
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
        val d = stub.decide(decisionRequest { token = validToken; datasourceName = ds.name; connectionId = open(validToken); sql = "select 1 from foo" })
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
            statusOf { stub.decide(decisionRequest { token = t.token; datasourceName = ds.name; this.connectionId = connectionId; sql = "select 1" }) },
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
        val before = stub.decide(decisionRequest { token = tok; datasourceName = ds.name; connectionId = open(tok); sql = "select 1 from t" })
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
        val after = stub.decide(decisionRequest { token = tok; datasourceName = ds.name; connectionId = open(tok); sql = "select 1 from t" })
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
        val userDecision = stub.decide(decisionRequest { token = userTok; datasourceName = ds.name; connectionId = open(userTok); sql = "select 1" })
        assertEquals(EnfAction.DENY, userDecision.verdict.decision, "a native-wire token's on-token roles must be IGNORED (server-resolved)")
        assertTrue("no access to datasource" in userDecision.verdict.denyReason, "native: ${userDecision.verdict.denyReason}")

        val execTok = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "exec-asserter", listOf("elevated"), null, 3600).token
        val execDecision = stub.decide(decisionRequest { token = execTok; datasourceName = ds.name; connectionId = open(execTok); sql = "select 1" })
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
        val withRDecision = stub.decide(decisionRequest { token = withR; datasourceName = ds.name; connectionId = open(withR); sql = "select 1" })
        assertEquals(EnfAction.ALLOW, withRDecision.verdict.decision, "with-R approver-exec runs at workflow-executor → connect: ${withRDecision.verdict.denyReason}")

        val noR = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "no-r", emptyList(), null, 3600).token
        val noRDecision = stub.decide(decisionRequest { token = noR; datasourceName = ds.name; connectionId = open(noR); sql = "select 1" })
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

    // ---- The ControlPlaneCore.runRequesterIps carrier reaches the Cedar context ----

    @Test
    fun `an EDITOR token's registered requester_ip reaches Cedar and satisfies an ip-gated permit`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-editor-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.EDITOR, "ipgate-editor-user", emptyList(), null, 3600)
        core.runRequesterIps.put(tokenHash(issued.token), "203.0.113.10")

        val decision = stub.decide(decisionRequest { token = issued.token; datasourceName = ds.name; connectionId = open(issued.token); sql = "select 1 from t" })
        assertEquals(
            EnfAction.DENY, decision.verdict.decision,
            "connect now passes via the ip-gated permit; the deny should have moved off connect to the kind gate: ${decision.verdict.denyReason}",
        )
        assertTrue("statement kind 'select' is not permitted" in decision.verdict.denyReason, "expected the connect gate to pass: ${decision.verdict.denyReason}")
    }

    @Test
    fun `an APPROVER_EXEC token's registered requester_ip also reaches Cedar (run-minted, not just openSession-minted)`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-approver-exec-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        // APPROVER_EXEC tokens are ONLY minted by RunExecService.run() — openSession() mints EDITOR only —
        // so covering the registry write here is what makes this token kind's requester_ip real.
        val issued = core.tokenStore.issue(TokenKind.APPROVER_EXEC, "ipgate-approver-exec-user", emptyList(), null, 3600)
        core.runRequesterIps.put(tokenHash(issued.token), "203.0.113.20")

        val decision = stub.decide(decisionRequest { token = issued.token; datasourceName = ds.name; connectionId = open(issued.token); sql = "select 1 from t" })
        assertTrue("statement kind 'select' is not permitted" in decision.verdict.denyReason, "expected the connect gate to pass: ${decision.verdict.denyReason}")
    }

    @Test
    fun `a registry entry is ignored for a native-wire (USER) token — gated strictly on kind, never merely 'an entry exists'`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-kind-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        val issued = core.tokenStore.issue(TokenKind.USER, "ipgate-wire-user", emptyList(), null, 3600)
        // Plant an entry under this USER token's hash directly — a WIRE token must never pick it up even if
        // (by whatever means) the registry happened to carry a matching entry.
        core.runRequesterIps.put(tokenHash(issued.token), "203.0.113.30")

        val decision = stub.decide(decisionRequest { token = issued.token; datasourceName = ds.name; connectionId = open(issued.token); sql = "select 1 from t" })
        assertEquals(EnfAction.DENY, decision.verdict.decision)
        assertTrue(
            "no access to datasource" in decision.verdict.denyReason,
            "a WIRE token must never read the editor/approver-exec requester_ip registry: ${decision.verdict.denyReason}",
        )
    }

    @Test
    fun `an EDITOR token with no registry entry does NOT fall back to the proxy client_addr — requester_ip stays absent`() = runBlocking {
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ipgate-editor-no-entry-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${ds.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        // EDITOR token, but NOTHING put into runRequesterIps. The proxy sends a client_addr that IS in range;
        // on the native-wire channel that would satisfy the ip-gated permit, but an editor decision must NOT
        // borrow the proxy-supplied client_addr — requester_ip stays ABSENT (fail-closed), so the permit never
        // fires and connect is denied. This is the channel-selected-source contract (not a nullable fallback).
        val issued = core.tokenStore.issue(TokenKind.EDITOR, "ipgate-editor-no-entry", emptyList(), null, 3600)
        val decision = stub.decide(
            decisionRequest {
                token = issued.token; datasourceName = ds.name; connectionId = open(issued.token)
                sql = "select 1 from t"; clientAddr = "/203.0.113.10:1234"
            },
        )
        assertEquals(EnfAction.DENY, decision.verdict.decision)
        assertTrue(
            "no access to datasource" in decision.verdict.denyReason,
            "an EDITOR decision must not fall back to client_addr — requester_ip must be absent: ${decision.verdict.denyReason}",
        )
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
        // The complement of the EDITOR-no-entry case: on the WIRE channel the proxy observed the DB client's
        // socket peer directly, so client_addr IS the attested requester_ip — the ip-gated permit fires and the
        // deny moves off the connect gate. Together the two tests prove the source is CHANNEL-selected, not a
        // "editor ignores client_addr, wire always trusts it" nullable fallback.
        val issued = core.tokenStore.issue(TokenKind.USER, "ipgate-wire-clientaddr", emptyList(), null, 3600)
        val decision = stub.decide(
            decisionRequest {
                token = issued.token; datasourceName = ds.name; connectionId = open(issued.token)
                sql = "select 1 from t"; clientAddr = "/203.0.113.40:5432"
            },
        )
        assertTrue(
            "statement kind 'select' is not permitted" in decision.verdict.denyReason,
            "a WIRE token's client_addr must satisfy the ip-gated connect permit: ${decision.verdict.denyReason}",
        )
    }
}
