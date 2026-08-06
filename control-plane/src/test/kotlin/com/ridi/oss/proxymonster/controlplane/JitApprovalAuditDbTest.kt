package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.SQLException
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The JIT-elevation and approval-DECISION events (ROLE request create/approve/reject/grant-revoke and QUERY
 * request create/approve/reject) each write one `kind="admin"` management event on the SAME transaction as
 * the mutation. Mirrors [ManagementAuditDbTest]: exact descriptor per event, atomic rollback, no-op silence,
 * and a re-verified hash chain.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JitApprovalAuditDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var recorder: ManagementAuditRecorder
    private lateinit var role: Role
    private lateinit var datasource: Datasource

    private val requester = "jit-audit-requester@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_jit_approval_audit"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        recorder = ManagementAuditRecorder(core.auditStore)
        role = core.policyStore.createRole(RoleInput("jit-audit-role"))
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "jit-audit-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
    }

    private fun actor() = AuditActor("jit-audit-${System.nanoTime()}@example.com", clientAddr = "192.0.2.1", channel = AuditSource.CONSOLE)

    private fun seedRoleRequest() = core.accessStore.createRequest(
        requester, AccessRequestInput(roleId = role.id, datasourceId = datasource.id, reason = "need it"),
    )

    private fun seedQueryRequest() = core.accessStore.createQueryRequest(
        principal = requester, datasourceId = datasource.id, sql = "select 1", denyReason = "denied",
        sourceDecisionId = null, reason = "need it", title = null, evaluatedDecision = "DENY", roleId = role.id,
    )

    private fun grantIdFor(requestId: Long): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM access_grant WHERE request_id = ? ORDER BY id DESC LIMIT 1").use { ps ->
            ps.setLong(1, requestId)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    @Test
    fun `ROLE create, approve, reject, and grant revoke each record one admin event`() {
        val actor = actor()

        val request = core.accessStore.createRequest(
            requester, AccessRequestInput(roleId = role.id, datasourceId = datasource.id, reason = "need it"), actor, recorder,
        )
        assertEvent(actor.principal, AuthzAction.TASK_REQUEST, "AccessRequest::\"${request.id}\"", "open access request #${request.id} for role '${role.name}'")

        val approved = core.accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        assertEquals("APPROVED", approved?.status)
        val grantId = grantIdFor(request.id)
        // The grant exists (written on the same transaction as its audit row).
        assertEquals(1, count("SELECT count(*) FROM access_grant WHERE request_id = ?", request.id))
        assertEvent(
            actor.principal, AuthzAction.TASK_APPROVE, "AccessGrant::\"$grantId\"",
            "approve access request #${request.id}: grant role '${role.name}' to '$requester' for 3600s",
        )

        val toReject = seedRoleRequest()
        core.accessStore.reject(toReject.id, reason = "no", decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        assertEvent(actor.principal, AuthzAction.TASK_APPROVE, "AccessRequest::\"${toReject.id}\"", "reject access request #${toReject.id} from '$requester'")

        assertEquals(true, core.accessStore.revoke(grantId, actor, recorder))
        assertEvent(
            actor.principal, AuthzAction.GRANT_REVOKE, "AccessGrant::\"$grantId\"",
            "revoke access grant #$grantId (role '${role.name}' from '$requester')",
        )
        verifyAuditChain(dataSource)
    }

    @Test
    fun `QUERY create, approve, and reject each record one admin event`() {
        val actor = actor()

        val request = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = datasource.id, sql = "select 1", denyReason = "denied",
            sourceDecisionId = null, reason = "need it", title = null, evaluatedDecision = "DENY", roleId = role.id,
            actor = actor, recorder = recorder,
        )
        assertEvent(actor.principal, AuthzAction.TASK_REQUEST, "AccessRequest::\"${request.id}\"", "open query request #${request.id} under role '${role.name}'")

        val approved = core.accessStore.decideQueryRequest(request.id, approved = true, rejectionReason = null, decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        assertEquals("APPROVED", approved?.status)
        assertEvent(actor.principal, AuthzAction.TASK_APPROVE, "AccessRequest::\"${request.id}\"", "approve query request #${request.id} under role '${role.name}'")

        val toReject = seedQueryRequest()
        core.accessStore.decideQueryRequest(toReject.id, approved = false, rejectionReason = "no", decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        assertEvent(actor.principal, AuthzAction.TASK_APPROVE, "AccessRequest::\"${toReject.id}\"", "reject query request #${toReject.id}")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `a rejected audit insert rolls back the approval it describes`() {
        val actor = actor()
        val request = seedRoleRequest()
        val headBefore = auditChainHead(dataSource)
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_reject_approval_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced approval audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_reject_approval_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.kind = 'admin' AND NEW.statement LIKE 'approve access request #${request.id}:%')
               EXECUTE FUNCTION pm_test_reject_approval_audit()""",
        )
        try {
            assertFailsWith<SQLException> {
                core.accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com", actor = actor, recorder = recorder)
            }
            // The mutation the failed audit described rolled back: no approval, no grant, no audit row.
            assertEquals("PENDING", core.accessStore.getRequest(request.id)?.status)
            assertEquals(0, count("SELECT count(*) FROM access_grant WHERE request_id = ?", request.id))
            assertEquals(0, count("SELECT count(*) FROM audit_event WHERE principal = ?", actor.principal))
            val headAfter = auditChainHead(dataSource)
            assertEquals(headBefore.first, headAfter.first)
            assertContentEquals(headBefore.second, headAfter.second)
        } finally {
            execute("DROP TRIGGER IF EXISTS pm_test_reject_approval_audit ON audit_event")
            execute("DROP FUNCTION IF EXISTS pm_test_reject_approval_audit()")
        }
        verifyAuditChain(dataSource)
    }

    @Test
    fun `re-approving and re-revoking record nothing the second time`() {
        val actor = actor()
        val request = seedRoleRequest()

        core.accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        val grantId = grantIdFor(request.id)
        // A second approve finds no PENDING row: no new grant, and no second audit row.
        core.accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com", actor = actor, recorder = recorder)
        assertEquals(1, count("SELECT count(*) FROM access_grant WHERE request_id = ?", request.id))
        assertEquals(1, count("SELECT count(*) FROM audit_event WHERE principal = ? AND action = 'task.approve'", actor.principal))

        core.accessStore.revoke(grantId, actor, recorder)
        // A second revoke matches no still-open grant: no second audit row.
        assertEquals(false, core.accessStore.revoke(grantId, actor, recorder))
        assertEquals(1, count("SELECT count(*) FROM audit_event WHERE principal = ? AND action = 'grant.revoke'", actor.principal))
        verifyAuditChain(dataSource)
    }

    private fun count(sql: String, id: Long): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun count(sql: String, value: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            ps.setString(1, value)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun execute(sql: String) =
        dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun assertEvent(principal: String, action: AuthzAction, resource: String, statement: String) {
        val rows = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT action, resource, statement, outcome, kind, channel, decision, datasource
                   FROM audit_event WHERE principal=? AND resource=? AND statement=? ORDER BY id""",
            ).use { ps ->
                ps.setString(1, principal); ps.setString(2, resource); ps.setString(3, statement)
                ps.executeQuery().use { rs ->
                    buildList { while (rs.next()) add((1..8).map(rs::getString)) }
                }
            }
        }
        assertEquals(1, rows.size)
        assertEquals(listOf(action.cedarId, resource, statement, "ALLOW", "admin", "console", "ALLOW", "control-plane"), rows.single())
    }
}
