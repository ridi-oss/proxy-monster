package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.DriverManager
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `SHOW WARNINGS` / `SHOW ERRORS` are a PII exfiltration channel: a prior statement whose expression fails a
 * conversion echoes the offending value verbatim into the session's warning buffer — e.g.
 * `SELECT CAST(ssn AS UNSIGNED) FROM users ORDER BY (ssn = 'target') DESC LIMIT 1` leaves
 * `Truncated incorrect INTEGER value: '987-65-4320'` there — and `SHOW WARNINGS` reads it back. The proxy
 * masks the SELECT's result columns, but the warning buffer is a side channel the mask never touches, so the
 * defense is to DENY the retrieval. These statements classify (kind) as benign `stmt.cat.metadata`, but carry
 * the `system:data-leak` tag (resource `session-diagnostics`), so the shipped floor forbid denies them on the
 * production floor — relaxed only on `system:development`, where there is no PII.
 *
 * This is an end-to-end enforcement test on a real MySQL backend: it first proves the leak is REAL (the
 * backend does echo the value into the warning buffer), then proves the control-plane decision denies the
 * retrieval, and that the deny is the data-leak forbid — it overrides even a broad any-action grant.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ShowWarningsExfilDbTest {
    private lateinit var fx: EnforcementFixture
    private val classifier = SystemClassificationService()
    private val analyst = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        // The production floor: the shipped system:data-leak forbid is unconditional here (it is relaxed only
        // on system:development). Tag it explicitly so the intent is legible.
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = '[\"system:production\"]'::jsonb WHERE id = ?").use { ps ->
                ps.setLong(1, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun decide(sql: String, who: String = analyst): EnfAction = decideQuery(
        principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = classifier,
    ).action

    @Test
    fun `SHOW WARNINGS cannot exfiltrate a value the backend leaked into the warning buffer`() {
        val secret = fx.cleartextSsn[0]

        // (1) The vector is REAL — on ONE backend session, the failing CAST echoes the value into the warning
        // buffer and SHOW WARNINGS reads it back verbatim. If this precondition ever stops holding the test
        // proves nothing, so it is asserted, not assumed.
        DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { c ->
            c.createStatement().use { st ->
                st.execute("SELECT CAST(ssn AS UNSIGNED) FROM users ORDER BY (ssn = '$secret') DESC LIMIT 1")
                st.executeQuery("SHOW WARNINGS").use { rs ->
                    var leaked = false
                    while (rs.next()) {
                        if (rs.getString("Message")?.contains(secret) == true) leaked = true
                    }
                    assertTrue(leaked, "precondition: the backend must echo the raw value into the warning buffer")
                }
            }
        }

        // (2) The defense — the control-plane decision denies retrieving that buffer on the production floor, so
        // no client ever reads it. Both diagnostics SHOWs are system:data-leak.
        assertEquals(EnfAction.DENY, decide("SHOW WARNINGS"), "SHOW WARNINGS must be denied on the production floor (system:data-leak)")
        assertEquals(EnfAction.DENY, decide("SHOW ERRORS"), "SHOW ERRORS must be denied on the production floor (system:data-leak)")
    }

    @Test
    fun `the deny is the data-leak forbid — it overrides even a broad any-action grant`() {
        // Make the forbid LOAD-BEARING: a principal with an any-action grant on the whole datasource would
        // otherwise sail past every permit gate. The shipped system:data-leak forbid still denies.
        val broad = "broad@example.com"
        val role = fx.policyStore.createRole(RoleInput("broad-diag"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "broad-diag-grant",
                cedarSrc = """permit(principal in Role::"broad-diag", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        assertEquals(EnfAction.DENY, decide("SHOW WARNINGS", broad), "the data-leak forbid overrides even a broad any-action grant")
        assertEquals(EnfAction.DENY, decide("SHOW ERRORS", broad), "the data-leak forbid overrides even a broad any-action grant")
    }
}
