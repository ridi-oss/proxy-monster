package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The statement-kind gate closes the connect-only admin gaps on the production floor. A principal with
 * connect + a data category (read/write/ddl) but NO `stmt.cat.admin` is denied the admin.* statements at
 * the KIND gate — the class of statement that, before statement classification, slipped through on connect
 * alone (ANALYZE TABLE, SHOW MASTER STATUS, …). Because the gate is the statement's own kind, `SELECT …
 * INTO OUTFILE` — kind `select_into_outfile`, a member of `admin.file` — needs admin.file even from a
 * ddl-granted principal, while a benign schema `SHOW` stays a metadata passthrough. Real MySQL + real Cedar
 * with the shipped schema; asserts the exact kind-gate denyReason so a deny at some other stage would fail
 * the test rather than pass as a false positive.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StatementKindGapDenialDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    private fun decide(sql: String, principal: String) = decideQuery(
        principal = principal, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
    )

    @Test
    fun `admin gaps deny at the kind gate for a principal with every benign category but not admin`() {
        // The negative control holds EVERY non-admin datasource category — read + metadata + session + ddl —
        // but NOT admin. So a deny below proves the statement's kind is genuinely admin-classified: were a gap
        // kind accidentally reclassified into read/metadata/session/ddl, this principal would ALLOW it and the
        // test would fail, catching the over-grant. A connect+ddl-only principal could not tell those apart.
        val benign = "benignmax@example.com"
        val role = fx.policyStore.createRole(RoleInput("benign-max"))
        fx.policyStore.createAssignment(RoleAssignmentInput(benign, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "benign-max-grant",
                cedarSrc = """permit(principal in Role::"benign-max", action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.metadata", Action::"stmt.cat.session", Action::"stmt.cat.ddl"], resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )

        // Positive control: a benign metadata statement runs — confirming the principal actually holds metadata,
        // which is what makes each admin deny below load-bearing (a gap kind reclassified to metadata would
        // ALLOW here, not deny).
        assertEquals(EnfAction.ALLOW, decide("SHOW TABLES", benign).action, "benign metadata runs for this principal")

        // The admin.maintenance / admin.replication statements deny at the kind gate. Before classification
        // each fell through the passthrough allow on connect alone; now the kind gate catches it first — and
        // only because the kind is admin, which this principal lacks.
        val gaps = mapOf(
            "ANALYZE TABLE users" to "analyze_table",
            "SHOW MASTER STATUS" to "show_master_status",
            "SHOW BINARY LOGS" to "show_binary_logs",
            "SHOW REPLICAS" to "show_replicas",
        )
        for ((sql, kind) in gaps) {
            val d = decide(sql, benign)
            assertEquals(EnfAction.DENY, d.action, "`$sql` must deny without admin")
            assertEquals("statement kind '$kind' is not permitted", d.denyReason, "`$sql` denies at the kind gate")
        }

        // The binlog control denies at the kind gate too: its kind is set_sql_log_bin (stmt.cat.admin.replication)
        // and the analyzer emits no utility grant for it. The principal HAS session, so a deny proves it is NOT a
        // benign set_session_var (which a session grant would clear); pinning the exact kind reason closes that gap.
        val logBin = decide("SET sql_log_bin = 0", benign)
        assertEquals(EnfAction.DENY, logBin.action, "`SET sql_log_bin` must deny without admin")
        assertEquals("statement kind 'set_sql_log_bin' is not permitted", logBin.denyReason, "denies at the kind gate as set_sql_log_bin")
    }

    @Test
    fun `OUTFILE is gated on admin_file, not ddl`() {
        // `SELECT … INTO OUTFILE`'s kind (select_into_outfile) sits under admin.file — a server-side file
        // export, not plain ddl. A ddl grant alone must not authorize it: the admin.file kind is the gate.
        val writer = "writer@example.com"
        val d = decide("SELECT 1 INTO OUTFILE '/tmp/pm_probe_out'", writer)
        assertEquals(EnfAction.DENY, d.action, "a ddl grant alone must not authorize OUTFILE")
        assertEquals("statement kind 'select_into_outfile' is not permitted", d.denyReason, "OUTFILE denies at the admin.file kind gate")

        // admin.file alone authorizes it — the kind gate is the whole gate; no separate ddl grant is required.
        val file = "filegrant@example.com"
        val fileRole = fx.policyStore.createRole(RoleInput("file-op"))
        fx.policyStore.createAssignment(RoleAssignmentInput(file, fileRole.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "file-op-grant",
                cedarSrc = """permit(principal in Role::"file-op", action in [Action::"datasource.connect", Action::"stmt.cat.admin.file"], resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        assertEquals(EnfAction.ALLOW, decide("SELECT 1 INTO OUTFILE '/tmp/pm_probe_out'", file).action, "admin.file alone authorizes OUTFILE")
    }

    @Test
    fun `ANALYZE TABLE holding the admin kind but no read on the table denies at the read gate — the existence oracle is closed`() {
        // The kind gate is not the whole gate for ANALYZE: a table-targeted ANALYZE also carries the target's
        // result-read grant, so `ANALYZE TABLE users` is authorized like `SELECT * FROM users`. This principal
        // holds stmt.cat.admin.maintenance — it PASSES the analyze_table kind gate — but has no read on `users`,
        // so the read gate denies. Before the analyzer gated the read, ANALYZE resolved connect-only and an
        // unauthorized principal learned the table exists (and error-probed it). The deny must NOT be the kind
        // reason: that would mean the kind gate caught it and the read gate never ran.
        val maint = "maint-only@example.com"
        val role = fx.policyStore.createRole(RoleInput("maint-only"))
        fx.policyStore.createAssignment(RoleAssignmentInput(maint, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "maint-only-grant",
                cedarSrc = """permit(principal in Role::"maint-only", action in [Action::"datasource.connect", Action::"stmt.cat.admin.maintenance"], resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val d = decide("ANALYZE TABLE users", maint)
        assertEquals(EnfAction.DENY, d.action, "ANALYZE must deny without a read grant on the table")
        // The deny must come from the READ gate, which names the target table — not the kind gate (which this
        // principal clears) and not an unrelated structural stage.
        assertTrue(
            d.denyReason.orEmpty() != "statement kind 'analyze_table' is not permitted" && d.denyReason.orEmpty().contains("users"),
            "the deny must be the read gate naming the table: ${d.denyReason}",
        )
    }

    @Test
    fun `a benign metadata SHOW stays allowed while a replication SHOW denies`() {
        // `analyst@example.com` has stmt.cat.metadata + stmt.cat.session (not admin). The SHOW split holds:
        // a schema-introspecting SHOW is metadata (passthrough allow), a replication SHOW is admin.
        val analyst = "analyst@example.com"
        assertEquals(EnfAction.ALLOW, decide("SHOW TABLES", analyst).action, "schema-introspecting SHOW is metadata")
        val d = decide("SHOW MASTER STATUS", analyst)
        assertEquals(EnfAction.DENY, d.action, "a replication SHOW is admin, not metadata")
        assertEquals("statement kind 'show_master_status' is not permitted", d.denyReason, "denies at the kind gate, not by metadata")
    }
}
