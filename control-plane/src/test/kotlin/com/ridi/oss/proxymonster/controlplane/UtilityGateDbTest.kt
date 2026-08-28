package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.InvalidCedarPolicyException
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

/**
 * Utility gate, end-to-end on real MySQL + real Cedar: a data-bearing SHOW command (SHOW
 * PROCESSLIST / BINLOG EVENTS / WARNINGS) is admitted with a Utility FACT and DENIED by the shipped
 * `system:activity`/`system:data-leak` policy, which a `system:development` datasource can relax.
 * Ordinary metadata (SHOW TABLES) stays
 * passthrough. A datasource with no governing manifest DENIES a recognized utility deny-by-default
 * (fail-closed — utilities are token-recognized, so this needs no function catalog).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UtilityGateDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    private fun setEngineVersion(v: String?) = exec("UPDATE datasource SET engine_version = ? WHERE id = ?") {
        it.setString(1, v); it.setLong(2, fx.datasource.id)
    }

    private fun setTags(tagsJson: String) = exec("UPDATE datasource SET tags = ?::jsonb WHERE id = ?") {
        it.setString(1, tagsJson); it.setLong(2, fx.datasource.id)
    }

    private fun exec(sql: String, bind: (java.sql.PreparedStatement) -> Unit) {
        fx.dataSource.connection.use { c -> c.prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() } }
    }

    private fun decide(sql: String) = decideQuery(
        principal = principal, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = SystemClassificationService(),
    ).action

    @Test
    fun `a data-bearing SHOW is denied on the floor and relaxed on a preset-development datasource`() {
        setEngineVersion("8.0.44")
        setTags("""["system:production"]""")
        // Floor: forbidden by the shipped system:activity / system:data-leak guards.
        assertEquals(EnfAction.DENY, decide("SHOW BINLOG EVENTS"), "SHOW BINLOG EVENTS (system:data-leak) denies on the floor")
        assertEquals(EnfAction.DENY, decide("SHOW WARNINGS"), "SHOW WARNINGS (system:data-leak) denies on the floor")
        // GET DIAGNOSTICS launders a diagnostic string into a user var; it is denied on the floor
        // (an unpermitted statement kind), so the read-back path is closed at CP admission, not the proxy.
        assertEquals(EnfAction.DENY, decide("GET DIAGNOSTICS @n = NUMBER"), "GET DIAGNOSTICS denied on the floor")
        // Ordinary metadata carries no utility fact → the gate is inert → passthrough ALLOW (unchanged).
        assertEquals(EnfAction.ALLOW, decide("SHOW TABLES"), "ordinary SHOW TABLES still passthrough-allows")
        assertEquals(EnfAction.ALLOW, decide("SHOW STATUS"), "SHOW STATUS (never hardcode-denied) still passthrough-allows")
        // SET GLOBAL / SET PASSWORD are system:critical utilities (the -130 guard is UNCONDITIONAL) — denied
        // on the floor, and NOT relaxed even on a dev datasource (a server-state mutation is never a dev
        // convenience). The SET slice denies these through policy, not a hardcoded scan list.
        assertEquals(EnfAction.DENY, decide("SET GLOBAL max_connections=1"), "SET GLOBAL (system:critical) denies on the floor")
        assertEquals(EnfAction.DENY, decide("SET PASSWORD='x'"), "SET PASSWORD (system:critical) denies on the floor")
        // SET PERSIST / PERSIST_ONLY persist a global to mysqld-auto.cnf — also system:critical, so they
        // are gated here, not relayed as a SESSION_MUTATING passthrough.
        assertEquals(EnfAction.DENY, decide("SET PERSIST max_connections=5000"), "SET PERSIST (system:critical) denies on the floor")
        assertEquals(EnfAction.DENY, decide("SET PERSIST_ONLY max_connections=5000"), "SET PERSIST_ONLY (system:critical) denies on the floor")
        // Dev datasource: the -110/-120 activity/data-leak permits fire (V32, role-agnostic) → the SHOW is allowed.
        setTags("""["system:development"]""")
        assertEquals(EnfAction.ALLOW, decide("SHOW BINLOG EVENTS"), "SHOW BINLOG EVENTS relaxed on a dev datasource")
        // SHOW WARNINGS relaxes on a dev datasource too (dev has no PII, so its diagnostics buffer
        // carries nothing to leak) — matching the production-posture diagnostic-redaction flag.
        assertEquals(EnfAction.ALLOW, decide("SHOW WARNINGS"), "SHOW WARNINGS relaxed on a dev datasource")
        // ...but system:critical SET GLOBAL / SET PERSIST are NEVER relaxed, even on a dev datasource.
        assertEquals(EnfAction.DENY, decide("SET GLOBAL max_connections=1"), "SET GLOBAL stays denied even on a dev datasource (critical, unconditional)")
        assertEquals(EnfAction.DENY, decide("SET PERSIST max_connections=5000"), "SET PERSIST stays denied even on a dev datasource (critical, unconditional)")
        setTags("""["system:production"]""")
    }

    @Test
    fun `an unclassifiable utility is hard-denied even against a broad Datasource read grant`() {
        // With no manifest the utility is UNCLASSIFIED (no system: tag). Its Cedar entity
        // still has a Datasource parent, so a Datasource-scoped `result.read.unmasked` grant (the documented
        // broad / no-masking posture) WOULD permit it — re-opening the SHOW leak the hardcode blocked. The fix
        // hard-denies an unclassified recognized utility in Query.kt, ahead of Cedar, so the grant can't reach
        // it. This test gives the principal exactly that broad grant, on a no-manifest datasource.
        setEngineVersion(null)
        setTags("""["system:production"]""")
        val broad = "broad-util@example.com"
        val role = fx.policyStore.createRole(RoleInput("broad-util-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-broad-util-grant",
                cedarSrc = """permit(principal in Role::"broad-util-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fun decideAs(who: String, sql: String) = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = SystemClassificationService(),
        ).action
        // The broad grant is genuinely load-bearing: an ordinary passthrough SHOW (no utility fact) allows.
        assertEquals(EnfAction.ALLOW, decideAs(broad, "SHOW TABLES"), "broad grant permits ordinary metadata (proves it's live)")
        // ...but the unclassified dangerous SHOW is HARD-denied ahead of Cedar — the grant cannot reach it.
        val warnings = decideQuery(
            principal = broad, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = "SHOW WARNINGS", channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = SystemClassificationService(),
        )
        assertEquals(
            EnfAction.DENY,
            warnings.action,
            "no manifest → unclassified utility hard-denied even WITH a Datasource read grant: ${warnings.detail}",
        )
        assertEquals(EnfAction.DENY, decideAs(broad, "SHOW BINLOG EVENTS"), "no manifest → hard-denied despite the broad grant")
        // And the analyst (no grant at all) is denied too — deny-by-default AND the hard-deny both hold.
        assertEquals(EnfAction.DENY, decideAs(principal, "SHOW WARNINGS"), "no manifest → denied with no grant")
        setEngineVersion("8.0.44")
    }

    @Test
    fun `a broad production permit cannot reach a data-leak SHOW, and an operator forbid on it still bites`() {
        // A statement that still carries a Utility must stay governed by it: a broad action-unscoped
        // datasource permit must not reach SHOW BINLOG EVENTS, and an operator forbid written against the
        // Utility EUID must still be evaluated. (SHOW GRANTS / SHOW PROCESSLIST no longer emit one — they
        // gate on stmt.cat.admin.* alone.)
        setEngineVersion("8.0.44")
        setTags("""["system:production"]""")
        val wide = "wide-prod@example.com"
        val role = fx.policyStore.createRole(RoleInput("wide-prod-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(wide, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-wide-prod-grant",
                cedarSrc = """permit(principal in Role::"wide-prod-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fun decideWide(sql: String) = decideQuery(
            principal = wide, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = SystemClassificationService(),
        ).action
        assertEquals(EnfAction.DENY, decideWide("SHOW BINLOG EVENTS"), "the system:data-leak floor must survive a broad datasource permit")
        assertEquals(EnfAction.DENY, decideWide("SHOW CREATE USER CURRENT_USER()"), "system:critical must survive a broad datasource permit")

        val forbid = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-operator-binlog-forbid",
                cedarSrc = """forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource == Utility::"${fx.datasource.name}/SHOW_BINLOG_EVENTS");""",
            ),
            updatedBy = "test",
        )
        try {
            setTags("""["system:development"]""")
            assertEquals(
                EnfAction.DENY,
                decideWide("SHOW BINLOG EVENTS"),
                "an operator forbid on the Utility EUID must override even the dev relaxation — a dead forbid is fail-open",
            )
        } finally {
            fx.cedarPolicyStore.delete(forbid.id)
            setTags("""["system:production"]""")
        }
    }

    @Test
    fun `a policy naming a retired Utility command is rejected, not silently inert`() {
        // Utility is still a valid entity type, so forbid(... resource == Utility::"ds/SHOW_GRANTS") passes
        // schema validation and then never matches — an operator's carve-out would stop working in silence.
        // Reject it at write time and name the replacement.
        val ds = fx.datasource.name
        for (cmd in listOf("SHOW_GRANTS", "SHOW_PROCESSLIST")) {
            val e = assertFailsWith<InvalidCedarPolicyException> {
                fx.cedarPolicyStore.create(
                    CedarPolicyInput(
                        name = "retired-$cmd",
                        cedarSrc = """forbid(principal, action in [Action::"result.read.unmasked"], resource == Utility::"$ds/$cmd");""",
                    ),
                    updatedBy = "test",
                )
            }
            assertTrue(e.message.orEmpty().contains("no longer emitted"), "must say why: ${e.message}")
            assertTrue(e.message.orEmpty().contains("stmt.kind."), "must name the replacement: ${e.message}")
        }
        // A utility that IS still emitted stays writable.
        val ok = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "live-utility-policy",
                cedarSrc = """forbid(principal, action in [Action::"result.read.unmasked"], resource == Utility::"$ds/SHOW_BINLOG_EVENTS");""",
            ),
            updatedBy = "test",
        )
        fx.cedarPolicyStore.delete(ok.id)
    }
}