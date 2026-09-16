package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ColumnVerdict
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumns
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceActionId
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * V32 bootstrap-policy package on real PostgreSQL + real Cedar. Central fact: a development datasource holds
 * no PII by definition, so:
 *  - development reads CLEARTEXT — ordinary AND pii-tagged columns alike — for any principal that reached the
 *    datasource; roles gate only connect + the matching sql.* kind;
 *  - the system-object floor permits catalog everywhere and activity/data-leak on dev, but critical is always
 *    forbidden — even on dev;
 *  - production is disabled by default; once enabled it masks PII, and only a production-pii-accessor on the
 *    trusted-network earns cleartext — driven by the SHIPPED -300 Tailscale example (100.100.0.0/16);
 *  - the default system:developer group aggregates the five development roles.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PresetPolicyDbTest {
    private lateinit var fx: EnforcementFixture

    private val principals = mapOf(
        "system:development-viewer" to "dev-viewer@example.com",
        "system:development-pii-accessor" to "dev-pii@example.com",
        "system:development-updater" to "dev-updater@example.com",
        "system:development-deleter" to "dev-deleter@example.com",
        "system:development-architect" to "dev-architect@example.com",
        "system:production-viewer" to "prod-viewer@example.com",
        "system:production-pii-accessor" to "prod-pii@example.com",
        "system:production-updater" to "prod-updater@example.com",
        "system:production-deleter" to "prod-deleter@example.com",
        "system:production-architect" to "prod-architect@example.com",
    )
    private val developer = "developer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        exec("UPDATE datasource SET engine_version = ? WHERE id = ?") {
            it.setString(1, "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
            it.setLong(2, fx.datasource.id)
        }

        val roles = fx.policyStore.listRoles().associateBy { it.name }
        for ((roleName, principal) in principals) {
            fx.policyStore.createAssignment(RoleAssignmentInput(principal, roles.getValue(roleName).id))
        }
        // Exercise the real default aggregate group rather than manually assigning its five roles.
        fx.userGroupStore.provisionFromOidc(
            developer,
            developer,
            listOf("okta-developers"),
            OidcGroupMapping(mapOf("okta-developers" to "system:developer"), null),
        )
        // No test-authored trusted-network producer: the shipped -300 example (100.100.0.0/16) is the producer.
    }

    @BeforeEach
    fun reset() {
        setTags("system:development")
        // Dev package on, production off; disabling -262 too so a test that enables it doesn't leak onward.
        (listOf(-200L) + (230L..235L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-reset") }
        (listOf(-300L, -262L) + (250L..259L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, false, "test-reset") }
    }

    private fun setTags(posture: String) = exec("UPDATE datasource SET tags = ?::jsonb WHERE id = ?") {
        it.setString(1, "[\"$posture\"]")
        it.setLong(2, fx.datasource.id)
    }

    private fun exec(sql: String, bind: (java.sql.PreparedStatement) -> Unit) {
        fx.dataSource.connection.use { c -> c.prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() } }
    }

    private fun decide(principal: String, sql: String, requesterIp: String? = null, channel: Channel = Channel.WIRE) = decideQuery(
        principal = principal,
        ds = fx.datasourceStore.get(fx.datasource.id)!!,
        sql = sql,
        channel = channel,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        context = AuthzContext(requesterIp = requesterIp),
        systemClassification = SystemClassificationService(),
    )

    // Categories are Cedar policy handles (strings), not control-plane constants — a preset grants a
    // category, and a kind gates against it via the schema. So the test authorizes by the raw action id.
    private fun actionAllowed(principal: String, cedarActionId: String): Boolean {
        val ds = fx.datasourceStore.get(fx.datasource.id)!!
        return fx.authz.authorizeDatasourceActionId(
            principal,
            fx.roleResolver.resolve(principal),
            cedarActionId,
            ds.name,
            datasourceTags = ds.tags,
        ) is AuthzDecision.Allow
    }

    @Test
    fun `development role matrix grants connect and only the corresponding SQL kind`() {
        val expected = mapOf(
            "system:development-viewer" to setOf("stmt.cat.read"),
            "system:development-pii-accessor" to setOf("stmt.cat.read"),
            "system:development-updater" to setOf("stmt.cat.write.insert", "stmt.cat.write.update"),
            "system:development-deleter" to setOf("stmt.cat.write.delete"),
            "system:development-architect" to setOf("stmt.cat.ddl"),
        )
        val sqlActions = setOf(
            "stmt.cat.read", "stmt.cat.write.insert", "stmt.cat.write.update",
            "stmt.cat.write.delete", "stmt.cat.ddl",
        )
        for ((role, granted) in expected) {
            val principal = principals.getValue(role)
            assertEquals(true, actionAllowed(principal, AuthzAction.DATASOURCE_CONNECT.cedarId), "$role connect")
            for (action in sqlActions) {
                assertEquals(action in granted, actionAllowed(principal, action), "$role $action")
            }
        }
    }

    @Test
    fun `production role matrix grants connect and only the corresponding SQL kind once enabled`() {
        setTags("system:production")
        (listOf(-300L) + (250L..258L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }
        val expected = mapOf(
            "system:production-viewer" to setOf("stmt.cat.read"),
            "system:production-pii-accessor" to setOf("stmt.cat.read"),
            "system:production-updater" to setOf("stmt.cat.write.insert", "stmt.cat.write.update"),
            "system:production-deleter" to setOf("stmt.cat.write.delete"),
            "system:production-architect" to setOf("stmt.cat.ddl"),
        )
        val sqlActions = setOf(
            "stmt.cat.read", "stmt.cat.write.insert", "stmt.cat.write.update",
            "stmt.cat.write.delete", "stmt.cat.ddl",
        )
        for ((role, granted) in expected) {
            val principal = principals.getValue(role)
            assertEquals(true, actionAllowed(principal, AuthzAction.DATASOURCE_CONNECT.cedarId), "$role connect")
            for (action in sqlActions) {
                assertEquals(action in granted, actionAllowed(principal, action), "$role $action")
            }
        }
    }

    @Test
    fun `development reads cleartext including PII because dev holds no PII`() {
        val viewer = principals.getValue("system:development-viewer")
        val accessor = principals.getValue("system:development-pii-accessor")
        // Ordinary non-PII columns read cleartext.
        assertEquals(EnfAction.ALLOW, decide(viewer, "select id, region from users").action)
        // A pii-tagged column ALSO reads cleartext on a dev datasource — trusted-network is irrelevant here.
        assertEquals(EnfAction.ALLOW, decide(viewer, "select ssn from users").action, "dev has no PII -> ssn is cleartext")
        assertEquals(EnfAction.ALLOW, decide(accessor, "select ssn from users", "100.99.1.10").action, "off trusted-network is still cleartext on dev")
    }

    @Test
    fun `development system floor permits catalog activity and data-leak but never critical`() {
        val viewer = principals.getValue("system:development-viewer")
        assertEquals(EnfAction.ALLOW, decide(viewer, "select count(*) from pg_catalog.pg_class").action, "catalog")
        assertEquals(EnfAction.ALLOW, decide(viewer, "select count(*) from pg_catalog.pg_stat_activity").action, "activity on dev")
        assertEquals(EnfAction.ALLOW, decide(viewer, "select count(*) from pg_catalog.pg_stats").action, "data-leak on dev")
        assertEquals(EnfAction.DENY, decide(viewer, "select count(*) from pg_catalog.pg_authid").action, "critical stays forbidden even on dev")
    }

    @Test
    fun `production is denied until enabled then masks PII unless a pii-accessor earns trusted-network`() {
        setTags("system:production")
        val viewer = principals.getValue("system:production-viewer")
        val accessor = principals.getValue("system:production-pii-accessor")

        // Disabled by default: even a correctly-assigned production role is denied.
        assertEquals(EnfAction.DENY, decide(viewer, "select id from users").action, "production select disabled by default")

        // Enabling production PII access means enabling its trusted-network producer (-300) too.
        (listOf(-300L) + (250L..258L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }
        assertEquals(EnfAction.ALLOW, decide(viewer, "select id from users").action, "non-PII cleartext")
        assertEquals(EnfAction.MASK, decide(viewer, "select ssn from users").action, "viewer masks PII")
        assertEquals(EnfAction.MASK, decide(viewer, "select ssn from users", "100.100.1.10").action, "viewer never gets PII cleartext, trusted-network or not")
        assertEquals(EnfAction.MASK, decide(accessor, "select ssn from users", "100.99.1.10").action, "pii-accessor masks off trusted-network")
        // The SHIPPED -300 example trusts 100.100.0.0/16, so an in-range request earns the tag and -258 fires.
        assertEquals(EnfAction.ALLOW, decide(accessor, "select ssn from users", "100.100.1.10").action, "pii-accessor reads cleartext on trusted-network")
    }

    @Test
    fun `production PII unmasks via the workflow-executor channel off trusted-network and re-masks at the viewer`() {
        setTags("system:production")
        val accessor = principals.getValue("system:production-pii-accessor")
        val viewer = principals.getValue("system:production-viewer")
        val offNetwork = "100.99.1.10" // outside the shipped -300 trusted range (100.100.0.0/16)

        // Enable the whole production package INCLUDING -259 (the executor-channel unmask) and the -300 producer.
        (listOf(-300L) + (250L..259L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }

        // -259: an approved run on the workflow-executor channel unmasks pii even OFF the trusted network.
        assertEquals(
            EnfAction.ALLOW,
            decide(accessor, "select ssn from users", offNetwork, Channel.WORKFLOW_EXECUTOR).action,
            "-259: pii-accessor unmasks off-network on the workflow-executor channel",
        )
        // The viewer channel does NOT match -259, so off-network it falls through to -257 (masked) — this is
        // the re-mask that bounds a saved result at view time.
        assertEquals(
            EnfAction.MASK,
            decide(accessor, "select ssn from users", offNetwork, Channel.WORKFLOW_VIEWER).action,
            "workflow-viewer re-masks off-network (-259 does not match the viewer channel)",
        )
        // The wire channel likewise masks off-network — -259 is workflow-executor only, never the raw wire.
        assertEquals(
            EnfAction.MASK,
            decide(accessor, "select ssn from users", offNetwork, Channel.WIRE).action,
            "wire masks off-network (the executor-channel unmask never reaches the native wire)",
        )
        // -259 is role-scoped to pii-accessor: a plain production-viewer on workflow-executor still masks.
        assertEquals(
            EnfAction.MASK,
            decide(viewer, "select ssn from users", offNetwork, Channel.WORKFLOW_EXECUTOR).action,
            "-259 grants only system:production-pii-accessor; a viewer still masks",
        )

        // Load-bearing: with -259 DISABLED (its shipped default), even the workflow-executor channel masks
        // off-network. Deleting V41 or dropping its channel guard would flip this back to MASK and be caught.
        fx.cedarPolicyStore.setEnabled(-259, false, "test-disable-259")
        assertEquals(
            EnfAction.MASK,
            decide(accessor, "select ssn from users", offNetwork, Channel.WORKFLOW_EXECUTOR).action,
            "-259 disabled (shipped default) -> workflow-executor masks off-network",
        )
    }

    @Test
    fun `diagnostic redaction follows the decision, not the datasource-wide unmasked permit`() {
        setTags("system:production")
        val viewer = principals.getValue("system:production-viewer")
        val accessor = principals.getValue("system:production-pii-accessor")
        val updater = principals.getValue("system:production-updater")
        val trusted = "100.100.1.10" // inside the shipped -300 trusted range (100.100.0.0/16)
        val offNetwork = "100.99.1.10"
        (listOf(-300L) + (250L..258L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }

        // #228: the viewer's datasource-wide -256 grant must not unredact a MASK of a pii column.
        assertTrue(decide(viewer, "select ssn from users").sanitizeDiagnostics, "a MASK redacts its diagnostic")
        assertFalse(decide(viewer, "select id from users").sanitizeDiagnostics, "a read of only readable columns leaks nothing")

        assertFalse(decide(accessor, "select ssn from users", trusted).sanitizeDiagnostics, "reads ssn unmasked -> no redaction")
        assertTrue(decide(accessor, "select ssn from users", offNetwork).sanitizeDiagnostics, "loses unmasked ssn off-network -> redact")

        // The whole-row `DETAIL` dump puts masked ssn in the leak set even though the INSERT writes only id.
        val write = decide(updater, "insert into users (id) values (1)")
        assertEquals(EnfAction.ALLOW, write.action, "the updater's INSERT is allowed: ${write.denyReason}")
        assertTrue(write.sanitizeDiagnostics, "the whole-row leak set includes masked ssn -> redact")
    }

    @Test
    fun `an EXPLAIN-only unmasked grant does not make a principal a full-cleartext reader for diagnostics`() {
        setTags("system:production")
        val accessor = principals.getValue("system:production-pii-accessor")
        val offNetwork = "100.99.1.10" // outside the shipped -300 trusted range
        (listOf(-300L, -262L) + (250L..258L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }

        assertEquals(EnfAction.MASK, decide(accessor, "select ssn from users", offNetwork).action, "plain SELECT masks off-network")
        val explain = decide(accessor, "explain select ssn from users", offNetwork)
        assertEquals(EnfAction.ALLOW, explain.action, "EXPLAIN of pii is unmasked under -262")
        // Otherwise an EXPLAIN ANALYZE (which executes) would leak the value its conversion error echoes.
        assertTrue(explain.sanitizeDiagnostics, "an EXPLAIN-only grant must not skip diagnostic redaction")
    }

    @Test
    fun `production system surfaces stay closed even for a pii-accessor on trusted-network`() {
        setTags("system:production")
        val accessor = principals.getValue("system:production-pii-accessor")
        // Enabling production PII access means enabling its trusted-network producer (-300) too.
        (listOf(-300L) + (250L..258L).map { -it }).forEach { fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production") }
        // activity/data-leak have no production permit (dev-only); critical is forbidden. Trusted-network and
        // the pii-accessor role do not open them.
        assertEquals(EnfAction.DENY, decide(accessor, "select count(*) from pg_catalog.pg_stat_activity", "100.100.1.10").action, "no production activity permit")
        assertEquals(EnfAction.DENY, decide(accessor, "select count(*) from pg_catalog.pg_stats", "100.100.1.10").action, "no production data-leak permit")
        assertEquals(EnfAction.DENY, decide(accessor, "select count(*) from pg_catalog.pg_authid", "100.100.1.10").action, "critical forbid")
        // Catalog structure stays browsable (the -100 permit is environment-agnostic).
        assertEquals(EnfAction.ALLOW, decide(accessor, "select count(*) from pg_catalog.pg_class", "100.100.1.10").action, "catalog remains browsable")
    }

    @Test
    fun `default developer group connects selects writes and reads dev data cleartext`() {
        assertEquals(true, actionAllowed(developer, AuthzAction.DATASOURCE_CONNECT.cedarId), "developer connect")
        assertEquals(true, actionAllowed(developer, "stmt.cat.read"), "developer select")
        assertEquals(true, actionAllowed(developer, "stmt.cat.write.insert"), "developer insert")
        assertEquals(true, actionAllowed(developer, "stmt.cat.write.update"), "developer update")
        assertEquals(true, actionAllowed(developer, "stmt.cat.write.delete"), "developer delete")
        assertEquals(true, actionAllowed(developer, "stmt.cat.ddl"), "developer ddl")
        assertEquals(EnfAction.ALLOW, decide(developer, "select ssn from users").action, "developer reads dev PII cleartext")
    }

    @Test
    fun `the shipped development permit matches a system-development tag wherever it sits`() {
        // `system:development` reaches the shipped -200 permit whether it sits on the datasource or on the
        // column. Either write takes the same instance-wide admin.datasources authority.
        val tagged = ColumnRef(key = "k", catalog = "pm", schema = "public", table = "users", column = "ssn", tags = listOf("system:development"))
        val plain = ColumnRef(key = "k", catalog = "pm", schema = "public", table = "users", column = "ssn")
        val nobody = "nobody@example.com" // no preset role; relies solely on the shipped -200 preset permit
        // On the DATASOURCE: every column under it is in system:development via its datasource parent.
        assertEquals(
            ColumnVerdict.UNMASKED,
            fx.authz.authorizeColumns(nobody, emptySet(), fx.datasource.name, listOf(plain), datasourceTags = listOf("system:development"))["k"],
            "system:development on the DATASOURCE unmasks its columns (the -200 permit)",
        )
        // On the COLUMN: the same name, reaching the same permit directly.
        assertEquals(
            ColumnVerdict.UNMASKED,
            fx.authz.authorizeColumns(nobody, emptySet(), fx.datasource.name, listOf(tagged), datasourceTags = listOf("system:production"))["k"],
            "system:development on the COLUMN reaches the same permit — no tag is filtered by resource type",
        )
        // And the verdict comes from the tag: with neither, -200 cannot fire and deny-by-default holds.
        assertEquals(
            ColumnVerdict.DENIED,
            fx.authz.authorizeColumns(nobody, emptySet(), fx.datasource.name, listOf(plain), datasourceTags = listOf("system:production"))["k"],
            "untagged on a production datasource, the same read is denied",
        )
    }
}
