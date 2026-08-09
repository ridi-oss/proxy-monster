package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end system-classification on real PostgreSQL + real Cedar: the shipped `system:catalog` permit makes
 * system structure browsable, while the dangerous tags (`system:critical`/`data-leak`/`activity`) are
 * forbidden on the production floor by the shipped forbids — the forbid overriding even a broad grant.
 * `system:critical` is never relaxed; `system:activity`/`data-leak` are relaxed on `system:development` (V32).
 * The classifier keys off `datasource.engine_version` (set here to a PG-17 `version()` string). A datasource
 * with NO version resolves to no manifest → no system tag → deny-by-default (system schemas closed) — the
 * transitional/fail-closed posture. Running this test also proves the shipped SYSTEM policies compile against
 * schema.cedarschema at boot (the fixture's CedarEngine load).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SystemClassificationEnforcementDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"
    private val classifier = SystemClassificationService()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private fun setEngineVersion(v: String?) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET engine_version = ? WHERE id = ?").use { ps ->
                ps.setString(1, v)
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun decide(sql: String): EnfAction {
        val ds = fx.datasourceStore.get(fx.datasource.id)!! // re-fetch so ds.engineVersion reflects setEngineVersion
        return decideQuery(
            principal = principal, ds = ds, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        ).action
    }

    @Test
    fun `a column classification may name a product system tag but not invent one`() {
        // The six names the product defines are writable on anything; an invented `system:` name is
        // refused. A column carrying `system:critical` reaches the shipped critical forbid like any other
        // tag, which denies it — the write is honest about what it asks for.
        val ex = assertFailsWith<ManagementException> {
            fx.datasourceStore.upsertClassification(
                fx.datasource.id,
                ClassificationInput(schema = "public", table = "users", column = "ssn", tags = listOf("pii", "system:invented")),
            )
        }
        assertEquals("datasource.reserved_tag", ex.error.code, "the refusal must use the one shared error code")
        assertEquals("system:invented", ex.error.params["tag"], "and must name the offending tag: ${ex.error.params}")

        // A product `system:` name writes fine — it is a tag like any other.
        val product = fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(schema = "public", table = "users", column = "ssn", tags = listOf("pii", "system:critical")),
        )
        assertEquals(listOf("pii", "system:critical"), product.tags)

        // And an ordinary tag, the common case.
        val ok = fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(schema = "public", table = "users", column = "ssn", tags = listOf("pii")),
        )
        assertEquals(listOf("pii"), ok.tags)
    }

    @Test
    fun `on a PG-17 datasource, catalog structure browses and dangerous surfaces deny`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        // system:catalog — structure is browsable (the shipped system:catalog permit), via the table gate
        // (count(*)) AND the column path (a projected column inherits the Table's system:catalog tag).
        assertEquals(EnfAction.ALLOW, decide("select count(*) from pg_catalog.pg_class"), "pg_class (system:catalog) must browse")
        assertEquals(EnfAction.ALLOW, decide("select relname from pg_catalog.pg_class"), "a system:catalog column must read")
        // dangerous tags — forbidden on the production floor by the shipped forbids (critical/data-leak/activity)
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_authid"), "pg_authid (system:critical) must deny")
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_stats"), "pg_stats (system:data-leak) must deny")
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_stat_activity"), "pg_stat_activity (system:activity) must deny")
    }

    @Test
    fun `the dangerous forbids override even a broad datasource read grant`() {
        // The DENY cases above are deny-by-default for the ungranted analyst. This case makes the forbids
        // LOAD-BEARING: a principal with a broad any-action grant on the whole datasource. Without the shipped
        // forbids the dangerous tags would ALLOW via that grant; with them, Cedar's forbid overrides the permit.
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val broad = "broad@example.com"
        val role = fx.policyStore.createRole(RoleInput("broad-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-broad-reader-grant",
                cedarSrc = """permit(principal in Role::"broad-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fun decideAs(who: String, sql: String) = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        ).action
        // The broad grant genuinely permits: system:catalog browses.
        assertEquals(EnfAction.ALLOW, decideAs(broad, "select count(*) from pg_catalog.pg_class"), "broad grant permits system:catalog")
        // ...but the shipped forbids OVERRIDE that broad grant on every dangerous tag (production floor).
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_authid"), "critical forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_stats"), "data-leak forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_stat_activity"), "activity forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select rolname from pg_catalog.pg_authid"), "forbid overrides on the column path too")
    }

    @Test
    fun `without an engine_version, system schemas stay deny-by-default`() {
        setEngineVersion(null)
        // No version → no manifest → no system tag → the object is ungranted → deny-by-default (safe).
        // Even the otherwise-open pg_class is denied because there is no classification to permit it.
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_class"), "no version → no system:catalog permit → deny")
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_authid"), "no version → still denied (fail-closed)")
    }

    // A query calling a dangerous builtin is DENIED by the shipped system:data-leak/critical
    // forbid, via the Cedar Function resource the classifier marshals from the emitted bare call name.
    // These functions (pg_terminate_backend/get_raw_page) are NOT in the dangerousFuncs admission backstop,
    // so the DENY here proves the POLICY path — the net-new coverage — not the pre-existing hardcode. The
    // FROM clause lets the statement pass admission (the no-FROM guard) and reach the function gate; the
    // table (pg_class, system:catalog) is itself browsable, so absent the function the query would ALLOW.
    @Test
    fun `a dangerous system function denies by policy on a versioned datasource`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        // Safe baseline: the same browsable table with a SAFE function still ALLOWs — the gate is specific
        // to dangerous functions, it does not deny every function.
        assertEquals(EnfAction.ALLOW, decide("select now() from pg_catalog.pg_class"), "a safe function must not trip the gate")
        // critical (pg_catalog exact, net-new vs dangerousFuncs) and data-leak (pageinspect *) both deny.
        assertEquals(EnfAction.DENY, decide("select pg_terminate_backend(1) from pg_catalog.pg_class"), "pg_terminate_backend (system:critical) must deny by policy")
        assertEquals(EnfAction.DENY, decide("select get_raw_page('pg_class', 0) from pg_catalog.pg_class"), "get_raw_page (system:data-leak) must deny by policy")
        // No version → no classification → the function gate is inert (this DENY is deny-by-default for the
        // ungranted table scan, not the function forbid — proven by the safe-baseline ALLOW above flipping).
        setEngineVersion(null)
        assertEquals(EnfAction.DENY, decide("select now() from pg_catalog.pg_class"), "no version → table scan itself denies (function gate inert)")
    }

    @Test
    fun `the dangerous function forbid overrides even a broad datasource read grant`() {
        // Load-bearing forbid, mirroring the table case: a principal with a broad any-action grant on the
        // whole datasource. The broad grant permits the browsable table AND (via the Datasource parent) the
        // Function resource, but Cedar's forbid on system:critical/data-leak overrides the permit → DENY.
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val broad = "broad-fn@example.com"
        val role = fx.policyStore.createRole(RoleInput("broad-fn-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-broad-fn-reader-grant",
                cedarSrc = """permit(principal in Role::"broad-fn-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fun decideAs(who: String, sql: String) = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        ).action
        // The broad grant genuinely permits: a safe function over the table ALLOWs.
        assertEquals(EnfAction.ALLOW, decideAs(broad, "select now() from pg_catalog.pg_class"), "broad grant permits a safe function")
        // ...but the forbid OVERRIDES that broad grant on a dangerous function (critical AND data-leak).
        assertEquals(EnfAction.DENY, decideAs(broad, "select pg_terminate_backend(1) from pg_catalog.pg_class"), "forbid overrides the broad grant (critical function)")
        assertEquals(EnfAction.DENY, decideAs(broad, "select get_raw_page('pg_class', 0) from pg_catalog.pg_class"), "forbid overrides the broad grant (data-leak function)")
    }

    // Regression: the dangerous-function gate runs FIRST — ahead of the uncovered-table
    // gate — so when a query would trip BOTH, the DENY attributes to the dangerous function, not to a bland
    // uncovered-table scan. `get_raw_page('users',0) from users` traces no column, so `users` scans uncovered;
    // a principal with connect+select but NO table read reaches BOTH gates, so the winning deny reason is
    // observable. Both orderings deny, but only the function-first ordering names the function — the clearer
    // audit/approval reason, and a guard that the function gate isn't dropped or reordered below the data gates.
    @Test
    fun `the dangerous-function deny wins over the uncovered-table deny`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val who = "fngate@example.com"
        val role = fx.policyStore.createRole(RoleInput("fngate-connect-only"))
        fx.policyStore.createAssignment(RoleAssignmentInput(who, role.id))
        // connect + select ONLY — no table read on `users`, so the uncovered-table gate WOULD also deny.
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-fngate-connect-select",
                cedarSrc = """permit(principal in Role::"fngate-connect-only", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val ctx = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!,
            sql = "select get_raw_page('users', 0) from users", channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        )
        assertEquals(EnfAction.DENY, ctx.action)
        val reason = ctx.denyReason.orEmpty()
        assertTrue("get_raw_page" in reason, "the deny reason must name the dangerous function (function gate first): $reason")
        assertFalse("no read grant for scanned table" in reason, "the uncovered-table gate must NOT win — the function gate runs first: $reason")
    }
}
