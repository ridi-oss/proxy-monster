package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
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
 * with NO version resolves to no manifest, so its fixed system schemas stay closed: an explicitly-dangerous
 * table keeps its tag, and any unrecognized/catalog-default one is treated as critical and denied even under
 * a broad grant — fail-closed, since an unrecognized system table cannot be assumed benign catalog metadata.
 * Running this test also proves the shipped SYSTEM policies compile against
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

    private fun decideContext(
        sql: String,
        who: String = principal,
        postgresSystemXidVisible: Boolean? = null,
    ) = decideQuery(
        principal = who,
        ds = fx.datasourceStore.get(fx.datasource.id)!!,
        sql = sql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        postgresSystemXidVisible = postgresSystemXidVisible,
        systemClassification = classifier,
    )

    private fun decide(sql: String): EnfAction = decideContext(sql).action

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
    fun `only the transaction id column of pg_locks is catalog-readable`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val decision = decideContext(
            """select L.transactionid::varchar::bigint as transaction_id
                |from pg_catalog.pg_locks L
                |where L.transactionid is not null
                |order by pg_catalog.age(L.transactionid) desc
                |limit 1
            """.trimMargin(),
        )
        assertEquals(EnfAction.ALLOW, decision.action)
        assertEquals(null, decision.rewrittenSql, "the target DB must execute the original query")
        assertEquals(EnfAction.DENY, decide("select pid from pg_catalog.pg_locks"))
        assertEquals(EnfAction.DENY, decide("select transactionid, pid from pg_catalog.pg_locks"))
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_locks"))
    }

    @Test
    fun `foreign catalog metadata stays browsable while credential options are always null`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        assertEquals(EnfAction.ALLOW, decide("select oid, srvname from pg_catalog.pg_foreign_server"))
        val star = decideContext("select * from pg_catalog.pg_foreign_server")
        assertEquals(EnfAction.MASK, star.action)
        assertTrue(star.rewrittenSql != null)
        assertEquals("srvoptions", star.masks.single().column)
        assertEquals(7, star.masks.single().ordinal)
        assertEquals("NULL", star.masks.single().kind)

        for ((table, key, option) in listOf(
            Triple("pg_foreign_data_wrapper", "oid", "fdwoptions"),
            Triple("pg_foreign_server", "oid", "srvoptions"),
            Triple("pg_user_mapping", "oid", "umoptions"),
            Triple("pg_foreign_table", "ftrelid", "ftoptions"),
        )) {
            val output = decideContext("select $key, $option from pg_catalog.$table")
            assertEquals(EnfAction.MASK, output.action, "$table.$option output must be redacted")
            val mask = output.masks.single()
            assertEquals(option, mask.column)
            assertEquals("redact", mask.maskFn)
            assertEquals("NULL", mask.kind)

            assertEquals(
                EnfAction.DENY,
                decide("select $key from pg_catalog.$table where $option is not null"),
                "$table.$option must not affect row selection",
            )
            assertEquals(
                EnfAction.DENY,
                decide("select $key from pg_catalog.$table order by $option"),
                "$table.$option must not affect row order",
            )
        }

        val dataGrip = decideContext(
            """select ft.ftrelid as table_id,
                |       srv.srvname as table_server,
                |       ft.ftoptions as table_options,
                |       pg_catalog.pg_get_userbyid(cls.relowner) as "owner"
                |from pg_catalog.pg_foreign_table ft
                |     left outer join pg_catalog.pg_foreign_server srv on ft.ftserver = srv.oid
                |     join pg_catalog.pg_class cls on ft.ftrelid = cls.oid
                |where cls.relnamespace = 2200::oid
                |  and pg_catalog.age(ft.xmin) <= coalesce(
                |      nullif(greatest(pg_catalog.age('0'::varchar::xid), -1), -1),
                |      2147483647
                |  )
                |order by table_id
            """.trimMargin(),
            postgresSystemXidVisible = true,
        )
        assertEquals(EnfAction.MASK, dataGrip.action)
        val mask = dataGrip.masks.single()
        assertEquals("table_options", mask.column)
        assertEquals("redact", mask.maskFn)
        assertEquals("NULL", mask.kind)
    }

    @Test
    fun `forced redaction dominates an ordinary mask on the same set-operation output`() {
        fx.execOnTarget("create schema app")
        fx.execOnTarget("create table app.secrets (secret_options text[])")
        fx.datasourceStore.pushTestCatalog(
            fx.datasource,
            fx.targetJdbcUrl,
            fx.targetUser,
            fx.targetPassword,
        )
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val last4 = fx.policyStore.getMaskFnByName("last4")!!
        fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(
                schema = "app",
                table = "secrets",
                column = "secret_options",
                tags = listOf("pii"),
                maskFnId = last4.id,
            ),
        )
        val secret = fx.datasourceStore.catalog(fx.datasource.id).single {
            it.schema == "app" && it.table == "secrets" && it.column == "secret_options"
        }
        val tableEuid = listOf(
            fx.datasource.name,
            secret.catalog,
            secret.schema,
            secret.table,
        ).joinToString("/")
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-union-secret-mask",
                cedarSrc =
                    """permit(principal in Role::"${fx.role}", action == Action::"result.read.masked", resource in Table::"$tableEuid") when { resource in Tag::"pii" };""",
            ),
            updatedBy = "test",
        )

        val sql =
            """select secret_options as value from app.secrets
                |union all
                |select srvoptions from pg_catalog.pg_foreign_server
            """.trimMargin()
        fx.execOnTarget(sql)
        val output = decideContext(sql)
        assertEquals(EnfAction.MASK, output.action, output.detail)
        val mask = output.masks.single()
        assertEquals(0, mask.ordinal)
        assertEquals("value", mask.column)
        assertEquals("redact", mask.maskFn)
        assertEquals("NULL", mask.kind)
    }

    @Test
    fun `forced redaction does not override a Cedar denial`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val who = "redaction-denied@example.com"
        val srvoptions = fx.datasourceStore.catalog(fx.datasource.id).single {
            it.schema == "pg_catalog" && it.table == "pg_foreign_server" && it.column == "srvoptions"
        }
        val columnEuid = listOf(
            fx.datasource.name,
            srvoptions.catalog,
            srvoptions.schema,
            srvoptions.table,
            srvoptions.column,
        ).joinToString("/")
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-redaction-reader",
                cedarSrc = """permit(principal == User::"$who", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-redaction-column-forbid",
                cedarSrc = """forbid(principal == User::"$who", action, resource == Column::"$columnEuid");""",
            ),
            updatedBy = "test",
        )

        assertEquals(EnfAction.ALLOW, decideContext("select oid from pg_catalog.pg_foreign_server", who).action)
        val denied = decideContext("select srvoptions from pg_catalog.pg_foreign_server", who)
        assertEquals(EnfAction.DENY, denied.action)
        assertTrue(denied.detail?.contains("policy denies column") == true)
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
        fun decideAsContext(who: String, sql: String) = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        )
        fun decideAs(who: String, sql: String) = decideAsContext(who, sql).action
        // The broad grant genuinely permits: system:catalog browses.
        assertEquals(EnfAction.ALLOW, decideAs(broad, "select count(*) from pg_catalog.pg_class"), "broad grant permits system:catalog")
        val redacted = decideAsContext(broad, "select oid, srvoptions from pg_catalog.pg_foreign_server")
        assertEquals(EnfAction.MASK, redacted.action, "a broad unmasked grant cannot expose srvoptions")
        assertEquals("NULL", redacted.masks.single().kind)
        assertFalse(redacted.unmaskablePermitted, "mandatory redaction cannot be bypassed on a binary wire path")
        val redactedForeignTable = decideAsContext(broad, "select ftrelid, ftoptions from pg_catalog.pg_foreign_table")
        assertEquals(EnfAction.MASK, redactedForeignTable.action, "a broad unmasked grant cannot expose ftoptions")
        assertEquals("NULL", redactedForeignTable.masks.single().kind)
        assertFalse(redactedForeignTable.unmaskablePermitted, "mandatory redaction cannot be bypassed on a binary wire path")
        assertEquals(EnfAction.ALLOW, decideAs(broad, "select transactionid from pg_catalog.pg_locks"))
        assertEquals(EnfAction.DENY, decideAs(broad, "select pid from pg_catalog.pg_locks"))
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_locks"))
        // ...but the shipped forbids OVERRIDE that broad grant on every dangerous tag (production floor).
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_authid"), "critical forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_stats"), "data-leak forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_stat_activity"), "activity forbid overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select rolname from pg_catalog.pg_authid"), "forbid overrides on the column path too")
    }

    @Test
    fun `mandatory system redaction disables unmaskable relay alongside an ordinary derived mask`() {
        setEngineVersion("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")
        val who = "mixed-redaction@example.com"
        val role = fx.policyStore.createRole(RoleInput("mixed-redaction-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(who, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-mixed-redaction-reader-grant",
                cedarSrc = """permit(principal in Role::"mixed-redaction-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-mixed-redaction-reader-pii-forbid",
                cedarSrc = """forbid(principal in Role::"mixed-redaction-reader", action == Action::"result.read.unmasked", resource) when { resource in Tag::"pii" };""",
            ),
            updatedBy = "test",
        )

        val mixed = decideContext(
            "select lower(u.ssn), s.srvoptions from public.users u cross join pg_catalog.pg_foreign_server s",
            who,
        )
        assertEquals(EnfAction.MASK, mixed.action, mixed.denyReason)
        assertEquals(listOf(0, 1), mixed.masks.sortedBy { it.ordinal }.map { it.ordinal })
        assertEquals(listOf("NULL", "NULL"), mixed.masks.sortedBy { it.ordinal }.map { it.kind })
        assertFalse(mixed.unmaskablePermitted)
    }

    @Test
    fun `without an engine_version, fixed system schemas stay closed`() {
        setEngineVersion(null)
        // No manifest governs, so a fixed system schema is closed: an unrecognized/catalog-default table
        // (pg_class) is treated as critical and denied, and pg_authid is denied too. Fail-closed — an
        // unrecognized fixed-system table cannot be assumed benign catalog metadata.
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_class"), "no version → pg_class treated as critical → denied")
        assertEquals(EnfAction.DENY, decide("select count(*) from pg_catalog.pg_authid"), "no version → pg_authid denied")
        assertEquals(EnfAction.DENY, decide("select oid from pg_catalog.pg_foreign_server"), "no version → foreign metadata stays closed")
    }

    @Test
    fun `without an engine_version, the floor still forbids a system table under a broad datasource grant`() {
        // The advisory case (GHSA-j984-q948-4xq8): a datasource with no governing manifest, a broad Datasource
        // read grant, and a query on a fixed system table. Before the floor, pg_authid was untagged and the
        // broad grant read it; the floor now tags it system:critical so the shipped forbid overrides the grant.
        setEngineVersion(null)
        val broad = "broad-nomanifest@example.com"
        val role = fx.policyStore.createRole(RoleInput("broad-nomanifest-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-broad-nomanifest-grant",
                cedarSrc = """permit(principal in Role::"broad-nomanifest-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        fun decideAs(who: String, sql: String) = decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        ).action
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_authid"), "no-manifest critical floor overrides the broad grant")
        assertEquals(EnfAction.DENY, decideAs(broad, "select rolname from pg_catalog.pg_authid"), "and on the column path too")
        // And an unrecognized/catalog-default fixed-system table is closed under the same grant — the fix does
        // not open the -100 catalog permit to unclassified system relations on an unmanifested datasource.
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from pg_catalog.pg_class"), "no-manifest pg_class is closed, not browsable")
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
        // No version → the fixed system table itself is closed (pg_class treated as critical), so even a safe
        // function over it denies at the table gate — the function gate is not reached.
        setEngineVersion(null)
        assertEquals(EnfAction.DENY, decide("select now() from pg_catalog.pg_class"), "no version → pg_class closed → table scan denies")
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
