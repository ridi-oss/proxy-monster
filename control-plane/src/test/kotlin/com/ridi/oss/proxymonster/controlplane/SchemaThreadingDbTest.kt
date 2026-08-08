package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.decideAndAudit
import com.ridi.oss.proxymonster.controlplane.support.execOnTarget
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.runEnforcedForTest
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.Connection
import java.sql.DriverManager
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private const val READER_PRINCIPAL = "schema-reader@example.com"
private const val WRITER_PRINCIPAL = "schema-writer@example.com"
private const val READER_ROLE = "schema-reader"
private const val WRITER_ROLE = "schema-writer"

data class SchemaThreadingFixture(
    val engine: String,
    val datasource: Datasource,
    // The shared enforcement graph; decideAndAudit takes this directly. The individual store/authz
    // fields below are the SAME instances (derived from `core`) so decideAndAudit and the editor-path
    // helpers agree.
    val core: ControlPlaneCore,
    val datasourceStore: DatasourceStore,
    val policyStore: PolicyStore,
    val auditStore: AuditStore,
    val accessStore: AccessStore,
    val userGroupStore: UserGroupStore,
    val roleResolver: RoleResolver,
    val authz: Authz,
    val targetJdbcUrl: String,
    val targetUser: String,
    val targetPassword: String,
    val catalog: String,
    val defaultSchema: String,
    val analyticsSchema: String,
    val defaultRrn: String,
    val analyticsRrn: String,
) {
    val defaultTable: String get() = "$defaultSchema.users"
    val analyticsTable: String get() = "$analyticsSchema.users"

    fun run(sql: String, principal: String = READER_PRINCIPAL): QueryResponse = runEnforcedForTest(
        principal = principal,
        ds = datasource,
        sql = sql,
        maxRows = 100,
        clientAddr = "127.0.0.1",
        datasourceStore = datasourceStore,
        policyStore = policyStore,
        auditStore = auditStore,
        accessStore = accessStore,
        userGroupStore = userGroupStore,
        roleResolver = roleResolver,
        authz = authz,
        execute = { sql, maxRows -> execOnTarget(targetJdbcUrl, targetUser, targetPassword, sql, maxRows) },
    )

    fun decide(
        sql: String,
        principal: String = WRITER_PRINCIPAL,
        liveSearchPath: List<String>? = null,
    ): DecisionContext = decideQuery(
        principal = principal,
        ds = datasource,
        sql = sql,
        channel = Channel.EDITOR,
        catalog = datasourceStore.catalog(datasource.id),
        policyStore = policyStore,
        accessStore = accessStore,
        userGroupStore = userGroupStore,
        roleResolver = roleResolver,
        authz = authz,
        liveSearchPath = liveSearchPath,
    )

    fun rowJson(table: String): String = if (engine == "postgres") {
        "select row_to_json(u) from $table u"
    } else {
        "select json_object('id', u.id, 'email', u.email, 'rrn', u.rrn, 'region', u.region) from $table u"
    }

    fun aliasOrComposite(table: String): String = if (engine == "postgres") {
        "select (u).rrn as exposed_rrn from $table u"
    } else {
        "select u.rrn as exposed_rrn from $table u"
    }

    fun protectedUpdateSql(): String = if (engine == "postgres") {
        "update users set rrn = rrn || '-blocked' where rrn = '$defaultRrn'"
    } else {
        "update users set rrn = concat(rrn, '-blocked') where rrn = '$defaultRrn'"
    }

    fun analyticsUpdateSql(): String = if (engine == "postgres") {
        "update $analyticsTable set rrn = rrn || '-allowed' where rrn = '$analyticsRrn'"
    } else {
        "update $analyticsTable set rrn = concat(rrn, '-allowed') where rrn = '$analyticsRrn'"
    }

    /** Execute a real UPDATE, observe its mutation, roll it back, then verify a fresh connection sees no mutation. */
    fun executeRolledBack(sql: String, table: String, before: String, after: String) {
        DriverManager.getConnection(targetJdbcUrl, targetUser, targetPassword).use { c ->
            c.autoCommit = false
            try {
                val count = c.createStatement().use { it.executeUpdate(sql) }
                assertTrue(count > 0, "expected a row-affecting backend UPDATE, count=$count: $sql")
                assertEquals(after, readRrn(c, table), "the backend did not execute the claimed mutation: $sql")
            } finally {
                c.rollback()
            }
        }
        DriverManager.getConnection(targetJdbcUrl, targetUser, targetPassword).use { c ->
            assertEquals(before, readRrn(c, table), "the test UPDATE escaped its rollback: $sql")
        }
    }

    private fun readRrn(c: Connection, table: String): String = c.createStatement().use { st ->
        st.executeQuery("select rrn from $table where id = 1").use { rs ->
            assertTrue(rs.next(), "missing seeded row in $table")
            rs.getString(1)
        }
    }
}

object SchemaThreadingFixtures {
    fun postgres(): SchemaThreadingFixture {
        val stores = metadataStores()
        val database = SharedPostgres.freshDatabase("pm_schema_target")
        val defaultRrn = "PG_DEFAULT_RRN_1111"
        val analyticsRrn = "PG_ANALYTICS_RRN_9999"
        val jdbcUrl = SharedPostgres.jdbcUrlFor(database)
        DriverManager.getConnection(jdbcUrl, SharedPostgres.username(), SharedPostgres.password()).use { c ->
            c.createStatement().use { st ->
                st.execute("CREATE SCHEMA analytics")
                createUsers(st, "public.users", defaultRrn)
                createUsers(st, "analytics.users", analyticsRrn)
            }
        }
        val created = stores.datasourceStore.create(
            DatasourceInput(
                name = "schema-pg",
                engine = "postgres",
                host = SharedPostgres.host(),
                port = SharedPostgres.port(),
                dbName = database,
            ),
        )
        return finish(
            stores = stores,
            created = created,
            targetJdbcUrl = jdbcUrl,
            targetUser = SharedPostgres.username(),
            targetPassword = SharedPostgres.password(),
            catalog = database,
            defaultSchema = "public",
            analyticsSchema = "analytics",
            defaultRrn = defaultRrn,
            analyticsRrn = analyticsRrn,
        )
    }

    fun mysql(): SchemaThreadingFixture {
        val stores = metadataStores()
        val database = SharedMySql.freshDatabase("pm_schema_app")
        val analytics = SharedMySql.freshDatabase("pm_schema_analytics")
        val defaultRrn = "MYSQL_DEFAULT_RRN_2222"
        val analyticsRrn = "MYSQL_ANALYTICS_RRN_8888"
        DriverManager.getConnection(SharedMySql.jdbcUrlFor(database), SharedMySql.username(), SharedMySql.password()).use { c ->
            c.createStatement().use { st -> createUsers(st, "$database.users", defaultRrn) }
        }
        DriverManager.getConnection(SharedMySql.jdbcUrlFor(analytics), SharedMySql.username(), SharedMySql.password()).use { c ->
            c.createStatement().use { st -> createUsers(st, "$analytics.users", analyticsRrn) }
        }
        val created = stores.datasourceStore.create(
            DatasourceInput(
                name = "schema-mysql",
                engine = "mysql",
                host = SharedMySql.host(),
                port = SharedMySql.port(),
                dbName = database,
            ),
        )
        return finish(
            stores = stores,
            created = created,
            targetJdbcUrl = SharedMySql.jdbcUrlFor(database),
            targetUser = SharedMySql.username(),
            targetPassword = SharedMySql.password(),
            catalog = "def",
            defaultSchema = database,
            analyticsSchema = analytics,
            defaultRrn = defaultRrn,
            analyticsRrn = analyticsRrn,
        )
    }

    private fun createUsers(st: java.sql.Statement, table: String, rrn: String) {
        st.execute("CREATE TABLE $table (id BIGINT PRIMARY KEY, email VARCHAR(64), rrn VARCHAR(128), region VARCHAR(16))")
        st.execute("INSERT INTO $table VALUES (1, 'sentinel@example.com', '$rrn', 'KR')")
    }

    private fun finish(
        stores: MetaStores,
        created: Datasource,
        targetJdbcUrl: String,
        targetUser: String,
        targetPassword: String,
        catalog: String,
        defaultSchema: String,
        analyticsSchema: String,
        defaultRrn: String,
        analyticsRrn: String,
    ): SchemaThreadingFixture {
        stores.datasourceStore.pushTestCatalog(created, targetJdbcUrl, targetUser, targetPassword)
        val refreshed = stores.datasourceStore.get(created.id)
            ?: error("datasource disappeared after catalog push")
        val schemas = stores.datasourceStore.catalog(created.id)
            .filter { it.table == "users" }
            .map { it.schema }
            .toSet()
        check(defaultSchema in schemas) { "catalog push missed default schema $defaultSchema: $schemas" }
        check(analyticsSchema in schemas) { "catalog push missed analytics schema $analyticsSchema: $schemas" }

        val maskFn = stores.policyStore.createMaskFn(MaskFnInput("schema-last4", "LAST_N"))
        stores.datasourceStore.upsertClassification(
            created.id,
            ClassificationInput(
                schema = defaultSchema,
                table = "users",
                column = "rrn",
                tags = listOf("pii"),
                maskFnId = maskFn.id,
            ),
        )

        val defaultTableEuid = "${created.name}/$catalog/$defaultSchema/users"
        val analyticsTableEuid = "${created.name}/$catalog/$analyticsSchema/users"
        seedRole(
            stores,
            roleName = READER_ROLE,
            principal = READER_PRINCIPAL,
            datasourceName = created.name,
            sqlActions = listOf("stmt.cat.read"),
            defaultTableEuid = defaultTableEuid,
            analyticsTableEuid = analyticsTableEuid,
        )
        seedRole(
            stores,
            roleName = WRITER_ROLE,
            principal = WRITER_PRINCIPAL,
            datasourceName = created.name,
            sqlActions = listOf("stmt.cat.write.update", "stmt.cat.write.insert"),
            defaultTableEuid = defaultTableEuid,
            analyticsTableEuid = analyticsTableEuid,
        )

        // One shared graph for the fixture (policies were seeded above via `stores`, i.e. committed to
        // the same DB, so this core reads them on its first decision).
        val core = ControlPlaneCore(stores.metadata)
        return SchemaThreadingFixture(
            engine = created.engine.wireName,
            datasource = refreshed,
            core = core,
            datasourceStore = core.datasourceStore,
            policyStore = core.policyStore,
            auditStore = core.auditStore,
            accessStore = core.accessStore,
            userGroupStore = core.userGroupStore,
            roleResolver = core.roleResolver,
            authz = core.authz,
            targetJdbcUrl = targetJdbcUrl,
            targetUser = targetUser,
            targetPassword = targetPassword,
            catalog = catalog,
            defaultSchema = defaultSchema,
            analyticsSchema = analyticsSchema,
            defaultRrn = defaultRrn,
            analyticsRrn = analyticsRrn,
        )
    }

    private fun seedRole(
        stores: MetaStores,
        roleName: String,
        principal: String,
        datasourceName: String,
        sqlActions: List<String>,
        defaultTableEuid: String,
        analyticsTableEuid: String,
    ) {
        val role = stores.policyStore.createRole(RoleInput(roleName))
        stores.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        val kindActions = (listOf("datasource.connect") + sqlActions).joinToString(", ") { """Action::"$it"""" }
        stores.createPolicy(
            "$roleName-connect-kind",
            """permit(principal in Role::"$roleName", action in [$kindActions], resource in Datasource::"$datasourceName");""",
        )
        stores.createPolicy(
            "$roleName-default-unmasked",
            """permit(principal in Role::"$roleName", action == Action::"result.read.unmasked", resource in Table::"$defaultTableEuid") unless { resource in Tag::"pii" };""",
        )
        stores.createPolicy(
            "$roleName-default-masked",
            """permit(principal in Role::"$roleName", action == Action::"result.read.masked", resource in Table::"$defaultTableEuid") when { resource in Tag::"pii" };""",
        )
        stores.createPolicy(
            "$roleName-analytics-unmasked",
            """permit(principal in Role::"$roleName", action == Action::"result.read.unmasked", resource in Table::"$analyticsTableEuid");""",
        )
    }

    private fun metadataStores(): MetaStores {
        val metadata = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_schema_meta"))
        Flyway.configure().dataSource(metadata).load().migrate()
        return MetaStores(
            metadata = metadata,
            datasourceStore = DatasourceStore(metadata),
            policyStore = PolicyStore(metadata),
            auditStore = AuditStore(metadata),
            accessStore = AccessStore(metadata),
            userGroupStore = UserGroupStore(metadata),
            cedarPolicyStore = CedarPolicyStore(metadata),
        )
    }

    private data class MetaStores(
        val metadata: DataSource,
        val datasourceStore: DatasourceStore,
        val policyStore: PolicyStore,
        val auditStore: AuditStore,
        val accessStore: AccessStore,
        val userGroupStore: UserGroupStore,
        val cedarPolicyStore: CedarPolicyStore,
    ) {
        fun createPolicy(name: String, source: String) {
            cedarPolicyStore.create(CedarPolicyInput(name, source), updatedBy = "schema-threading-test")
        }
    }
}

/** Shared live-backend contract, run once against PostgreSQL and once against MySQL. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class SchemaThreadingDbContract {
    protected lateinit var fx: SchemaThreadingFixture

    protected abstract fun createFixture(): SchemaThreadingFixture

    @BeforeAll
    fun setupSchemaThreadingFixture() {
        requireDockerOrSkip()
        fx = createFixture()
    }

    @Test
    fun `explicit default schema masks while explicit analytics stays unmasked`() {
        val protected = fx.run("select id, rrn from ${fx.defaultTable} order by id")
        assertEquals(EnfAction.MASK, protected.decision, "reason=${protected.denyReason}")
        assertEquals(1, protected.rows.size)
        assertNoCleartext(protected, fx.defaultRrn)

        val analytics = fx.run("select id, rrn from ${fx.analyticsTable} order by id")
        assertEquals(EnfAction.ALLOW, analytics.decision, "reason=${analytics.denyReason}")
        assertEquals(fx.analyticsRrn, analytics.rows.single()[1])
        assertNotEquals(fx.defaultRrn, analytics.rows.single()[1])
    }

    @Test
    fun `bare users resolves to the captured default namespace and masks`() {
        val response = fx.run("select rrn from users")
        assertEquals(EnfAction.MASK, response.decision, "reason=${response.denyReason}")
        assertNoCleartext(response, fx.defaultRrn)
    }

    @Test
    fun `unknown table schema and foreign catalog deny without rows`() {
        val sql = listOf(
            "select rrn from missing_users",
            "select rrn from missing_schema.users",
            "select rrn from foreign_catalog.${fx.defaultSchema}.users",
        )
        for (query in sql) {
            val response = fx.run(query)
            assertEquals(EnfAction.DENY, response.decision, "must fail closed: $query; reason=${response.denyReason}")
            assertTrue(response.rows.isEmpty(), "a denied query returned rows: $query")
        }
    }

    @Test
    fun `qualified star preserves schema-specific classification`() {
        val protected = fx.run("select u.* from ${fx.defaultTable} u")
        assertEquals(EnfAction.MASK, protected.decision, "reason=${protected.denyReason}")
        assertNoCleartext(protected, fx.defaultRrn)

        val analytics = fx.run("select u.* from ${fx.analyticsTable} u")
        assertEquals(EnfAction.ALLOW, analytics.decision, "reason=${analytics.denyReason}")
        assertTrue(analytics.rows.flatten().contains(fx.analyticsRrn), "analytics sentinel was not returned unchanged")
    }

    @Test
    fun `whole-row JSON cannot bypass default PII and analytics does not inherit it`() {
        val protected = fx.run(fx.rowJson(fx.defaultTable))
        assertEquals(EnfAction.DENY, protected.decision, "whole-row PII is not field-maskable: ${protected.denyReason}")
        assertTrue(protected.denyReason?.contains("rrn") == true, "whole-row deny did not trace the protected field: ${protected.denyReason}")
        assertNoCleartext(protected, fx.defaultRrn)

        val analytics = fx.run(fx.rowJson(fx.analyticsTable))
        assertEquals(EnfAction.ALLOW, analytics.decision, "reason=${analytics.denyReason}")
        assertTrue(analytics.rows.flatten().any { it?.contains(fx.analyticsRrn) == true })
    }

    @Test
    fun `alias or composite resolution keeps the physical schema identity`() {
        val protected = fx.run(fx.aliasOrComposite(fx.defaultTable))
        assertTrue(
            protected.decision == EnfAction.MASK || protected.decision == EnfAction.DENY,
            "default alias/composite read must be protected; reason=${protected.denyReason}",
        )
        if (protected.decision == EnfAction.DENY) {
            assertTrue(protected.denyReason?.contains("rrn") == true, "composite deny did not trace rrn: ${protected.denyReason}")
        }
        assertNoCleartext(protected, fx.defaultRrn)

        val analytics = fx.run(fx.aliasOrComposite(fx.analyticsTable))
        assertEquals(EnfAction.ALLOW, analytics.decision, "reason=${analytics.denyReason}")
        assertEquals(fx.analyticsRrn, analytics.rows.single().single())
    }

    @Test
    fun `protected bare-target update is valid and mutating on the backend but enforcement denies it`() {
        val sql = fx.protectedUpdateSql()
        fx.executeRolledBack(sql, fx.defaultTable, fx.defaultRrn, "${fx.defaultRrn}-blocked")

        val decision = fx.decide(sql)
        assertEquals(EnfAction.DENY, decision.action, "protected UPDATE was admitted: $sql")
        assertTrue(decision.denyReason?.contains("rrn") == true, "deny reason did not identify the protected read: ${decision.denyReason}")
    }

    @Test
    fun `explicit analytics update is allowed executes and rolls back without persistence`() {
        val original = fx.analyticsUpdateSql()
        val decision = fx.decide(original)
        assertEquals(EnfAction.ALLOW, decision.action, "reason=${decision.denyReason}")

        val executable = decision.rewrittenSql ?: original
        fx.executeRolledBack(executable, fx.analyticsTable, fx.analyticsRrn, "${fx.analyticsRrn}-allowed")
    }

    private fun assertNoCleartext(response: QueryResponse, cleartext: String) {
        assertTrue(
            response.rows.flatten().none { it?.contains(cleartext) == true },
            "cleartext sentinel leaked in ${response.rows}",
        )
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SchemaThreadingPostgresDbTest : SchemaThreadingDbContract() {
    override fun createFixture(): SchemaThreadingFixture = SchemaThreadingFixtures.postgres()

    @Test
    fun `live search path pivots unqualified resolution without changing the default`() {
        val default = fx.decide("SELECT rrn FROM users", principal = READER_PRINCIPAL)
        assertEquals(EnfAction.MASK, default.action, "reason=${default.denyReason}")

        val analytics = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf("analytics"),
        )
        assertEquals(EnfAction.ALLOW, analytics.action, "reason=${analytics.denyReason}")
        assertTrue(analytics.masks.isEmpty())

        val public = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf("public"),
        )
        assertEquals(EnfAction.MASK, public.action, "reason=${public.denyReason}")
    }

    @Test
    fun `invalid or unresolvable live search paths fail closed`() {
        val empty = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = emptyList(),
        )
        assertEquals(EnfAction.DENY, empty.action)
        assertEquals("catalog", empty.failedStage)

        val blank = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf(" "),
        )
        assertEquals(EnfAction.DENY, blank.action)
        assertEquals("catalog", blank.failedStage)

        val unknown = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf("no_such_schema"),
        )
        assertEquals(EnfAction.DENY, unknown.action)
    }

    @Test
    fun `missing pg-temp catalog entry skips to the next live search path schema`() {
        val decision = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf("pg_temp_3", "public"),
        )
        assertEquals(EnfAction.MASK, decision.action, "reason=${decision.denyReason}")
    }

    @Test
    fun `decideAndAudit threads and audits the live search path`() {
        val analyticsSql = "SELECT rrn FROM users /* route_analytics */"
        val (analyticsDecision, _) = decideAndAudit(
            fx.core, READER_PRINCIPAL, fx.datasource, analyticsSql, listOf("analytics"), clientAddr = null,
        )
        assertEquals(EnfAction.ALLOW, analyticsDecision.action, "reason=${analyticsDecision.denyReason}")
        assertEquals(
            listOf("analytics"),
            fx.auditStore.recent(100).single { it.statement == analyticsSql }.effectiveNamespace,
        )

        val defaultSql = "SELECT rrn FROM users /* route_default */"
        val (defaultDecision, _) = decideAndAudit(
            fx.core, READER_PRINCIPAL, fx.datasource, defaultSql, null, clientAddr = null,
        )
        assertEquals(EnfAction.MASK, defaultDecision.action, "reason=${defaultDecision.denyReason}")
        assertEquals(
            fx.datasource.defaultSchemas,
            fx.auditStore.recent(100).single { it.statement == defaultSql }.effectiveNamespace,
        )

        val emptySql = "SELECT rrn FROM users /* route_empty */"
        val (emptyDecision, _) = decideAndAudit(
            fx.core, READER_PRINCIPAL, fx.datasource, emptySql, emptyList(), clientAddr = null,
        )
        assertEquals(EnfAction.DENY, emptyDecision.action)
        val emptyAudit = fx.auditStore.recent(100).single { it.statement == emptySql }
        assertEquals("catalog", emptyAudit.failedStage)
        assertEquals(emptyList(), emptyAudit.effectiveNamespace)
    }

    @Test
    fun `relation-valued update returning cannot disclose protected rrn`() {
        // The target has a scalar `region` column, so use a non-colliding alias to exercise relation lookup.
        val sql = """
            update ${fx.analyticsTable} as target
            set rrn = ((source_row).sub).rrn
            from (select users as sub from users) as source_row
            where target.id = 1
            returning ((source_row).sub).rrn
        """.trimIndent()

        DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { c ->
            c.autoCommit = false
            try {
                c.createStatement().use { st ->
                    st.executeQuery(sql).use { rs ->
                        assertTrue(rs.next(), "UPDATE RETURNING did not expose the mutated row")
                        assertEquals(fx.defaultRrn, rs.getString(1), "UPDATE RETURNING did not expose the protected value")
                    }
                    st.executeQuery("select rrn from ${fx.analyticsTable} where id = 1").use { rs ->
                        assertTrue(rs.next(), "missing seeded row in ${fx.analyticsTable}")
                        assertEquals(fx.defaultRrn, rs.getString(1), "the backend did not persist the protected value in the transaction")
                    }
                }
            } finally {
                c.rollback()
            }
        }
        DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { c ->
            c.createStatement().use { st ->
                st.executeQuery("select rrn from ${fx.analyticsTable} where id = 1").use { rs ->
                    assertTrue(rs.next(), "missing seeded row in ${fx.analyticsTable}")
                    assertEquals(fx.analyticsRrn, rs.getString(1), "the test UPDATE escaped its rollback")
                }
            }
        }

        val decision = fx.decide(sql)
        assertEquals(EnfAction.DENY, decision.action, "relation-valued UPDATE RETURNING was admitted: $sql")
        assertTrue(decision.denyReason?.contains("rrn") == true, "deny reason did not identify rrn: ${decision.denyReason}")
    }

    @Test
    fun `system catalogs are introspected as first-class resources, not shadowed`() {
        // pg_catalog is on the effective search path, so excluding it from the
        // mapping makes a bare name the backend binds there fall through to a user schema (shadow
        // leak). System schemas must be introspected — this assertion fails if the NOT IN (...)
        // exclusion is re-added.
        val schemas = fx.datasourceStore.catalog(fx.datasource.id).map { it.schema }.toSet()
        assertTrue("pg_catalog" in schemas, "pg_catalog was excluded from introspection (shadowing): $schemas")
        assertTrue("information_schema" in schemas, "information_schema was excluded from introspection")
        // A bare reference to a pg_catalog table resolves THERE (pg_catalog is implicit-first) and is
        // deny-by-default — never a user-schema shadow, never unresolved.
        val bare = fx.run("select rolname from pg_authid")
        assertEquals(EnfAction.DENY, bare.decision, "bare pg_catalog name must resolve to pg_catalog + deny: ${bare.denyReason}")
        assertTrue(bare.rows.isEmpty(), "denied system-catalog query returned rows")
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SchemaThreadingMysqlDbTest : SchemaThreadingDbContract() {
    override fun createFixture(): SchemaThreadingFixture = SchemaThreadingFixtures.mysql()

    @Test
    fun `live current database pivots unqualified resolution without changing the default`() {
        val default = fx.decide("SELECT rrn FROM users", principal = READER_PRINCIPAL)
        assertEquals(EnfAction.MASK, default.action, "reason=${default.denyReason}")

        val analytics = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf(fx.analyticsSchema),
        )
        assertEquals(EnfAction.ALLOW, analytics.action, "reason=${analytics.denyReason}")
        assertTrue(analytics.masks.isEmpty())

        val original = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf(fx.defaultSchema),
        )
        assertEquals(EnfAction.MASK, original.action, "reason=${original.denyReason}")
    }

    @Test
    fun `invalid or unresolvable live current databases fail closed`() {
        val empty = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = emptyList(),
        )
        assertEquals(EnfAction.DENY, empty.action)
        assertEquals("catalog", empty.failedStage)

        val blank = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf(" "),
        )
        assertEquals(EnfAction.DENY, blank.action)
        assertEquals("catalog", blank.failedStage)

        val unknown = fx.decide(
            "SELECT rrn FROM users",
            principal = READER_PRINCIPAL,
            liveSearchPath = listOf("no_such_db"),
        )
        assertEquals(EnfAction.DENY, unknown.action)
    }

    @Test
    fun `lctn=0 CTE output-column write cannot smuggle masked rrn`() {
        // Under lower_case_table_names=0 MySQL still resolves column and
        // column-alias names case-insensitively (lctn governs only table/db names), so a CTE's explicit
        // output-column name binds its consumer regardless of case. A fold that lowercased
        // column REFERENCES but never the CTE output-column LIST would resolve the write's payload to NO
        // base column → empty lineage → the write reading the masked default users.rrn ALLOWed
        // (fail-open; live-verified on MySQL 8.4 lctn=0: the INSERT copies users.rrn verbatim). sqlglot-go's
        // role-aware strategy folds the output-column list, so the write's lineage carries the
        // masked rrn and enforcement DENIES. Guard the mode: the leak is mode-0-specific (lctn=1/2 folded
        // everything already), so this must run under lower_case_table_names=0 (Testcontainers mysql:8.4).
        val lctn = DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { c ->
            c.createStatement().use { st ->
                st.executeQuery("select @@lower_case_table_names").use { it.next(); it.getInt(1) }
            }
        }
        assertEquals(0, lctn, "this regression must exercise lower_case_table_names=0")

        val sql = "insert into ${fx.analyticsTable} (id, email, rrn, region) " +
            "with cte (Secret) as (select rrn from ${fx.defaultTable}) " +
            "select 999, 'sink@example.com', secret, 'KR' from cte"
        val decision = fx.decide(sql)
        assertEquals(EnfAction.DENY, decision.action, "CTE output-column write smuggled masked rrn: reason=${decision.denyReason}")
        assertTrue(decision.denyReason?.contains("rrn") == true, "deny did not trace the masked rrn: ${decision.denyReason}")
    }
}
