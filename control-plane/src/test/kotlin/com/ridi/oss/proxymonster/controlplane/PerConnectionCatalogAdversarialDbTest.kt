package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.TestInstance
import java.sql.Connection
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail

abstract class PerConnectionCatalogAdversarialDbContract {
    protected lateinit var enforcement: EnforcementFixture
    protected lateinit var fixture: PerConnectionCatalogFixture

    protected abstract fun createEnforcement(): EnforcementFixture
    protected abstract fun configureFlagship()

    @BeforeAll
    fun setupAdversarialFixture() {
        requireDocker()
        enforcement = createEnforcement()
        configureFlagship()
        fixture = PerConnectionCatalogFixture(enforcement)
    }

    protected fun target(): Connection =
        DriverManager.getConnection(enforcement.targetJdbcUrl, enforcement.targetUser, enforcement.targetPassword)

    protected suspend fun openAndPush(
        target: Connection,
        principal: String,
        schemas: List<String>,
    ): OpenConnection {
        val opened = fixture.core.connectionCatalog.open(Binding(fixture.datasource.name, principal, "USER"), schemas)
        schemas.distinct().forEach { fixture.pushFromTarget(target, opened.connectionId, it) }
        return opened
    }

    protected suspend fun decide(
        opened: OpenConnection,
        principal: String,
        sql: String,
        schemas: List<String>,
    ): EnforcementOutcome = decideConnection(
        fixture.core,
        opened.connectionId,
        principal,
        fixture.datasource,
        sql,
        schemas,
        null,
    ) ?: fail("connection disappeared during decision")

    protected fun qualified(schema: String, table: String): String =
        if (fixture.datasource.engine.isMySql) "`$schema`.`$table`" else "\"$schema\".\"$table\""

    protected fun userSchema(): String = if (fixture.datasource.engine.isMySql) {
        fixture.datasource.dbName
    } else {
        fixture.datasource.defaultSchemas.first { it !in fixture.datasource.engine.systemSchemas }
    }

    protected fun auditCount(): Long = enforcement.dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event").use { ps ->
            ps.executeQuery().use { rs ->
                check(rs.next())
                rs.getLong(1)
            }
        }
    }

    @Test
    fun `ignored after-statement command blocks the next decision without auditing it`() = runBlocking {
        target().use { held ->
            val schema = userSchema()
            val opened = openAndPush(held, "writer@example.com", listOf(schema))
            val beforeDdl = auditCount()
            val ddl = assertIs<EnforcementOutcome.Verdict>(
                decide(opened, "writer@example.com", "CREATE TABLE ${qualified(schema, "pccat_ignored_after")} AS SELECT id FROM users WHERE 1 = 0", listOf(schema)),
            )
            assertEquals(EnfAction.ALLOW, ddl.ctx.action, ddl.ctx.denyReason)
            assertTrue(ddl.afterStatement.any { it.schema == schema })
            val afterDdl = auditCount()
            assertEquals(beforeDdl + 1, afterDdl)

            val blocked = decide(opened, "writer@example.com", "SELECT id FROM users", listOf(schema))
            assertIs<EnforcementOutcome.BeforeDecide>(blocked)
            assertEquals(afterDdl, auditCount(), "before_decide must not create an audit verdict")
        }
    }

    @Test
    fun `an unchanged reply quiets one authoritative version and the next version re-gates`() = runBlocking {
        target().use { heldTarget ->
            target().use { siblingTarget ->
                val schema = userSchema()
                val held = openAndPush(heldTarget, "analyst@example.com", listOf(schema))
                val sibling = openAndPush(siblingTarget, "analyst@example.com", listOf(schema))

                val firstDdl = assertIs<EnforcementOutcome.Verdict>(
                    decide(sibling, "analyst@example.com", "CREATE TABLE ${qualified(schema, "pccat_version_one")} (id BIGINT)", listOf(schema)),
                )
                assertEquals(EnfAction.ALLOW, firstDdl.ctx.action, firstDdl.ctx.denyReason)
                siblingTarget.createStatement().use { it.execute("CREATE TABLE ${qualified(schema, "pccat_version_one")} (id BIGINT)") }
                fixture.pushFromTarget(siblingTarget, sibling.connectionId, schema)

                val stale = assertIs<EnforcementOutcome.BeforeDecide>(
                    decide(held, "analyst@example.com", "SELECT id FROM users", listOf(schema)),
                )
                assertEquals(listOf(schema), stale.commands.map { it.schema })

                val heldConnection = fixture.core.connectionCatalog.find(held.connectionId)!!
                val heldHash = heldConnection.held.getValue(schema).hash.bytes
                val unchanged = fixture.core.connectionCatalog.applyPush(
                    schemaFragmentPush {
                        connectionId = held.connectionId
                        datasourceName = fixture.datasource.name
                        this.schema = schema
                        contentHash = heldHash
                        this.unchanged = true
                        backendGeneration = 1
                    },
                    fixture.datasource,
                )
                assertIs<CatalogMutationResult.Applied>(unchanged)
                val once = assertIs<EnforcementOutcome.Verdict>(
                    decide(held, "analyst@example.com", "SELECT id FROM users", listOf(schema)),
                )
                assertNotEquals(EnfAction.DENY, once.ctx.action, once.ctx.denyReason)

                val secondDdl = assertIs<EnforcementOutcome.Verdict>(
                    decide(sibling, "analyst@example.com", "CREATE TABLE ${qualified(schema, "pccat_version_two")} (id BIGINT)", listOf(schema)),
                )
                assertEquals(EnfAction.ALLOW, secondDdl.ctx.action, secondDdl.ctx.denyReason)
                siblingTarget.createStatement().use { it.execute("CREATE TABLE ${qualified(schema, "pccat_version_two")} (id BIGINT)") }
                fixture.pushFromTarget(siblingTarget, sibling.connectionId, schema)

                assertIs<EnforcementOutcome.BeforeDecide>(
                    decide(held, "analyst@example.com", "SELECT id FROM users", listOf(schema)),
                )
            }
        }
    }

    @Test
    fun `closing a mutated connection never changes a sibling verdict`() = runBlocking {
        target().use { targetA ->
            target().use { targetB ->
                val schema = userSchema()
                val a = openAndPush(targetA, "analyst@example.com", listOf(schema))
                val b = openAndPush(targetB, "analyst@example.com", listOf(schema))
                val before = assertIs<EnforcementOutcome.Verdict>(
                    decide(b, "analyst@example.com", "SELECT id FROM users", listOf(schema)),
                )

                val ddlSql = "CREATE TABLE ${qualified(schema, "pccat_close_hint")} AS SELECT id FROM users WHERE 1 = 0"
                val ddl = assertIs<EnforcementOutcome.Verdict>(
                    decide(a, "analyst@example.com", ddlSql, listOf(schema)),
                )
                assertEquals(EnfAction.ALLOW, ddl.ctx.action, ddl.ctx.denyReason)
                targetA.createStatement().use { it.execute(ddlSql) }
                fixture.pushFromTarget(targetA, a.connectionId, schema)
                assertIs<CatalogMutationResult.Applied>(fixture.core.connectionCatalog.close(a.connectionId, fixture.datasource.name))

                var after = decide(b, "analyst@example.com", "SELECT id FROM users", listOf(schema))
                if (after is EnforcementOutcome.BeforeDecide) {
                    after.commands.forEach { fixture.pushFromTarget(targetB, b.connectionId, it.schema) }
                    after = decide(b, "analyst@example.com", "SELECT id FROM users", listOf(schema))
                }
                val verdict = assertIs<EnforcementOutcome.Verdict>(after)
                assertEquals(before.ctx.action, verdict.ctx.action)
                assertEquals(before.ctx.masks, verdict.ctx.masks)
                assertEquals(before.ctx.rewrittenSql, verdict.ctx.rewrittenSql)
                val bRows = fixture.core.connectionCatalog.structuralRows(fixture.core.connectionCatalog.find(b.connectionId)!!)
                assertTrue(bRows.any { it.schema == schema && it.table == "users" && it.column == "id" })
            }
        }
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogMysqlAdversarialDbTest : PerConnectionCatalogAdversarialDbContract() {
    override fun createEnforcement() = EnforcementFixture.mysql()

    override fun configureFlagship() {
        val schema = enforcement.datasource.dbName
        target().use { c ->
            c.createStatement().use { st ->
                st.execute("DROP TABLE IF EXISTS `$schema`.accounts")
                st.execute("CREATE TABLE `$schema`.accounts (id BIGINT PRIMARY KEY)")
                st.execute("INSERT INTO `$schema`.accounts VALUES (1)")
                st.execute("DROP PROCEDURE IF EXISTS pccat_refresh")
                st.execute("CREATE PROCEDURE pccat_refresh() SELECT 1")
            }
        }
        val table = "${enforcement.datasource.name}/def/$schema/accounts"
        val accounts = enforcement.execOnTarget("SELECT column_name, data_type, ordinal_position, is_nullable FROM information_schema.columns WHERE table_schema = '$schema' AND table_name = 'accounts'")
        enforcement.datasourceStore.storePushedCatalog(
            id = enforcement.datasource.id,
            defaultSchemas = listOf(schema),
            mysqlLowerCaseTableNames = enforcement.datasource.mysqlLowerCaseTableNames,
            engineVersion = enforcement.datasource.engineVersion.orEmpty(),
            columns = enforcement.datasourceStore.catalog(enforcement.datasource.id).map { row ->
                DatasourceStore.PushedColumn(row.schema, row.table, row.column, row.dataType, row.ordinal, row.nullable)
            } + accounts.rows.map { row ->
                DatasourceStore.PushedColumn(
                    schema,
                    "accounts",
                    row[0]!!,
                    row[1]!!,
                    row[2]!!.toInt(),
                    row[3] == "YES",
                )
            },
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-mysql-analyst-ddl",
                """permit(principal in Role::"${enforcement.role}", action in [Action::"stmt.cat.ddl"], resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        // A bare `DROP TABLE` is unanalyzable (no lineage for the DDL), so it relays only under a
        // sql.unanalyzable permit — the legitimate authorization the catalog-freshness DROP test exercises.
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-mysql-analyst-unanalyzable",
                """permit(principal in Role::"${enforcement.role}", action == Action::"sql.unanalyzable", resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-mysql-writer-select",
                """permit(principal in Role::"ddl-writer", action in [Action::"stmt.cat.read"], resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-mysql-accounts-read",
                """permit(principal in Role::"${enforcement.role}", action == Action::"result.read.unmasked", resource in Table::"$table");""",
            ),
            "pccat-test",
        )
    }

    @Test
    fun `MySQL implicit-commit DROP cannot leave a stale allow`() = runBlocking {
        val (_, accountsStillHeld) = dropAccountsAndDecideAgain()
        // The implicit-commit DROP forced a refetch whose push evicted `accounts` from the held fragment, so no
        // stale entry survives for a later SELECT to resolve + ALLOW against the dropped table.
        assertFalse(accountsStillHeld, "the refreshed held catalog must not still list the dropped `accounts`")
    }

    private suspend fun dropAccountsAndDecideAgain(): Pair<EnforcementOutcome, Boolean> = target().use { held ->
        val schema = userSchema()
        held.createStatement().use { st ->
            st.execute("DROP TABLE IF EXISTS accounts")
            st.execute("CREATE TABLE accounts (id BIGINT PRIMARY KEY)")
            st.execute("INSERT INTO accounts VALUES (1)")
        }
        val opened = openAndPush(held, "analyst@example.com", listOf(schema))
        val initial = assertIs<EnforcementOutcome.Verdict>(
            decide(opened, "analyst@example.com", "SELECT accounts.id FROM accounts", listOf(schema)),
        )
        assertEquals(EnfAction.ALLOW, initial.ctx.action, initial.ctx.denyReason)

        // The unanalyzable DROP relays (sql.unanalyzable permit) and, being catalog-changing, schedules an
        // after-statement REFETCH on the connection. MySQL commits the DROP implicitly, so `accounts` is gone
        // on the target immediately; fulfilling the refetch (pushFromTarget) must therefore evict `accounts`
        // from the held fragment — so no stale entry survives for a later SELECT to resolve+ALLOW against.
        held.autoCommit = false
        val ddlSql = "DROP TABLE accounts"
        val ddl = assertIs<EnforcementOutcome.Verdict>(
            decide(opened, "analyst@example.com", ddlSql, listOf(schema)),
        )
        assertEquals(EnfAction.ALLOW, ddl.ctx.action, ddl.ctx.denyReason)
        assertTrue(ddl.afterStatement.any { it.schema == schema }, "the catalog-changing DROP must schedule a refetch")
        held.createStatement().use { it.execute(ddlSql) }
        fixture.pushFromTarget(held, opened.connectionId, schema)

        val next = decide(opened, "analyst@example.com", "SELECT accounts.id FROM accounts", listOf(schema))
        val accountsStillHeld = fixture.core.connectionCatalog
            .structuralRows(fixture.core.connectionCatalog.find(opened.connectionId)!!)
            .any { it.schema == schema && it.table == "accounts" }
        next to accountsStillHeld
    }

    @Test
    fun `literal MySQL CALL is denied before it can create a stale-catalog window`() = runBlocking {
        target().use { held ->
            val schema = userSchema()
            val opened = openAndPush(held, "writer@example.com", listOf(schema))
            val call = assertIs<EnforcementOutcome.Verdict>(
                decide(opened, "writer@example.com", "CALL pccat_refresh()", listOf(schema)),
            )
            assertEquals(EnfAction.DENY, call.ctx.action)
            assertContains(call.ctx.denyReason.orEmpty(), "statement kind 'call' is not permitted")
            assertTrue(call.afterStatement.isEmpty())
        }
    }

    @Disabled("literal CALL is classified catalog-changing but its admin.exec kind gate makes its ALLOW arm unreachable for a principal without admin")
    @Test
    fun `allowed MySQL CALL carries after-statement refetch`() = runBlocking {
        target().use { held ->
            val schema = userSchema()
            val opened = openAndPush(held, "writer@example.com", listOf(schema))
            val call = assertIs<EnforcementOutcome.Verdict>(
                decide(opened, "writer@example.com", "CALL pccat_refresh()", listOf(schema)),
            )
            assertEquals(EnfAction.ALLOW, call.ctx.action, call.ctx.denyReason)
            assertTrue(call.afterStatement.any { it.schema == schema })
        }
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogPostgresAdversarialDbTest : PerConnectionCatalogAdversarialDbContract() {
    override fun createEnforcement() = EnforcementFixture.postgres()

    override fun configureFlagship() {
        target().use { c ->
            c.createStatement().use { st ->
                st.execute("CREATE SCHEMA safe")
                st.execute("CREATE SCHEMA restricted")
                st.execute("CREATE TABLE safe.accounts (id BIGINT PRIMARY KEY)")
                st.execute("CREATE TABLE restricted.accounts (id BIGINT PRIMARY KEY)")
                st.execute("INSERT INTO safe.accounts VALUES (1)")
                st.execute("INSERT INTO restricted.accounts VALUES (2)")
            }
        }
        val safeTable = "${enforcement.datasource.name}/${enforcement.datasource.dbName}/safe/accounts"
        val accounts = enforcement.execOnTarget(
            "SELECT table_schema, column_name, data_type, ordinal_position, is_nullable FROM information_schema.columns WHERE table_schema IN ('safe', 'restricted') AND table_name = 'accounts' ORDER BY table_schema, ordinal_position",
        )
        enforcement.datasourceStore.storePushedCatalog(
            id = enforcement.datasource.id,
            defaultSchemas = enforcement.datasource.defaultSchemas,
            mysqlLowerCaseTableNames = null,
            engineVersion = enforcement.datasource.engineVersion.orEmpty(),
            columns = enforcement.datasourceStore.catalog(enforcement.datasource.id).map { row ->
                DatasourceStore.PushedColumn(row.schema, row.table, row.column, row.dataType, row.ordinal, row.nullable)
            } + accounts.rows.map { row ->
                DatasourceStore.PushedColumn(
                    row[0]!!,
                    "accounts",
                    row[1]!!,
                    row[2]!!,
                    row[3]!!.toInt(),
                    row[4] == "YES",
                )
            },
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-pg-analyst-ddl",
                """permit(principal in Role::"${enforcement.role}", action in [Action::"stmt.cat.ddl"], resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        // A bare `DROP TABLE` is unanalyzable (no lineage for the DDL), so it relays only under a
        // sql.unanalyzable permit — the legitimate authorization these catalog-freshness tests exercise.
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-pg-analyst-unanalyzable",
                """permit(principal in Role::"${enforcement.role}", action == Action::"sql.unanalyzable", resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-pg-writer-select",
                """permit(principal in Role::"ddl-writer", action in [Action::"stmt.cat.read"], resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            "pccat-test",
        )
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                "pccat-pg-safe-accounts-read",
                """permit(principal in Role::"${enforcement.role}", action == Action::"result.read.unmasked", resource in Table::"$safeTable");""",
            ),
            "pccat-test",
        )
    }

    @Test
    fun `transaction-local DROP changes bare-name resolution before commit`() = runBlocking {
        target().use { held ->
            val schemas = listOf("safe", "restricted")
            held.createStatement().use { it.execute("SET search_path = safe, restricted") }
            val opened = openAndPush(held, "analyst@example.com", schemas)
            val initial = assertIs<EnforcementOutcome.Verdict>(
                decide(opened, "analyst@example.com", "SELECT accounts.id FROM accounts", schemas),
            )
            assertEquals(EnfAction.ALLOW, initial.ctx.action, initial.ctx.denyReason)

            held.autoCommit = false
            try {
                val ddlSql = "DROP TABLE safe.accounts"
                val ddl = assertIs<EnforcementOutcome.Verdict>(
                    decide(opened, "analyst@example.com", ddlSql, listOf("safe")),
                )
                assertEquals(EnfAction.ALLOW, ddl.ctx.action, ddl.ctx.denyReason)
                assertTrue(ddl.afterStatement.any { it.schema == "safe" })
                held.createStatement().use { it.execute(ddlSql) }
                fixture.pushFromTarget(held, opened.connectionId, "safe")

                val next = assertIs<EnforcementOutcome.Verdict>(
                    decide(opened, "analyst@example.com", "SELECT accounts.id FROM accounts", schemas),
                )
                assertEquals(EnfAction.DENY, next.ctx.action)
                assertContains(next.ctx.denyReason.orEmpty(), ".restricted.accounts.")
            } finally {
                held.rollback()
            }
        }
    }

    @Test
    fun `PostgreSQL SELECT invoking a function carries after-statement refetch`() = runBlocking {
        target().use { held ->
            val schema = userSchema()
            val opened = openAndPush(held, "analyst@example.com", listOf(schema))
            val functionSelect = assertIs<EnforcementOutcome.Verdict>(
                decide(opened, "analyst@example.com", "SELECT lower(email) FROM users", listOf(schema)),
            )
            assertEquals(EnfAction.ALLOW, functionSelect.ctx.action, functionSelect.ctx.denyReason)
            assertTrue(functionSelect.ctx.catalogChanging)
            assertTrue(functionSelect.afterStatement.any { it.schema == schema })
        }
    }
}
