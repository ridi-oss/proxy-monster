package com.ridi.oss.sqlglotgo

import com.ridi.oss.proxymonster.analyzer.pb.ColumnSpec
import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.Namespace
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.analyzer.pb.analyzeRequest
import com.ridi.oss.proxymonster.analyzer.pb.columnSpec
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.grpc.Engine
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SqlglotTest {
    private fun column(catalog: String, schema: String, table: String, column: String, dataType: String): ColumnSpec =
        columnSpec {
            this.catalog = catalog
            identity = relationIdentity {
                this.schema = schema
                this.table = table
                this.column = column
            }
            this.dataType = dataType
        }

    private val postgresCatalog = listOf(
        column("acme", "public", "users", "id", "BIGINT"),
        column("acme", "public", "users", "name", "VARCHAR"),
        column("acme", "public", "users", "ssn", "VARCHAR"),
        column("acme", "public", "orders", "id", "BIGINT"),
        column("acme", "public", "orders", "user_id", "BIGINT"),
        column("acme", "analytics", "users", "id", "BIGINT"),
        column("acme", "analytics", "users", "score", "BIGINT"),
    )
    private val postgresNamespace: Namespace = namespace {
        catalog = "acme"
        searchPath.add("public")
    }
    private val mysqlCatalog = postgresCatalog.map {
        it.toBuilder().setCatalog("def").setIdentity(it.identity.toBuilder().setSchema(if (it.identity.schema == "public") "app" else it.identity.schema)).build()
    }
    private val mysqlNamespace: Namespace = namespace {
        catalog = "def"
        searchPath.add("app")
    }

    private fun catalog(dialect: String) = if (dialect == "mysql") mysqlCatalog else postgresCatalog
    private fun namespaceFor(dialect: String) = if (dialect == "mysql") mysqlNamespace else postgresNamespace
    private fun engineConfigFor(dialect: String): EngineConfig = engineConfig {
        if (dialect == "mysql") {
            engine = Engine.MYSQL
            engineVersion = "8.0.46"
            mysqlLowerCaseTableNames = 2
        } else {
            engine = Engine.POSTGRES
        }
    }

    private fun facts(sql: String, dialect: String, namespace: Namespace = namespaceFor(dialect)): StatementFacts {
        val request = analyzeRequest {
            this.sql = sql
            this.namespace = namespace
            catalog.addAll(catalog(dialect))
            engineConfig = engineConfigFor(dialect)
        }
        return StatementFacts.parseFrom(Sqlglot.analyzeStatement(request.toByteArray()))
    }

    @Test
    fun emitsStructuredColumnGrants() {
        for (dialect in listOf("mysql", "postgres")) {
            val result = facts("SELECT id, ssn FROM users", dialect)
            val prefix = if (dialect == "mysql") "def.app" else "acme.public"
            assertTrue(result.resolved, "[$dialect] expected resolved=true, got: $result")
            val columns = result.resultReadsList.mapNotNull { it.column.takeIf { _ -> it.hasColumn() } }
                .map { "${it.catalog}.${it.identity.schema}.${it.identity.table}.${it.identity.column}" }
            assertTrue("$prefix.users.id" in columns)
            assertTrue("$prefix.users.ssn" in columns)
        }
    }

    @Test
    fun sqlNormalizeReturnsCanonicalSqlAndFailsClosed() {
        assertEquals("select id from users", Sqlglot.sqlNormalize("SELECT id FROM users", "postgres"))
        assertNull(Sqlglot.sqlNormalize("SELECT 'unterminated", "postgres"))
        assertNull(Sqlglot.sqlNormalize("SELECT 1", "sqlite"))
        assertNull(Sqlglot.sqlNormalize("SELECT id /*!50000 , secret */ FROM users", "mysql"))
        assertNull(Sqlglot.sqlNormalize("SELECT /*+ MAX_EXECUTION_TIME(1000) */ id FROM users", "mysql"))
    }

    @Test
    fun sqlNormalizePreservesTheByteExactNativeBoundary() {
        assertEquals("select '한글'", Sqlglot.sqlNormalize("SELECT '한글'", "postgres"))
        val prefix = assertNotNull(Sqlglot.sqlNormalize("SELECT 1", "postgres"))
        val embeddedNul = Sqlglot.sqlNormalize("SELECT 1\u0000 UNION SELECT 2", "postgres")
        assertNull(embeddedNul)
        assertNotEquals(prefix, embeddedNul)
        assertNotEquals(
            assertNotNull(Sqlglot.sqlNormalize("SELECT id FROM \"Users\"", "postgres")),
            assertNotNull(Sqlglot.sqlNormalize("SELECT id FROM \"users\"", "postgres")),
        )
    }

    @Test
    fun sqlNormalizeRejectsUnpairedUtf16Surrogates() {
        assertNull(Sqlglot.sqlNormalize(String(charArrayOf(0xD800.toChar())), "postgres"))
        assertNull(Sqlglot.sqlNormalize(String(charArrayOf(0xDC00.toChar())), "mysql"))
    }

    @Test
    fun preservesSidecarFacts() {
        val schema = facts("SELECT score FROM analytics.users", "postgres")
        assertTrue(schema.resolved)
        assertTrue("analytics" in schema.schemaQualifierCandidatesList)
        val write = facts("INSERT INTO users (id, name) VALUES (1, 'x')", "postgres")
        assertEquals(StatementKind.STATEMENT_KIND_INSERT, write.statementExec.statementKind)
    }

    @Test
    fun failuresRemainValidAndFailClosed() {
        assertTrue(!facts("SELECT id FROM other.public.users", "postgres").resolved)
        assertTrue(!facts("SELECT id FROM users", "postgres", Namespace.getDefaultInstance()).resolved)
        val malformed = StatementFacts.parseFrom(Sqlglot.analyzeStatement(byteArrayOf(0xff.toByte(), 0x00, 0x01)))
        assertTrue(!malformed.resolved)
        for (sql in listOf("this is not sql", "SELECT * FROM nonexistent_table", "SELECT ;; nonsense")) {
            assertTrue(!facts(sql, "postgres").resolved)
        }
    }

    @Test
    fun concurrentStress() {
        val queries = listOf(
            "SELECT id, ssn FROM users",
            "SELECT u.ssn, o.id FROM users u JOIN orders o ON u.id = o.user_id",
            "WITH c AS (SELECT ssn FROM users) SELECT ssn FROM c",
            "INSERT INTO users (id) VALUES (1)",
            "garbage not sql",
            "SELECT * FROM missing",
        )
        val pool = Executors.newFixedThreadPool(16)
        val ok = AtomicInteger()
        val bad = AtomicInteger()
        val total = 4000
        repeat(total) { i ->
            pool.submit {
                try {
                    facts(queries[i % queries.size], if (i % 2 == 0) "mysql" else "postgres")
                    ok.incrementAndGet()
                } catch (_: Exception) {
                    bad.incrementAndGet()
                }
            }
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS))
        assertEquals(0, bad.get())
        assertEquals(total, ok.get())
    }
}
