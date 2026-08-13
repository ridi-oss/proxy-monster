package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/**
 * A classification's schema decides whether enforcement can ever find it: `classificationsFor` keys on
 * exactly `(schema, table, column)`, so a row stored under a schema no query resolves to is invisible
 * while the real column stays untagged and reads cleartext. Every write path in — REST, the MCP tools —
 * funnels through `upsertClassification`, so the resolution rule is pinned here, at that chokepoint.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClassificationSchemaResolutionDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: DatasourceStore

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_classification_schema"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = DatasourceStore(dataSource)
    }

    @AfterAll
    fun close() {
        (dataSource as? AutoCloseable)?.close()
    }

    @Test
    fun `a blank schema resolves to the datasource default instead of being stored literally`() {
        val id = datasource("blank-schema-datasource")
        val stored = store.upsertClassification(id, ClassificationInput("", "users", "ssn", listOf("pii"), null))
        assertEquals("public", stored.schema)
        assertEquals(0L, rowsUnderSchema(id, ""))
        assertEquals(1L, rowsUnderSchema(id, "public"))

        // A blank schema and an omitted one name the SAME column, so the second write updates the first
        // row rather than adding a second one that shadows it.
        store.upsertClassification(id, ClassificationInput(null, "users", "ssn", listOf("contact"), null))
        assertEquals(1L, rowsUnderSchema(id, "public"))
        assertEquals(
            listOf("contact"),
            store.classificationsFor(id).getValue(Triple("public", "users", "ssn")).tags,
        )
    }

    @Test
    fun `an explicit schema is still stored verbatim`() {
        val id = datasource("explicit-schema-datasource")
        val stored = store.upsertClassification(id, ClassificationInput("analytics", "users", "ssn", listOf("pii"), null))
        assertEquals("analytics", stored.schema)
        assertEquals(1L, rowsUnderSchema(id, "analytics"))
        assertEquals(0L, rowsUnderSchema(id, "public"))
    }

    private fun datasource(name: String): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(
            """INSERT INTO datasource(name, engine, host, port, db_name, default_schemas)
               VALUES (?, 'postgres', '127.0.0.1', 5432, 'pm', '["public"]'::jsonb) RETURNING id""",
        ).use { statement ->
            statement.setString(1, name)
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }
    }

    private fun rowsUnderSchema(id: Long, schema: String): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(
            "SELECT count(*) FROM column_classification WHERE datasource_id=? AND schema_name=?",
        ).use { statement ->
            statement.setLong(1, id)
            statement.setString(2, schema)
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }
    }
}
