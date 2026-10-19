package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.Test
import java.sql.SQLException
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The audit store's structural contract on a real control-plane store (docs/audit-trail-hardening.md):
 * `audit_event.id` carries no sequence default (AuditStore assigns it under the chain-head lock, so id
 * order is chain order), the chain starts at genesis, `access_request.source_decision_id` is a real
 * foreign key, and the first appended event chains onto genesis.
 */
class AuditTrailSchemaDbTest {
    @Test
    fun `a clean store has no id sequence a genesis head and a live source-decision foreign key`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_audit_trail_schema"))

        dataSource.connection.use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery(
                    "SELECT to_regclass('audit_event') IS NOT NULL, to_regclass('idx_audit_event_ts') IS NOT NULL",
                ).use { result ->
                    result.next()
                    assertTrue(result.getBoolean(1))
                    assertTrue(result.getBoolean(2))
                }
                // No sequence and no default: a sequence could hand out an id out of chain order.
                statement.executeQuery("SELECT pg_get_serial_sequence('audit_event', 'id')").use { result ->
                    result.next()
                    assertNull(result.getString(1))
                }
                statement.executeQuery(
                    "SELECT column_default FROM information_schema.columns " +
                        "WHERE table_schema = current_schema() AND table_name = 'audit_event' AND column_name = 'id'",
                ).use { result ->
                    result.next()
                    assertNull(result.getString(1))
                }
                statement.executeQuery("SELECT id, last_id, head_hash FROM audit_chain_head").use { result ->
                    assertTrue(result.next())
                    assertEquals(1, result.getInt("id"))
                    assertEquals(0, result.getLong("last_id"))
                    assertContentEquals(GENESIS, result.getBytes("head_hash"))
                    assertFalse(result.next(), "the chain head is a single row")
                }
            }
        }

        // The first appended event chains onto genesis.
        val firstChained = AuditStore(dataSource).insert(
            AuditEvent(
                ts = "2026-07-01T00:00:00.123456Z",
                principal = "new-event",
                datasource = "audit-schema-ds",
                statement = "select 3",
                decision = Decision.ALLOW,
            ),
        )
        assertEquals(1, firstChained)
        dataSource.connection.use { connection ->
            connection.prepareStatement("SELECT chain_version, prev_hash FROM audit_event WHERE id = ?").use { statement ->
                statement.setLong(1, firstChained)
                statement.executeQuery().use { result ->
                    result.next()
                    assertEquals(AuditCanonical.CHAIN_VERSION, result.getInt("chain_version"))
                    assertContentEquals(GENESIS, result.getBytes("prev_hash"))
                }
            }
        }

        // source_decision_id is a real FK: a task may point at a recorded decision, never at a
        // nonexistent one.
        val datasourceId = seedDatasource(dataSource)
        val requestId = seedAccessRequest(dataSource, datasourceId, firstChained)
        dataSource.connection.use { connection ->
            connection.prepareStatement("SELECT source_decision_id FROM access_request WHERE id = ?").use { statement ->
                statement.setLong(1, requestId)
                statement.executeQuery().use { result -> result.next(); assertEquals(firstChained, result.getLong(1)) }
            }
        }
        assertFailsWith<SQLException> { seedAccessRequest(dataSource, datasourceId, Long.MAX_VALUE) }
    }

    private fun seedDatasource(dataSource: DataSource): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(
            "INSERT INTO datasource (name, engine, host, port, db_name) " +
                "VALUES ('audit-schema-ds', 'postgres', 'localhost', 5432, 'app') RETURNING id",
        ).use { statement -> statement.executeQuery().use { result -> result.next(); result.getLong(1) } }
    }

    private fun seedAccessRequest(dataSource: DataSource, datasourceId: Long, sourceDecisionId: Long): Long =
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                "INSERT INTO access_request " +
                    "(principal, kind, datasource_id, status, reason, source_decision_id, creator_kind) " +
                    "VALUES ('requester', 'QUERY', ?, 'PENDING', 'need it', ?, 'WORKFLOW') RETURNING id",
            ).use { statement ->
                statement.setLong(1, datasourceId)
                statement.setLong(2, sourceDecisionId)
                statement.executeQuery().use { result -> result.next(); result.getLong(1) }
            }
        }

    private companion object {
        val GENESIS = "88d4f4719f26cf7f32839ac30b1d6a94edf3f9133fb75667d1415fff81bbcd08".hexBytes()

        fun String.hexBytes(): ByteArray =
            ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
