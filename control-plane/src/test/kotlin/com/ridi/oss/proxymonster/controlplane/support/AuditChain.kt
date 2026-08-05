package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.AuditCanonical
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.Decision
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

private val json = Json
private val stringList = ListSerializer(String.serializer())

/** The `prev_hash` the first chained row links to, seeded by the audit migration. */
private val genesis = "88d4f4719f26cf7f32839ac30b1d6a94edf3f9133fb75667d1415fff81bbcd08".hexBytes()

/**
 * Recompute the whole audit hash chain from the stored rows and assert it still reproduces itself, then
 * assert the head row points at the last one. Any test that writes audit rows can call this to prove the
 * rows it added are genuinely chained rather than merely present — a broken link, an altered field, or a
 * head left behind all surface as a failure here.
 */
internal fun verifyAuditChain(dataSource: DataSource) {
    val rows = readRows(dataSource)
    val chainStartId = dataSource.connection.use { connection ->
        connection.prepareStatement("SELECT COALESCE(MIN(id), 1) FROM audit_event WHERE row_hash IS NOT NULL").use { statement ->
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }
    }
    val baseLastId = chainStartId - 1
    rows.forEachIndexed { index, row ->
        val expectedPrev = if (index == 0) genesis else rows[index - 1].rowHash
        assertContentEquals(expectedPrev, row.prevHash, "chain link at ${row.id}")
        assertEquals(AuditCanonical.CHAIN_VERSION, row.chainVersion, "chain version at ${row.id}")
        assertContentEquals(
            AuditCanonical.rowHash(row.id, row.event, row.tsMicros, row.prevHash),
            row.rowHash,
            "row hash at ${row.id}",
        )
    }
    val head = auditChainHead(dataSource)
    assertEquals(rows.lastOrNull()?.id ?: baseLastId, head.first)
    if (rows.isEmpty()) assertContentEquals(genesis, head.second) else assertContentEquals(rows.last().rowHash, head.second)
}

private fun readRows(dataSource: DataSource): List<PersistedRow> = dataSource.connection.use { connection ->
    connection.prepareStatement(
        """SELECT id, ts, principal, roles, datasource, client_addr, statement, decision, failed_stage,
                  effective_namespace, masked_columns, pii_touched, latency_ms, detail, channel, context_tags,
                  action, resource, outcome, kind, rows_returned, bytes_returned, decision_id,
                  chain_version, prev_hash, row_hash
           FROM audit_event WHERE row_hash IS NOT NULL ORDER BY id""",
    ).use { statement ->
        statement.executeQuery().use { result ->
            buildList {
                while (result.next()) {
                    val instant = result.getTimestamp("ts").toInstant()
                    val event = AuditEvent(
                        id = result.getLong("id"), ts = instant.toString(), principal = result.getString("principal"),
                        roles = decodeArray(result.getString("roles")), datasource = result.getString("datasource"),
                        clientAddr = result.getString("client_addr"), statement = result.getString("statement"),
                        decision = Decision.valueOf(result.getString("decision")), failedStage = result.getString("failed_stage"),
                        effectiveNamespace = decodeArray(result.getString("effective_namespace")),
                        maskedColumns = decodeArray(result.getString("masked_columns")),
                        piiTouched = decodeArray(result.getString("pii_touched")),
                        latencyMs = result.getLong("latency_ms"), detail = result.getString("detail"),
                        channel = result.getString("channel"), contextTags = decodeArray(result.getString("context_tags")),
                        authzAction = result.getString("action"), authzResource = result.getString("resource"),
                        outcome = result.getString("outcome"), kind = result.getString("kind"),
                        rowsReturned = result.longOrNull("rows_returned"),
                        bytesReturned = result.longOrNull("bytes_returned"),
                        decisionId = result.longOrNull("decision_id"),
                    )
                    add(
                        PersistedRow(
                            event.id!!, AuditCanonical.epochMicros(instant), event,
                            result.getInt("chain_version"), result.getBytes("prev_hash"), result.getBytes("row_hash"),
                        ),
                    )
                }
            }
        }
    }
}

internal fun auditChainHead(dataSource: DataSource): Pair<Long, ByteArray> = dataSource.connection.use { connection ->
    connection.prepareStatement("SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1").use { statement ->
        statement.executeQuery().use { result -> result.next(); result.getLong(1) to result.getBytes(2) }
    }
}

private fun decodeArray(value: String?): List<String> = json.decodeFromString(stringList, value ?: "[]")

private fun java.sql.ResultSet.longOrNull(column: String): Long? =
    getLong(column).let { if (wasNull()) null else it }

private fun String.hexBytes(): ByteArray =
    ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }

private data class PersistedRow(
    val id: Long,
    val tsMicros: Long,
    val event: AuditEvent,
    val chainVersion: Int,
    val prevHash: ByteArray,
    val rowHash: ByteArray,
)
