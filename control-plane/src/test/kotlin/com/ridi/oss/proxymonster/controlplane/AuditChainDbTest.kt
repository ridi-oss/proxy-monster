package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.SQLException
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuditChainDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: AuditStore
    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_audit_chain"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = AuditStore(dataSource)
    }

    @Test
    fun `single-argument inserts allocate contiguous ids and persist a recomputable chain`() {
        val first = store.insert(event("single first", ts = "2026-07-01T01:02:03.123456789Z"))
        val second = store.insert(event("single second", ts = "2026-07-01T01:02:04.654321999Z"))
        assertEquals(first + 1, second)

        val rows = readRows(listOf(first, second))
        assertContentEquals(rows[0].rowHash, rows[1].prevHash)
        rows.forEach { row ->
            assertContentEquals(
                AuditCanonical.rowHash(row.id, row.event, row.tsMicros, row.prevHash),
                row.rowHash,
                "persisted row ${row.id} must reproduce its stored hash",
            )
        }
        assertEquals("2026-07-01T01:02:03.123456Z", rows[0].event.ts)
        verifyWalk()
    }

    @Test
    fun `connection overload commits linked and rollback leaves both event and head untouched`() {
        val committed = dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                store.insert(connection, event("connection commit"))
                    .also { connection.commit() }
            } finally {
                connection.autoCommit = true
            }
        }
        assertEquals(committed, store.get(committed)?.id)

        val headBefore = chainHead()
        val rolledBack = dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                store.insert(connection, event("connection rollback")).also { connection.rollback() }
            } finally {
                connection.autoCommit = true
            }
        }
        assertNull(store.get(rolledBack))
        val headAfter = chainHead()
        assertEquals(headBefore.first, headAfter.first)
        assertContentEquals(headBefore.second, headAfter.second)
        verifyWalk()
    }

    @Test
    fun `completion fields round-trip chain and reject a bogus decision id`() {
        val decisionId = store.insert(event("decision source"))
        val completionId = store.insert(
            event("completion event").copy(
                kind = "completion",
                rowsReturned = 123,
                bytesReturned = 4567,
                decisionId = decisionId,
            ),
        )
        val completion = store.get(completionId)!!
        assertEquals("completion", completion.kind)
        assertEquals(123, completion.rowsReturned)
        assertEquals(4567, completion.bytesReturned)
        assertEquals(decisionId, completion.decisionId)
        verifyWalk()

        val headBefore = chainHead()
        assertFailsWith<SQLException> {
            store.insert(event("bad completion").copy(kind = "completion", decisionId = Long.MAX_VALUE))
        }
        val headAfter = chainHead()
        assertEquals(headBefore.first, headAfter.first)
        assertContentEquals(headBefore.second, headAfter.second)
        verifyWalk()
    }

    @Test
    fun `verify walk detects a historical event mutation`() {
        val id = store.insert(event("tamper original"))
        verifyWalk()
        dataSource.connection.use { connection ->
            connection.prepareStatement("UPDATE audit_event SET statement = 'tampered' WHERE id = ?").use { statement ->
                statement.setLong(1, id)
                assertEquals(1, statement.executeUpdate())
            }
        }
        assertFailsWith<AssertionError> { verifyWalk() }
        dataSource.connection.use { connection ->
            connection.prepareStatement("UPDATE audit_event SET statement = 'tamper original' WHERE id = ?").use { statement ->
                statement.setLong(1, id)
                assertEquals(1, statement.executeUpdate())
            }
        }
        verifyWalk()
    }

    @Test
    fun `concurrent appends serialize without duplicate ids and preserve the chain`() {
        val threads = 6
        val perThread = 8
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(threads)
        val ids = Collections.synchronizedList(mutableListOf<Long>())
        val futures = (0 until threads).map { thread ->
            executor.submit {
                start.await()
                repeat(perThread) { index -> ids += store.insert(event("concurrent-$thread-$index")) }
            }
        }
        start.countDown()
        futures.forEach { it.get(60, TimeUnit.SECONDS) }
        executor.shutdown()
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))

        assertEquals(threads * perThread, ids.size)
        assertEquals(ids.size, ids.toSet().size)
        val sorted = ids.sorted()
        assertEquals((sorted.first()..sorted.last()).toList(), sorted)
        verifyWalk()
    }

    private fun event(statement: String, ts: String? = null) = AuditEvent(
        ts = ts,
        principal = "audit-chain",
        // A comma-bearing role plus a duplicate: the persisted row must reproduce these bytes exactly,
        // so lossy comma-joined storage would break recomputation here.
        roles = listOf("finance,prod", "a", "a"),
        datasource = "main",
        statement = statement,
        decision = Decision.ALLOW,
        effectiveNamespace = listOf("main", "public"),
        contextTags = listOf("trusted", "alpha"),
    )

    private fun verifyWalk() = verifyAuditChain(dataSource)

    private fun readRows(ids: List<Long>?): List<PersistedRow> = dataSource.connection.use { connection ->
        val condition = if (ids == null) "row_hash IS NOT NULL" else "id IN (${ids.joinToString(",")})"
        connection.prepareStatement(
            """SELECT id, ts, principal, roles, datasource, client_addr, statement, decision, failed_stage,
                      effective_namespace, masked_columns, pii_touched, latency_ms, detail, channel, context_tags,
                      action, resource, outcome, kind, rows_returned, bytes_returned, decision_id,
                      chain_version, prev_hash, row_hash
               FROM audit_event WHERE $condition ORDER BY id""",
        ).use { statement ->
            statement.executeQuery().use { result ->
                buildList {
                    while (result.next()) {
                        val instant = result.getTimestamp("ts").toInstant()
                        val event = AuditEvent(
                            id = result.getLong("id"),
                            ts = instant.toString(),
                            principal = result.getString("principal"),
                            roles = decodeArray(result.getString("roles")),
                            datasource = result.getString("datasource"),
                            clientAddr = result.getString("client_addr"),
                            statement = result.getString("statement"),
                            decision = Decision.valueOf(result.getString("decision")),
                            failedStage = result.getString("failed_stage"),
                            effectiveNamespace = decodeArray(result.getString("effective_namespace")),
                            maskedColumns = decodeArray(result.getString("masked_columns")),
                            piiTouched = decodeArray(result.getString("pii_touched")),
                            latencyMs = result.getLong("latency_ms"),
                            detail = result.getString("detail"),
                            channel = result.getString("channel"),
                            contextTags = decodeArray(result.getString("context_tags")),
                            authzAction = result.getString("action"),
                            authzResource = result.getString("resource"),
                            outcome = result.getString("outcome"),
                            kind = result.getString("kind"),
                            rowsReturned = result.longOrNull("rows_returned"),
                            bytesReturned = result.longOrNull("bytes_returned"),
                            decisionId = result.longOrNull("decision_id"),
                        )
                        add(
                            PersistedRow(
                                event.id!!,
                                AuditCanonical.epochMicros(instant),
                                event,
                                result.getInt("chain_version"),
                                result.getBytes("prev_hash"),
                                result.getBytes("row_hash"),
                            ),
                        )
                    }
                }
            }
        }
    }

    private fun chainHead(): Pair<Long, ByteArray> = auditChainHead(dataSource)

    private fun decodeArray(value: String?): List<String> =
        json.decodeFromString(stringList, value ?: "[]")

    private fun java.sql.ResultSet.longOrNull(column: String): Long? =
        getLong(column).let { if (wasNull()) null else it }

    private data class PersistedRow(
        val id: Long,
        val tsMicros: Long,
        val event: AuditEvent,
        val chainVersion: Int,
        val prevHash: ByteArray,
        val rowHash: ByteArray,
    )
}
