package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Types
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import javax.sql.DataSource

/**
 * Plain-JDBC persistence for [AuditEvent]s. Every new event is linked to the current chain head while
 * holding a row lock until commit; recent/detail reads retain the normal audit.read visibility model.
 */
class AuditStore(private val dataSource: DataSource) {
    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    /** Insert one audit event in its own transaction and return its app-allocated id. */
    fun insert(rec: AuditEvent): Long = dataSource.inTx { insert(it, rec) }

    /**
     * Insert on a caller-provided transaction so an audit event can commit atomically with its state change.
     * The caller owns commit/rollback; failures propagate so the enclosing operation fails closed.
     */
    fun insert(conn: Connection, rec: AuditEvent): Long {
        val (lastId, headHash) = conn.prepareStatement(CHAIN_HEAD_LOCK_SQL).use { ps ->
            ps.executeQuery().use { rs ->
                check(rs.next()) { "audit chain head is missing" }
                val hash = rs.getBytes("head_hash")
                check(hash.size == SHA256_BYTES) { "audit chain head hash must be exactly $SHA256_BYTES bytes" }
                rs.getLong("last_id") to hash
            }
        }
        val newId = Math.addExact(lastId, 1L)
        val instant = (rec.ts?.let(Instant::parse) ?: Instant.now()).truncatedTo(ChronoUnit.MICROS)
        val tsMicros = AuditCanonical.epochMicros(instant)
        val rowHash = AuditCanonical.rowHash(newId, rec, tsMicros, headHash)

        conn.prepareStatement(INSERT_SQL).use { ps ->
            ps.setLong(1, newId)
            ps.setObject(2, OffsetDateTime.ofInstant(instant, ZoneOffset.UTC))
            ps.setString(3, rec.principal)
            ps.setString(4, json.encodeToString(stringList, rec.roles))
            ps.setString(5, rec.datasource)
            ps.setString(6, rec.clientAddr)
            ps.setString(7, rec.statement)
            ps.setString(8, rec.decision.name)
            ps.setString(9, rec.failedStage)
            ps.setString(10, json.encodeToString(stringList, rec.maskedColumns))
            ps.setString(11, json.encodeToString(stringList, rec.piiTouched))
            ps.setLong(12, rec.latencyMs)
            ps.setString(13, rec.detail)
            ps.setString(14, json.encodeToString(stringList, rec.effectiveNamespace))
            ps.setString(15, rec.channel)
            ps.setString(16, json.encodeToString(stringList, rec.contextTags))
            ps.setString(17, rec.authzAction)
            ps.setString(18, rec.authzResource)
            ps.setString(19, rec.outcome)
            ps.setString(20, rec.kind)
            ps.setNullableLong(21, rec.rowsReturned)
            ps.setNullableLong(22, rec.bytesReturned)
            ps.setNullableLong(23, rec.decisionId)
            ps.setInt(24, AuditCanonical.CHAIN_VERSION)
            ps.setBytes(25, headHash)
            ps.setBytes(26, rowHash)
            check(ps.executeUpdate() == 1) { "audit event insert did not affect exactly one row" }
        }

        conn.prepareStatement(CHAIN_HEAD_UPDATE_SQL).use { ps ->
            ps.setLong(1, newId)
            ps.setBytes(2, rowHash)
            check(ps.executeUpdate() == 1) { "audit chain head update did not affect exactly one row" }
        }
        return newId
    }

    /** Most recent audit events first for a caller authorized to read the whole log. */
    fun recent(limit: Int): List<AuditEvent> {
        val sql = """
            $AUDIT_SELECT
            ORDER BY ts DESC
            LIMIT ?
        """.trimIndent()
        dataSource.connection.use { conn ->
            conn.prepareStatement(sql).use { ps ->
                ps.setInt(1, limit)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<AuditEvent>()
                    while (rs.next()) out += rs.toRecord()
                    return out
                }
            }
        }
    }

    /** Most recent audit events owned by [principal], filtering ownership before applying [limit]. */
    fun recent(limit: Int, principal: String): List<AuditEvent> {
        val sql = """
            $AUDIT_SELECT
            WHERE principal = ?
            ORDER BY ts DESC
            LIMIT ?
        """.trimIndent()
        dataSource.connection.use { conn ->
            conn.prepareStatement(sql).use { ps ->
                ps.setString(1, principal)
                ps.setInt(2, limit)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<AuditEvent>()
                    while (rs.next()) out += rs.toRecord()
                    return out
                }
            }
        }
    }

    fun get(id: Long): AuditEvent? {
        val sql = """
            $AUDIT_SELECT
            WHERE id = ?
        """.trimIndent()
        dataSource.connection.use { conn ->
            conn.prepareStatement(sql).use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> return if (rs.next()) rs.toRecord() else null }
            }
        }
    }

    private fun ResultSet.toRecord(): AuditEvent {
        return AuditEvent(
            id = getLong("id"),
            ts = getTimestamp("ts")?.toInstant()?.toString(),
            principal = getString("principal"),
            roles = json.decodeFromString(stringList, getString("roles") ?: "[]"),
            datasource = getString("datasource"),
            clientAddr = getString("client_addr"),
            statement = getString("statement"),
            decision = Decision.valueOf(getString("decision")),
            failedStage = getString("failed_stage"),
            effectiveNamespace = json.decodeFromString(stringList, getString("effective_namespace") ?: "[]"),
            maskedColumns = json.decodeFromString(stringList, getString("masked_columns") ?: "[]"),
            piiTouched = json.decodeFromString(stringList, getString("pii_touched") ?: "[]"),
            latencyMs = getLong("latency_ms"),
            detail = getString("detail"),
            channel = getString("channel"),
            contextTags = json.decodeFromString(stringList, getString("context_tags") ?: "[]"),
            authzAction = getString("action"),
            authzResource = getString("resource"),
            outcome = getString("outcome"),
            kind = getString("kind"),
            rowsReturned = longOrNull("rows_returned"),
            bytesReturned = longOrNull("bytes_returned"),
            decisionId = longOrNull("decision_id"),
        )
    }

    private fun ResultSet.longOrNull(column: String): Long? = getLong(column).let { if (wasNull()) null else it }

    private fun java.sql.PreparedStatement.setNullableLong(index: Int, value: Long?) {
        if (value == null) setNull(index, Types.BIGINT) else setLong(index, value)
    }

    private companion object {
        const val SHA256_BYTES = 32
        const val CHAIN_HEAD_LOCK_SQL =
            "SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE"
        const val CHAIN_HEAD_UPDATE_SQL =
            "UPDATE audit_chain_head SET last_id = ?, head_hash = ? WHERE id = 1"
        const val INSERT_SQL = """
            INSERT INTO audit_event
                (id, ts, principal, roles, datasource, client_addr, statement, decision,
                 failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
                 channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
                 decision_id, chain_version, prev_hash, row_hash)
            VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?::jsonb,
                    ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        const val AUDIT_SELECT =
            """SELECT id, ts, principal, roles, datasource, client_addr, statement, decision,
                      failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
                      channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
                      decision_id
               FROM audit_event"""
    }
}
