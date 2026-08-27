package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.ResultFingerprint
import com.google.protobuf.InvalidProtocolBufferException
import com.ridi.oss.proxymonster.storage.StoredResult
import com.ridi.oss.proxymonster.grpc.RunError
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runValue
import com.ridi.oss.proxymonster.storage.storedResult
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource
import org.postgresql.util.PGobject

@Serializable
data class QueryResultMeta(
    val taskId: Long,
    val executedBy: String? = null,
    val executedAt: String? = null,
    val rowCount: Int? = null,
    val expiresAt: String? = null,
    val status: String? = null,
    val errorCode: String? = null,
    // Set only on a POLICY denial: the reason the decision recorded, and the audit decision it was recorded
    // under. A polling client sees only this row, so without them a denial is indistinguishable from a
    // generic failure and it cannot offer the approval request that a denial is supposed to lead to.
    val denyReason: String? = null,
    val decisionId: Long? = null,
    val columns: List<String> = emptyList(),
)

@Serializable
data class DecryptedResult(
    val columns: List<String>,
    val rows: List<List<String?>>,
    // The backend's own affected-row count for a DML statement (UPDATE/INSERT/DELETE), which has no result
    // set of its own. Null for a statement that returns rows (e.g. SELECT), where [rows].size IS the count.
    val rowsAffected: Int? = null,
    // The executed decision's requirements (ResultFingerprint), frozen with the bytes so a view denies drift
    // ([decideResultView]). NULL for a result stored before this field existed (legacy) — distinct from a
    // present-but-empty fingerprint (a genuine passthrough result), so a legacy view always fails closed
    // rather than being mistaken for a grant-less passthrough and released raw.
    @Serializable(with = ResultFingerprintSerializer::class)
    val resultFingerprint: ResultFingerprint? = null,
)

/**
 * A one-read snapshot of a task's latest result child, so a concurrent re-execute cannot swap the row
 * between the authz check and the decrypt. Decryption is lazy — first read, after the caller authorized
 * on [meta].
 */
class ResultAccess(
    val meta: QueryResultMeta,
    val sql: String?,
    decrypt: () -> DecryptedResult?,
    decryptError: () -> RunError? = { null },
) {
    val decrypted: DecryptedResult? by lazy(decrypt)
    val errorDetail: RunError? by lazy(decryptError)
}

/** Protobuf at rest, so a Go control-plane reads the same bytes. The JSON fallback covers results stored
 *  before the migration and dies with them, one retention window later. */
internal object ResultPayloadCodec {
    private val json = Json
    private val legacySerializer = DecryptedResult.serializer()

    fun encode(result: DecryptedResult): ByteArray = storedResult {
        rows = runResultRows {
            columns.addAll(result.columns)
            rows.addAll(
                result.rows.map { row ->
                    runRow {
                        values.addAll(row.map { cell -> runValue { value = cell ?: ""; isNull = cell == null } })
                    }
                },
            )
        }
        result.rowsAffected?.let { rowsAffected = it }
        result.resultFingerprint?.let { resultFingerprint = it }
    }.toByteArray()

    fun decode(plaintext: ByteArray): DecryptedResult =
        try {
            fromStored(StoredResult.parseFrom(plaintext))
        } catch (protoFailure: InvalidProtocolBufferException) {
            // Parsing decides the format, never the leading byte: `{` is itself a valid protobuf tag
            // (field 15), so a newer schema's unknown field would be misread as JSON.
            try {
                json.decodeFromString(legacySerializer, plaintext.toString(Charsets.UTF_8))
            } catch (jsonFailure: Exception) {
                throw protoFailure.also { it.addSuppressed(jsonFailure) }
            }
        }

    private fun fromStored(stored: StoredResult) = DecryptedResult(
        columns = stored.rows.columnsList,
        rows = stored.rows.rowsList.map { row -> row.valuesList.map { if (it.isNull) null else it.value } },
        rowsAffected = if (stored.hasRowsAffected()) stored.rowsAffected else null,
        resultFingerprint = if (stored.hasResultFingerprint()) stored.resultFingerprint else null,
    )
}

class QueryResultStore(private val dataSource: DataSource, private val crypto: ResultCrypto) {
    private class RawResultRow(
        val meta: QueryResultMeta,
        val sql: String?,
        val ciphertext: ByteArray?,
        val errorDetail: ByteArray?,
    )

    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    private fun ResultSet.toMeta() = QueryResultMeta(
        taskId = getLong("task_id"),
        executedBy = getString("executed_by"),
        executedAt = getTimestamp("executed_at")?.toInstant()?.toString(),
        rowCount = getInt("row_count").let { if (wasNull()) null else it },
        expiresAt = getTimestamp("expires_at")?.toInstant()?.toString(),
        status = getString("status"),
        errorCode = getString("error_code"),
        denyReason = getString("deny_reason"),
        decisionId = getLong("decision_id").let { if (wasNull()) null else it },
        columns = json.decodeFromString(stringList, getString("columns") ?: "[]"),
    )

    fun startRun(taskId: Long, executedBy: String): QueryResultMeta? = dataSource.connection.use { c ->
        val childId = latestChildId(c, taskId, "status IS NULL") ?: return@use null
        val started = c.prepareStatement(
            "UPDATE query_result SET status = 'RUNNING', executed_by = ?, error_code = NULL WHERE id = ? AND status IS NULL",
        ).use { ps ->
            ps.setString(1, executedBy)
            ps.setLong(2, childId)
            ps.executeUpdate() > 0
        }
        if (started) meta(taskId, c) else null
    }

    /**
     * Atomically claim a task for execution AND start its run: the parent's `APPROVED → EXECUTING` flip
     * (via [claimParent]) and the child's `NULL → RUNNING` flip commit in ONE transaction. This closes the
     * window a separate claim-then-start left open — where a cancel arriving between the two saw an
     * `EXECUTING` parent with no `RUNNING` child yet, so [cancelRun] no-oped and the query ran anyway. After
     * this, an `EXECUTING` task always has a `RUNNING` child for a cancel to catch.
     *
     * Returns the `RUNNING` child meta on success; `null` when [claimParent] finds the task not `APPROVED`
     * (already claimed/terminal → the caller treats it as already-executed). A claimed parent with no
     * pending child is an invariant violation that rolls the whole claim back (leaving the task `APPROVED`).
     */
    fun claimAndStartRun(
        taskId: Long,
        executedBy: String,
        claimParent: (Connection) -> Boolean,
    ): QueryResultMeta? = dataSource.inTx { c ->
        if (!claimParent(c)) return@inTx null
        val childId = latestChildId(c, taskId, "status IS NULL")
            ?: error("task $taskId claimed for execution but has no pending child")
        val started = c.prepareStatement(
            "UPDATE query_result SET status = 'RUNNING', executed_by = ?, error_code = NULL WHERE id = ? AND status IS NULL",
        ).use { ps ->
            ps.setString(1, executedBy)
            ps.setLong(2, childId)
            ps.executeUpdate() > 0
        }
        if (!started) error("task $taskId child $childId not startable")
        meta(taskId, c)
    }

    fun completeRun(
        taskId: Long,
        result: DecryptedResult,
        retentionSec: Long,
        audit: (Connection, QueryResultMeta) -> Unit = { _, _ -> },
    ): QueryResultMeta? {
        val blob = crypto.encrypt(ResultPayloadCodec.encode(result))
        val now = Instant.now()
        return dataSource.inTx { c ->
            val childId = latestChildId(c, taskId, "status = 'RUNNING'")
            val updated = childId != null && c.prepareStatement(
                """UPDATE query_result
                   SET status = 'DONE', ciphertext = ?, row_count = ?, columns = ?,
                       executed_at = ?, expires_at = ?, error_code = NULL
                   WHERE id = ? AND status = 'RUNNING'""",
            ).use { ps ->
                ps.setBytes(1, blob)
                ps.setInt(2, result.rowsAffected ?: result.rows.size)
                val columnsJson = json.encodeToString(stringList, result.columns)
                if (c.metaData.databaseProductName.contains("PostgreSQL", ignoreCase = true)) {
                    ps.setObject(3, PGobject().apply { type = "jsonb"; value = columnsJson })
                } else {
                    ps.setString(3, columnsJson)
                }
                ps.setTimestamp(4, Timestamp.from(now))
                ps.setTimestamp(5, Timestamp.from(now.plusSeconds(retentionSec)))
                ps.setLong(6, childId)
                ps.executeUpdate() > 0
            }
            val meta = if (updated) meta(taskId, c) else null
            if (meta != null) audit(c, meta)
            meta
        }
    }

    fun failRun(
        taskId: Long,
        errorCode: String,
        // Set only when the failure is a POLICY DENIAL, carrying that decision's reason and audit id onto
        // the child. A client polling this row can then present the denial as a decision it may request
        // approval for, rather than as an opaque failure.
        denyReason: String? = null,
        decisionId: Long? = null,
        // A target-DB failure's error (both forms), encrypted into error_detail.
        diagnostic: RunError? = null,
        // Runs in the child's RUNNING → FAILED transaction (mirrors [completeRun]) so the caller can
        // terminalize the parent atomically; a throw here rolls the child transition back too.
        onFailed: (Connection, QueryResultMeta) -> Unit = { _, _ -> },
    ): QueryResultMeta? = dataSource.inTx { c ->
        val now = Instant.now()
        val childId = latestChildId(c, taskId, "status = 'RUNNING'")
        val updated = childId != null && c.prepareStatement(
            "UPDATE query_result SET status = 'FAILED', error_code = ?, deny_reason = ?, decision_id = ?, " +
                "error_detail = ?, expires_at = ? WHERE id = ? AND status = 'RUNNING'",
        ).use { ps ->
            ps.setString(1, errorCode)
            ps.setString(2, denyReason)
            if (decisionId == null) ps.setNull(3, java.sql.Types.BIGINT) else ps.setLong(3, decisionId)
            if (diagnostic == null) ps.setNull(4, java.sql.Types.BINARY)
            else ps.setBytes(4, crypto.encrypt(diagnostic.toByteArray()))
            ps.setTimestamp(5, Timestamp.from(now.plusSeconds(RESULT_RETENTION_SEC)))
            ps.setLong(6, childId)
            ps.executeUpdate() > 0
        }
        val meta = if (updated) meta(taskId, c) else null
        if (meta != null) onFailed(c, meta)
        meta
    }

    fun cancelRun(
        taskId: Long,
        onCancelled: (Connection, QueryResultMeta) -> Unit = { _, _ -> },
    ): QueryResultMeta? = dataSource.inTx { c ->
        val now = Instant.now()
        val childId = latestChildId(c, taskId, "status = 'RUNNING'")
        val updated = childId != null && c.prepareStatement(
            "UPDATE query_result SET status = 'CANCELLED', error_code = 'approval.canceled', expires_at = ? " +
                "WHERE id = ? AND status = 'RUNNING'",
        ).use { ps ->
            ps.setTimestamp(1, Timestamp.from(now.plusSeconds(RESULT_RETENTION_SEC)))
            ps.setLong(2, childId)
            ps.executeUpdate() > 0
        }
        val meta = if (updated) meta(taskId, c) else null
        if (meta != null) onCancelled(c, meta)
        meta
    }

    fun meta(taskId: Long): QueryResultMeta? = dataSource.connection.use { c -> meta(taskId, c) }

    // The active child is selected by a SEPARATE read, then updated by its own id. The per-status guard
    // stays on the UPDATE, so the transition is still a race-safe compare-and-set.
    private fun latestChildId(c: Connection, taskId: Long, statusClause: String): Long? = c.prepareStatement(
        "SELECT id FROM query_result WHERE task_id = ? AND $statusClause ORDER BY id DESC LIMIT 1",
    ).use { ps ->
        ps.setLong(1, taskId)
        ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
    }

    private fun meta(taskId: Long, c: Connection): QueryResultMeta? = c.prepareStatement(
        "SELECT $META_COLS FROM query_result WHERE task_id = ? ORDER BY id DESC LIMIT 1",
    ).use { ps ->
        ps.setLong(1, taskId)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toMeta() else null }
    }

    fun accessFor(taskId: Long): ResultAccess? {
        val row = dataSource.connection.use { c ->
            c.prepareStatement(
                "SELECT $META_COLS, qr.sql, ciphertext, error_detail FROM query_result qr " +
                    "WHERE task_id = ? ORDER BY id DESC LIMIT 1",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.executeQuery().use { rs ->
                    if (!rs.next()) return null
                    RawResultRow(rs.toMeta(), rs.getString("sql"), rs.getBytes("ciphertext"), rs.getBytes("error_detail"))
                }
            }
        }
        val meta = row.meta
        val expired = meta.expiresAt != null && Instant.parse(meta.expiresAt).isBefore(Instant.now())
        if (expired) purgeExpired()
        // Rows and the failure diagnostic release behind the same gate and vanish on expiry; both decrypt
        // lazily so a caller rejected on [meta] never triggers a decrypt.
        val payload = if (meta.status == "DONE" && !expired) row.ciphertext else null
        val errorBytes = if (!expired) row.errorDetail else null
        return ResultAccess(
            meta,
            row.sql,
            decrypt = { payload?.let { ResultPayloadCodec.decode(crypto.decrypt(it)) } },
            decryptError = { errorBytes?.let { RunError.parseFrom(crypto.decrypt(it)) } },
        )
    }

    // Expiry drops the decryptable PAYLOAD (ciphertext, row_count, columns, the encrypted error_detail) and
    // clears expires_at, but keeps the child row and its sql/sql_hash/status/error_code/executed_* for durable
    // audit and web preview. A purged row still exists yet reads back with no payload (accessFor's `decrypted`
    // is null → the route returns 410). Clearing expires_at makes the row fall out of this sweep's WHERE, so
    // it isn't reprocessed.
    fun purgeExpired(): Int = dataSource.connection.use { c ->
        c.prepareStatement(
            "UPDATE query_result SET ciphertext = NULL, row_count = NULL, columns = NULL, error_detail = NULL, " +
                "expires_at = NULL WHERE expires_at <= ?",
        ).use { ps ->
            ps.setTimestamp(1, Timestamp.from(Instant.now()))
            ps.executeUpdate()
        }
    }

    /** Drop the result child(ren) of one task outright (close-tab). Editor tabs are 1:child, so this
     *  removes exactly the tab's saved rows. Returns the number of rows deleted (0 = already gone → idempotent). */
    fun deleteResultsForTask(taskId: Long): Int = dataSource.connection.use { c ->
        c.prepareStatement("DELETE FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeUpdate()
        }
    }

    /** Drop every EDITOR result child owned by [principal] — the delete-on-session-end backstop (logout,
     *  deprovision, device-mismatch, newest-wins displacement all funnel through PrincipalSessionStore's
     *  end seam). Only EDITOR children are removed; a workflow task's saved result is untouched. */
    fun deleteEditorResultsForPrincipal(principal: String): Int =
        dataSource.connection.use { c -> deleteEditorResultsForPrincipal(principal, c) }

    /** Same as [deleteEditorResultsForPrincipal], composed onto a caller-supplied connection [c] — the
     *  session-end seam passes the connection that performed the end-write, so this delete joins the same
     *  transaction and commits or rolls back atomically with it (never orphaning a committed delete under a
     *  rolled-back deprovision teardown).
     *
     *  Deletes the principal's EDITOR *tasks* (access_request), cascading their query_result children, rather
     *  than only the children: dropping the whole task terminalizes any that were still EXECUTING when the
     *  session ended (a child-only delete would strand the parent EXECUTING until the boot reconcile) and
     *  leaves no empty editor task rows behind. Only creator_kind='EDITOR' rows for this principal — a
     *  WORKFLOW approval is never touched. */
    fun deleteEditorResultsForPrincipal(principal: String, c: Connection): Int = c.prepareStatement(
        "DELETE FROM access_request WHERE creator_kind = 'EDITOR' AND principal = ?",
    ).use { ps ->
        ps.setString(1, principal)
        ps.executeUpdate()
    }

    /**
     * GC expired EDITOR result children by DELETING them outright — unlike [purgeExpired], which keeps a
     * workflow child's row (NULLs only the payload) for durable audit/preview. An editor tab has no such
     * audit obligation, so its expired child is removed whole. Runs on the same background sweep.
     */
    fun purgeExpiredEditorChildren(): Int = dataSource.connection.use { c ->
        c.prepareStatement(
            "DELETE FROM query_result WHERE expires_at <= ? AND task_id IN " +
                "(SELECT id FROM access_request WHERE creator_kind = 'EDITOR')",
        ).use { ps ->
            ps.setTimestamp(1, Timestamp.from(Instant.now()))
            ps.executeUpdate()
        }
    }

    companion object {
        const val RESULT_RETENTION_SEC = 86_400L
        // Every column [toMeta] reads. The mapper reads by NAME, so a column added there and missed here
        // fails the read at runtime rather than at compile time — keep the two in step.
        private const val META_COLS =
            "task_id, executed_by, executed_at, row_count, expires_at, status, error_code, " +
                "deny_reason, decision_id, columns"
    }
}
