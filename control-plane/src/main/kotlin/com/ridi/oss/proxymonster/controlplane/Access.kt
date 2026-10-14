package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.probe.Dialect
import com.ridi.oss.proxymonster.probe.sqlGrantHash
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.math.BigInteger
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant
import javax.sql.DataSource

// ---- DTOs — the wire contract for /api/access-requests** + /api/access-grants** ----------

/** What an edit sets besides the statements: the new SQL's hash and analysis, and a title or reason to replace (null keeps). */
data class RequestEdit(
    val contentHash: String,
    val denyReason: String?,
    val evaluatedDecision: String?,
    val carriesProtectedLiteral: Boolean?,
    val title: String? = null,
    val reason: String? = null,
    /** A pull request's file: its new key and the head it was filed for. */
    val origin: RequestOrigin? = null,
)

@Serializable
data class AccessRequest(
    val id: Long, val principal: String, val roleId: Long? = null, val roleName: String? = null,
    val datasourceId: Long? = null, val datasourceName: String? = null,
    val reason: String? = null,
    val requestedDurationSec: Long, val status: String, val decidedBy: String? = null,
    val executedBy: String? = null,
    val decidedAt: String? = null, val rejectionReason: String? = null, val createdAt: String,
    val kind: String = "ROLE",
    /** The task's statements joined in run order — the request's readable form. Each statement is
     *  authorized, executed, and stored on its own child; this text is never the unit of authorization. */
    val sql: String? = null,
    val sqlHash: String? = null,
    /** How many statements the task holds. 1 for an ordinary single-statement request. */
    val statementCount: Int = 1,
    val denyReason: String? = null, val sourceDecisionId: Long? = null,
    val title: String? = null, val evaluatedDecision: String? = null,
    val approvedAt: String? = null,
    val executingAt: String? = null,
    // Terminal-success only. An in-flight or failed task keeps this null.
    val executedAt: String? = null,
    val executeAs: List<String> = emptyList(),
    val creatorKind: String? = null,
    /** Advisory, best-effort hint (NOT a security boundary): true when the statement compares a literal
     *  against a CLASSIFIED column, so its TEXT should not be forwarded outside the console (the value sits in
     *  the query, where masking cannot reach it). Reader-neutral — keyed on classification, never on who
     *  composed it. NULL (never analyzed) is treated as true; absence is not proof the statement is clean. */
    val statementCarriesProtectedLiteral: Boolean? = null,
    val source: String = "console",
    val scope: String? = null,
    /** The file's key from its name: what orders a pull request's files and, with [contentHash], keys the change. */
    val fileKey: String? = null,
    val changeKey: String? = null,
    val mergedAt: String? = null,
    /** Starts at 1 and grows with each edit of the SQL; an approval names the revision it approves. */
    val revision: Int,
    val revisedAt: String? = null,
    /** [contentHash] of the request's SQL; an edit that keeps it keeps the revision and the approval. */
    val contentHash: String? = null,
    val pullRequest: PullRequestRef? = null,
    /** An admin let this request run past its scope's freshness and one-PR-at-a-time checks. */
    val forceRun: Boolean = false,
    val forceRunBy: String? = null,
    val ccs: List<String> = emptyList(),
) {
    val fromPullRequest: Boolean get() = source == SOURCE_GITHUB
}

/** [AccessRequest.source] of a request filed from a GitHub pull request. */
const val SOURCE_GITHUB = "github"

/** The pull request a GitHub request came from. */
@Serializable
data class PullRequestRef(
    /** `owner/name` of the pull request's repository. */
    val repository: String,
    val pr: Int,
    val prUrl: String? = null,
    val path: String? = null,
    /** The pull request head the request was last filed for. */
    val headSha: String? = null,
    val defaultSchema: String? = null,
    /** How the scope's latest filing orders file keys: `numeric` or `string`. */
    val keyOrder: String? = null,
    /** The head of its scope's latest filing; the request belongs to that filing when [headSha] equals it. */
    val filedHead: String? = null,
    /** The pull request's merge commit, recorded when it merged. */
    val mergeSha: String? = null,
    val prAutoMerge: Boolean = false,
    /** The review an approval came from; null for a console or Slack approval. */
    val approvedReviewId: String? = null,
)

/** Where a request filed from a source repository sits: its ordered line, its file, and its pull request. */
data class RequestOrigin(
    val scope: String,
    val fileKey: String,
    val contentHash: String,
    val changeKey: String,
    val pullRequest: PullRequestRef,
)

/**
 * The authz view of this persisted approval request, built from its row so every route that decides a task
 * asks Cedar the same question from one place. The prospective auto-approval check (before a row exists)
 * builds its resource inline instead.
 */
fun AccessRequest.toApprovalResource() = AuthzResource.ApprovalRequest(
    requester = principal, approver = decidedBy, executedBy = executedBy,
    datasourceName = datasourceName, roleName = roleName, source = source, ccs = ccs,
)

@Serializable
data class AccessRequestInput(
    val roleId: Long, val datasourceId: Long? = null,
    val reason: String? = null, val requestedDurationSec: Long = 3600,
)

/** Ask an approver to reset the caller's spent `@cap` rates (docs/result-caps.md); [denyReason] is the spent rate. */
@Serializable
data class RateResetRequestInput(val reason: String, val denyReason: String? = null)

/** An admin resets a principal's spent rates directly; the reason is recorded with the marker. */
@Serializable
data class RateResetInput(val reason: String)

@Serializable
data class AccessGrant(
    val id: Long, val principal: String, val roleId: Long, val roleName: String,
    val grantedBy: String? = null, val grantedAt: String,
    val expiresAt: String? = null, val revokedAt: String? = null,
)

@Serializable data class ApproveInput(val durationSec: Long? = null)
@Serializable data class RejectInput(val reason: String)

/** `n:` the SQL's grant hash, or `r:` its raw bytes' hash when the normalizer refuses it. */
fun contentHash(sql: String, dialect: Dialect): String =
    sqlGrantHash(sql, dialect)?.let { "n:$it" } ?: "r:${sha256Hex(sql)}"

fun changeKey(fileKey: String, contentHash: String): String = sha256Hex(fileKey + "\n" + contentHash)

/** How a pull request's file keys sort: `numeric` keeps `9` before `10`, `string` compares bytes. */
@Serializable
enum class KeyOrder {
    @SerialName("numeric") NUMERIC,
    @SerialName("string") STRING,
    ;

    val wireName: String get() = name.lowercase()

    companion object {
        fun fromWire(value: String?): KeyOrder = entries.firstOrNull { it.wireName == value } ?: NUMERIC
    }
}

/** Orders `(fileKey, path)` pairs by key, then by path; [KeyOrder.NUMERIC] needs every key to be digits. */
fun compareFileKeys(order: KeyOrder): Comparator<Pair<String, String>> {
    val byKey: Comparator<Pair<String, String>> = when (order) {
        KeyOrder.NUMERIC -> compareBy { BigInteger(it.first) }
        KeyOrder.STRING -> Comparator { a, b -> compareBytes(a.first, b.first) }
    }
    return byKey.thenComparing { a, b -> compareBytes(a.second, b.second) }
}

private fun compareBytes(a: String, b: String): Int =
    java.util.Arrays.compareUnsigned(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

// ---- Store -------------------------------------------------------------------------------

class DuplicatePendingQueryRequestException : RuntimeException("a pending query request already exists for this decision")

/** An approval not run within this long returns the request to PENDING. */
val APPROVAL_TTL: Duration = Duration.ofHours(24)

class AccessStore(internal val dataSource: DataSource) {
    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    private fun ResultSet.longOrNull(col: String): Long? = getLong(col).let { if (wasNull()) null else it }

    fun getRequest(id: Long): AccessRequest? = dataSource.connection.use { getRequest(id, it) }

    /** Read on the caller's connection so an in-transaction read never borrows a second pooled connection. */
    fun getRequest(id: Long, c: Connection): AccessRequest? =
        c.prepareStatement("$REQ_SELECT WHERE ar.id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRequest() else null }
        }

    /** ROLE and RATE_RESET requests: both are decided PENDING → APPROVED | REJECTED by the same routes. */
    fun listRequests(status: String?): List<AccessRequest> = dataSource.connection.use { c ->
        val sql = if (status != null) {
            "$REQ_SELECT WHERE ar.kind IN ('ROLE', 'RATE_RESET') AND ar.status = ? ORDER BY ar.created_at DESC"
        } else {
            "$REQ_SELECT WHERE ar.kind IN ('ROLE', 'RATE_RESET') ORDER BY ar.created_at DESC"
        }
        c.prepareStatement(sql).use { ps ->
            if (status != null) ps.setString(1, status)
            ps.executeQuery().use { rs -> val o = ArrayList<AccessRequest>(); while (rs.next()) o += rs.toRequest(); o }
        }
    }

    fun createRequest(principal: String, input: AccessRequestInput, source: String = "console"): AccessRequest {
        val id = dataSource.inTx { c -> createRequest(principal, input, c, source) }
        return getRequest(id)!!
    }

    /** Insert a ROLE access request on the caller's transaction, returning its id. */
    fun createRequest(principal: String, input: AccessRequestInput, c: Connection, source: String = "console"): Long =
        c.prepareStatement(
            """INSERT INTO access_request (principal, role_id, datasource_id, reason, requested_duration_sec, source)
               VALUES (?, ?, ?, ?, ?, ?) RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setLong(2, input.roleId)
            if (input.datasourceId == null) ps.setNull(3, java.sql.Types.BIGINT) else ps.setLong(3, input.datasourceId)
            ps.setString(4, input.reason)
            ps.setLong(5, input.requestedDurationSec)
            ps.setString(6, source)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }

    /** Open a ROLE access request, recording the [TASK_REQUEST][AuthzAction.TASK_REQUEST] event atomically. */
    fun createRequest(
        principal: String,
        input: AccessRequestInput,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        source: String = "console",
    ): AccessRequest {
        val id = dataSource.inTx { c ->
            val newId = createRequest(principal, input, c, source)
            val roleName = c.prepareStatement("SELECT name FROM app_role WHERE id = ?").use { ps ->
                ps.setLong(1, input.roleId)
                ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
            }
            recorder.record(
                c, actor, AuthzAction.TASK_REQUEST, auditEntity("AccessRequest", newId.toString()),
                "open access request #$newId for role '$roleName'",
            )
            newId
        }
        return getRequest(id)!!
    }

    /** Open a RATE_RESET request (docs/result-caps.md), recording it as a TASK_REQUEST atomically. */
    fun createRateResetRequest(
        principal: String,
        input: RateResetRequestInput,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
    ): AccessRequest {
        val id = dataSource.inTx { c ->
            val newId = c.prepareStatement(
                """INSERT INTO access_request (principal, kind, reason, deny_reason, requested_duration_sec)
                   VALUES (?, 'RATE_RESET', ?, ?, 0) RETURNING id""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setString(2, input.reason)
                ps.setString(3, input.denyReason)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            recorder.record(
                c, actor, AuthzAction.TASK_REQUEST, auditEntity("AccessRequest", newId.toString()),
                "open rate reset request #$newId",
            )
            newId
        }
        return getRequest(id)!!
    }

    fun createQueryRequest(
        principal: String,
        datasourceId: Long,
        // The batch's statements, in the order they run — one query_result child each, split server-side by
        // the analyzer. A single-statement request is the one-element case.
        statements: List<String>,
        denyReason: String?,
        sourceDecisionId: Long?,
        reason: String?,
        title: String?,
        evaluatedDecision: String?,
        // APPROVAL: the elevation role R the requester picked (role discovery). NULL = a legacy request with
        // no elevation role (the approver runs as themselves). The FK to app_role validates R.
        roleId: Long? = null,
        // Carried on the shared access_request row; not consumed by the query-approval flow (see
        // CreateQueryRequestInput.requestedDurationSec). Kept for the column the ROLE-elevation path needs.
        requestedDurationSec: Long = 3600,
        // Advisory hint: whether a literal was compared against a CLASSIFIED column (reader-neutral — see
        // AccessRequest.statementCarriesProtectedLiteral). NULL when not analyzed → downstream withholds.
        carriesProtectedLiteral: Boolean? = null,
        // Queues the "needs approval" notification in the SAME transaction as the insert, so a crash can
        // never leave a request pending with nobody told. No-op when notifications are not configured.
        onCreated: ((Connection, Long, String?) -> Unit)? = null,
        // Set on the audited create path (the /api/approvals routes); null on internal/test seeds. When both
        // are present the created request is recorded as a TASK_REQUEST on the insert's transaction.
        actor: AuditActor? = null,
        recorder: ManagementAuditRecorder? = null,
        source: String = "console",
        contentHash: String? = null,
        origin: RequestOrigin? = null,
    ): AccessRequest {
        require(statements.isNotEmpty()) { "a query request needs at least one statement" }
        val id = dataSource.inTx { c ->
            val executeAs = roleId?.let { id ->
                c.prepareStatement("SELECT name FROM app_role WHERE id = ? AND deleted_at IS NULL").use { ps ->
                    ps.setLong(1, id)
                    ps.executeQuery().use { rs -> if (rs.next()) listOf(rs.getString(1)) else emptyList() }
                }
            }.orEmpty()
            val taskId = c.prepareStatement(
                """INSERT INTO access_request
                   (principal, kind, role_id, datasource_id, deny_reason, source_decision_id, reason, title,
                    evaluated_decision, requested_duration_sec, execute_as, creator_kind,
                    statement_carries_protected_literal, source, scope, change_key, path, pr_url,
                    repository, pr, default_schema, head_sha, file_key, content_hash, key_order)
                   VALUES (?, 'QUERY', ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, 'WORKFLOW', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (source_decision_id) WHERE kind = 'QUERY' AND status = 'PENDING' AND source_decision_id IS NOT NULL
                   DO NOTHING
                   RETURNING id""",
            ).use { ps ->
                ps.setString(1, principal)
                if (roleId == null) ps.setNull(2, java.sql.Types.BIGINT) else ps.setLong(2, roleId)
                ps.setLong(3, datasourceId)
                ps.setString(4, denyReason)
                if (sourceDecisionId == null) ps.setNull(5, java.sql.Types.BIGINT) else ps.setLong(5, sourceDecisionId)
                ps.setString(6, reason)
                ps.setString(7, title)
                ps.setString(8, evaluatedDecision)
                ps.setLong(9, requestedDurationSec)
                ps.setString(10, json.encodeToString(stringList, executeAs))
                if (carriesProtectedLiteral == null) ps.setNull(11, java.sql.Types.BOOLEAN) else ps.setBoolean(11, carriesProtectedLiteral)
                ps.setString(12, source)
                val ref = origin?.pullRequest
                ps.setString(13, origin?.scope)
                ps.setString(14, origin?.changeKey)
                ps.setString(15, ref?.path)
                ps.setString(16, ref?.prUrl)
                ps.setString(17, ref?.repository)
                if (ref == null) ps.setNull(18, java.sql.Types.INTEGER) else ps.setInt(18, ref.pr)
                ps.setString(19, ref?.defaultSchema)
                ps.setString(20, ref?.headSha)
                ps.setString(21, origin?.fileKey)
                ps.setString(22, contentHash ?: origin?.contentHash)
                ps.setString(23, ref?.keyOrder)
                ps.executeQuery().use { rs ->
                    if (rs.next()) rs.getLong(1) else throw DuplicatePendingQueryRequestException()
                }
            }
            insertStatements(c, taskId, statements)
            RequestEvents.record(c, taskId, RequestEventKind.REQUESTED, principal, source)
            if (actor != null && recorder != null) {
                recorder.record(
                    c, actor, AuthzAction.TASK_REQUEST, auditEntity("AccessRequest", taskId.toString()),
                    "open query request #$taskId under role '${executeAs.firstOrNull()}'",
                )
            }
            onCreated?.invoke(c, taskId, executeAs.firstOrNull())
            taskId
        }
        return getRequest(id)!!
    }

    /**
     * Create a born-APPROVED EDITOR task with ONE result child (task:child 1:1 per editor submit). Unlike
     * [createQueryRequest] (a human-decided WORKFLOW request that starts PENDING under an elevation role R),
     * an editor submit auto-approves itself: [executeAs] is the caller's OWN server-resolved roles, freshly
     * resolved at submit — never an elevation, never frozen across submits (a re-run resolves again, so a
     * revoked role fails closed on the next submit). [approver] is the self-approver (== principal). The row
     * is stamped APPROVED/decided so the same single-execution status machine (claimExecution APPROVED →
     * EXECUTING → EXECUTED/FAILED) and boot reconcile drive it verbatim, exactly like an approved workflow
     * task — no editor-only status path.
     */
    fun createEditorTask(
        principal: String,
        datasourceId: Long,
        statements: List<String>,
        executeAs: List<String>,
        approver: String,
    ): AccessRequest {
        require(statements.isNotEmpty()) { "an editor task needs at least one statement" }
        val id = dataSource.inTx { c ->
            val now = Timestamp.from(Instant.now())
            val taskId = c.prepareStatement(
                """INSERT INTO access_request
                   (principal, kind, datasource_id, status, decided_by, decided_at, approved_at,
                    requested_duration_sec, execute_as, creator_kind)
                   VALUES (?, 'QUERY', ?, 'APPROVED', ?, ?, ?, ?, ?::jsonb, 'EDITOR')
                   RETURNING id""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setLong(2, datasourceId)
                ps.setString(3, approver)
                ps.setTimestamp(4, now)
                ps.setTimestamp(5, now)
                ps.setLong(6, 3600)
                ps.setString(7, json.encodeToString(stringList, executeAs))
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            insertStatements(c, taskId, statements)
            taskId
        }
        return getRequest(id)!!
    }

    /**
     * Insert a task's statements as its ordered result children — one row per statement, `ordinal` its
     * 0-based position in the batch. Each child carries its OWN sql and sql_hash: the batch is authorized,
     * executed, and stored per statement, so a hash over the joined text would identify nothing that runs.
     */
    private fun insertStatements(c: Connection, taskId: Long, statements: List<String>) {
        c.prepareStatement(
            "INSERT INTO query_result (task_id, ordinal, sql, sql_hash) VALUES (?, ?, ?, ?)",
        ).use { ps ->
            statements.forEachIndexed { ordinal, statement ->
                ps.setLong(1, taskId)
                ps.setInt(2, ordinal)
                ps.setString(3, statement)
                ps.setString(4, sha256Hex(statement))
                ps.addBatch()
            }
            ps.executeBatch()
        }
    }

    /**
     * Create the lifecycle record for one native-wire statement authorization. [sourceDecisionId] links the
     * childless task to the decision audit event that carries the statement text and verdict. The task stays
     * APPROVED until the proxy's post-relay completion confirms execution; because the relay streams directly
     * to the client and saves no result child, [getRequest] reads `sql`, `sqlHash`, and `executedBy` as null.
     *
     * The caller supplies [c] so the decision event and its task commit atomically.
     */
    fun createWireTask(
        c: Connection,
        principal: String,
        datasourceId: Long,
        executeAs: List<String>,
        sourceDecisionId: Long,
    ): Long {
        val now = Timestamp.from(Instant.now())
        return c.prepareStatement(
            """INSERT INTO access_request
               (principal, kind, datasource_id, status, decided_by, decided_at, approved_at,
                requested_duration_sec, execute_as, creator_kind, source_decision_id)
               VALUES (?, 'QUERY', ?, 'APPROVED', ?, ?, ?, ?, ?::jsonb, 'WIRE', ?)
               RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setLong(2, datasourceId)
            ps.setString(3, principal)
            ps.setTimestamp(4, now)
            ps.setTimestamp(5, now)
            ps.setLong(6, 3600)
            ps.setString(7, json.encodeToString(stringList, executeAs))
            ps.setLong(8, sourceDecisionId)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    /**
     * Find the native-wire task correlated to [decisionId]. WORKFLOW tasks also carry the DENY decision that
     * spawned them, so the creator-kind filter is required: a proxy completion must never terminalize one.
     */
    fun wireTaskIdForDecision(decisionId: Long, c: Connection): Long? = c.prepareStatement(
        """SELECT id FROM access_request
           WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND source_decision_id = ?""",
    ).use { ps ->
        ps.setLong(1, decisionId)
        ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
    }

    /** The id of an EDITOR task's FIRST result child — carried in the submit ack. */
    fun editorChildId(taskId: Long): Long? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM query_result WHERE task_id = ? ORDER BY ordinal LIMIT 1").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    }

    /**
     * Owner-scoped delete of an EDITOR task (close-tab). CASCADEs to its query_result child(ren). Restricted
     * to `creator_kind = 'EDITOR'` + the owner so a leaked task id can never delete another principal's task
     * (nor a human-approval WORKFLOW task). Idempotent: returns false when nothing matched.
     */
    fun deleteEditorTask(taskId: Long, principal: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            "DELETE FROM access_request WHERE id = ? AND kind = 'QUERY' AND creator_kind = 'EDITOR' AND principal = ?",
        ).use { ps ->
            ps.setLong(1, taskId)
            ps.setString(2, principal)
            ps.executeUpdate() > 0
        }
    }

    fun pendingQueryRequestExists(sourceDecisionId: Long): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT 1 FROM access_request
               WHERE kind = 'QUERY' AND source_decision_id = ? AND status = 'PENDING'
               LIMIT 1""",
        ).use { ps ->
            ps.setLong(1, sourceDecisionId)
            ps.executeQuery().use { rs -> rs.next() }
        }
    }

    /** Atomically decide a pending QUERY task. Approval authorizes execution; it does not run the statement. */
    fun decideQueryRequest(
        id: Long,
        approved: Boolean,
        rejectionReason: String?,
        decidedBy: String,
        revision: Int,
        reviewId: String? = null,
    ): AccessRequest? {
        val won = dataSource.inTx { c -> decideQueryRequest(id, approved, rejectionReason, decidedBy, c, revision, reviewId) }
        return if (won) getRequest(id) else null
    }

    /** Same as [decideQueryRequest], composed on the caller's transaction. Returns whether a row transitioned. */
    fun decideQueryRequest(
        id: Long,
        approved: Boolean,
        rejectionReason: String?,
        decidedBy: String,
        c: Connection,
        revision: Int,
        reviewId: String? = null,
    ): Boolean {
        val decidedAt = Timestamp.from(Instant.now())
        return c.prepareStatement(
            """UPDATE access_request
               SET status = ?, decided_by = ?, decided_at = ?, approved_at = ?, rejection_reason = ?, approved_review_id = ?
               WHERE id = ? AND kind = 'QUERY' AND revision = ?
                 AND (status = 'PENDING' OR (status = 'APPROVED' AND ? = 'REJECTED'))""",
        ).use { ps ->
            ps.setString(1, if (approved) "APPROVED" else "REJECTED")
            ps.setString(2, decidedBy)
            ps.setTimestamp(3, decidedAt)
            if (approved) ps.setTimestamp(4, decidedAt) else ps.setNull(4, java.sql.Types.TIMESTAMP)
            ps.setString(5, rejectionReason)
            ps.setString(6, if (approved) reviewId else null)
            ps.setLong(7, id)
            ps.setInt(8, revision)
            ps.setString(9, if (approved) "APPROVED" else "REJECTED")
            ps.executeUpdate() > 0
        }
    }

    /**
     * Decide a pending QUERY task, recording the [TASK_APPROVE][AuthzAction.TASK_APPROVE] decision atomically.
     * A task no longer PENDING, or edited past [revision], transitions no row, so nothing is recorded.
     */
    fun decideQueryRequest(
        id: Long,
        approved: Boolean,
        rejectionReason: String?,
        decidedBy: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        revision: Int,
        // Queues the decision notification in the SAME transaction as the transition, so a crash can never
        // leave a request decided with nobody told. No-op when the notification layer is not configured.
        onDecided: ((Connection, AccessRequest) -> Unit)? = null,
        // Appended to the audit summary, e.g. the review an approval came from.
        detail: String? = null,
        reviewId: String? = null,
    ): AccessRequest? {
        val before = getRequest(id)
        val roleName = before?.roleName
        val won = dataSource.inTx { c ->
            decideQueryRequest(id, approved, rejectionReason, decidedBy, c, revision, reviewId).also { transitioned ->
                if (transitioned) {
                    RequestEvents.record(
                        c, id, if (approved) RequestEventKind.APPROVED else RequestEventKind.REJECTED,
                        decidedBy, actor.channel, rejectionReason,
                    )
                    recorder.record(
                        c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessRequest", id.toString()),
                        (if (approved) "approve query request #$id revision $revision under role '$roleName'" else "reject query request #$id revision $revision") +
                            (detail?.let { " ($it)" } ?: ""),
                    )
                    // The row the hook sees carries the decision that just landed: the pre-read plus the
                    // fields this transaction set, since the UPDATE is not visible to another connection yet.
                    before?.let { prior ->
                        onDecided?.invoke(
                            c,
                            prior.copy(
                                status = if (approved) "APPROVED" else "REJECTED",
                                decidedBy = decidedBy,
                                rejectionReason = rejectionReason,
                                pullRequest = prior.pullRequest?.copy(approvedReviewId = if (approved) reviewId else null),
                            ),
                        )
                    }
                }
            }
        }
        return if (won) getRequest(id) else null
    }

    /**
     * Replace a PENDING or APPROVED workflow request's statements, returning it to PENDING under the next revision
     * and recording a [TASK_REQUEST][AuthzAction.TASK_REQUEST] event. Null when it is no longer editable.
     */
    fun editQueryRequest(
        id: Long,
        statements: List<String>,
        edit: RequestEdit,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        onEdited: ((Connection, AccessRequest) -> Unit)? = null,
    ): AccessRequest? {
        require(statements.isNotEmpty()) { "a query request needs at least one statement" }
        val edited = dataSource.inTx { c ->
            val revision = c.prepareStatement(
                """UPDATE access_request
                   SET status = 'PENDING', decided_by = NULL, decided_at = NULL, approved_at = NULL,
                       rejection_reason = NULL, source_decision_id = NULL, deny_reason = ?, evaluated_decision = ?,
                       statement_carries_protected_literal = ?, title = COALESCE(?, title), reason = COALESCE(?, reason),
                       content_hash = ?, revision = revision + 1, revised_at = now(), approved_review_id = NULL,
                       force_run = FALSE, force_run_by = NULL,
                       file_key = COALESCE(?, file_key),
                       change_key = COALESCE(?, change_key), head_sha = COALESCE(?, head_sha)
                   WHERE id = ? AND kind = 'QUERY' AND creator_kind = 'WORKFLOW' AND status IN ('PENDING', 'APPROVED')
                   RETURNING revision""",
            ).use { ps ->
                ps.setString(1, edit.denyReason)
                ps.setString(2, edit.evaluatedDecision)
                if (edit.carriesProtectedLiteral == null) ps.setNull(3, java.sql.Types.BOOLEAN) else ps.setBoolean(3, edit.carriesProtectedLiteral)
                ps.setString(4, edit.title)
                ps.setString(5, edit.reason)
                ps.setString(6, edit.contentHash)
                ps.setString(7, edit.origin?.fileKey)
                ps.setString(8, edit.origin?.changeKey)
                ps.setString(9, edit.origin?.pullRequest?.headSha)
                ps.setLong(10, id)
                ps.executeQuery().use { rs -> if (rs.next()) rs.getInt(1) else null }
            } ?: return@inTx false
            c.prepareStatement("DELETE FROM query_result WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
            insertStatements(c, id, statements)
            RequestEvents.record(c, id, RequestEventKind.EDITED, actor.principal, actor.channel)
            recorder.record(
                c, actor, AuthzAction.TASK_REQUEST, auditEntity("AccessRequest", id.toString()),
                "edit query request #$id to revision $revision (sql ${sha256Hex(statements.joinToString(";\n")).take(12)})",
            )
            onEdited?.invoke(c, c.prepareStatement("$REQ_SELECT WHERE ar.id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> rs.next(); rs.toRequest() }
            })
            true
        }
        return if (edited) getRequest(id) else null
    }

    /**
     * Replace the title or reason (null keeps) of a PENDING or APPROVED request whose SQL did not change, and a
     * pull request's file its [pullRequest] path and head.
     */
    fun editQueryRequestDetails(
        id: Long,
        title: String?,
        reason: String?,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        pullRequest: PullRequestRef? = null,
    ): AccessRequest? {
        val edited = dataSource.inTx { c ->
            val revision = c.prepareStatement(
                """UPDATE access_request SET title = COALESCE(?, title), reason = COALESCE(?, reason),
                       path = COALESCE(?, path), head_sha = COALESCE(?, head_sha)
                   WHERE id = ? AND kind = 'QUERY' AND creator_kind = 'WORKFLOW' AND status IN ('PENDING', 'APPROVED')
                   RETURNING revision""",
            ).use { ps ->
                ps.setString(1, title)
                ps.setString(2, reason)
                ps.setString(3, pullRequest?.path)
                ps.setString(4, pullRequest?.headSha)
                ps.setLong(5, id)
                ps.executeQuery().use { rs -> if (rs.next()) rs.getInt(1) else null }
            } ?: return@inTx false
            recorder.record(
                c, actor, AuthzAction.TASK_REQUEST, auditEntity("AccessRequest", id.toString()),
                "edit query request #$id at revision $revision (same sql)",
            )
            true
        }
        return if (edited) getRequest(id) else null
    }

    /** Atomically claim an approved task for execution. Exactly one concurrent caller wins. */
    fun claimExecution(id: Long): Boolean = dataSource.inTx { c -> claimExecution(id, c) }

    /**
     * Same as [claimExecution], on the caller's transaction. A scoped request also needs no other run open
     * in its scope, else [TaskServiceException] 409 `approval.scope_busy`.
     */
    fun claimExecution(id: Long, c: Connection): Boolean {
        val scope = c.prepareStatement("SELECT status, scope FROM access_request WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next() && rs.getString(1) == "APPROVED") rs.getString(2) else null }
        }
        if (scope != null) checkOrdering(id, scope, c)
        return c.prepareStatement(
            """UPDATE access_request SET status = 'EXECUTING', executing_at = ?
               WHERE id = ? AND kind = 'QUERY' AND status = 'APPROVED' AND $APPROVAL_LIVE""",
        ).use { ps ->
            val now = Instant.now()
            ps.setTimestamp(1, Timestamp.from(now))
            ps.setLong(2, id)
            ps.setTimestamp(3, Timestamp.from(now.minus(APPROVAL_TTL)))
            ps.executeUpdate() > 0
        }
    }

    private fun checkOrdering(id: Long, scope: String, c: Connection) {
        c.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, scope)
            ps.executeQuery().use { it.next() }
        }
        // Re-read under the lock: a concurrent winner has moved the row off APPROVED and loses as false.
        var repository: String? = null
        var pr: Int? = null
        c.prepareStatement("SELECT status, repository, pr, force_run FROM access_request WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next() || rs.getString(1) != "APPROVED" || rs.getBoolean(4)) return
                repository = rs.getString(2)
                pr = rs.getInt(3).takeUnless { rs.wasNull() }
            }
        }
        val busy = c.prepareStatement("SELECT 1 FROM access_request r WHERE $SCOPE_BUSY_WHERE LIMIT 1").use { ps ->
            ps.setScopeBusy(scope, id, repository, pr)
            ps.executeQuery().use { it.next() }
        }
        if (busy) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.scope_busy"))
    }

    private fun PreparedStatement.setScopeBusy(scope: String, id: Long, repository: String?, pr: Int?) {
        setString(1, scope)
        setLong(2, id)
        setString(3, repository)
        if (pr == null) setNull(4, java.sql.Types.INTEGER) else setInt(4, pr)
    }

    /** Every request filed from one pull request, any status, in file order. */
    fun listGithubRequests(repository: String, pr: Int): List<AccessRequest> = dataSource.connection.use { c ->
        c.prepareStatement(
            "$REQ_SELECT WHERE ar.source = 'github' AND ar.repository = ? AND ar.pr = ? ORDER BY ar.path, ar.id",
        ).use { ps ->
            ps.setString(1, repository)
            ps.setInt(2, pr)
            ps.executeQuery().use { rs -> val o = ArrayList<AccessRequest>(); while (rs.next()) o += rs.toRequest(); o }
        }
    }

    /**
     * Pull requests, by repository, with a request waiting to be approved or run, or run but not yet merged, or
     * carrying the key of another pull request's unmerged run.
     */
    fun pullRequestsToPoll(): Map<String, List<Int>> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT DISTINCT ar.repository, ar.pr FROM access_request ar
               WHERE ar.source = 'github' AND ar.repository IS NOT NULL AND ar.pr IS NOT NULL
                 AND (ar.status IN ('PENDING', 'APPROVED', 'EXECUTING')
                      OR (ar.status = 'EXECUTED' AND ar.merged_at IS NULL)
                      OR (ar.status = 'ALREADY_RAN' AND ar.merged_at IS NULL
                          AND EXISTS (SELECT 1 FROM access_request x
                                      WHERE x.scope = ar.scope AND x.change_key = ar.change_key
                                        AND x.status = 'EXECUTED' AND x.merged_at IS NULL)))
               ORDER BY ar.repository, ar.pr""",
        ).use { ps ->
            ps.executeQuery().use { rs ->
                val o = LinkedHashMap<String, MutableList<Int>>()
                while (rs.next()) o.getOrPut(rs.getString(1)) { ArrayList() } += rs.getInt(2)
                o
            }
        }
    }

    fun changeKeyExecuted(scope: String, changeKey: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT 1 FROM access_request WHERE scope = ? AND change_key = ? AND status = 'EXECUTED' LIMIT 1",
        ).use { ps ->
            ps.setString(1, scope)
            ps.setString(2, changeKey)
            ps.executeQuery().use { it.next() }
        }
    }

    /** The request that keeps [scope] busy for a pull request other than [excludeRepository]#[excludePr]. */
    fun scopeBlocker(scope: String, excludeRepository: String, excludePr: Int): AccessRequest? = dataSource.connection.use { c ->
        c.prepareStatement(
            "$REQ_SELECT WHERE ar.id = (SELECT MIN(r.id) FROM access_request r WHERE $SCOPE_BUSY_WHERE)",
        ).use { ps ->
            ps.setScopeBusy(scope, 0, excludeRepository, excludePr)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRequest() else null }
        }
    }

    /** End a request that has not started with [status]: DELETED, ALREADY_RAN or CANCELLED. */
    fun endUnstarted(id: Long, status: String): Boolean = dataSource.connection.use { c ->
        require(status in setOf("DELETED", "ALREADY_RAN", "CANCELLED"))
        c.prepareStatement(
            "UPDATE access_request SET status = ? WHERE id = ? AND kind = 'QUERY' AND status IN ('PENDING', 'APPROVED')",
        ).use { ps ->
            ps.setString(1, status)
            ps.setLong(2, id)
            ps.executeUpdate() > 0
        }
    }

    /** Return an approved, not-started request to PENDING, recording a [TASK_APPROVE][AuthzAction.TASK_APPROVE] event. */
    fun reopenQueryRequest(
        id: Long,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        detail: String,
        event: RequestEventKind = RequestEventKind.WITHDRAWN,
        onReopened: ((Connection, AccessRequest) -> Unit)? = null,
    ): Boolean =
        dataSource.inTx { c ->
            val won = c.prepareStatement(
                """UPDATE access_request SET status = 'PENDING', decided_by = NULL, decided_at = NULL, approved_at = NULL,
                       approved_review_id = NULL
                   WHERE id = ? AND kind = 'QUERY' AND status = 'APPROVED'""",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate() > 0
            }
            if (won) {
                recorder.record(
                    c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessRequest", id.toString()),
                    "withdraw the approval of query request #$id ($detail)",
                )
                RequestEvents.record(c, id, event, actor.principal.takeIf { event != RequestEventKind.EXPIRED }, actor.channel)
                onReopened?.let { hook -> getRequest(id, c)?.let { hook(c, it) } }
            }
            won
        }

    /** Ids of console requests approved longer than [APPROVAL_TTL] ago and not yet started. */
    fun expiredApprovals(): List<Long> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id FROM access_request
               WHERE kind = 'QUERY' AND creator_kind = 'WORKFLOW' AND status = 'APPROVED' AND source <> 'github'
                 AND NOT $APPROVAL_LIVE""",
        ).use { ps ->
            ps.setTimestamp(1, Timestamp.from(Instant.now().minus(APPROVAL_TTL)))
            ps.executeQuery().use { rs -> val o = ArrayList<Long>(); while (rs.next()) o += rs.getLong(1); o }
        }
    }

    /** End a PENDING or APPROVED request as CANCELLED, recording a [TASK_CANCEL][AuthzAction.TASK_CANCEL] event. */
    fun closeQueryRequest(
        id: Long,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        onClosed: ((Connection, AccessRequest) -> Unit)? = null,
    ): AccessRequest? = dataSource.inTx { c ->
        val won = c.prepareStatement(
            "UPDATE access_request SET status = 'CANCELLED' WHERE id = ? AND kind = 'QUERY' AND status IN ('PENDING', 'APPROVED')",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }
        if (!won) return@inTx null
        recorder.record(c, actor, AuthzAction.TASK_CANCEL, auditEntity("AccessRequest", id.toString()), "close query request #$id")
        RequestEvents.record(c, id, RequestEventKind.CLOSED, actor.principal, actor.channel)
        getRequest(id, c)?.also { onClosed?.invoke(c, it) }
    }

    /**
     * Mark a GitHub request, PENDING or APPROVED, to run past its scope's checks, recording a
     * [TASK_FORCE_RUN][AuthzAction.TASK_FORCE_RUN] event. Null when there is no such row not yet forced.
     */
    fun forceRun(
        id: Long,
        admin: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        onForced: (Connection, AccessRequest) -> Unit,
    ): AccessRequest? = dataSource.inTx { c ->
        val won = c.prepareStatement(
            """UPDATE access_request SET force_run = TRUE, force_run_by = ?
               WHERE id = ? AND kind = 'QUERY' AND source = 'github' AND status IN ('PENDING', 'APPROVED')
                 AND force_run = FALSE""",
        ).use { ps ->
            ps.setString(1, admin)
            ps.setLong(2, id)
            ps.executeUpdate() > 0
        }
        if (!won) return@inTx null
        recorder.record(
            c, actor, AuthzAction.TASK_FORCE_RUN, auditEntity("AccessRequest", id.toString()),
            "force-run query request #$id past the scope checks",
        )
        val forced = c.prepareStatement("$REQ_SELECT WHERE ar.id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> rs.next(); rs.toRequest() }
        }
        onForced(c, forced)
        forced
    }

    /**
     * Record that a pull request merged: its own requests, and the scope's executed requests carrying its keys.
     * [mergeSha] is recorded only on rows of [repository], since only its history can contain it.
     */
    fun markMerged(repository: String, pr: Int, scope: String, changeKeys: List<String>, at: Instant, mergeSha: String?) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE access_request SET merged_at = ?, merge_sha = CASE WHEN repository = ? THEN ? END
                   WHERE merged_at IS NULL
                     AND ((source = 'github' AND repository = ? AND pr = ? AND scope = ?)
                       OR (source = 'github' AND scope = ? AND status = 'EXECUTED' AND change_key = ANY (?)))""",
            ).use { ps ->
                ps.setTimestamp(1, Timestamp.from(at))
                ps.setString(2, repository)
                ps.setString(3, mergeSha)
                ps.setString(4, repository)
                ps.setInt(5, pr)
                ps.setString(6, scope)
                ps.setString(7, scope)
                ps.setArray(8, c.createArrayOf("text", changeKeys.toTypedArray()))
                ps.executeUpdate()
            }
        }
    }

    /**
     * Stamp [headSha] on the pull request's requests in [scope] whose key is still among [changeKeys], and record
     * it, with the filing's [keyOrder], as the scope's filed head on all of them.
     */
    fun setPrHead(repository: String, pr: Int, scope: String, changeKeys: List<String>, headSha: String, keyOrder: String) {
        dataSource.inTx { c ->
            c.prepareStatement(
                """UPDATE access_request SET head_sha = ?
                   WHERE source = 'github' AND repository = ? AND pr = ? AND scope = ? AND change_key = ANY (?)
                     AND head_sha IS DISTINCT FROM ?""",
            ).use { ps ->
                ps.setString(1, headSha)
                ps.setString(2, repository)
                ps.setInt(3, pr)
                ps.setString(4, scope)
                ps.setArray(5, c.createArrayOf("text", changeKeys.toTypedArray()))
                ps.setString(6, headSha)
                ps.executeUpdate()
            }
            c.prepareStatement(
                """UPDATE access_request SET filed_head = ?, key_order = ?
                   WHERE source = 'github' AND repository = ? AND pr = ? AND scope = ?""",
            ).use { ps ->
                ps.setString(1, headSha)
                ps.setString(2, keyOrder)
                ps.setString(3, repository)
                ps.setInt(4, pr)
                ps.setString(5, scope)
                ps.executeUpdate()
            }
        }
    }

    /** The latest run in [scope] whose pull request in [repository] merged with a recorded merge commit. */
    fun lastMergedRun(scope: String, repository: String): AccessRequest? = dataSource.connection.use { c ->
        c.prepareStatement(
            """$REQ_SELECT
               WHERE ar.scope = ? AND ar.repository = ? AND ar.source = 'github' AND ar.status = 'EXECUTED'
                 AND ar.merge_sha IS NOT NULL
               ORDER BY ar.merged_at DESC, ar.id DESC LIMIT 1""",
        ).use { ps ->
            ps.setString(1, scope)
            ps.setString(2, repository)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRequest() else null }
        }
    }

    fun setPrAutoMerge(repository: String, pr: Int, enabled: Boolean) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                "UPDATE access_request SET pr_auto_merge = ? WHERE source = 'github' AND repository = ? AND pr = ? AND pr_auto_merge <> ?",
            ).use { ps ->
                ps.setBoolean(1, enabled)
                ps.setString(2, repository)
                ps.setInt(3, pr)
                ps.setBoolean(4, enabled)
                ps.executeUpdate()
            }
        }
    }

    fun markExecuted(id: Long): Boolean = dataSource.connection.use { c -> markExecuted(id, c) }

    /**
     * Same as [markExecuted], composed onto a caller-supplied connection so the parent's
     * `EXECUTING → EXECUTED` flip can be committed in the SAME transaction as the child's `DONE`
     * (see [QueryResultStore.completeRun]'s audit hook). Keeping both writes in one commit is what
     * makes terminal success atomic: a crash can never leave a DONE child under a still-EXECUTING task.
     */
    fun markExecuted(id: Long, c: Connection): Boolean = c.prepareStatement(
        "UPDATE access_request SET status = 'EXECUTED', executed_at = ? WHERE id = ? AND kind = 'QUERY' AND status = 'EXECUTING'",
    ).use { ps ->
        ps.setTimestamp(1, Timestamp.from(Instant.now()))
        ps.setLong(2, id)
        ps.executeUpdate() > 0
    }.also { if (it) RequestEvents.record(c, id, RequestEventKind.EXECUTED, null, SYSTEM_ORIGIN) }

    fun markFailed(id: Long): Boolean = dataSource.connection.use { c -> markFailed(id, c) }

    /**
     * Same as [markFailed], composed onto a caller-supplied connection so the parent's
     * `EXECUTING → FAILED` flip commits in the SAME transaction as the child's `FAILED`
     * (see [QueryResultStore.failRun]'s hook). Terminal failure is thereby atomic in the same way
     * terminal success is: a crash can never leave a FAILED child under a still-EXECUTING task, nor
     * the inverse — the pair a restart's [reconcileOrphanedExecutions] would otherwise have to repair.
     */
    fun markFailed(id: Long, c: Connection): Boolean = c.prepareStatement(
        "UPDATE access_request SET status = 'FAILED' WHERE id = ? AND kind = 'QUERY' AND status = 'EXECUTING'",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeUpdate() > 0
    }.also { if (it) RequestEvents.record(c, id, RequestEventKind.FAILED, null, SYSTEM_ORIGIN) }

    fun markCancelled(id: Long): Boolean = dataSource.connection.use { c -> markCancelled(id, c) }

    /** Atomically terminalize an executing task in the caller's transaction. */
    fun markCancelled(id: Long, c: Connection): Boolean = c.prepareStatement(
        "UPDATE access_request SET status = 'CANCELLED' WHERE id = ? AND kind = 'QUERY' AND status = 'EXECUTING'",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeUpdate() > 0
    }.also { if (it) RequestEvents.record(c, id, RequestEventKind.CANCELLED, null, SYSTEM_ORIGIN) }

    fun markDeleted(id: Long): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            "UPDATE access_request SET status = 'DELETED' WHERE id = ? AND kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'REJECTED')",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }
    }

    fun resubmit(id: Long): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            "UPDATE access_request SET status = 'PENDING', decided_by = NULL, decided_at = NULL, rejection_reason = NULL WHERE id = ? AND kind = 'QUERY' AND status = 'REJECTED'",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }
    }

    fun reconcileOrphanedExecutions() {
        dataSource.inTx { c ->
            c.prepareStatement("UPDATE access_request SET status = 'FAILED' WHERE kind = 'QUERY' AND status = 'EXECUTING'").use {
                it.executeUpdate()
            }
            // Set expires_at too, so purgeExpired eventually GCs this orphaned metadata — otherwise a
            // NULL-expiry FAILED row accumulates on every restart-with-orphan (no ciphertext, but unbounded).
            val expiry = Timestamp.from(Instant.now().plusSeconds(QueryResultStore.RESULT_RETENTION_SEC))
            c.prepareStatement(
                "UPDATE query_result SET status = 'FAILED', error_code = 'task.orphaned_on_restart', expires_at = ? WHERE status = 'RUNNING'",
            ).use { ps ->
                ps.setTimestamp(1, expiry)
                ps.executeUpdate()
            }
            // A crash BETWEEN a batch's statements leaves no RUNNING child to carry the orphan reason — the
            // previous statement is DONE and the next never started. Fail the lowest pending child of each
            // orphaned task so the failure is attributed to the statement that would have run next, rather
            // than leaving a FAILED task whose children are all DONE/SKIPPED and explain nothing.
            c.prepareStatement(
                """UPDATE query_result SET status = 'FAILED', error_code = 'task.orphaned_on_restart', expires_at = ?
                   WHERE id IN (
                       SELECT DISTINCT ON (qr.task_id) qr.id
                         FROM query_result qr
                         JOIN access_request ar ON ar.id = qr.task_id
                        WHERE qr.status IS NULL AND ar.kind = 'QUERY' AND ar.status = 'FAILED'
                          AND NOT EXISTS (
                              SELECT 1 FROM query_result done
                               WHERE done.task_id = qr.task_id AND done.status = 'FAILED'
                          )
                        ORDER BY qr.task_id, qr.ordinal
                   )""",
            ).use { ps ->
                ps.setTimestamp(1, expiry)
                ps.executeUpdate()
            }
            // The statements after the orphaned one will never run either — the task is FAILED. Terminalize
            // them as SKIPPED so no child of a finished task still reads as "not started yet".
            c.prepareStatement(
                """UPDATE query_result SET status = 'SKIPPED', expires_at = ?
                   WHERE status IS NULL AND task_id IN (SELECT id FROM access_request WHERE kind = 'QUERY' AND status = 'FAILED')""",
            ).use { ps ->
                ps.setTimestamp(1, expiry)
                ps.executeUpdate()
            }
        }
    }

    /**
     * The human query-approval feed: WORKFLOW-origin QUERY tasks only. EDITOR and WIRE tasks share the
     * access_request table but are internal lifecycle records (an editor tab's saved result; a native-wire
     * statement's per-statement authorization) — they carry null SQL, are never decided by an approver, and
     * must never surface on the /api/approvals workflow. The creator_kind filter is what keeps them off it.
     */
    fun listQueryRequests(status: String?, principal: String?): List<AccessRequest> = dataSource.connection.use { c ->
        val sql = StringBuilder("$REQ_SELECT WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW'")
        val args = ArrayList<String>()
        if (status != null) {
            sql.append(" AND ar.status = ?")
            args += status
        }
        if (principal != null) {
            sql.append(" AND ar.principal = ?")
            args += principal
        }
        sql.append(" ORDER BY ar.created_at DESC")
        c.prepareStatement(sql.toString()).use { ps ->
            args.forEachIndexed { i, arg -> ps.setString(i + 1, arg) }
            ps.executeQuery().use { rs -> val o = ArrayList<AccessRequest>(); while (rs.next()) o += rs.toRequest(); o }
        }
    }

    /** Workflow QUERY requests [principal] filed or took part in, newest first, at most [limit]. */
    fun listInvolvedQueryRequests(principal: String, limit: Int): List<AccessRequest> = dataSource.connection.use { c ->
        c.prepareStatement(
            """$REQ_SELECT
               WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW'
                 AND (ar.principal = ? OR EXISTS (
                      SELECT 1 FROM request_participant p WHERE p.request_id = ar.id AND p.principal = ?))
               ORDER BY ar.created_at DESC LIMIT ?""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setString(2, principal)
            ps.setInt(3, limit)
            ps.executeQuery().use { rs -> val o = ArrayList<AccessRequest>(); while (rs.next()) o += rs.toRequest(); o }
        }
    }

    /** Approve: mark the request APPROVED and insert a time-boxed grant. */
    fun approve(id: Long, durationSec: Long?, decidedBy: String): AccessRequest? {
        dataSource.inTx { c -> approve(id, durationSec, decidedBy, c) }
        return getRequest(id)
    }

    /**
     * Same as [approve], composed on the caller's transaction. Flips a PENDING request to APPROVED and inserts
     * its time-boxed grant, returning the new grant's id — or null when the request no longer exists, carries
     * no role, or is no longer PENDING (nothing inserted).
     */
    fun approve(id: Long, durationSec: Long?, decidedBy: String, c: Connection): Long? {
        val req = getRequest(id, c) ?: return null
        if (req.kind == "RATE_RESET") return approveRateReset(req, decidedBy, c)
        val roleId = req.roleId ?: return null
        val dur = durationSec ?: req.requestedDurationSec
        val expires = Timestamp.from(Instant.now().plusSeconds(dur))
        val won = c.prepareStatement(
            "UPDATE access_request SET status='APPROVED', decided_by=?, decided_at=now() WHERE id=? AND status='PENDING'",
        ).use { ps ->
            ps.setString(1, decidedBy); ps.setLong(2, id); ps.executeUpdate() > 0
        }
        if (!won) return null
        return c.prepareStatement(
            """INSERT INTO access_grant (request_id, principal, role_id, granted_by, granted_at, expires_at)
               VALUES (?, ?, ?, ?, now(), ?) RETURNING id""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.setString(2, req.principal)
            ps.setLong(3, roleId)
            ps.setString(4, decidedBy)
            ps.setTimestamp(5, expires)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    /**
     * Approving a RATE_RESET writes the principal's reset marker (docs/result-caps.md) in place of a grant and
     * returns the request id so the caller's audit row still fires. Nothing about `@cap` changes.
     */
    private fun approveRateReset(req: AccessRequest, decidedBy: String, c: Connection): Long? {
        val won = c.prepareStatement(
            "UPDATE access_request SET status='APPROVED', decided_by=?, decided_at=now() WHERE id=? AND status='PENDING'",
        ).use { ps -> ps.setString(1, decidedBy); ps.setLong(2, req.id); ps.executeUpdate() > 0 }
        if (!won) return null
        AuditStore(dataSource).insertRateReset(c, req.principal, decidedBy, req.reason ?: "approved rate reset request #${req.id}")
        return req.id
    }

    /**
     * Approve a ROLE or RATE_RESET request, recording the decision ([TASK_APPROVE][AuthzAction.TASK_APPROVE])
     * atomically. A request no longer PENDING changes nothing, so nothing is recorded.
     */
    fun approve(
        id: Long,
        durationSec: Long?,
        decidedBy: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
    ): AccessRequest? {
        val req = getRequest(id) ?: return null
        val dur = durationSec ?: req.requestedDurationSec
        dataSource.inTx { c ->
            approve(id, durationSec, decidedBy, c)?.let { grantId ->
                if (req.kind == "RATE_RESET") {
                    recorder.record(
                        c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessRequest", id.toString()),
                        "approve rate reset request #$id: reset spent rates of '${req.principal}'",
                    )
                } else {
                    recorder.record(
                        c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessGrant", grantId.toString()),
                        "approve access request #$id: grant role '${req.roleName}' to '${req.principal}' for ${dur}s",
                    )
                }
            }
        }
        return getRequest(id)
    }

    /** An admin's direct reset (docs/result-caps.md), recorded as ADMIN_IDENTITY on the same transaction. */
    fun resetRate(
        principal: String,
        reason: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
    ): RateReset = dataSource.inTx { c -> resetRate(principal, reason, actor, recorder, c) }

    /** Same as [resetRate], composed on the caller's transaction. */
    fun resetRate(
        principal: String,
        reason: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        c: Connection,
    ): RateReset {
        val reset = AuditStore(dataSource).insertRateReset(c, principal, actor.principal, reason)
        recorder.record(
            c, actor, AuthzAction.ADMIN_IDENTITY, auditEntity("User", principal),
            "reset spent result rates of '$principal': $reason",
        )
        return reset
    }

    fun reject(id: Long, reason: String, decidedBy: String): AccessRequest? {
        if (getRequest(id) == null) return null
        dataSource.inTx { c -> reject(id, reason, decidedBy, c) }
        return getRequest(id)
    }

    /** Same as [reject], composed on the caller's transaction. Returns whether a PENDING request transitioned. */
    fun reject(id: Long, reason: String, decidedBy: String, c: Connection): Boolean =
        c.prepareStatement(
            "UPDATE access_request SET status='REJECTED', rejection_reason=?, decided_by=?, decided_at=now() WHERE id=? AND status='PENDING'",
        ).use { ps ->
            ps.setString(1, reason); ps.setString(2, decidedBy); ps.setLong(3, id); ps.executeUpdate() > 0
        }

    /**
     * Reject a ROLE or RATE_RESET request, recording the [TASK_APPROVE][AuthzAction.TASK_APPROVE] decision atomically.
     * A request no longer PENDING transitions no row, so nothing is recorded.
     */
    fun reject(
        id: Long,
        reason: String,
        decidedBy: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
    ): AccessRequest? {
        val req = getRequest(id) ?: return null
        dataSource.inTx { c ->
            if (reject(id, reason, decidedBy, c)) {
                recorder.record(
                    c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessRequest", id.toString()),
                    "reject access request #$id from '${req.principal}'",
                )
            }
        }
        return getRequest(id)
    }

    fun listGrants(principal: String?, activeOnly: Boolean): List<AccessGrant> = dataSource.connection.use { c ->
        val sql = StringBuilder("$GRANT_SELECT WHERE 1=1")
        if (principal != null) sql.append(" AND ag.principal = ?")
        if (activeOnly) sql.append(" AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())")
        sql.append(" ORDER BY ag.granted_at DESC")
        c.prepareStatement(sql.toString()).use { ps ->
            if (principal != null) ps.setString(1, principal)
            ps.executeQuery().use { rs -> val o = ArrayList<AccessGrant>(); while (rs.next()) o += rs.toGrant(); o }
        }
    }

    fun getGrant(id: Long): AccessGrant? = dataSource.connection.use { c ->
        c.prepareStatement("$GRANT_SELECT WHERE ag.id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toGrant() else null }
        }
    }

    fun revoke(id: Long): Boolean = dataSource.inTx { c -> revoke(id, c) }

    /** Same as [revoke], composed on the caller's transaction. */
    fun revoke(id: Long, c: Connection): Boolean =
        c.prepareStatement("UPDATE access_grant SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL").use { ps ->
            ps.setLong(1, id); ps.executeUpdate() > 0
        }

    /**
     * Revoke a JIT grant, recording the [GRANT_REVOKE][AuthzAction.GRANT_REVOKE] event atomically. An
     * already-revoked grant matches no row, so nothing is recorded.
     */
    fun revoke(id: Long, actor: AuditActor, recorder: ManagementAuditRecorder): Boolean {
        val grant = getGrant(id)
        return dataSource.inTx { c ->
            revoke(id, c).also { won ->
                if (won && grant != null) {
                    recorder.record(
                        c, actor, AuthzAction.GRANT_REVOKE, auditEntity("AccessGrant", id.toString()),
                        "revoke access grant #$id (role '${grant.roleName}' from '${grant.principal}')",
                    )
                }
            }
        }
    }

    /**
     * Revoke every currently-active JIT grant for [principal] — the deprovisioning backstop
     * (docs/auth-model.md), paired with [TokenStore.revokeAllForPrincipal] in [revokeActiveCredentials].
     * Returns the number of grants revoked.
     */
    fun revokeAllForPrincipal(principal: String): Int = dataSource.connection.use { c -> revokeAllForPrincipal(principal, c) }

    /** Same as [revokeAllForPrincipal], composed onto a caller-supplied connection [c] (see Tokens.kt's [TokenStore.issue] overload doc). */
    fun revokeAllForPrincipal(principal: String, c: Connection): Int =
        c.prepareStatement("UPDATE access_grant SET revoked_at = now() WHERE principal = ? AND revoked_at IS NULL").use { ps ->
            ps.setString(1, principal); ps.executeUpdate()
        }

    private fun ResultSet.toRequest() = AccessRequest(
        id = getLong("id"), principal = getString("principal"), roleId = longOrNull("role_id"), roleName = getString("role_name"),
        datasourceId = longOrNull("datasource_id"), datasourceName = getString("datasource_name"),
        reason = getString("reason"), requestedDurationSec = getLong("requested_duration_sec"), status = getString("status"),
        decidedBy = getString("decided_by"), executedBy = getString("executed_by"),
        decidedAt = getTimestamp("decided_at")?.toInstant()?.toString(),
        rejectionReason = getString("rejection_reason"), createdAt = getTimestamp("created_at").toInstant().toString(),
        kind = getString("kind"), sql = getString("task_sql"), sqlHash = getString("task_sql_hash"),
        statementCount = getInt("statement_count"),
        denyReason = getString("deny_reason"), sourceDecisionId = longOrNull("source_decision_id"),
        title = getString("title"), evaluatedDecision = getString("evaluated_decision"),
        approvedAt = getTimestamp("approved_at")?.toInstant()?.toString(),
        executingAt = getTimestamp("executing_at")?.toInstant()?.toString(),
        executedAt = getTimestamp("executed_at")?.toInstant()?.toString(),
        executeAs = json.decodeFromString(stringList, getString("execute_as") ?: "[]"),
        creatorKind = getString("creator_kind"),
        statementCarriesProtectedLiteral = getBoolean("statement_carries_protected_literal").let { if (wasNull()) null else it },
        source = getString("source") ?: "console",
        scope = getString("scope"),
        fileKey = getString("file_key"),
        changeKey = getString("change_key"),
        mergedAt = getTimestamp("merged_at")?.toInstant()?.toString(),
        revision = getInt("revision"),
        revisedAt = getTimestamp("revised_at")?.toInstant()?.toString(),
        contentHash = getString("content_hash"),
        pullRequest = pullRequestRef(),
        forceRun = getBoolean("force_run"),
        forceRunBy = getString("force_run_by"),
        ccs = (getArray("ccs")?.array as? Array<*>)?.map { it as String }.orEmpty(),
    )

    private fun ResultSet.pullRequestRef(): PullRequestRef? {
        if (getString("source") != SOURCE_GITHUB) return null
        val repository = getString("repository") ?: return null
        val pr = getInt("pr").takeUnless { wasNull() } ?: return null
        return PullRequestRef(
            repository, pr,
            prUrl = getString("pr_url"),
            path = getString("path"),
            headSha = getString("head_sha"),
            defaultSchema = getString("default_schema"),
            keyOrder = getString("key_order"),
            filedHead = getString("filed_head"),
            mergeSha = getString("merge_sha"),
            prAutoMerge = getBoolean("pr_auto_merge"),
            approvedReviewId = getString("approved_review_id"),
        )
    }

    private fun ResultSet.toGrant() = AccessGrant(
        id = getLong("id"), principal = getString("principal"), roleId = getLong("role_id"), roleName = getString("role_name"),
        grantedBy = getString("granted_by"), grantedAt = getTimestamp("granted_at").toInstant().toString(),
        expiresAt = getTimestamp("expires_at")?.toInstant()?.toString(), revokedAt = getTimestamp("revoked_at")?.toInstant()?.toString(),
    )

    private companion object {
        // A pull request's approval lasts until its merge runs it. Binds the oldest approved_at still live.
        const val APPROVAL_LIVE = "(source = 'github' OR approved_at IS NULL OR approved_at > ?)"
        const val REQ_SELECT =
            """SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
                      ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by, ar.decided_at, ar.rejection_reason, ar.created_at,
                      ar.kind,
                      -- The whole batch as one text, statements in run order. Each child keeps its own sql and
                      -- sql_hash; this is the request's readable form (list preview, notifications), never the
                      -- unit of authorization.
                      (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS task_sql,
                      (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
                      (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS task_sql_hash,
                      (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
                      ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
                      ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
                      ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key,
                      ar.merged_at, ar.revision, ar.revised_at, ar.path, ar.pr_url, ar.repository, ar.pr,
                      ar.default_schema, ar.pr_auto_merge, ar.head_sha, ar.merge_sha,
                      ar.approved_review_id, ar.filed_head, ar.file_key, ar.content_hash, ar.key_order,
                      ar.force_run, ar.force_run_by,
                      (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
                       WHERE p.request_id = ar.id AND p.kind = 'cc') AS ccs
               FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
               LEFT JOIN datasource d ON d.id = ar.datasource_id"""
        // The app_role join is filtered to LIVE roles: a grant of a soft-deleted role must resolve to no
        // role (fail-closed in RoleResolver.resolve), so it drops out of listGrants here rather than
        // silently granting a role the operator deleted.
        const val GRANT_SELECT =
            """SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name,
                      ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
               FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL"""

        /**
         * Over `access_request r`: another pull request's run that holds the scope, unless that pull request's
         * latest filing has a file whose current version failed. Binds scope, id, repository, pr.
         */
        const val SCOPE_BUSY_WHERE =
            """r.scope = ? AND r.id <> ?
               AND NOT COALESCE(r.source = 'github' AND r.repository = ? AND r.pr = ?, FALSE)
               AND (r.status = 'EXECUTING'
                    OR (r.status = 'EXECUTED' AND r.merged_at IS NULL AND r.source = 'github'
                        AND NOT EXISTS (SELECT 1 FROM access_request f
                                        WHERE f.scope = r.scope AND f.repository = r.repository AND f.pr = r.pr
                                          AND f.status = 'FAILED' AND f.head_sha IS NOT DISTINCT FROM f.filed_head
                                          AND NOT EXISTS (SELECT 1 FROM access_request n
                                                          WHERE n.scope = f.scope AND n.repository = f.repository
                                                            AND n.pr = f.pr AND n.path = f.path AND n.id > f.id
                                                            AND n.status NOT IN ('DELETED', 'ALREADY_RAN', 'CANCELLED')))))"""
    }
}

// ---- Routes ------------------------------------------------------------------------------

fun Route.accessRoutes(
    config: Config,
    store: AccessStore,
    authz: Authz,
    datasourceStore: DatasourceStore,
    roleResolver: RoleResolver,
    recorder: ManagementAuditRecorder,
    service: AccessService = AccessService(store, datasourceStore, AuditStore(store.dataSource), roleResolver, authz, recorder),
) {
    get("/api/access-requests") {
        val caller = call.requireApi() ?: return@get
        call.respond(service.listRequests(caller, call.request.queryParameters["status"]))
    }
    post("/api/access-requests") {
        val principal = call.requireApi() ?: return@post
        val input = call.receive<AccessRequestInput>()
        try {
            call.respond(
                HttpStatusCode.Created,
                service.createRequest(principal, call.httpRequesterIp(config), call.auditActor(config), input),
            )
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
    // A user whose `@cap` rate is spent asks an approver to reset it (docs/result-caps.md). Authentication
    // alone opens it: there is no datasource to decide task.request against, and the approver decides.
    post("/api/access-requests/rate-reset") {
        val principal = call.requireApi() ?: return@post
        val input = call.receive<RateResetRequestInput>()
        try {
            call.respond(HttpStatusCode.Created, service.requestRateReset(principal, call.auditActor(config), input))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
    // An admin resets a principal's spent rates directly, reason required.
    post("/api/access/principals/{principal}/rate-reset") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val principal = call.parameters["principal"]?.takeIf { it.isNotBlank() } ?: return@post call.badId()
        val input = call.receive<RateResetInput>()
        try {
            call.respond(service.resetRate(principal, input.reason, call.auditActor(config)))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
    get("/api/access/principals/{principal}/rate-reset") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        val principal = call.parameters["principal"]?.takeIf { it.isNotBlank() } ?: return@get call.badId()
        service.lastRateReset(principal)?.let { call.respond(it) } ?: call.respond(HttpStatusCode.NoContent)
    }
    post("/api/access-requests/{id}/approve") {
        val approver = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.badId()
        val body = runCatching { call.receive<ApproveInput>() }.getOrDefault(ApproveInput())
        try {
            call.respond(service.approve(approver, call.httpRequesterIp(config), call.auditActor(config), id, body.durationSec))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
    post("/api/access-requests/{id}/reject") {
        val approver = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.badId()
        try {
            service.requireApprover(approver, call.httpRequesterIp(config), id)
            val body = call.receive<RejectInput>()
            call.respond(service.rejectApproved(approver, call.auditActor(config), id, body.reason))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
    get("/api/access-grants") {
        val caller = call.requireApi() ?: return@get
        val principal = call.request.queryParameters["principal"]
        val active = call.request.queryParameters["active"]?.toBoolean() ?: false
        call.respond(service.listGrants(caller, principal, active))
    }
    post("/api/access-grants/{id}/revoke") {
        val id = call.idParam() ?: return@post call.badId()
        // A missing grant is 404 before the session is asked for, as before any authorization.
        val caller = call.userSession()?.principal ?: return@post if (store.getGrant(id) == null) {
            call.notFound("access grant")
        } else {
            call.respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
        }
        try {
            service.revokeGrant(caller, call.httpRequesterIp(config), call.auditActor(config), id)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}
