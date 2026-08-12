package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.authz.requireAuthz
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.security.MessageDigest
import javax.sql.DataSource

// ---- DTOs — the wire contract for /api/access-requests** + /api/access-grants** ----------

@Serializable
data class AccessRequest(
    val id: Long, val principal: String, val roleId: Long? = null, val roleName: String? = null,
    val datasourceId: Long? = null, val datasourceName: String? = null,
    val reason: String? = null,
    val requestedDurationSec: Long, val status: String, val decidedBy: String? = null,
    val executedBy: String? = null,
    val decidedAt: String? = null, val rejectionReason: String? = null, val createdAt: String,
    val kind: String = "ROLE", val sql: String? = null, val sqlHash: String? = null,
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
)

/**
 * The authz view of this persisted approval request. Keys the Cedar `Request` EUID off the durable
 * [AccessRequest.id] so a per-request approval policy cannot carry over to a later request with the same
 * requester and datasource. This is the only persisted-path constructor of the resource, so no call site
 * can reintroduce the non-unique legacy key.
 */
fun AccessRequest.toApprovalResource() = AuthzResource.ApprovalRequest(
    requester = principal, id = id, approver = decidedBy, executedBy = executedBy,
    datasourceName = datasourceName, roleName = roleName,
)

@Serializable
data class AccessRequestInput(
    val roleId: Long, val datasourceId: Long? = null,
    val reason: String? = null, val requestedDurationSec: Long = 3600,
)

@Serializable
data class AccessGrant(
    val id: Long, val principal: String, val roleId: Long, val roleName: String,
    val grantedBy: String? = null, val grantedAt: String,
    val expiresAt: String? = null, val revokedAt: String? = null,
)

@Serializable data class ApproveInput(val durationSec: Long? = null)
@Serializable data class RejectInput(val reason: String)

// ---- Store -------------------------------------------------------------------------------

class DuplicatePendingQueryRequestException : RuntimeException("a pending query request already exists for this decision")

class AccessStore(private val dataSource: DataSource) {
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

    fun listRequests(status: String?): List<AccessRequest> = dataSource.connection.use { c ->
        val sql = if (status != null) {
            "$REQ_SELECT WHERE ar.kind = 'ROLE' AND ar.status = ? ORDER BY ar.created_at DESC"
        } else {
            "$REQ_SELECT WHERE ar.kind = 'ROLE' ORDER BY ar.created_at DESC"
        }
        c.prepareStatement(sql).use { ps ->
            if (status != null) ps.setString(1, status)
            ps.executeQuery().use { rs -> val o = ArrayList<AccessRequest>(); while (rs.next()) o += rs.toRequest(); o }
        }
    }

    fun createRequest(principal: String, input: AccessRequestInput): AccessRequest {
        val id = dataSource.inTx { c -> createRequest(principal, input, c) }
        return getRequest(id)!!
    }

    /** Insert a ROLE access request on the caller's transaction, returning its id. */
    fun createRequest(principal: String, input: AccessRequestInput, c: Connection): Long =
        c.prepareStatement(
            """INSERT INTO access_request (principal, role_id, datasource_id, reason, requested_duration_sec)
               VALUES (?, ?, ?, ?, ?) RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setLong(2, input.roleId)
            if (input.datasourceId == null) ps.setNull(3, java.sql.Types.BIGINT) else ps.setLong(3, input.datasourceId)
            ps.setString(4, input.reason)
            ps.setLong(5, input.requestedDurationSec)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }

    /** Open a ROLE access request, recording the [TASK_REQUEST][AuthzAction.TASK_REQUEST] event atomically. */
    fun createRequest(
        principal: String,
        input: AccessRequestInput,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
    ): AccessRequest {
        val id = dataSource.inTx { c ->
            val newId = createRequest(principal, input, c)
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

    fun createQueryRequest(
        principal: String,
        datasourceId: Long,
        sql: String,
        denyReason: String?,
        sourceDecisionId: Long?,
        reason: String?,
        title: String?,
        evaluatedDecision: String?,
        // APPROVAL: the elevation role R the requester picked (role discovery). NULL = a legacy request with
        // no elevation role (the approver runs as themselves). The FK to app_role validates R.
        roleId: Long? = null,
        // Carried on the shared access_request row; not consumed by the query-approval flow (see
        // CreateApprovalInput.requestedDurationSec). Kept for the column the ROLE-elevation path needs.
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
    ): AccessRequest {
        val sqlHash = MessageDigest.getInstance("SHA-256")
            .digest(sql.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
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
                    statement_carries_protected_literal)
                   VALUES (?, 'QUERY', ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, 'WORKFLOW', ?)
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
                ps.executeQuery().use { rs ->
                    if (rs.next()) rs.getLong(1) else throw DuplicatePendingQueryRequestException()
                }
            }
            c.prepareStatement(
                "INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, ?)",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.setString(2, sql)
                ps.setString(3, sqlHash)
                ps.executeUpdate()
            }
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
        sql: String,
        executeAs: List<String>,
        approver: String,
    ): AccessRequest {
        val sqlHash = MessageDigest.getInstance("SHA-256")
            .digest(sql.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
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
            c.prepareStatement(
                "INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, ?)",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.setString(2, sql)
                ps.setString(3, sqlHash)
                ps.executeUpdate()
            }
            taskId
        }
        return getRequest(id)!!
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

    /** The id of an EDITOR task's single result child (task:child 1:1) — carried in the submit ack. */
    fun editorChildId(taskId: Long): Long? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM query_result WHERE task_id = ? ORDER BY id DESC LIMIT 1").use { ps ->
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
    ): AccessRequest? {
        val won = dataSource.inTx { c -> decideQueryRequest(id, approved, rejectionReason, decidedBy, c) }
        return if (won) getRequest(id) else null
    }

    /** Same as [decideQueryRequest], composed on the caller's transaction. Returns whether a row transitioned. */
    fun decideQueryRequest(
        id: Long,
        approved: Boolean,
        rejectionReason: String?,
        decidedBy: String,
        c: Connection,
    ): Boolean {
        val decidedAt = Timestamp.from(Instant.now())
        return c.prepareStatement(
            """UPDATE access_request
               SET status = ?, decided_by = ?, decided_at = ?, approved_at = ?, rejection_reason = ?
               WHERE id = ? AND kind = 'QUERY' AND status = 'PENDING'""",
        ).use { ps ->
            ps.setString(1, if (approved) "APPROVED" else "REJECTED")
            ps.setString(2, decidedBy)
            ps.setTimestamp(3, decidedAt)
            if (approved) ps.setTimestamp(4, decidedAt) else ps.setNull(4, java.sql.Types.TIMESTAMP)
            ps.setString(5, rejectionReason)
            ps.setLong(6, id)
            ps.executeUpdate() > 0
        }
    }

    /**
     * Decide a pending QUERY task, recording the [TASK_APPROVE][AuthzAction.TASK_APPROVE] decision atomically.
     * A task no longer PENDING transitions no row, so nothing is recorded.
     */
    fun decideQueryRequest(
        id: Long,
        approved: Boolean,
        rejectionReason: String?,
        decidedBy: String,
        actor: AuditActor,
        recorder: ManagementAuditRecorder,
        // Queues the decision notification in the SAME transaction as the transition, so a crash can never
        // leave a request decided with nobody told. No-op when the notification layer is not configured.
        onDecided: ((Connection, AccessRequest) -> Unit)? = null,
    ): AccessRequest? {
        val before = getRequest(id)
        val roleName = before?.roleName
        val won = dataSource.inTx { c ->
            decideQueryRequest(id, approved, rejectionReason, decidedBy, c).also { transitioned ->
                if (transitioned) {
                    recorder.record(
                        c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessRequest", id.toString()),
                        if (approved) "approve query request #$id under role '$roleName'" else "reject query request #$id",
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
                            ),
                        )
                    }
                }
            }
        }
        return if (won) getRequest(id) else null
    }

    /** Atomically claim an approved task for execution. Exactly one concurrent caller wins. */
    fun claimExecution(id: Long): Boolean = dataSource.connection.use { c -> claimExecution(id, c) }

    /** Same as [claimExecution], composed onto a caller-supplied transaction. */
    fun claimExecution(id: Long, c: Connection): Boolean = c.prepareStatement(
        "UPDATE access_request SET status = 'EXECUTING', executing_at = ? WHERE id = ? AND kind = 'QUERY' AND status = 'APPROVED'",
    ).use { ps ->
        ps.setTimestamp(1, Timestamp.from(Instant.now()))
        ps.setLong(2, id)
        ps.executeUpdate() > 0
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
    }

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
    }

    fun markCancelled(id: Long): Boolean = dataSource.connection.use { c -> markCancelled(id, c) }

    /** Atomically terminalize an executing task in the caller's transaction. */
    fun markCancelled(id: Long, c: Connection): Boolean = c.prepareStatement(
        "UPDATE access_request SET status = 'CANCELLED' WHERE id = ? AND kind = 'QUERY' AND status = 'EXECUTING'",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeUpdate() > 0
    }

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
            c.prepareStatement(
                "UPDATE query_result SET status = 'FAILED', error_code = 'task.orphaned_on_restart', expires_at = ? WHERE status = 'RUNNING'",
            ).use { ps ->
                ps.setTimestamp(1, Timestamp.from(Instant.now().plusSeconds(QueryResultStore.RESULT_RETENTION_SEC)))
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
     * Approve a ROLE request, recording the granted elevation ([TASK_APPROVE][AuthzAction.TASK_APPROVE]) atomically.
     * A request no longer PENDING inserts no grant, so nothing is recorded.
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
                recorder.record(
                    c, actor, AuthzAction.TASK_APPROVE, auditEntity("AccessGrant", grantId.toString()),
                    "approve access request #$id: grant role '${req.roleName}' to '${req.principal}' for ${dur}s",
                )
            }
        }
        return getRequest(id)
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
     * Reject a ROLE request, recording the [TASK_APPROVE][AuthzAction.TASK_APPROVE] decision atomically.
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
        denyReason = getString("deny_reason"), sourceDecisionId = longOrNull("source_decision_id"),
        title = getString("title"), evaluatedDecision = getString("evaluated_decision"),
        approvedAt = getTimestamp("approved_at")?.toInstant()?.toString(),
        executingAt = getTimestamp("executing_at")?.toInstant()?.toString(),
        executedAt = getTimestamp("executed_at")?.toInstant()?.toString(),
        executeAs = json.decodeFromString(stringList, getString("execute_as") ?: "[]"),
        creatorKind = getString("creator_kind"),
        statementCarriesProtectedLiteral = getBoolean("statement_carries_protected_literal").let { if (wasNull()) null else it },
    )

    private fun ResultSet.toGrant() = AccessGrant(
        id = getLong("id"), principal = getString("principal"), roleId = getLong("role_id"), roleName = getString("role_name"),
        grantedBy = getString("granted_by"), grantedAt = getTimestamp("granted_at").toInstant().toString(),
        expiresAt = getTimestamp("expires_at")?.toInstant()?.toString(), revokedAt = getTimestamp("revoked_at")?.toInstant()?.toString(),
    )

    private companion object {
        const val REQ_SELECT =
            """SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
                      ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by, ar.decided_at, ar.rejection_reason, ar.created_at,
                      ar.kind,
                      (SELECT qr.sql FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS task_sql,
                      (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS task_sql_hash,
                      (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS executed_by,
                      ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
                      ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
                      ar.statement_carries_protected_literal
               FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
               LEFT JOIN datasource d ON d.id = ar.datasource_id"""
        // The app_role join is filtered to LIVE roles: a grant of a soft-deleted role must resolve to no
        // role (fail-closed in RoleResolver.resolve), so it drops out of listGrants here rather than
        // silently granting a role the operator deleted.
        const val GRANT_SELECT =
            """SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name,
                      ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
               FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL"""
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
) {
    get("/api/access-requests") {
        if (!call.requireApi(config)) return@get
        // Forward-filter by task.read (self seed shows own; admin/oversight shows all),
        // replacing the unfiltered listing that exposed every principal's requests. authDebug (no
        // session) keeps the full list, matching requireApi's dev bypass.
        val caller = call.userSession()?.principal
        val rows = store.listRequests(call.request.queryParameters["status"])
        call.respond(
            if (caller == null) {
                rows
            } else {
                rows.filter {
                    authz.authorize(
                        caller, AuthzAction.TASK_READ, it.toApprovalResource(),
                    ) is AuthzDecision.Allow
                }
            },
        )
    }
    post("/api/access-requests") {
        if (!call.requireApi(config)) return@post
        val principal = call.userSession()?.principal ?: "debug-user"
        val input = call.receive<AccessRequestInput>()
        // Opening a request against a datasource is gated by task.request on that datasource. A role
        // elevation need not target one (datasourceId is optional); a datasource-less request has no
        // Datasource resource to decide, so authentication alone admits it. authDebug bypasses.
        val ds = input.datasourceId?.let(datasourceStore::get)
        // A datasourceId that names no LIVE datasource (soft-deleted or never-existed) must not fall through
        // to createRequest: the tombstone row still satisfies the FK, so the insert would otherwise succeed
        // while skipping the task.request gate that a live datasource would enforce.
        if (input.datasourceId != null && ds == null) {
            return@post call.notFound("datasource")
        }
        if (ds != null && !config.authDebug) {
            val roles = roleResolver.resolve(principal)
            val raw = call.httpAuthzContext(config)
            val tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)
            val decision = authz.authorizeDatasourceAction(
                principal, roles, AuthzAction.TASK_REQUEST, ds.name, raw.copy(tags = tags), ds.tags,
            )
            if (decision is AuthzDecision.Deny) {
                return@post call.respondError(HttpStatusCode.Forbidden, "approval.request_not_permitted")
            }
        }
        call.respond(HttpStatusCode.Created, store.createRequest(principal, input, call.auditActor(config), recorder))
    }
    post("/api/access-requests/{id}/approve") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.badId()
        val req = store.getRequest(id) ?: return@post call.notFound("access request")
        if (req.kind != "ROLE") {
            return@post call.respondError(HttpStatusCode.BadRequest, "approval.use_query_approval_endpoint")
        }
        val approver = call.userSession()?.principal ?: "debug-user"
        // Self-approval is governed entirely by Cedar policy (the `no-self-approval` forbid, V11
        // seed) — never a hardcoded app-level rule. A deployment may disable that policy (dev/eval);
        // this route only ever asks authz "may this principal do this?" (docs/approval-workflow.md).
        if (!config.authDebug) {
            // roleName places the request in `Role::"<name>"` so a policy can scope who may approve by
            // the ROLE being requested (`resource in Role::...`), not just the requester (Authz.kt,
            // AuthzTest's Request-in-Role case). Without it that capability would be unreachable here.
            // requester_ip + (when a datasource is in scope) its derived context.tags, resolved
            // over a SINGLE role snapshot (authorizeWithContext) — the ROLE-request analog of the QUERY
            // approval routes' mayDecide (task.approve) call in Approvals.kt.
            val decision = authz.authorizeWithContext(
                approver, AuthzAction.TASK_APPROVE, req.toApprovalResource(),
                call.httpAuthzContext(config, Channel.WORKFLOW_VIEWER),
                req.datasourceName,
                req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
            )
            if (decision is AuthzDecision.Deny) {
                return@post call.respondError(HttpStatusCode.Forbidden, "approval.not_approver")
            }
        }
        val body = runCatching { call.receive<ApproveInput>() }.getOrDefault(ApproveInput())
        store.approve(id, body.durationSec, approver, call.auditActor(config), recorder)?.let { call.respond(it) }
            ?: call.notFound("access request")
    }
    post("/api/access-requests/{id}/reject") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.badId()
        val req = store.getRequest(id) ?: return@post call.notFound("access request")
        if (req.kind != "ROLE") {
            return@post call.respondError(HttpStatusCode.BadRequest, "approval.use_query_approval_endpoint")
        }
        val approver = call.userSession()?.principal ?: "debug-user"
        // Self-approval is governed entirely by Cedar policy (the `no-self-approval` forbid, V11
        // seed) — never a hardcoded app-level rule. A deployment may disable that policy (dev/eval);
        // this route only ever asks authz "may this principal do this?" (docs/approval-workflow.md).
        if (!config.authDebug) {
            // Same role-scoped approver check as /approve — the reject path must ask the identical
            // Cedar question, so a role-scoped approval policy governs reject too (see /approve above).
            val decision = authz.authorizeWithContext(
                approver, AuthzAction.TASK_APPROVE, req.toApprovalResource(),
                call.httpAuthzContext(config, Channel.WORKFLOW_VIEWER),
                req.datasourceName,
                req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
            )
            if (decision is AuthzDecision.Deny) {
                return@post call.respondError(HttpStatusCode.Forbidden, "approval.not_approver")
            }
        }
        val body = call.receive<RejectInput>()
        store.reject(id, body.reason, approver, call.auditActor(config), recorder)?.let { call.respond(it) }
            ?: call.notFound("access request")
    }
    get("/api/access-grants") {
        if (!call.requireApi(config)) return@get
        val principal = call.request.queryParameters["principal"]
        val active = call.request.queryParameters["active"]?.toBoolean() ?: false
        // Forward-filter by task.read — an arbitrary ?principal= does not leak another
        // principal's grants; each row is kept only if the caller may read it (own, or oversight).
        val caller = call.userSession()?.principal
        val rows = store.listGrants(principal, active)
        call.respond(
            if (caller == null) {
                rows
            } else {
                rows.filter {
                    authz.authorize(
                        caller, AuthzAction.TASK_READ,
                        AuthzResource.AccessGrant(owner = it.principal, id = it.id, roleName = it.roleName),
                    ) is AuthzDecision.Allow
                }
            },
        )
    }
    post("/api/access-grants/{id}/revoke") {
        val id = call.idParam() ?: return@post call.badId()
        // Load the grant so Cedar decides against its owner (grant.revoke) — closes the
        // IDOR where any authenticated principal could revoke anyone's grant by enumerating the id.
        val grant = store.getGrant(id) ?: return@post call.notFound("access grant")
        if (!call.requireAuthz(
                config, authz, AuthzAction.GRANT_REVOKE,
                AuthzResource.AccessGrant(owner = grant.principal, id = grant.id, roleName = grant.roleName),
            )
        ) {
            return@post
        }
        if (store.revoke(id, call.auditActor(config), recorder)) call.respond(HttpStatusCode.NoContent) else call.notFound("access grant")
    }
}
