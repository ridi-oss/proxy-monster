package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.RunError
import com.ridi.oss.proxymonster.probe.splitStatements
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * The editor-as-task lifecycle shared by the REST editor routes and the MCP query tools. A submit is a
 * born-APPROVED EDITOR task run async on [appScope] under the caller's own roles on the EDITOR channel; rows
 * are owner-scoped and gated by task.assume plus a live re-decision. Failures throw [TaskServiceException].
 */
class EditorTaskService(
    private val config: Config,
    private val datasourceStore: DatasourceStore,
    private val accessStore: AccessStore,
    // null when PM_RESULT_KEY is unset → submit is refused fail-closed (no plaintext PII persisted).
    private val queryResultStore: QueryResultStore?,
    private val policyStore: PolicyStore,
    private val userGroupStore: UserGroupStore,
    private val roleResolver: RoleResolver,
    private val authz: Authz,
    private val runExecService: RunExecService,
    private val appScope: CoroutineScope,
    private val systemClassification: SystemClassificationService? = null,
    private val taskCompletionHub: TaskCompletionHub? = null,
    private val auditStore: AuditStore? = null,
    private val log: Logger = LoggerFactory.getLogger(EditorTaskService::class.java),
) {
    data class Submission(val response: EditorSubmitResponse, val job: Job)

    private class Batch(
        val taskId: Long,
        val statementCount: Int,
        val preflight: () -> Boolean,
        val statementAt: suspend (Int) -> String?,
        val onStatement: suspend (Int, QueryResponse) -> Boolean,
    )

    /** Submit on a held editor session (its one target-DB connection). */
    fun submitOnSession(principal: String, requesterIp: String?, sessionId: String, sql: String, maxRows: Int): Submission {
        val ownRoles = submitterRoles(principal, sql)
        // Owner-scoped: a leaked session id can't target another principal's connection.
        val dsName = runExecService.sessionDatasourceName(sessionId, principal) ?: throw serviceNotFound("editor session")
        val ds = datasourceStore.getByName(dsName) ?: throw serviceNotFound("datasource")
        return start(principal, requesterIp, ds, ownRoles, sql) { b ->
            // One mutex hold for the batch, so a concurrent submit cannot land inside its transaction.
            runExecService.runBatchOnSession(
                sessionId, principal, statementCount = b.statementCount, maxRows = maxRows,
                statementAt = b.statementAt, onStatement = b.onStatement,
                requesterIp = requesterIp, taskId = b.taskId, preflight = b.preflight,
                exchangeTimeoutMs = config.queryExchangeTimeoutMs,
            )
        }
    }

    /** Submit on a one-shot connection that lives for this batch only. */
    fun submitOneShot(principal: String, requesterIp: String?, datasourceName: String, sql: String, maxRows: Int): Submission {
        val ownRoles = submitterRoles(principal, sql)
        val ds = datasourceStore.getByName(datasourceName) ?: throw serviceNotFound("datasource")
        return start(principal, requesterIp, ds, ownRoles, sql) { b ->
            // No assumeRoles: an EDITOR token, so every statement decides on the editor channel.
            runExecService.runBatch(
                principal, ds, statementCount = b.statementCount, maxRows = maxRows,
                statementAt = b.statementAt, onStatement = b.onStatement,
                approverExec = false, requesterIp = requesterIp, taskId = b.taskId, preflight = b.preflight,
                exchangeTimeoutMs = config.queryExchangeTimeoutMs,
            )
        }
    }

    private fun submitterRoles(principal: String, sql: String): Set<String> {
        if (sql.isBlank()) {
            throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "sql")))
        }
        // Resolved at THIS submit, never frozen across submits: a revoked role fails closed on the next run.
        val ownRoles = roleResolver.resolve(principal)
        if (ownRoles.isEmpty()) throw serviceForbidden()
        return ownRoles
    }

    private fun start(
        principal: String,
        requesterIp: String?,
        ds: Datasource,
        ownRoles: Set<String>,
        sql: String,
        runner: suspend (Batch) -> Unit,
    ): Submission {
        val store = queryResultStore
            ?: throw resultStorageNotConfigured()
        // Self-approve on the editor channel: must clear task.request AND task.approve.
        if (!autoApproveTask(principal, ownRoles, ds, AuthzContext(requesterIp = requesterIp), authz, Channel.EDITOR)) {
            throw serviceForbidden()
        }
        val splitConfig = ds.splitEngineConfig() ?: throw unsplittableSql()
        val statements = splitStatements(sql, splitConfig) ?: throw unsplittableSql()
        val task = accessStore.createEditorTask(principal, ds.id, statements, ownRoles.toList(), approver = principal)
        val childId = accessStore.editorChildId(task.id) ?: -1L
        // APPROVED → EXECUTING and the child NULL → RUNNING commit together, so a cancel can't slip into a gap.
        if (store.claimAndStartRun(task.id, principal) { c -> accessStore.claimExecution(task.id, c) } == null) {
            throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.already_executed"))
        }

        val job = appScope.launch {
            // A policy DENY carries its reason and audit decision id onto the failed child, so the polling
            // tab can offer an approval request built from that decision instead of showing a bare error.
            var denyReason: String? = null
            var denyDecisionId: Long? = null
            // The target-DB error behind a failure (both forms), stored so the FAILED view releases one per viewer.
            var diagnostic: RunError? = null
            val failureCode = try {
                var batchFailure: String? = null
                runner(
                    Batch(
                        taskId = task.id,
                        statementCount = statements.size,
                        preflight = { store.meta(task.id)?.status == "RUNNING" },
                        // Statement 0 is RUNNING from the claim; a cancel between statements leaves none
                        // pending, so the batch stops here.
                        statementAt = { ordinal ->
                            if (ordinal == 0) statements[0] else store.startNextRun(task.id, principal)?.sql
                        },
                        onStatement = { ordinal, response ->
                            if (response.decision == EnfAction.DENY) {
                                denyReason = response.denyReason
                                denyDecisionId = response.decisionId
                                // Reuses the channel-agnostic approval.* result codes the web already localizes.
                                batchFailure = "approval.execute_denied"
                                false
                            } else {
                                val result = DecryptedResult(response.columns, response.rows, response.rowsAffected, response.resultFingerprint, response.truncatedByCap)
                                // The parent flips to EXECUTED only on the LAST statement. The per-statement Decide
                                // already wrote the real audit decision, so no task-level row is added here.
                                val last = ordinal == statements.lastIndex
                                val completed = store.completeRun(task.id, result, QueryResultStore.RESULT_RETENTION_SEC, response.decisionId) { conn, _ ->
                                    if (last && !accessStore.markExecuted(task.id, conn)) {
                                        throw IllegalStateException("editor task ${task.id} left EXECUTING before completion")
                                    }
                                }
                                if (completed == null) {
                                    batchFailure = "approval.query_failed"
                                    false
                                } else {
                                    true
                                }
                            }
                        },
                    ),
                )
                batchFailure
            } catch (_: RunCanceledBeforeStartException) {
                null
            } catch (_: NoProxyAttachedException) {
                "query.no_proxy_attached"
            } catch (_: ProxyStreamWedgedException) {
                "query.proxy_stream_wedged"
            } catch (_: ProxyRunTimeoutException) {
                "query.proxy_timeout"
            } catch (e: TargetDbRunException) {
                // The target DB's own error for the failed statement, stored encrypted and re-gated per viewer.
                diagnostic = e.toDiagnostic()
                "approval.query_failed"
            } catch (_: ProxyRunException) {
                "approval.query_failed"
            } catch (t: Throwable) {
                log.error("editor task execution failed task=${task.id}", t)
                "approval.query_failed"
            }
            if (failureCode != null) {
                // Child FAILED + parent FAILED in ONE transaction (mirrors the success path's single commit).
                runCatching {
                    store.failRun(task.id, failureCode, denyReason, denyDecisionId, diagnostic = diagnostic) { conn, _ ->
                        accessStore.markFailed(task.id, conn)
                    }
                }
                    .onFailure { log.error("editor task failure transition failed task=${task.id}", it) }
            }
            // Push the ACTUAL terminal state (EXECUTED / FAILED / or CANCELLED if a cancel raced) to the owner;
            // best-effort, the tab also polls (see TaskCompletionHub).
            accessStore.getRequest(task.id)?.status?.let { taskCompletionHub?.publish(principal, TaskEvent(task.id, it)) }
        }
        return Submission(EditorSubmitResponse(taskId = task.id, childId = childId, statements = statements), job)
    }

    /** Task status + child metadata. Rows stay behind [result]. */
    fun status(principal: String, requesterIp: String?, taskId: Long): EditorTaskStatus {
        val task = ownedTask(principal, taskId)
        // The owner guard is not a substitute: a Cedar forbid on task.read must still override the self-read permit.
        if (decide(principal, AuthzAction.TASK_READ, task, AuthzContext(requesterIp = requesterIp)) is AuthzDecision.Deny) {
            throw serviceNotFound("editor task")
        }
        return EditorTaskStatus(
            task.id, task.status, queryResultStore?.meta(taskId),
            statements = queryResultStore?.statements(taskId).orEmpty(),
        )
    }

    suspend fun cancel(principal: String, requesterIp: String?, taskId: Long): EditorTaskStatus {
        val task = ownedTask(principal, taskId)
        if (decide(principal, AuthzAction.TASK_CANCEL, task, AuthzContext(requesterIp = requesterIp)) is AuthzDecision.Deny) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        if (task.status != "EXECUTING") {
            return EditorTaskStatus(
                task.id, task.status, queryResultStore?.meta(taskId),
                statements = queryResultStore?.statements(taskId).orEmpty(),
            )
        }
        val store = queryResultStore
            ?: throw resultStorageNotConfigured()
        val cancelled = store.cancelRun(taskId) { conn, _ ->
            if (!accessStore.markCancelled(taskId, conn)) {
                throw IllegalStateException("editor task $taskId left EXECUTING before cancellation")
            }
        }
        if (cancelled != null) {
            runExecService.cancelActiveRun(taskId)
            // The CAS may win well before the run coroutine unwinds, so push CANCELLED now.
            taskCompletionHub?.publish(principal, TaskEvent(taskId, "CANCELLED"))
        }
        val updated = accessStore.getRequest(taskId) ?: throw serviceNotFound("editor task")
        return EditorTaskStatus(updated.id, updated.status, store.meta(taskId), statements = store.statements(taskId))
    }

    /**
     * The saved rows of statement [ordinal] (null = the active one), re-decided live under the task's roles on
     * the EDITOR channel. Owner-only: task.assume is defense in depth, since an assume grantee is not the owner.
     */
    fun result(principal: String, requesterIp: String?, taskId: Long, ordinal: Int?): QueryResultView {
        val task = ownedTask(principal, taskId)
        // Deprovisioning gate before result lookup (defense in depth; the live decide repeats it).
        if (userGroupStore.isDeactivated(principal)) throw serviceNotFound("editor task")
        // One read captures ciphertext + meta; decrypt is lazy, only after authz passes.
        val access = queryResultStore?.accessFor(taskId, ordinal) ?: throw serviceNotFound("editor task")
        val editorCtx = AuthzContext(requesterIp = requesterIp, channel = Channel.EDITOR.contextValue)
        if (decide(principal, AuthzAction.TASK_ASSUME, task, editorCtx) is AuthzDecision.Deny) {
            throw serviceNotFound("editor task")
        }
        val meta = access.meta
        // One re-decision gates both the FAILED diagnostic and the DONE rows. Not audited here — the
        // per-statement Decide already recorded it. No AuditStore: the rows were charged at execution.
        val ctx = viewerDecision(
            principal, task, access.sql, AuthzContext(requesterIp = requesterIp),
            datasourceStore, policyStore, accessStore, userGroupStore, roleResolver, authz,
            systemClassification, Channel.EDITOR,
        )
        if (meta.status == "FAILED" && access.errorDetail != null) {
            return QueryResultView(meta, emptyList(), emptyList(), errorDetail = failedDiagnosticForViewer(ctx, access.errorDetail))
        }
        if (meta.status != "DONE") throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.result_not_ready"))
        val decrypted = access.decrypted
            ?: throw TaskServiceException(HttpStatusCode.Gone, ApiError("approval.result_expired"))
        val viewDecision =
            if (ctx == null) ResultViewDecision.Denied("stored result has no live decision to re-mask under")
            else decideResultView(ctx, decrypted)
        when (viewDecision) {
            is ResultViewDecision.Denied -> {
                log.warn("editor result view denied task={} viewer={} reason={}", taskId, principal, viewDecision.reason)
                throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.result_view_denied"))
            }
            is ResultViewDecision.Allowed ->
                return QueryResultView(
                    meta, viewDecision.columns, viewDecision.rows,
                    // MASK iff this view actually masked something; the editor labels its result from this.
                    decision = if (viewDecision.maskedColumns.isEmpty()) Decision.ALLOW else Decision.MASK,
                    maskedColumns = viewDecision.maskedColumns,
                    truncatedAt = viewDecision.truncatedAt,
                    truncatedByCap = decrypted.truncatedByCap,
                )
        }
    }

    /** Drop the task's saved rows and its row. A non-owner or unknown id is a silent no-op. */
    suspend fun delete(principal: String, taskId: Long) {
        val task = accessStore.getRequest(taskId)
        if (task != null && task.isEditorTaskOf(principal)) {
            if (task.status == "EXECUTING") runExecService.cancelActiveRun(taskId)
            queryResultStore?.deleteResultsForTask(taskId)
            accessStore.deleteEditorTask(taskId, principal)
        }
    }

    // 404 for a non-owner / non-EDITOR id, so it's not an existence oracle.
    private fun ownedTask(principal: String, taskId: Long): AccessRequest =
        accessStore.getRequest(taskId)?.takeIf { it.isEditorTaskOf(principal) } ?: throw serviceNotFound("editor task")

    private fun AccessRequest.isEditorTaskOf(principal: String) =
        kind == "QUERY" && creatorKind == "EDITOR" && this.principal == principal

    private fun decide(principal: String, action: AuthzAction, task: AccessRequest, ctx: AuthzContext) =
        authz.authorizeWithContext(
            principal, action, task.toApprovalResource(), ctx, task.datasourceName,
            task.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
}
