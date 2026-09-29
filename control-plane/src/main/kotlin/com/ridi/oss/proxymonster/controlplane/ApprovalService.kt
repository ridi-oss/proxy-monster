package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.probe.splitStatements
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * The query-approval workflow shared by the REST approval routes and the MCP approval tools: create, decide,
 * cancel, execute under R, and view the result. Every Cedar decision runs on a REST channel built here from
 * the requester IP, never on the caller's own. Failures throw [TaskServiceException].
 */
class ApprovalService(
    private val config: Config,
    private val accessStore: AccessStore,
    private val auditStore: AuditStore,
    private val datasourceStore: DatasourceStore,
    private val policyStore: PolicyStore,
    private val userGroupStore: UserGroupStore,
    // null when PM_RESULT_KEY is unset → execute-under-R refused
    private val queryResultStore: QueryResultStore?,
    private val roleResolver: RoleResolver,
    private val authz: Authz,
    // Approval execution runs on the proxy; the control plane never dials the target.
    private val runExecService: RunExecService,
    private val appScope: CoroutineScope,
    // Null keeps system schemas deny-by-default in view-as-R decisions.
    private val systemClassification: SystemClassificationService? = null,
    private val taskCompletionHub: TaskCompletionHub? = null,
    // Null = the notification layer is not configured.
    private val notifications: NotificationService? = null,
    private val log: Logger = LoggerFactory.getLogger(ApprovalService::class.java),
) {
    // Decisions (approve/reject) record a kind="admin" management event; the result lifecycle
    // (execute/cancel/view) uses e3Record's separate approval_lifecycle path.
    private val recorder = ManagementAuditRecorder(auditStore)

    /**
     * Whether [principal] may open a query-approval request against [ds] (task.request on the Datasource).
     * The shipped global permit keeps this open by default; an operator can forbid it per datasource.
     */
    fun mayRequest(principal: String, requesterIp: String?, ds: Datasource): Boolean {
        val roles = roleResolver.resolve(principal)
        val raw = AuthzContext(requesterIp = requesterIp)
        val tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)
        val decision = authz.authorizeDatasourceAction(
            principal, roles, AuthzAction.TASK_REQUEST, ds.name, raw.copy(tags = tags), ds.tags,
        )
        return decision !is AuthzDecision.Deny
    }

    /**
     * The single authorization for a task action on a query-approval request, decided by Cedar against the
     * Request with requester != approver enforced by the shipped no-self-approval forbid.
     *
     * The channel is WORKFLOW_VIEWER, never `editor` or `wire`: those carry the self-approve permits that
     * suit a machine task under the caller's own roles, while a human approval elevates to R.
     */
    fun mayDecide(principal: String, requesterIp: String?, action: AuthzAction, req: AccessRequest): Boolean =
        authorizeOnViewer(principal, requesterIp, action, req)

    /** Result rows require Cedar authority to assume the task's R. No authDebug bypass: data confidentiality. */
    fun mayReadResult(principal: String, requesterIp: String?, req: AccessRequest): Boolean =
        authorizeOnViewer(principal, requesterIp, AuthzAction.TASK_ASSUME, req)

    private fun authorizeOnViewer(principal: String, requesterIp: String?, action: AuthzAction, req: AccessRequest): Boolean {
        val decision = authz.authorizeWithContext(
            principal,
            action,
            req.toApprovalResource(),
            AuthzContext(requesterIp = requesterIp, channel = Channel.WORKFLOW_VIEWER.contextValue),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        return decision !is AuthzDecision.Deny
    }

    fun create(principal: String, requesterIp: String?, actor: AuditActor, input: CreateApprovalInput): CreateApprovalResponse {
        if (input.reason.isBlank()) throw fieldRequired("reason")

        val hasSource = input.sourceDecisionId != null
        val hasProactive = input.datasourceId != null || input.sql != null
        if (hasSource == hasProactive) {
            throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.exactly_one_source_required"))
        }
        // Every new request carries R; the roleId check follows each branch's field validation so an
        // incomplete form names its missing field first.

        if (hasSource) {
            val sourceDecisionId = input.sourceDecisionId!!
            val decision = auditStore.get(sourceDecisionId)
            when (validateApprovalSource(decision, principal)) {
                SourceValidation.OK -> Unit
                SourceValidation.NOT_FOUND -> throw serviceNotFound("decision")
                SourceValidation.NOT_DENY ->
                    throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.only_denied_queries"))
            }
            val source = decision!!

            if (accessStore.pendingQueryRequestExists(sourceDecisionId)) throw pendingExists()

            val ds = datasourceStore.list().firstOrNull { it.name == source.datasource }
                ?: throw TaskServiceException(HttpStatusCode.Conflict, notFoundError("datasource"))
            if (!mayRequest(principal, requesterIp, ds)) throw serviceForbidden()
            if (input.roleId == null) throw roleRequired()

            val request = try {
                accessStore.createQueryRequest(
                    principal = principal,
                    datasourceId = ds.id,
                    // The source decision authorized one statement, so there is no batch to split.
                    statements = listOf(source.statement),
                    denyReason = source.detail,
                    sourceDecisionId = sourceDecisionId,
                    reason = input.reason.trim(),
                    title = trimmedTitle(input.title),
                    evaluatedDecision = "DENY",
                    roleId = input.roleId,
                    requestedDurationSec = input.requestedDurationSec,
                    actor = actor,
                    recorder = recorder,
                    // Nothing re-analyzes the copied statement, so it is unknown and delivery withholds the text.
                    carriesProtectedLiteral = null,
                    onCreated = { c, taskId, roleName -> notifications?.emitRequested(c, taskId, principal, ds, roleName) },
                )
            } catch (_: DuplicatePendingQueryRequestException) {
                throw pendingExists()
            }
            notifications?.wake()
            return CreateApprovalResponse(request, wouldAllow = false)
        }

        validateProactiveCompose(input.datasourceId, input.sql, input.title, input.reason)?.let { throw fieldRequired(it) }
        val ds = datasourceStore.get(input.datasourceId!!) ?: throw serviceNotFound("datasource")
        val sql = input.sql!!
        if (!mayRequest(principal, requesterIp, ds)) throw serviceForbidden()
        if (input.roleId == null) throw roleRequired()

        // Split server-side, so the stored boundary is the engine's rather than a client's guess.
        val splitConfig = ds.splitEngineConfig() ?: throw unsplittableSql()
        val statements = splitStatements(sql, splitConfig) ?: throw unsplittableSql()

        // Analysis only: nothing executes and no audit row is written. Each statement previews on its own.
        val catalog = datasourceStore.catalog(ds.id)
        // Carries requester_ip so the preview matches the real editor execution's verdict.
        val composeContext = AuthzContext(requesterIp = requesterIp)
        val decisions = statements.map { statement ->
            decideQuery(
                principal = principal,
                ds = ds,
                sql = statement,
                channel = Channel.EDITOR,
                catalog = catalog,
                policyStore = policyStore,
                accessStore = accessStore,
                userGroupStore = userGroupStore,
                roleResolver = roleResolver,
                authz = authz, auditStore = auditStore,
                context = composeContext,
                systemClassification = systemClassification,
            )
        }
        // Worst statement wins (DENY > MASK > ALLOW).
        val decision = decisions.firstOrNull { it.action == EnfAction.DENY }
            ?: decisions.firstOrNull { it.masks.isNotEmpty() }
            ?: decisions.first()
        val request = accessStore.createQueryRequest(
            principal = principal,
            datasourceId = ds.id,
            statements = statements,
            denyReason = if (decision.action == EnfAction.DENY) (decision.denyReason ?: decision.detail) else null,
            sourceDecisionId = null,
            reason = input.reason.trim(),
            title = input.title!!.trim(),
            evaluatedDecision = decision.action.name,
            roleId = input.roleId,
            requestedDurationSec = input.requestedDurationSec,
            actor = actor,
            recorder = recorder,
            // The disclosure hint is reader-neutral and independent of the authorization decision: null
            // (unanalyzable) and true both withhold; only a proven clean batch discloses. A catalog-changing
            // statement can change what a later one binds to, so any such statement makes the hint unknown.
            carriesProtectedLiteral = if (decisions.any { it.catalogChanging }) {
                null
            } else {
                statements
                    .map { protectedPredicateLiterals(ds, it, catalog)?.isNotEmpty() }
                    .reduce { a, b -> if (a == null || b == null) null else a || b }
            },
            onCreated = { c, taskId, roleName -> notifications?.emitRequested(c, taskId, principal, ds, roleName) },
        )
        notifications?.wake()
        return CreateApprovalResponse(request, wouldAllow = decision.action == EnfAction.ALLOW)
    }

    /**
     * Role discovery: every role the statement runs under, held or not. A dry run — no audit row. Candidates
     * preview on WORKFLOW_EXECUTOR, the channel an approved query runs on, so channel-scoped grants count.
     */
    fun discoverRoles(principal: String, requesterIp: String?, datasourceId: Long, sql: String): DiscoverRolesResponse {
        val ds = datasourceStore.get(datasourceId) ?: throw serviceNotFound("datasource")
        val discoverContext = AuthzContext(requesterIp = requesterIp)
        val splitConfig = ds.splitEngineConfig() ?: throw unsplittableSql()
        val statements = splitStatements(sql, splitConfig) ?: throw unsplittableSql()
        val catalog = datasourceStore.catalog(ds.id)
        return discoverRoles(policyStore.listRoles(), statements.size) { index, roles, channel ->
            decideQuery(
                principal = principal, ds = ds, sql = statements[index], channel = channel,
                catalog = catalog, policyStore = policyStore, accessStore = accessStore,
                userGroupStore = userGroupStore, roleResolver = roleResolver, authz = authz, auditStore = auditStore,
                providedRoles = roles, context = discoverContext, systemClassification = systemClassification,
            )
        }
    }

    fun listOwn(principal: String, status: String?): List<AccessRequest> =
        accessStore.listQueryRequests(status = status, principal = principal)

    /** Every PENDING request the caller may approve (Cedar task.approve), not a group-membership join. */
    fun inbox(principal: String, requesterIp: String?): List<AccessRequest> =
        accessStore.listQueryRequests("PENDING", null).filter { mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, it) }

    fun detail(principal: String, requesterIp: String?, id: Long): ApprovalDetail {
        val req = workflowRequest(id)
        val isApprover = mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req)
        // Task metadata is gated by task.read. Saved rows are separate and remain behind task.assume.
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_READ, req)) throw serviceNotFound(REQUEST)
        // Row count and column shape are cardinality/existence oracles, so they need task.assume too.
        val mayReadRows = mayReadResult(principal, requesterIp, req)
        fun visible(meta: QueryResultMeta) =
            if (mayReadRows) meta else meta.copy(rowCount = null, columns = emptyList())
        val visibleMeta = queryResultStore?.meta(id)?.let(::visible)
        val visibleStatements = queryResultStore?.statements(id).orEmpty().map(::visible)
        // Mirrors execute's gates: only the approver of record gets a Run affordance.
        val canExecute = queryResultStore != null && isApprover && req.status == "APPROVED" && req.decidedBy == principal
        val canCancel = req.status == "EXECUTING" && mayDecide(principal, requesterIp, AuthzAction.TASK_CANCEL, req)
        return ApprovalDetail(
            req,
            canDecide = req.status == "PENDING" && isApprover,
            result = visibleMeta,
            statements = visibleStatements,
            canExecute = canExecute,
            canCancel = canCancel,
        )
    }

    fun approve(principal: String, requesterIp: String?, actor: AuditActor, id: Long): AccessRequest {
        val req = workflowRequest(id)
        if (req.status != "PENDING") throw alreadyDecided()
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req)) throw notApprover()
        val updated = accessStore.decideQueryRequest(
            id, approved = true, rejectionReason = null, decidedBy = principal,
            actor = actor, recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: throw alreadyDecided()
        notifications?.wake()
        log.info(
            "query approval approved request={} requester={} decider={} sourceDecisionId={}",
            id, req.principal, principal, req.sourceDecisionId,
        )
        return updated
    }

    fun reject(principal: String, requesterIp: String?, actor: AuditActor, id: Long, reason: String): AccessRequest {
        if (reason.isBlank()) throw fieldRequired("reason")
        val req = workflowRequest(id)
        if (req.status != "PENDING") throw alreadyDecided()
        // Reject is the same task.approve decision as approve.
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req)) throw notApprover()
        val updated = accessStore.decideQueryRequest(
            id, approved = false, rejectionReason = reason.trim(), decidedBy = principal,
            actor = actor, recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: throw alreadyDecided()
        notifications?.wake()
        log.info(
            "query approval rejected request={} requester={} decider={} sourceDecisionId={}",
            id, req.principal, principal, req.sourceDecisionId,
        )
        return updated
    }

    suspend fun cancel(principal: String, requesterIp: String?, id: Long): AccessRequest {
        val req = workflowRequest(id)
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_CANCEL, req)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        when (req.status) {
            "EXECUTED", "FAILED", "CANCELLED" -> return req
            "EXECUTING" -> Unit
            else -> throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
        }
        val store = queryResultStore ?: throw resultStorageNotConfigured()
        val cancelled = store.cancelRun(id) { conn, _ ->
            if (!accessStore.markCancelled(id, conn)) {
                throw IllegalStateException("task $id left EXECUTING before cancellation")
            }
            auditStore.insert(conn, e3Record(principal, req, "result-canceled", Channel.WORKFLOW_EXECUTOR))
        }
        if (cancelled != null) {
            runExecService.cancelActiveRun(id)
            // The CAS can win before the run coroutine unwinds, so push CANCELLED to both parties now.
            taskCompletionHub?.publish(listOf(req.principal, req.decidedBy).filterNotNull(), TaskEvent(id, "CANCELLED"))
            accessStore.getRequest(id)?.let { notifications?.enqueueTerminal(it) }
        }
        return accessStore.getRequest(id) ?: throw serviceNotFound(REQUEST)
    }

    /** Claim the approved task and launch its run under R. The returned [Job] completes at its terminal state. */
    fun execute(executor: String, requesterIp: String?, id: Long): Pair<ExecuteApprovalResponse, Job> {
        val req = workflowRequest(id)
        // Authorize BEFORE disclosing task state, so the 409s below are never a state oracle for a non-approver.
        if (!mayDecide(executor, requesterIp, AuthzAction.TASK_APPROVE, req)) throw notApprover()
        if (req.status in setOf("EXECUTING", "EXECUTED", "FAILED", "CANCELLED")) throw alreadyExecuted()
        if (req.status != "APPROVED") throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_approved"))
        // The approver of record executes, so the run's identity always falls inside the task.assume permit.
        // No authDebug bypass: this is an identity invariant.
        if (req.decidedBy != executor) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.not_the_approver"))
        }
        val store = queryResultStore ?: throw resultStorageNotConfigured()
        val ds = req.datasourceId?.let(datasourceStore::get)
            ?: throw TaskServiceException(HttpStatusCode.Conflict, notFoundError("datasource"))
        if (store.statements(id).none { it.sql != null }) {
            throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.no_sql"))
        }
        // Only LIVE execute-as roles; an empty set has no R to enforce the run under, so it fails closed
        // rather than falling through to the requester's own roles.
        val executeAs = policyStore.liveRoleNames(req.executeAs)
        if (executeAs.isEmpty()) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.no_execute_role"))

        // Claim and start the child in ONE transaction, so a cancel never lands in an EXECUTING-without-child gap.
        if (store.claimAndStartRun(id, executor) { c -> accessStore.claimExecution(id, c) } == null) throw alreadyExecuted()

        val job = appScope.launch {
            runApprovedTask(
                id = id, executor = executor, ds = ds, executeAs = executeAs,
                requesterIp = requesterIp, requesterPrincipal = req.principal, req = req,
                config = config, accessStore = accessStore, store = store, auditStore = auditStore,
                runExecService = runExecService, taskCompletionHub = taskCompletionHub,
                notifications = notifications, log = log,
            )
        }
        return ExecuteApprovalResponse(decision = "EXECUTING") to job
    }

    /**
     * The decrypted rows of statement [ordinal] (null = the active one): task.assume gates the viewer, then the
     * stored result is re-decided live under exactly the task's R on workflow-viewer. Every view and live-decision
     * denial is audited before responding.
     */
    fun result(principal: String, requesterIp: String?, id: Long, ordinal: Int?): QueryResultView {
        val req = workflowRequest(id)
        // Deprovisioning gate before result lookup; NotFound so it is no result-existence oracle.
        if (userGroupStore.isDeactivated(principal)) throw serviceNotFound(REQUEST)
        // One read captures ciphertext + meta; decrypt is lazy, only after authorization passes.
        val access = queryResultStore?.accessFor(id, ordinal) ?: throw serviceNotFound(REQUEST)
        val meta = access.meta
        if (!mayReadResult(principal, requesterIp, req)) throw serviceNotFound(REQUEST)
        // One re-decision on the released child's own statement gates both the FAILED diagnostic and the rows.
        // No AuditStore: the rows were charged at execution, so a spent rate must not gate the view.
        val ctx = viewerDecision(
            principal, req, access.sql, AuthzContext(requesterIp = requesterIp),
            datasourceStore, policyStore, accessStore, userGroupStore, roleResolver, authz,
            systemClassification, Channel.WORKFLOW_VIEWER,
        )
        if (meta.status == "FAILED" && access.errorDetail != null) {
            val viewEvent = when (principal) {
                req.principal -> "result-failure-viewed-by-requester"
                req.decidedBy -> "result-failure-viewed-by-approver"
                else -> "result-failure-viewed-by-assumer"
            }
            auditStore.insert(e3Record(principal, req, viewEvent, Channel.WORKFLOW_VIEWER))
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
                log.warn("query approval result view denied request={} viewer={} reason={}", id, principal, viewDecision.reason)
                auditStore.insert(e3Record(principal, req, "result-view-denied", Channel.WORKFLOW_VIEWER))
                throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.result_view_denied"))
            }
            is ResultViewDecision.Allowed -> {
                // By the viewer's relationship to the task: an assumer is neither party.
                val viewEvent = when (principal) {
                    req.principal -> "result-viewed-by-requester"
                    req.decidedBy -> "result-viewed-by-approver"
                    else -> "result-viewed-by-assumer"
                }
                // Audit before returning rows, and charge the released volume against the stored rows' decision
                // in the same transaction; a failed insert propagates, so rows never leave unrecorded.
                val (rowCount, bytes) = resultVolume(viewDecision.rows)
                val chargeDecision = listOfNotNull(meta.decisionId, req.sourceDecisionId)
                    .firstNotNullOfOrNull { id -> auditStore.get(id)?.let { id to it } }
                auditStore.insertAll(
                    listOfNotNull(
                        e3Record(principal, req, viewEvent, Channel.WORKFLOW_VIEWER),
                        chargeDecision?.let { (decisionId, decision) ->
                            completionEvent(
                                decision, decisionId, rowCount, bytes, "ok", 0,
                                principal = principal, channel = Channel.WORKFLOW_VIEWER.contextValue,
                            )
                        },
                    ),
                )
                return QueryResultView(
                    meta, viewDecision.columns, viewDecision.rows,
                    // Labels the release, which the viewer's context may have narrowed past the execution.
                    decision = if (viewDecision.maskedColumns.isEmpty()) Decision.ALLOW else Decision.MASK,
                    maskedColumns = viewDecision.maskedColumns,
                    truncatedAt = viewDecision.truncatedAt,
                    truncatedByCap = decrypted.truncatedByCap,
                )
            }
        }
    }

    private fun workflowRequest(id: Long): AccessRequest =
        accessStore.getRequest(id)?.takeIf { it.isWorkflowApproval } ?: throw serviceNotFound(REQUEST)

    private fun trimmedTitle(input: String?): String? = input?.trim()?.takeIf { it.isNotEmpty() }

    // A task result event in audit_decision. The shared /api/decisions feed exposes it, so it carries no
    // result-derived data — only the event, the actor, and the approval id.
    private fun e3Record(principal: String, req: AccessRequest, event: String, channel: Channel? = null): AuditEvent =
        AuditEvent(
            principal = principal,
            // The retained name, so a datasource soft-deleted after the run still names itself.
            datasource = req.datasourceName ?: "?",
            statement = "approval #${req.id} $event",
            decision = Decision.ALLOW, detail = "APPROVER_EXEC $event",
            channel = channel?.contextValue,
            kind = "approval_lifecycle",
        )

    private fun fieldRequired(field: String) =
        TaskServiceException(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to field)))

    private fun roleRequired() = TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.role_required"))

    private fun pendingExists() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.pending_request_exists"))

    private fun alreadyDecided() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.already_decided"))

    private fun alreadyExecuted() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.already_executed"))

    private fun notApprover() = TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))

    private companion object {
        const val REQUEST = "query approval request"
    }
}
