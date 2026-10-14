package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
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
import java.time.Instant

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
    fun mayRequest(principal: String, requesterIp: String?, ds: Datasource): Boolean =
        mayRequestOn(authz, roleResolver, principal, requesterIp, ds)

    /**
     * The single authorization for a task action on a query-approval request, decided by Cedar against the
     * Request with requester != approver enforced by the shipped no-self-approval forbid.
     *
     * The channel is WORKFLOW_VIEWER, never `editor` or `wire`: those carry the self-approve permits that
     * suit a machine task under the caller's own roles, while a human approval elevates to R.
     */
    fun mayDecide(
        principal: String,
        requesterIp: String?,
        action: AuthzAction,
        req: AccessRequest,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): Boolean = authorize(principal, requesterIp, action, req, channel)

    /** Result rows require Cedar authority to assume the task's R. No authDebug bypass: data confidentiality. */
    fun mayReadResult(principal: String, requesterIp: String?, req: AccessRequest): Boolean =
        authorize(principal, requesterIp, AuthzAction.TASK_ASSUME, req, Channel.WORKFLOW_VIEWER)

    private fun authorize(principal: String, requesterIp: String?, action: AuthzAction, req: AccessRequest, channel: Channel): Boolean {
        val decision = authz.authorizeWithContext(
            principal,
            action,
            req.toApprovalResource(),
            AuthzContext(requesterIp = requesterIp, channel = channel.contextValue),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        return decision !is AuthzDecision.Deny
    }

    /** [roleName] names R when [CreateQueryRequestInput.roleId] is null; it resolves only after the task.request gate. */
    fun create(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        input: CreateQueryRequestInput,
        roleName: String? = null,
        source: String = "console",
    ): CreateQueryRequestResponse {
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
            val denied = decision!!

            if (accessStore.pendingQueryRequestExists(sourceDecisionId)) throw pendingExists()

            val ds = datasourceStore.list().firstOrNull { it.name == denied.datasource }
                ?: throw TaskServiceException(HttpStatusCode.Conflict, notFoundError("datasource"))
            if (!mayRequest(principal, requesterIp, ds)) throw serviceForbidden()
            val roleId = roleIdOf(input, roleName)

            val request = try {
                accessStore.createQueryRequest(
                    principal = principal,
                    datasourceId = ds.id,
                    // The source decision authorized one statement, so there is no batch to split.
                    statements = listOf(denied.statement),
                    denyReason = denied.detail,
                    sourceDecisionId = sourceDecisionId,
                    reason = input.reason.trim(),
                    title = trimmedTitle(input.title),
                    evaluatedDecision = "DENY",
                    roleId = roleId,
                    requestedDurationSec = input.requestedDurationSec,
                    actor = actor,
                    recorder = recorder,
                    // Nothing re-analyzes the copied statement, so it is unknown and delivery withholds the text.
                    carriesProtectedLiteral = null,
                    source = source,
                    contentHash = contentHash(denied.statement, ds.engine.dialect),
                    onCreated = { c, taskId, roleName -> notifications?.emitRequested(c, taskId, principal, ds, roleName) },
                )
            } catch (_: DuplicatePendingQueryRequestException) {
                throw pendingExists()
            }
            notifications?.wake()
            return CreateQueryRequestResponse(request, wouldAllow = false)
        }

        validateProactiveCompose(input.datasourceId, input.sql, input.title, input.reason)?.let { throw fieldRequired(it) }
        val ds = datasourceStore.get(input.datasourceId!!) ?: throw serviceNotFound("datasource")
        val sql = input.sql!!
        if (!mayRequest(principal, requesterIp, ds)) throw serviceForbidden()
        val roleId = roleIdOf(input, roleName)

        // Split server-side, so the stored boundary is the engine's rather than a client's guess.
        val splitConfig = ds.splitEngineConfig() ?: throw unsplittableSql()
        val statements = splitStatements(sql, splitConfig) ?: throw unsplittableSql()

        val analysis = analyze(principal, ds, statements, requesterIp)
        val request = accessStore.createQueryRequest(
            principal = principal,
            datasourceId = ds.id,
            statements = statements,
            denyReason = analysis.denyReason,
            sourceDecisionId = null,
            reason = input.reason.trim(),
            title = input.title!!.trim(),
            evaluatedDecision = analysis.decision.name,
            roleId = roleId,
            requestedDurationSec = input.requestedDurationSec,
            actor = actor,
            recorder = recorder,
            carriesProtectedLiteral = analysis.carriesProtectedLiteral,
            onCreated = { c, taskId, roleName -> notifications?.emitRequested(c, taskId, principal, ds, roleName) },
            source = source,
            contentHash = contentHash(sql, ds.engine.dialect),
        )
        notifications?.wake()
        return CreateQueryRequestResponse(request, wouldAllow = analysis.decision == EnfAction.ALLOW)
    }

    private class Analysis(val decision: EnfAction, val denyReason: String?, val carriesProtectedLiteral: Boolean?)

    /** Analysis only: nothing executes and no audit row is written. Each statement previews on its own. */
    private fun analyze(
        principal: String,
        ds: Datasource,
        statements: List<String>,
        requesterIp: String?,
        // A pull request's file runs in its own schema, so it is analyzed there too.
        searchPath: List<String>? = null,
    ): Analysis {
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
                liveSearchPath = searchPath,
            )
        }
        // Worst statement wins (DENY > MASK > ALLOW).
        val decision = decisions.firstOrNull { it.action == EnfAction.DENY }
            ?: decisions.firstOrNull { it.masks.isNotEmpty() }
            ?: decisions.first()
        return Analysis(
            decision = decision.action,
            denyReason = if (decision.action == EnfAction.DENY) (decision.denyReason ?: decision.detail) else null,
            // The disclosure hint is reader-neutral and independent of the authorization decision: null
            // (unanalyzable) and true both withhold; only a proven clean batch discloses. A catalog-changing
            // statement can change what a later one binds to, so any such statement makes the hint unknown.
            carriesProtectedLiteral = if (decisions.any { it.catalogChanging }) {
                null
            } else {
                statements
                    .map { protectedPredicateLiterals(ds, it, catalog, liveSearchPath = searchPath)?.isNotEmpty() }
                    .reduce { a, b -> if (a == null || b == null) null else a || b }
            },
        )
    }

    /**
     * Create the request for one SQL file of a pull request. An [alreadyRan] file's key already ran in its scope, so
     * its request is kept for merge tracking only and notifies no one.
     */
    fun requestFromPullRequest(
        requester: String,
        actor: AuditActor,
        ds: Datasource,
        roleName: String,
        statements: List<String>,
        origin: RequestOrigin,
        source: String,
        alreadyRan: Boolean,
    ): AccessRequest {
        val role = policyStore.getRoleByName(roleName) ?: throw serviceNotFound("role")
        val analysis = analyze(requester, ds, statements, requesterIp = null, origin.pullRequest.defaultSchema?.let(::listOf))
        val request = accessStore.createQueryRequest(
            principal = requester,
            datasourceId = ds.id,
            statements = statements,
            denyReason = analysis.denyReason,
            sourceDecisionId = null,
            reason = origin.pullRequest.prUrl,
            title = origin.pullRequest.path,
            evaluatedDecision = analysis.decision.name,
            roleId = role.id,
            actor = actor,
            recorder = recorder,
            carriesProtectedLiteral = analysis.carriesProtectedLiteral,
            onCreated = if (alreadyRan) {
                null
            } else {
                { c, taskId, executeAs ->
                    notifications?.emitRequested(c, taskId, requester, ds, executeAs, source, origin.pullRequest)
                }
            },
            source = source,
            origin = origin,
        )
        if (alreadyRan) {
            accessStore.endUnstarted(request.id, "ALREADY_RAN")
            return accessStore.getRequest(request.id)!!
        }
        notifications?.wake()
        return request
    }

    /**
     * Give a pull request's not-yet-run request [req] its file as of this filing, through [revise]. An
     * [alreadyRan] key is kept for merge tracking only and notifies no one.
     */
    fun editFromPullRequest(
        req: AccessRequest,
        sql: String,
        statements: List<String>,
        origin: RequestOrigin,
        actor: AuditActor,
        alreadyRan: Boolean,
    ): AccessRequest {
        val ds = req.datasourceId?.let(datasourceStore::get) ?: throw serviceNotFound("datasource")
        val edited = revise(req, ds, sql, statements, origin.pullRequest.path, null, actor, null, origin, notify = !alreadyRan)
            ?: return workflowRequest(req.id)
        if (alreadyRan) {
            accessStore.endUnstarted(edited.id, "ALREADY_RAN")
            return workflowRequest(edited.id)
        }
        return edited
    }

    /** Approve a PENDING request from a source review; null when Cedar denies [principal] or it is not PENDING. */
    fun approveFromReview(principal: String, id: Long, reviewId: String, reviewUrl: String): AccessRequest? {
        val req = accessStore.getRequest(id)?.takeIf { it.isWorkflowApproval && it.status == "PENDING" } ?: return null
        val decision = authz.authorizeWithContext(
            principal,
            AuthzAction.TASK_APPROVE,
            req.toApprovalResource(),
            // A review carries no attested address, so a policy requiring one denies.
            AuthzContext(channel = Channel.GITHUB.contextValue),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        if (decision is AuthzDecision.Deny) return null
        val updated = accessStore.decideQueryRequest(
            id, approved = true, rejectionReason = null, decidedBy = principal,
            actor = AuditActor(principal, clientAddr = null, channel = Channel.GITHUB.contextValue),
            recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
            detail = "review $reviewUrl",
            reviewId = reviewId,
            revision = req.revision,
        ) ?: return null
        notifications?.wake()
        log.info("query approval approved from review request={} requester={} decider={}", id, req.principal, principal)
        return updated
    }

    /** Return an approved, not-started request to PENDING because the review that approved it no longer counts. */
    fun withdrawApproval(id: Long, reviewUrl: String): Boolean {
        val req = accessStore.getRequest(id) ?: return false
        val actor = AuditActor(req.decidedBy ?: "github", clientAddr = null, channel = Channel.GITHUB.contextValue)
        return accessStore.reopenQueryRequest(id, actor, recorder, "review $reviewUrl")
    }

    /**
     * Run an approved pull-request request inline when its auto-merge triggers it, as [executor]. The ordering
     * gate's [TaskServiceException] (`approval.scope_busy`) propagates.
     */
    suspend fun runOnMerge(executor: String, id: Long): AccessRequest {
        val req = workflowRequest(id)
        if (req.status in setOf("EXECUTING", "EXECUTED", "FAILED", "CANCELLED")) throw alreadyExecuted()
        if (req.status != "APPROVED") throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_approved"))
        val store = queryResultStore ?: throw resultStorageNotConfigured()
        val ds = req.datasourceId?.let(datasourceStore::get)
            ?: throw TaskServiceException(HttpStatusCode.Conflict, notFoundError("datasource"))
        if (store.statements(id).none { it.sql != null }) {
            throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.no_sql"))
        }
        val executeAs = policyStore.liveRoleNames(req.executeAs)
        if (executeAs.isEmpty()) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.no_execute_role"))
        if (store.claimAndStartRun(id, executor) { c -> accessStore.claimExecution(id, c) } == null) throw alreadyExecuted()
        runApprovedTask(
            id = id, executor = executor, ds = ds, executeAs = executeAs,
            requesterIp = null, requesterPrincipal = req.principal, req = req,
            config = config, accessStore = accessStore, store = store, auditStore = auditStore,
            runExecService = runExecService, taskCompletionHub = taskCompletionHub,
            notifications = notifications, log = log,
            defaultSchema = req.pullRequest?.defaultSchema,
        )
        return accessStore.getRequest(id)!!
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

    /**
     * Requests the caller filed or took part in, from the participant list rather than a Cedar check per row.
     * Another person's statement shows only when it carries no protected literal, as in a Slack channel.
     */
    fun involved(principal: String): List<AccessRequest> =
        accessStore.listInvolvedQueryRequests(principal, INVOLVED_LIMIT).map { req ->
            if (req.principal == principal || req.statementCarriesProtectedLiteral == false) req else req.copy(sql = null)
        }

    /** Every PENDING request the caller may approve (Cedar task.approve), not a group-membership join. */
    fun inbox(principal: String, requesterIp: String?): List<AccessRequest> =
        accessStore.listQueryRequests("PENDING", null).filter { mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, it) }

    fun detail(principal: String, requesterIp: String?, id: Long): QueryRequestDetail {
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
        val approved = req.status == "APPROVED" && !req.fromPullRequest
        val canExecute = queryResultStore != null && approved && !req.approvalExpired() &&
            mayDecide(principal, requesterIp, AuthzAction.TASK_RUN, req)
        val mayCancel = mayDecide(principal, requesterIp, AuthzAction.TASK_CANCEL, req)
        val canCancel = req.status == "EXECUTING" && mayCancel
        val canForceRun = req.fromPullRequest && req.status in FORCEABLE && !req.forceRun &&
            mayDecide(principal, requesterIp, AuthzAction.TASK_FORCE_RUN, req)
        return QueryRequestDetail(
            req,
            canDecide = req.status == "PENDING" && isApprover,
            canApproveAndRun = req.status == "PENDING" && isApprover && !req.fromPullRequest && queryResultStore != null &&
                mayDecide(principal, requesterIp, AuthzAction.TASK_RUN, req),
            canReject = req.status in EDITABLE && isApprover,
            canUnapprove = approved && isApprover,
            canClose = req.status in EDITABLE && !req.fromPullRequest && mayCancel,
            result = visibleMeta,
            statements = visibleStatements,
            canExecute = canExecute,
            canCancel = canCancel,
            canEdit = req.principal == principal && req.status in EDITABLE && !req.fromPullRequest,
            canForceRun = canForceRun,
        )
    }

    /** Let a GitHub request run past its scope's freshness and one-PR-at-a-time checks; every other gate stays. */
    fun forceRun(principal: String, requesterIp: String?, actor: AuditActor, id: Long): AccessRequest {
        val req = workflowRequest(id)
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_FORCE_RUN, req)) throw notApprover()
        if (req.status in setOf("EXECUTING", "EXECUTED", "FAILED", "CANCELLED")) throw alreadyExecuted()
        if (!req.fromPullRequest || req.status !in FORCEABLE) throw alreadyDecided()
        if (req.forceRun) return req
        val forced = accessStore.forceRun(id, principal, actor, recorder) { c, r ->
            notifications?.emit(c, NotificationEvent.TASK_FORCE_RUN, r)
        } ?: return workflowRequest(id)
        notifications?.wake()
        log.info("query approval force-run request={} pr={}#{} by={}", id, req.pullRequest?.repository, req.pullRequest?.pr, principal)
        return forced
    }

    /** Approve [revision] of a request: the version the approver read. A later edit refuses it. */
    fun approve(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        revision: Int,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = workflowRequest(id)
        if (req.status != "PENDING") throw alreadyDecided()
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req, channel)) throw notApprover()
        if (req.revision != revision) throw requestChanged()
        val updated = accessStore.decideQueryRequest(
            id, approved = true, rejectionReason = null, decidedBy = principal,
            actor = actor, recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
            revision = revision,
        ) ?: throw if (accessStore.getRequest(id)?.status == "PENDING") requestChanged() else alreadyDecided()
        notifications?.wake()
        log.info(
            "query approval approved request={} requester={} decider={} sourceDecisionId={}",
            id, req.principal, principal, req.sourceDecisionId,
        )
        return updated
    }

    fun reject(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        reason: String,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        if (reason.isBlank()) throw fieldRequired("reason")
        val req = workflowRequest(id)
        if (req.status !in EDITABLE) throw alreadyDecided()
        // Reject is the same task.approve decision as approve.
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req, channel)) throw notApprover()
        val updated = accessStore.decideQueryRequest(
            id, approved = false, rejectionReason = reason.trim(), decidedBy = principal,
            actor = actor, recorder = recorder, revision = req.revision,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: throw alreadyDecided()
        notifications?.wake()
        log.info(
            "query approval rejected request={} requester={} decider={} sourceDecisionId={}",
            id, req.principal, principal, req.sourceDecisionId,
        )
        return updated
    }

    /**
     * Replace the SQL (and optionally the title or reason) of the caller's own PENDING or APPROVED request. It
     * goes back to PENDING under a new revision, so an earlier approval no longer counts.
     */
    /** Return an APPROVED request to PENDING. The same task.approve decision as approving it. */
    fun unapprove(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = workflowRequest(id)
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_APPROVE, req, channel)) throw notApprover()
        if (req.status != "APPROVED" || req.fromPullRequest) throw notApproved()
        if (!reopen(id, actor, "unapproved by $principal")) throw notApproved()
        log.info("query approval unapproved request={} by={}", id, principal)
        return workflowRequest(id)
    }

    /** Return every console request approved more than [APPROVAL_TTL] ago and not yet run to PENDING. */
    fun expireApprovals() {
        for (id in accessStore.expiredApprovals()) {
            if (reopen(id, SYSTEM_ACTOR, "approval expired")) log.info("query approval expired request={}", id)
        }
    }

    private fun reopen(id: Long, actor: AuditActor, detail: String): Boolean =
        accessStore.reopenQueryRequest(id, actor, recorder, detail) { c, r ->
            notifications?.emit(c, NotificationEvent.TASK_REOPENED, r)
        }.also { if (it) notifications?.wake() }

    fun edit(principal: String, requesterIp: String?, actor: AuditActor, id: Long, input: EditQueryRequestInput): AccessRequest {
        val req = workflowRequest(id)
        if (req.principal != principal) throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.edit_forbidden"))
        // The file in the pull request is the request's source, so a push is what changes it.
        if (req.fromPullRequest) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.github_edit_by_push"))
        if (req.status !in EDITABLE) throw notEditable()
        if (input.sql.isBlank()) throw fieldRequired("sql")
        if (input.reason != null && input.reason.isBlank()) throw fieldRequired("reason")
        val ds = req.datasourceId?.let(datasourceStore::get) ?: throw serviceNotFound("datasource")
        if (!mayRequest(principal, requesterIp, ds)) throw serviceForbidden()
        val splitConfig = ds.splitEngineConfig() ?: throw unsplittableSql()
        val statements = splitStatements(input.sql, splitConfig)?.takeIf { it.isNotEmpty() } ?: throw unsplittableSql()
        val edited = revise(req, ds, input.sql, statements, trimmedTitle(input.title), input.reason?.trim(), actor, requesterIp)
            ?: throw notEditable()
        log.info("query approval edited request={} revision={} by={}", id, edited.revision, principal)
        return edited
    }

    /**
     * Give a not-yet-run request [req] new SQL. SQL with the same [contentHash] keeps the revision and the
     * approval, so only the title or reason changes; other SQL is analyzed again and the request returns to
     * PENDING under the next revision. Null when [req] is no longer editable.
     */
    private fun revise(
        req: AccessRequest,
        ds: Datasource,
        sql: String,
        statements: List<String>,
        title: String?,
        reason: String?,
        actor: AuditActor,
        requesterIp: String?,
        origin: RequestOrigin? = null,
        notify: Boolean = true,
    ): AccessRequest? {
        val hash = contentHash(sql, ds.engine.dialect)
        if (hash == req.contentHash) {
            return accessStore.editQueryRequestDetails(req.id, title, reason, actor, recorder, origin?.pullRequest)
        }
        val analysis = analyze(req.principal, ds, statements, requesterIp, origin?.pullRequest?.defaultSchema?.let(::listOf))
        val edited = accessStore.editQueryRequest(
            req.id, statements,
            RequestEdit(hash, analysis.denyReason, analysis.decision.name, analysis.carriesProtectedLiteral, title, reason, origin),
            actor, recorder,
            onEdited = if (notify) { c, r -> notifications?.emit(c, NotificationEvent.TASK_EDITED, r) } else null,
        ) ?: return null
        notifications?.wake()
        return edited
    }

    /** Close a request that has not run, or stop one that is running. */
    suspend fun cancel(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = workflowRequest(id)
        if (!mayDecide(principal, requesterIp, AuthzAction.TASK_CANCEL, req, channel)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        when (req.status) {
            "EXECUTED", "FAILED", "CANCELLED" -> return req
            "EXECUTING" -> Unit
            in EDITABLE -> {
                if (req.fromPullRequest) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
                accessStore.closeQueryRequest(id, actor, recorder) { c, closed ->
                    notifications?.emit(c, NotificationEvent.TASK_CANCELLED, closed)
                } ?: throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
                notifications?.wake()
                log.info("query approval closed request={} by={}", id, principal)
                return workflowRequest(id)
            }
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
    fun execute(
        executor: String,
        requesterIp: String?,
        id: Long,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): Pair<ExecuteQueryRequestResponse, Job> {
        val req = workflowRequest(id)
        // Authorize BEFORE disclosing task state, so the 409s below are never a state oracle for a non-runner.
        if (!mayDecide(executor, requesterIp, AuthzAction.TASK_RUN, req, channel)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.not_runner"))
        }
        // The merge trigger runs it, so the run and the merge stay one outcome.
        if (req.fromPullRequest) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.github_runs_on_merge"))
        if (req.status in setOf("EXECUTING", "EXECUTED", "FAILED", "CANCELLED")) throw alreadyExecuted()
        if (req.status != "APPROVED") throw notApproved()
        if (req.approvalExpired()) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.expired"))
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
        return ExecuteQueryRequestResponse(decision = "EXECUTING") to job
    }

    /**
     * The decrypted rows of statement [ordinal] (null = the active one): task.assume gates the viewer, then the
     * stored result is re-decided live under exactly the task's R on workflow-viewer. Every view and live-decision
     * denial is audited before responding.
     */
    fun result(principal: String, requesterIp: String?, id: Long, ordinal: Int?, page: ResultPage? = null): QueryResultView {
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
        fun denyView(reason: String): Nothing {
            log.warn("query approval result view denied request={} viewer={} reason={}", id, principal, reason)
            auditStore.insert(e3Record(principal, req, "result-view-denied", Channel.WORKFLOW_VIEWER))
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.result_view_denied"))
        }
        // An uncharged view would escape the result caps, so no execution decision means no view.
        val (chargeDecisionId, chargeDecision) = meta.decisionId?.let { decisionId -> auditStore.get(decisionId)?.let { decisionId to it } }
            ?: denyView("stored result has no execution decision to charge")
        val viewDecision =
            if (ctx == null) ResultViewDecision.Denied("stored result has no live decision to re-mask under")
            else decideResultView(ctx, decrypted)
        when (viewDecision) {
            is ResultViewDecision.Denied -> denyView(viewDecision.reason)
            is ResultViewDecision.Allowed -> {
                // Only the released page is audited and charged.
                val (released, nextOffset) = viewDecision.page(page)
                // By the viewer's relationship to the task: an assumer is neither party.
                val viewEvent = when (principal) {
                    req.principal -> "result-viewed-by-requester"
                    req.decidedBy -> "result-viewed-by-approver"
                    else -> "result-viewed-by-assumer"
                }
                // Audit before returning rows, and charge the released volume against the execution decision
                // in the same transaction; a failed insert propagates, so rows never leave unrecorded.
                val (rowCount, bytes) = resultVolume(released.rows)
                auditStore.insertAll(
                    listOf(
                        e3Record(principal, req, viewEvent, Channel.WORKFLOW_VIEWER),
                        completionEvent(
                            chargeDecision, chargeDecisionId, rowCount, bytes, "ok", 0,
                            principal = principal, channel = Channel.WORKFLOW_VIEWER.contextValue,
                        ),
                    ),
                )
                return QueryResultView(
                    meta, released.columns, released.rows,
                    // Labels the release, which the viewer's context may have narrowed past the execution.
                    decision = if (released.maskedColumns.isEmpty()) Decision.ALLOW else Decision.MASK,
                    maskedColumns = released.maskedColumns,
                    truncatedAt = released.truncatedAt,
                    truncatedByCap = decrypted.truncatedByCap,
                    nextOffset = nextOffset,
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

    private fun roleIdOf(input: CreateQueryRequestInput, roleName: String?): Long = input.roleId
        ?: roleName?.let { (policyStore.getRoleByName(it) ?: throw serviceNotFound("role")).id }
        ?: throw roleRequired()

    private fun roleRequired() = TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.role_required"))

    private fun pendingExists() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.pending_request_exists"))

    private fun alreadyDecided() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.already_decided"))

    private fun requestChanged() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.request_changed"))

    private fun notEditable() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_editable"))

    private fun alreadyExecuted() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.already_executed"))

    private fun notApprover() = TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))

    private fun notApproved() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_approved"))

    private fun AccessRequest.approvalExpired(): Boolean =
        !fromPullRequest && approvedAt?.let { Instant.parse(it).isBefore(Instant.now().minus(APPROVAL_TTL)) } == true

    private companion object {
        const val REQUEST = "query approval request"
        const val INVOLVED_LIMIT = 200
        val SYSTEM_ACTOR = AuditActor("system", channel = "system")
        val EDITABLE = setOf("PENDING", "APPROVED")
        val FORCEABLE = setOf("PENDING", "APPROVED")
    }
}
