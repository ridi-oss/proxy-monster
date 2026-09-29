package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.RunError
import com.ridi.oss.proxymonster.probe.Masking
import com.ridi.oss.proxymonster.probe.bindMasks
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.Serializable

// ---- DTOs ---------------------------------------------------------------------------------

@Serializable
data class CreateApprovalInput(
    val sourceDecisionId: Long? = null,
    val datasourceId: Long? = null,
    val sql: String? = null,
    val title: String? = null,
    val reason: String = "",
    // APPROVAL: the elevation role R the requester picked from role discovery (POST /api/approvals/discover-roles).
    // NULL = no elevation role set. Execute-under-R keys off the stored access_request.role_id.
    val roleId: Long? = null,
    // Carried on the shared access_request row; not consumed by the query-approval flow (a QUERY approval is
    // executed under R by an approver, not re-run by the requester for a window). Kept for the shared column.
    val requestedDurationSec: Long = 3600,
)

@Serializable
data class DiscoverRolesRequest(val datasourceId: Long, val sql: String)

@Serializable data class CreateApprovalResponse(val request: AccessRequest, val wouldAllow: Boolean)

/**
 * A human query-approval request: a WORKFLOW-origin QUERY task. EDITOR and WIRE tasks share the
 * access_request table but are internal lifecycle records — an editor tab's saved result, a native-wire
 * statement's per-statement authorization — with null SQL and no approver, so they must never be
 * listed, fetched, decided, executed, or viewed through /api/approvals. Every id-addressed approval
 * route guards on this; the list/inbox feeds filter the same creator_kind in [AccessStore.listQueryRequests].
 */
internal val AccessRequest.isWorkflowApproval: Boolean
    get() = kind == "QUERY" && creatorKind == "WORKFLOW"

/**
 * A role the statement can run under (approval-workflow.md, "role discovery").
 *
 * [decision] and [maskedColumns] are the outcome under this role on the `workflow-executor` channel — the
 * channel an approved query runs on — PREVIEWED in the requester's current context. Execution runs in the
 * approver's context and can narrow further (e.g. off a trusted network), so this is the previewed outcome,
 * not a guaranteed one.
 */
@Serializable
data class RoleOption(
    val roleId: Long,
    val roleName: String,
    val decision: Decision = Decision.ALLOW,
    val maskedColumns: List<String> = emptyList(),
)

@Serializable
data class DiscoverRolesResponse(
    val options: List<RoleOption>,
)

/**
 * APPROVAL role discovery (approval-workflow.md — "the requester picks R"): list every role the statement can
 * run under — one entry per role that is not denied under that role alone. There is no baseline and no
 * held-vs-not-held concept: a role is offered whether or not the requester already holds it, so a statement
 * that already runs can still be taken through the workflow for approval/audit.
 *
 * PREVIEW PARITY: each role is previewed ALONE — `decide(setOf(role.name), …)`, never unioned with the
 * requester's own roles — because execute-under-R runs with `assumeRoles = setOf(R)` alone, on the
 * `workflow-executor` channel an approved query actually runs on. A unioned or wrong-channel preview could
 * ALLOW here and DENY at execute, offering a role the requester cannot actually run.
 *
 * [decide] runs the real decision path and MUST be side-effect-free — discovery is a dry run, no audit write.
 */
fun discoverRoles(
    allRoles: List<Role>,
    // A role is offered only if EVERY statement runs under it — the batch stops at the first denial.
    statementCount: Int,
    decide: (statementIndex: Int, roles: Set<String>, channel: Channel) -> DecisionContext,
): DiscoverRolesResponse {
    val options = allRoles.mapNotNull { role ->
        val masked = sortedSetOf<String>()
        for (index in 0 until statementCount) {
            val underR = decide(index, setOf(role.name), Channel.WORKFLOW_EXECUTOR)
            if (underR.action == EnfAction.DENY) return@mapNotNull null
            masked += underR.masks.map { it.column }
        }
        RoleOption(
            roleId = role.id,
            roleName = role.name,
            decision = if (masked.isEmpty()) Decision.ALLOW else Decision.MASK,
            maskedColumns = masked.toList(),
        )
    }
    return DiscoverRolesResponse(options = options)
}

@Serializable data class ApprovalDetail(
    val request: AccessRequest,
    val canDecide: Boolean,
    // The active statement's execution metadata. Rows remain behind the result endpoint.
    val result: QueryResultMeta? = null,
    // Every statement, in run order, with its own status.
    val statements: List<QueryResultMeta> = emptyList(),
    val canExecute: Boolean = false,
    val canCancel: Boolean = false,
)

/**
 * The decrypted rows of an execute-under-R result, plus its metadata — returned only to an authorized viewer.
 *
 * [decision] and [maskedColumns] describe the LIVE view re-decision these rows were released under, not the
 * execution that stored them: the viewer's own context can narrow an execution's ALLOW to a MASK. Without
 * them the caller cannot tell a masked cell from a value that genuinely looks like one, and a console
 * showing rows has nothing to label them with but a guess.
 */
@Serializable data class QueryResultView(
    val meta: QueryResultMeta,
    val columns: List<String>,
    val rows: List<List<String?>>,
    // The view re-decision's verdict; null on a FAILED view (no rows released to label).
    val decision: Decision? = null,
    val maskedColumns: List<String> = emptyList(),
    // A FAILED run's target-DB error — raw or redacted per this viewer (failedDiagnosticForViewer).
    val errorDetail: String? = null,
    /** Row count the viewer's own result cap cut this release to; null when every stored row was released. */
    val truncatedAt: Int? = null,
    // The EXECUTION's cap, not this view's, ended the stored rows. Independent of [truncatedAt]: a view can
    // narrow an already-capped result further, and either alone means the viewer is seeing a prefix.
    val truncatedByCap: Boolean = false,
    /** The next page's offset when this view is one page of the release; null on the last page or unpaged. */
    val nextOffset: Int? = null,
)

/** Submit acknowledgement. Completion is observed by polling the task detail/result endpoints. */
@Serializable data class ExecuteApprovalResponse(val decision: String)

// ---- APPROVAL execute-under-R + live view re-decision (approval-workflow.md) --------------------------
//
// Execute-under-R runs on the proxy via RunExecService.run(assumeRoles = {R}) — R alone — at the
// workflow-executor channel. The stored rows are R's execution-enforced output: masked per {R} in the
// executor's context, encrypted before persistence. GET /result then re-decides at workflow-viewer under
// exactly {R} and applies the viewer-context masks, narrowing further where that context requires — never
// revealing more than the stored bytes. A row with an empty {R} has no role to re-decide under and fails
// closed — there is no raw-snapshot side channel.

// ---- Pure policy helpers ------------------------------------------------------------------

enum class SourceValidation { OK, NOT_FOUND, NOT_DENY }

/** Fail-closed create-source check. Not-owned → NOT_FOUND (don't leak others' decision ids). */
fun validateApprovalSource(decision: AuditEvent?, requestingPrincipal: String): SourceValidation =
    when {
        decision == null || decision.principal != requestingPrincipal -> SourceValidation.NOT_FOUND
        decision.decision != Decision.DENY -> SourceValidation.NOT_DENY
        else -> SourceValidation.OK
    }

internal sealed class ResultViewDecision {
    /** [maskedColumns] are the columns this VIEW masked — the viewer's context can narrow an execution's
     *  ALLOW to a MASK, so the released rows are labelled by what happened to them, not by what was stored. */
    data class Allowed(
        val columns: List<String>,
        val rows: List<List<String?>>,
        val maskedColumns: List<String> = emptyList(),
        /** Row count the viewer's own result cap cut the release to; null when every stored row is released. */
        val truncatedAt: Int? = null,
    ) : ResultViewDecision()
    data class Denied(val reason: String) : ResultViewDecision()
}

/**
 * Which form of a FAILED run's stored [diagnostic] this viewer may see: the raw message when their view
 * decision relays raw, the redacted one when it sanitizes, neither on a deny or a missing re-decision.
 */
internal fun failedDiagnosticForViewer(ctx: DecisionContext?, diagnostic: RunError?): String? = when {
    ctx == null || diagnostic == null || ctx.action == EnfAction.DENY -> null
    ctx.sanitizeDiagnostics -> diagnostic.message
    else -> diagnostic.rawMessage
}

/**
 * The GET /result view's re-decision: decide [childSql] as [viewer] under its live execute-as roles {R}.
 * Null if the SQL, datasource, or roles are gone (a soft-deleted role grants nothing).
 */
internal fun viewerDecision(
    viewer: String,
    req: AccessRequest,
    childSql: String?,
    callerContext: AuthzContext,
    datasourceStore: DatasourceStore,
    policyStore: PolicyStore,
    accessStore: AccessStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    systemClassification: SystemClassificationService?,
    channel: Channel,
    auditStore: AuditStore? = null,
): DecisionContext? {
    val sql = childSql ?: return null
    val ds = req.datasourceId?.let(datasourceStore::get) ?: return null
    val roles = policyStore.liveRoleNames(req.executeAs).ifEmpty { return null }
    return decideQuery(
        principal = viewer, ds = ds, sql = sql, channel = channel,
        catalog = datasourceStore.catalog(ds.id), policyStore = policyStore, accessStore = accessStore,
        userGroupStore = userGroupStore, roleResolver = roleResolver, authz = authz, auditStore = auditStore,
        providedRoles = roles, context = callerContext, systemClassification = systemClassification,
    )
}

/**
 * Re-apply R's masks to a stored result's [decrypted] bytes under the viewer's live [ctx]. Every
 * uncertainty denies: policy DENY, passthrough mismatch, fingerprint drift, an unbound mask.
 */
internal fun decideResultView(ctx: DecisionContext, decrypted: DecryptedResult): ResultViewDecision {
    // The viewer's own caps bound the release exactly as they bound a wire relay: the longest prefix within
    // rows and bytes is released, the rest stays encrypted.
    fun allowed(columns: List<String>, rows: List<List<String?>>, maskedColumns: List<String> = emptyList()):
        ResultViewDecision.Allowed {
        var released = rows.size
        ctx.maxRows?.let { released = minOf(released.toLong(), it).toInt() }
        ctx.maxBytes?.let { maxBytes ->
            var bytes = 0L
            for ((index, row) in rows.withIndex()) {
                if (index >= released) break
                bytes += resultVolume(listOf(row)).second
                if (bytes > maxBytes) {
                    released = index
                    break
                }
            }
        }
        return if (released < rows.size) {
            ResultViewDecision.Allowed(columns, rows.take(released), maskedColumns, truncatedAt = released)
        } else {
            ResultViewDecision.Allowed(columns, rows, maskedColumns)
        }
    }
    if (ctx.action == EnfAction.DENY) {
        return ResultViewDecision.Denied(ctx.denyReason ?: ctx.detail ?: "view decision denied")
    }
    // A stored result must never be released through the passthrough relay unless it was itself frozen as a
    // grant-less passthrough. If its SQL became unanalyzable since execution (a dropped table/column →
    // exception.unanalyzable), the live re-decision turns passthrough while the stored bytes still hold the
    // columnar, possibly masked, result. A legacy result (null fingerprint) is likewise unverifiable. Both
    // fail closed — only a present, grant-less fingerprint takes the raw-release path below.
    val storedFingerprint = decrypted.resultFingerprint
    if (ctx.passthrough && (storedFingerprint == null || storedFingerprint.grantsList.isNotEmpty())) {
        return ResultViewDecision.Denied("stored result no longer matches the live query decision")
    }
    if (ctx.passthrough) {
        // The re-decision already ran full Cedar authorization under {R} in the viewer's live context and
        // returned non-DENY (checked above). A passthrough carries no column-masking model — there is nothing
        // to narrow for the viewer — so "authorized to run" IS "authorized to see the raw output": that is the
        // definition of the exception.unanalyzable relay and of an authorized SHOW/DESCRIBE. Release the stored
        // bytes; a viewer whose context should forbid it got DENY above. Context-sensitivity of unmasked
        // relays / critical-utility reads belongs in their Cedar grants, not a hardcoded view gate.
        //
        // Every decideQuery passthrough site constructs ALLOW with no masks (a passthrough has no column
        // model to mask). Assert it here so a future passthrough that ever carried a MASK verdict fails
        // CLOSED rather than releasing its stored bytes unmasked.
        if (ctx.action != EnfAction.ALLOW || ctx.masks.isNotEmpty()) {
            return ResultViewDecision.Denied("passthrough result carries a masking verdict")
        }
        if (decrypted.rows.any { it.size != decrypted.columns.size }) {
            return ResultViewDecision.Denied("stored result row width does not match its columns")
        }
        return allowed(decrypted.columns, decrypted.rows)
    }
    // Apply the re-decided masks only when the frozen requirements still match the live re-decision — then
    // each masked column keeps the same output ordinals, so ctx.masks bind to the same stored columns they
    // did at execution ([resultFingerprint]). Any drift (a reorder, a namespace change, a legacy result with
    // no frozen fingerprint) denies fail-closed. This does NOT freeze the mask FUNCTIONS or Cedar verdicts:
    // masking is re-decided under {R} at view, so a policy that liberalizes between execute and view can
    // still narrow (or widen) the masks — matched requirements only prove the ordinal binding is sound.
    if (storedFingerprint == null || storedFingerprint != fingerprintOf(ctx.resultFingerprint)) {
        return ResultViewDecision.Denied("stored result no longer matches the live query decision")
    }
    // A plan-only EXPLAIN's stored bytes are the target DB's plan output, not the inner query's columns
    // (the analyzer emits no output_columns for it), so the projection-width check below can never hold.
    // Release it only on a clean ALLOW: a protected predicate column (whose selectivity the plan leaks)
    // re-decides DENY via its DENY_STATEMENT grant and never reaches here.
    val planOnlyExplain = ctx.statementKind == StatementKind.STATEMENT_KIND_EXPLAIN &&
        ctx.action == EnfAction.ALLOW && ctx.masks.isEmpty() && ctx.outputColumns.isEmpty()
    if (planOnlyExplain) {
        if (decrypted.rows.any { it.size != decrypted.columns.size }) {
            return ResultViewDecision.Denied("stored result row width does not match its columns")
        }
        return allowed(decrypted.columns, decrypted.rows)
    }
    // The live projection must be the same width as the stored bytes a mask ordinal indexes into; this also
    // denies a plan-shaped result rather than releasing it raw when the EXPLAIN release above did not take it.
    if (ctx.outputColumns.size != decrypted.columns.size) {
        return ResultViewDecision.Denied("stored result columns no longer match the live query decision")
    }
    if (decrypted.rows.any { it.size != decrypted.columns.size }) {
        return ResultViewDecision.Denied("stored result row width does not match its columns")
    }
    val binding = bindMasks(ctx.masks, decrypted.columns.size)
    if (!binding.allBound) {
        return ResultViewDecision.Denied("required view mask could not be bound")
    }
    val rows = decrypted.rows.map { row ->
        row.mapIndexed { index, value ->
            // An index with NO bound mask keeps its value; an index WITH a mask takes Masking.apply's
            // result — which is null for a full redaction (kind NULL). Do NOT collapse the two with
            // `?: value`: that would fall a redacted-to-null cell back to the cleartext value.
            val kind = binding.byIndex[index]
            if (kind == null) value else Masking.apply(value, kind)
        }
    }
    // Named from the BOUND indices, not from ctx.masks: binding is what actually rewrote a cell, so a mask
    // the decision asked for but could not bind can never be reported as applied. (An unbound one denies
    // above, so the two agree here — reading the binding keeps them agreeing if that ever changes.)
    val maskedColumns = binding.byIndex.keys.sorted().map { decrypted.columns[it] }
    return allowed(decrypted.columns, rows, maskedColumns)
}

/**
 * The shared auto-approve gate for a self-approved task on a server-attested channel. Editor and wire tasks
 * must clear BOTH lifecycle checks a human request+approve would: [AuthzAction.TASK_REQUEST] on the datasource
 * and [AuthzAction.TASK_APPROVE] against a self-requested Request under the trusted [channel]. Both must
 * ALLOW; either Deny fails the task closed. [ownRoles] is the caller's server-resolved request-side role
 * snapshot; the approve side re-resolves its own snapshot inside [authorizeWithContext]. Returns true only
 * when the task may be born APPROVED.
 */
internal fun autoApproveTask(
    principal: String,
    ownRoles: Set<String>,
    ds: Datasource,
    rawCtx: AuthzContext,
    authz: Authz,
    channel: Channel,
): Boolean {
    val taskCtx = rawCtx.copy(channel = channel.contextValue)
    val tags = authz.resolveContextTags(principal, ownRoles, ds.name, taskCtx, ds.tags)
    val mayRequest = authz.authorizeDatasourceAction(
        principal, ownRoles, AuthzAction.TASK_REQUEST, ds.name, taskCtx.copy(tags = tags), ds.tags,
    )
    if (mayRequest is AuthzDecision.Deny) return false
    val mayApprove = authz.authorizeWithContext(
        principal,
        AuthzAction.TASK_APPROVE,
        AuthzResource.ApprovalRequest(requester = principal, approver = principal, datasourceName = ds.name),
        taskCtx,
        ds.name,
        ds.tags,
    )
    return mayApprove !is AuthzDecision.Deny
}

/** Fail-closed proactive-compose input check. Returns the missing/blank field name, or null when valid. */
fun validateProactiveCompose(datasourceId: Long?, sql: String?, title: String?, reason: String?): String? = when {
    datasourceId == null -> "datasourceId"
    sql.isNullOrBlank() -> "sql"
    title.isNullOrBlank() -> "title"
    reason.isNullOrBlank() -> "reason"
    else -> null
}

// ---- Routes -------------------------------------------------------------------------------

fun Route.approvalRoutes(
    config: Config,
    accessStore: AccessStore,
    auditStore: AuditStore,
    datasourceStore: DatasourceStore,
    policyStore: PolicyStore,
    userGroupStore: UserGroupStore,
    queryResultStore: QueryResultStore?, // null when PM_RESULT_KEY is unset → execute-under-R refused
    roleResolver: RoleResolver,
    authz: Authz,
    // Approval execution runs on the proxy (the control-plane never dials the target). Both the
    // execute-under-R and no-R approver-exec paths go through this — never a CP-side JDBC dial.
    runExecService: RunExecService,
    appScope: CoroutineScope = CoroutineScope(Dispatchers.Unconfined),
    // Threaded into view-as-R decisions so a query touching system tables classifies consistently.
    // Null keeps system schemas deny-by-default.
    systemClassification: SystemClassificationService? = null,
    // Pushes a task's terminal transition to the parties' (requester + approver) SSE streams so a watching
    // approval tab updates without waiting for its next poll (null in Config-free tests → publish no-ops).
    taskCompletionHub: TaskCompletionHub? = null,
    // Queues out-of-band notifications (docs/notifications.md). Null = the layer is not configured and the
    // workflow behaves exactly as before.
    notifications: NotificationService? = null,
    service: ApprovalService = ApprovalService(
        config, accessStore, auditStore, datasourceStore, policyStore, userGroupStore, queryResultStore, roleResolver,
        authz, runExecService, appScope, systemClassification, taskCompletionHub, notifications,
    ),
) {
    post("/api/approvals") {
        val principal = call.requireApi() ?: return@post
        val input = call.receive<CreateApprovalInput>()
        try {
            call.respond(
                HttpStatusCode.Created,
                service.create(principal, call.httpRequesterIp(config), call.auditActor(config), input),
            )
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/approvals/discover-roles") {
        val principal = call.requireApi() ?: return@post
        val input = call.receive<DiscoverRolesRequest>()
        try {
            call.respond(service.discoverRoles(principal, call.httpRequesterIp(config), input.datasourceId, input.sql))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    get("/api/approvals") {
        val principal = call.requireApi() ?: return@get
        call.respond(service.listOwn(principal, call.request.queryParameters["status"]))
    }

    get("/api/approvals/inbox") {
        val principal = call.requireApi() ?: return@get
        call.respond(service.inbox(principal, call.httpRequesterIp(config)))
    }

    get("/api/approvals/{id}") {
        val principal = call.requireApi() ?: return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(service.detail(principal, call.httpRequesterIp(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/approvals/{id}/approve") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(service.approve(principal, call.httpRequesterIp(config), call.auditActor(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/approvals/{id}/reject") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val body = call.receive<RejectInput>()
        try {
            call.respond(service.reject(principal, call.httpRequesterIp(config), call.auditActor(config), id, body.reason))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/approvals/{id}/cancel") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(service.cancel(principal, call.httpRequesterIp(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/approvals/{id}/execute") {
        val executor = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(HttpStatusCode.Accepted, service.execute(executor, call.httpRequesterIp(config), id).first)
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    // ?statement=<ordinal>; absent takes the active one. A malformed value is rejected, never silently
    // served from a different statement.
    get("/api/approvals/{id}/result") {
        val principal = call.requireApi() ?: return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val ordinalParam = call.request.queryParameters["statement"]
        val ordinal = if (ordinalParam == null) null else {
            ordinalParam.toIntOrNull()?.takeIf { it >= 0 }
                ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        }
        try {
            call.respond(service.result(principal, call.httpRequesterIp(config), id, ordinal))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}

/**
 * Run an approved task under its execute-as role set, then terminalize it.
 *
 * Shared by the HTTP `/execute` route and the Slack approve-and-run adapter, so a decision reached from
 * either surface runs through ONE lifecycle rather than two copies of it. The caller has already claimed the
 * task (APPROVED → EXECUTING with a RUNNING child, in one transaction), so this owns only the run and the
 * terminal transition.
 *
 * The run is initiated by and attributed to [executor] — the ephemeral token, the connection binding, and the
 * execution audit all carry their identity. Execute-as R is enforced separately via [executeAs]: the role the
 * decision runs AS, never who runs it.
 */
internal suspend fun runApprovedTask(
    id: Long,
    executor: String,
    ds: Datasource,
    executeAs: Set<String>,
    requesterIp: String?,
    requesterPrincipal: String,
    req: AccessRequest,
    config: Config,
    accessStore: AccessStore,
    store: QueryResultStore,
    auditStore: AuditStore,
    runExecService: RunExecService,
    taskCompletionHub: TaskCompletionHub?,
    notifications: NotificationService?,
    log: org.slf4j.Logger,
) {
    val dsName = req.datasourceId?.let { req.datasourceName } ?: "?"
    fun lifecycleRecord(event: String, channel: Channel) = AuditEvent(
        principal = executor, datasource = dsName,
        statement = "approval #$id $event",
        decision = Decision.ALLOW, detail = "APPROVER_EXEC $event",
        channel = channel.contextValue, kind = "approval_lifecycle",
    )

    // Statement 0 is already RUNNING (claimAndStartRun); the rest start as the batch reaches them.
    val statements = store.statements(id)
    var batchFailure: String? = null
    // Stamped onto the child that failed, so a poller tells a denial from an error and can raise a request.
    var denyReason: String? = null
    var denyDecisionId: Long? = null
    var diagnostic: RunError? = null
    val failureCode = try {
        runExecService.runBatch(
            principal = executor,
            ds = ds,
            statementCount = statements.size,
            maxRows = 5000,
            approverExec = true,
            assumeRoles = executeAs,
            requesterIp = requesterIp,
            taskId = id,
            preflight = { store.meta(id)?.status == "RUNNING" },
            exchangeTimeoutMs = config.queryExchangeTimeoutMs,
            statementAt = { ordinal ->
                if (ordinal == 0) statements[0].sql else store.startNextRun(id, executor)?.sql
            },
            onStatement = { ordinal, response ->
                val last = ordinal == statements.lastIndex
                if (response.decision == EnfAction.DENY) {
                    // failRun SKIPs the rest in the same transaction.
                    denyReason = response.denyReason
                    denyDecisionId = response.decisionId
                    batchFailure = "approval.execute_denied"
                    false
                } else {
                    val result = DecryptedResult(response.columns, response.rows, response.rowsAffected, response.resultFingerprint, response.truncatedByCap)
                    // The parent flips to EXECUTED only on the LAST statement, so a crash mid-batch cannot
                    // leave a task EXECUTED with statements unrun.
                    val completed = store.completeRun(id, result, QueryResultStore.RESULT_RETENTION_SEC, response.decisionId) { conn, _ ->
                        if (last && !accessStore.markExecuted(id, conn)) {
                            throw IllegalStateException("task $id left EXECUTING before completion")
                        }
                        auditStore.insert(conn, lifecycleRecord("result-executed", Channel.WORKFLOW_EXECUTOR))
                    }
                    if (completed == null) {
                        batchFailure = "approval.query_failed"
                        false
                    } else {
                        log.info(
                            "query approval executed request={} statement={} requester={} executor={} rows={}",
                            id, ordinal, requesterPrincipal, executor, result.rows.size,
                        )
                        true
                    }
                }
            },
        )
        batchFailure
    } catch (_: RunCanceledBeforeStartException) {
        null
    } catch (_: NoProxyAttachedException) {
        "query.no_proxy_attached"
    } catch (_: ProxyRunTimeoutException) {
        "query.proxy_timeout"
    } catch (e: TargetDbRunException) {
        // Must survive the batch walk rather than collapsing into a bare failure code.
        diagnostic = e.toDiagnostic()
        "approval.query_failed"
    } catch (_: ProxyRunException) {
        "approval.query_failed"
    } catch (t: Throwable) {
        log.error("query approval execution failed request=$id", t)
        "approval.query_failed"
    }
    if (failureCode != null) {
        // Child FAILED and parent FAILED commit in ONE transaction (mirrors the success path's single-commit
        // EXECUTED/DONE): a crash can never leave a FAILED child under a still-EXECUTING task, nor the
        // inverse — the split that boot reconcile would otherwise have to repair.
        runCatching {
            store.failRun(id, failureCode, denyReason, denyDecisionId, diagnostic) { conn, _ ->
                accessStore.markFailed(id, conn)
            }
        }
            .onFailure { log.error("task failure transition failed request=$id", it) }
    }
    // Push the ACTUAL terminal state (EXECUTED / FAILED / or CANCELLED if a cancel raced) to both parties'
    // SSE streams so a watching tab updates at once; best-effort, the tab also polls.
    accessStore.getRequest(id)?.let { finished ->
        taskCompletionHub?.publish(listOf(requesterPrincipal, executor), TaskEvent(id, finished.status))
        // Announced after the run settles, so it is not part of the execution transaction; the outbox row is
        // still written atomically inside enqueueTerminal.
        notifications?.enqueueTerminal(finished)
    }
}
