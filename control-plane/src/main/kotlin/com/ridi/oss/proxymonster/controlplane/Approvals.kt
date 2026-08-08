package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.probe.Masking
import com.ridi.oss.proxymonster.probe.bindMasks
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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
private val AccessRequest.isWorkflowApproval: Boolean
    get() = kind == "QUERY" && creatorKind == "WORKFLOW"

/**
 * A role the requester could ask to run Q under (approval-workflow.md, "role discovery").
 *
 * [decision] and [maskedColumns] are what Q returns under this role WHEN EXECUTED BY THE WORKFLOW — the
 * `workflow-executor` channel an approved query actually runs on, which is the only outcome the request
 * can deliver. A role is listed whenever that outcome is not a denial, rather than only when it beats the
 * requester's own roles: "runs, but still masked" is an answer they need in order to stop looking.
 *
 * [unmasksColumns] is the pre-existing summary: columns this role unmasks relative to the baseline.
 */
@Serializable
data class RoleOption(
    val roleId: Long,
    val roleName: String,
    val unmasksColumns: List<String>,
    val decision: Decision = Decision.ALLOW,
    val maskedColumns: List<String> = emptyList(),
)

@Serializable
data class DiscoverRolesResponse(val baselineAllowed: Boolean, val options: List<RoleOption>)

/**
 * APPROVAL role discovery (approval-workflow.md — "the requester picks R"): offer every role R the requester
 * does not already hold under which Q runs from SOME network posture, each with its per-posture outcome. R is
 * the elevation unit the request carries (`access_request.role_id`); the workflow adds lifecycle, not
 * authorization.
 *
 * PREVIEW PARITY: each candidate is previewed ALONE — `decide(setOf(role.name), …)`, never unioned with the
 * requester's own roles — because execute-under-R runs with `assumeRoles = setOf(R)` alone. A unioned preview
 * could ALLOW here and DENY at execute, offering a role the requester cannot actually run. Only the baseline
 * and the already-held filter are keyed on the requester's own roles.
 *
 * RESIDUAL GAP: the approver's own identity and address are not known at discovery time, so a policy
 * conditioned on them can still make an offered R deny at execute. The channel and network axes are modeled
 * (candidates preview on the execution channel, across both postures); the approver-identity axis is not.
 *
 * [decide] runs the real decision path and MUST be side-effect-free — discovery is a dry run, no audit write.
 */
fun discoverRoles(
    ownRoles: Set<String>,
    allRoles: List<Role>,
    decide: (roles: Set<String>, channel: Channel) -> DecisionContext,
): DiscoverRolesResponse {
    // The baseline answers "what do I get right now", so it decides where the requester is: the editor
    // channel, under their own roles.
    val baseline = decide(ownRoles, Channel.EDITOR)
    val baselineMasked = baseline.masks.map { it.column }.toSet()
    val baselineDenied = baseline.action == EnfAction.DENY

    val options = allRoles.filterNot { it.name in ownRoles }.mapNotNull { role ->
        val underR = decide(setOf(role.name), Channel.WORKFLOW_EXECUTOR)
        if (underR.action == EnfAction.DENY) return@mapNotNull null
        val masked = underR.masks.map { it.column }.distinct().sorted()
        RoleOption(
            roleId = role.id,
            roleName = role.name,
            unmasksColumns = (baselineMasked - masked.toSet()).sorted(),
            decision = if (masked.isEmpty()) Decision.ALLOW else Decision.MASK,
            maskedColumns = masked,
        )
    }
    return DiscoverRolesResponse(baselineAllowed = !baselineDenied, options = options)
}

@Serializable data class ApprovalDetail(
    val request: AccessRequest,
    val canDecide: Boolean,
    // The latest child execution metadata. Rows remain behind the result endpoint.
    val result: QueryResultMeta? = null,
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
    val decision: Decision = Decision.ALLOW,
    val maskedColumns: List<String> = emptyList(),
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
    ) : ResultViewDecision()
    data class Denied(val reason: String) : ResultViewDecision()
}

/**
 * Re-evaluate a stored execute-under-R result for the actual viewer in their live HTTP context. The store
 * holds R's execution-enforced output; this function re-applies R's masks for the viewer's current context,
 * narrowing further where it requires. Every uncertainty is a deny: no role/SQL, policy DENY, passthrough,
 * output-column drift, or an unbound mask.
 *
 * [childSql] is the statement of the SAME result child whose bytes are in [decrypted] (from
 * [ResultAccess.sql]) — NOT the task's first-child `req.sql`, which can diverge once a task holds plural
 * children. Re-deciding the released child's own statement keeps the masking verdict bound to those bytes.
 */
internal fun decideResultView(
    viewer: String,
    req: AccessRequest,
    childSql: String?,
    ds: Datasource,
    decrypted: DecryptedResult,
    callerContext: AuthzContext,
    datasourceStore: DatasourceStore,
    policyStore: PolicyStore,
    accessStore: AccessStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    systemClassification: SystemClassificationService?,
    // The decide-channel the released bytes are re-masked under. WORKFLOW_VIEWER for an approval view; the
    // editor result view passes EDITOR so its re-decision matches how runOnSession enforced the run (both on
    // the editor channel, under the same own-roles set), rather than a workflow viewer's context.
    channel: Channel = Channel.WORKFLOW_VIEWER,
): ResultViewDecision {
    val sql = childSql ?: return ResultViewDecision.Denied("saved result child has no SQL")
    // Drop any execute-as role soft-deleted since the snapshot was frozen: it must grant nothing, so a
    // stored result never re-decides under a role that no longer exists (an empty result denies below).
    val roles = policyStore.liveRoleNames(req.executeAs)
    if (roles.isEmpty()) return ResultViewDecision.Denied("approval request has no live execute-as roles")
    val ctx = decideQuery(
        principal = viewer,
        ds = ds,
        sql = sql,
        channel = channel,
        catalog = datasourceStore.catalog(ds.id),
        policyStore = policyStore,
        accessStore = accessStore,
        userGroupStore = userGroupStore,
        roleResolver = roleResolver,
        authz = authz,
        providedRoles = roles,
        context = callerContext,
        systemClassification = systemClassification,
    )
    if (ctx.action == EnfAction.DENY) {
        return ResultViewDecision.Denied(ctx.denyReason ?: ctx.detail ?: "view decision denied")
    }
    if (ctx.passthrough) {
        // The re-decision already ran full Cedar authorization under {R} in the viewer's live context and
        // returned non-DENY (checked above). A passthrough carries no column-masking model — there is nothing
        // to narrow for the viewer — so "authorized to run" IS "authorized to see the raw output": that is the
        // definition of the sql.unanalyzable relay and of an authorized SHOW/DESCRIBE. Release the stored
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
        return ResultViewDecision.Allowed(decrypted.columns, decrypted.rows)
    }
    if (
        ctx.outputColumns.size != decrypted.columns.size ||
        ctx.outputColumns.zip(decrypted.columns).any { (decided, stored) -> !decided.equals(stored, ignoreCase = true) }
    ) {
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
    return ResultViewDecision.Allowed(decrypted.columns, rows, maskedColumns)
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
) {
    // Query-approval DECISIONS (approve/reject) record a kind="admin" management event; the result
    // lifecycle (execute/cancel/view) uses e3Record's separate approval_lifecycle path.
    val recorder = ManagementAuditRecorder(auditStore)

    // Whether the caller may open a query-approval request against this datasource (task.request on the
    // Datasource). The shipped global permit keeps this open by default; an operator can forbid it per
    // datasource. authDebug bypasses.
    fun mayRequest(call: ApplicationCall, ds: Datasource): Boolean {
        if (config.authDebug) return true
        val principal = call.userSession()?.principal ?: "debug-user"
        val roles = roleResolver.resolve(principal)
        val raw = call.httpAuthzContext(config)
        val tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)
        val decision = authz.authorizeDatasourceAction(
            principal, roles, AuthzAction.TASK_REQUEST, ds.name, raw.copy(tags = tags), ds.tags,
        )
        return decision !is AuthzDecision.Deny
    }

    // The single authorization for a task action on a query-approval request: Cedar decides
    // task.approve (approve/reject/execute under R) or task.read (metadata) against the Request —
    // scoped to its role/datasource, with
    // requester != approver enforced by the shipped no-self-approval forbid. Approver eligibility is a
    // Cedar policy, never the datasource's approver GROUP. authDebug bypasses, matching every route.
    //
    // The console is a real surface, so it names itself: WORKFLOW_VIEWER, the same channel a result view
    // runs on. Deciding and viewing are both the unelevated human side of a task and are scoped together.
    // It must never be `editor` or `wire` — those two carry [system:task-editor-self-approve] /
    // [system:task-wire-self-approve], which permit self-approval because a machine task runs under the
    // caller's OWN roles. A human approval elevates to R, so it stays under the no-self-approval forbid.
    fun mayDecide(call: ApplicationCall, action: AuthzAction, req: AccessRequest): Boolean {
        if (config.authDebug) return true
        val decision = authz.authorizeWithContext(
            call.userSession()?.principal ?: "debug-user",
            action,
            AuthzResource.ApprovalRequest(
                requester = req.principal, approver = req.decidedBy, executedBy = req.executedBy,
                datasourceName = req.datasourceName, roleName = req.roleName,
            ),
            call.httpAuthzContext(config, Channel.WORKFLOW_VIEWER),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        return decision !is AuthzDecision.Deny
    }

    // Result rows require Cedar authority to assume the task's R. No authDebug bypass: this is data
    // confidentiality, enforced in development too. Same channel as [mayDecide] and as the per-column
    // re-decision the released rows go through, so one policy scopes the whole console surface.
    fun mayReadResult(call: ApplicationCall, req: AccessRequest): Boolean {
        val decision = authz.authorizeWithContext(
            call.userSession()?.principal ?: "debug-user",
            AuthzAction.TASK_ASSUME,
            AuthzResource.ApprovalRequest(
                requester = req.principal, approver = req.decidedBy, executedBy = req.executedBy,
                datasourceName = req.datasourceName, roleName = req.roleName,
            ),
            call.httpAuthzContext(config, Channel.WORKFLOW_VIEWER),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        return decision !is AuthzDecision.Deny
    }

    fun trimmedTitle(input: String?): String? = input?.trim()?.takeIf { it.isNotEmpty() }

    // Durable audit record for a task result event (execute/view), recorded in audit_decision. Execution
    // writes it in the same transaction as DONE; a view writes it before responding. audit_decision is exposed via the
    // shared /api/decisions feed, so this record deliberately carries NO result-derived data (no
    // row_count, no requester name) — only the event, the actor (record.principal = whoever acted:
    // the executor on execute, the requester/approver/assumer on view), and the approval id. The
    // requester↔approval linkage is reconstructable from access_request by an authorized auditor via the
    // id, but is not broadcast inline (result-access confidentiality).
    fun e3Record(principal: String, req: AccessRequest, event: String, channel: Channel? = null): AuditEvent {
        // The retained name from the (unfiltered) request join, so a datasource soft-deleted after the task
        // ran still names itself in the audit trail rather than degrading to "?".
        val dsName = req.datasourceName ?: "?"
        return AuditEvent(
            principal = principal, datasource = dsName,
            statement = "approval #${req.id} $event",
            decision = Decision.ALLOW, detail = "APPROVER_EXEC $event",
            // Stamp the channel on execution and live-view decisions.
            channel = channel?.contextValue,
            kind = "approval_lifecycle",
        )
    }

    post("/api/approvals") {
        if (!call.requireApi(config)) return@post
        val principal = call.userSession()?.principal ?: "debug-user"
        val input = call.receive<CreateApprovalInput>()
        if (input.reason.isBlank()) return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "reason")))

        val hasSource = input.sourceDecisionId != null
        val hasProactive = input.datasourceId != null || input.sql != null
        if (hasSource && hasProactive) {
            return@post call.respond(HttpStatusCode.BadRequest, ApiError("approval.exactly_one_source_required"))
        }
        if (!hasSource && !hasProactive) {
            return@post call.respond(HttpStatusCode.BadRequest, ApiError("approval.exactly_one_source_required"))
        }
        // A query approval always runs under an elevation role R (execute-under-R); the requester picks it via
        // role discovery. A NEW request must carry R — a query no role can satisfy has nothing to run under R,
        // and there is no requester-run mode. The `input.roleId == null` guard below is checked AFTER each
        // branch's field validation so an incomplete form still names its missing field first. (A row with
        // no R has no {R} to re-decide under, so /result fails it closed.)

        if (hasSource) {
            val sourceDecisionId = input.sourceDecisionId!!
            val decision = auditStore.get(sourceDecisionId)
            when (validateApprovalSource(decision, principal)) {
                SourceValidation.OK -> Unit
                SourceValidation.NOT_FOUND -> return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "decision")))
                SourceValidation.NOT_DENY -> return@post call.respond(HttpStatusCode.BadRequest, ApiError("approval.only_denied_queries"))
            }
            val source = decision!!

            if (accessStore.pendingQueryRequestExists(sourceDecisionId)) {
                return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.pending_request_exists"))
            }

            val ds = datasourceStore.list().firstOrNull { it.name == source.datasource }
                ?: return@post call.respond(HttpStatusCode.Conflict, ApiError("common.not_found", mapOf("resource" to "datasource")))
            val datasourceId = ds.id
            if (!mayRequest(call, ds)) {
                return@post call.respond(HttpStatusCode.Forbidden, ApiError("common.forbidden"))
            }
            if (input.roleId == null) return@post call.respond(HttpStatusCode.BadRequest, ApiError("approval.role_required"))

            val request = try {
                accessStore.createQueryRequest(
                    principal = principal,
                    datasourceId = datasourceId,
                    sql = source.statement,
                    denyReason = source.detail,
                    sourceDecisionId = sourceDecisionId,
                    reason = input.reason.trim(),
                    title = trimmedTitle(input.title),
                    evaluatedDecision = "DENY",
                    roleId = input.roleId,
                    requestedDurationSec = input.requestedDurationSec,
                    actor = call.auditActor(config),
                    recorder = recorder,
                    onCreated = { c, taskId -> notifications?.emitRequested(c, taskId, principal, ds) },
                )
            } catch (_: DuplicatePendingQueryRequestException) {
                return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.pending_request_exists"))
            }
            notifications?.wake()
            call.respond(HttpStatusCode.Created, CreateApprovalResponse(request, wouldAllow = false))
            return@post
        }

        validateProactiveCompose(input.datasourceId, input.sql, input.title, input.reason)?.let {
            return@post call.fieldRequired(it)
        }
        val ds = datasourceStore.get(input.datasourceId!!)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        val sql = input.sql!!
        if (!mayRequest(call, ds)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("common.forbidden"))
        }
        if (input.roleId == null) return@post call.respond(HttpStatusCode.BadRequest, ApiError("approval.role_required"))

        // Server-side analysis only: nothing executes and no audit row is written at compose time.
        val decision = decideQuery(
            principal = principal,
            ds = ds,
            sql = sql,
            channel = Channel.EDITOR,
            catalog = datasourceStore.catalog(ds.id),
            policyStore = policyStore,
            accessStore = accessStore,
            userGroupStore = userGroupStore,
            roleResolver = roleResolver,
            authz = authz,
            // This compose preview IS an HTTP request with a datasource in scope, so it carries the
            // server-attested requester_ip (decideQuery overlays the EDITOR channel + derives tags over it). A
            // preview that dropped it would report a DIFFERENT verdict than the real editor execution when a
            // policy conditions on requester_ip / a requester_ip-derived tag.
            context = call.httpAuthzContext(config),
            // Classify system tables + the dangerous-function gate here too, so the compose preview's verdict
            // matches what execution will do.
            systemClassification = systemClassification,
        )
        val request = accessStore.createQueryRequest(
            principal = principal,
            datasourceId = ds.id,
            sql = sql,
            denyReason = if (decision.action == EnfAction.DENY) (decision.denyReason ?: decision.detail) else null,
            sourceDecisionId = null,
            reason = input.reason.trim(),
            title = input.title!!.trim(),
            evaluatedDecision = decision.action.name,
            roleId = input.roleId,
            requestedDurationSec = input.requestedDurationSec,
            actor = call.auditActor(config),
            recorder = recorder,
            onCreated = { c, taskId -> notifications?.emitRequested(c, taskId, principal, ds) },
        )
        notifications?.wake()
        call.respond(HttpStatusCode.Created, CreateApprovalResponse(request, wouldAllow = decision.action == EnfAction.ALLOW))
    }

    // APPROVAL role discovery (approval-workflow.md — "the requester picks R"): evaluate Q under each
    // candidate role and offer the ones that return MORE than the requester's own roles. A dry-run — no
    // audit row is written.
    post("/api/approvals/discover-roles") {
        if (!call.requireApi(config)) return@post
        val principal = call.userSession()?.principal ?: "debug-user"
        val input = call.receive<DiscoverRolesRequest>()
        val ds = datasourceStore.get(input.datasourceId)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        val ownRoles = roleResolver.resolve(principal)
        // Resolve requester_ip ONCE here (the closure runs decideQuery per candidate role and posture).
        val discoverContext = call.httpAuthzContext(config)
        // Candidates preview on WORKFLOW_EXECUTOR, the channel an approved query actually runs on. A grant
        // scoped to that channel — the shipped -259 PII unmask — is invisible from any other, so previewing
        // candidates elsewhere hides roles that would in fact work.
        val response = discoverRoles(ownRoles, policyStore.listRoles()) { roles, channel ->
            decideQuery(
                principal = principal, ds = ds, sql = input.sql, channel = channel,
                catalog = datasourceStore.catalog(ds.id), policyStore = policyStore, accessStore = accessStore,
                userGroupStore = userGroupStore, roleResolver = roleResolver, authz = authz,
                providedRoles = roles, context = discoverContext, systemClassification = systemClassification,
            )
        }
        call.respond(response)
    }

    get("/api/approvals") {
        if (!call.requireApi(config)) return@get
        val principal = call.userSession()?.principal ?: "debug-user"
        call.respond(accessStore.listQueryRequests(status = call.request.queryParameters["status"], principal = principal))
    }

    get("/api/approvals/inbox") {
        if (!call.requireApi(config)) return@get
        // Forward filter: every PENDING request the caller may approve (Cedar task.approve), not a
        // group-membership join. authDebug shows all.
        val requests = accessStore.listQueryRequests("PENDING", null).filter { mayDecide(call, AuthzAction.TASK_APPROVE, it) }
        call.respond(requests)
    }

    get("/api/approvals/{id}") {
        if (!call.requireApi(config)) return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val principal = call.userSession()?.principal ?: "debug-user"
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        val isApprover = mayDecide(call, AuthzAction.TASK_APPROVE, req)
        // Task metadata is gated by task.read. Saved rows are separate and remain behind task.assume.
        if (!mayDecide(call, AuthzAction.TASK_READ, req)) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        }
        // task.read is a metadata gate; result-derived data stays behind task.assume. A caller who cannot
        // assume R sees execution status only (status/executor/timestamps/error) — never the result's row
        // count or output-column shape, which are cardinality/existence oracles the assume gate must close.
        val visibleMeta = queryResultStore?.meta(id)?.let { meta ->
            if (mayReadResult(call, req)) meta else meta.copy(rowCount = null, columns = emptyList())
        }
        // Mirror /execute's gates: only the approver OF RECORD (decided_by) can run it, so a merely-eligible
        // approver who did not approve THIS task gets no Run affordance that would just 403.
        val canExecute = queryResultStore != null && isApprover && req.status == "APPROVED" && req.decidedBy == principal
        val canCancel = req.status == "EXECUTING" && mayDecide(call, AuthzAction.TASK_CANCEL, req)
        call.respond(
            ApprovalDetail(
                req,
                canDecide = req.status == "PENDING" && isApprover,
                result = visibleMeta,
                canExecute = canExecute,
                canCancel = canCancel,
            ),
        )
    }

    post("/api/approvals/{id}/approve") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val principal = call.userSession()?.principal ?: "debug-user"
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        if (req.status != "PENDING") return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_decided"))
        // Cedar owns the authorization: task.approve on this request, scoped to its role/datasource,
        // with requester != approver via the no-self-approval forbid.
        if (!mayDecide(call, AuthzAction.TASK_APPROVE, req)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))
        }
        // An approved QUERY request is executed under role R by an approver (execute-under-R); there is no
        // requester-side re-run mode. The proxy masks the result exactly as role R would see it.
        val updated = accessStore.decideQueryRequest(
            id, approved = true, rejectionReason = null, decidedBy = principal,
            actor = call.auditActor(config), recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_decided"))
        notifications?.wake()
        call.application.environment.log.info(
            "query approval approved request={} requester={} decider={} sourceDecisionId={}",
            id,
            req.principal,
            principal,
            req.sourceDecisionId,
        )
        call.respond(updated)
    }

    post("/api/approvals/{id}/reject") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val principal = call.userSession()?.principal ?: "debug-user"
        val body = call.receive<RejectInput>()
        if (body.reason.isBlank()) return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "reason")))
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        if (req.status != "PENDING") return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_decided"))
        // Cedar owns the authorization: reject is the SAME task.approve decision as approve, scoped to its
        // role/datasource with requester != approver via the no-self-approval forbid.
        if (!mayDecide(call, AuthzAction.TASK_APPROVE, req)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))
        }
        val updated = accessStore.decideQueryRequest(
            id, approved = false, rejectionReason = body.reason.trim(), decidedBy = principal,
            actor = call.auditActor(config), recorder = recorder,
            onDecided = { c, decided -> notifications?.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_decided"))
        notifications?.wake()
        call.application.environment.log.info(
            "query approval rejected request={} requester={} decider={} sourceDecisionId={}",
            id,
            req.principal,
            principal,
            req.sourceDecisionId,
        )
        call.respond(updated)
    }

    post("/api/approvals/{id}/cancel") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val principal = call.userSession()?.principal ?: "debug-user"
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) {
            return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        }
        if (!mayDecide(call, AuthzAction.TASK_CANCEL, req)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        when (req.status) {
            "EXECUTED", "FAILED", "CANCELLED" -> return@post call.respond(req)
            "DRAFT", "PENDING", "APPROVED", "REJECTED" ->
                return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
            "EXECUTING" -> Unit
            else -> return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
        }
        val store = queryResultStore
            ?: return@post call.respond(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))
        val cancelled = store.cancelRun(id) { conn, _ ->
            if (!accessStore.markCancelled(id, conn)) {
                throw IllegalStateException("task $id left EXECUTING before cancellation")
            }
            auditStore.insert(conn, e3Record(principal, req, "result-canceled", Channel.WORKFLOW_EXECUTOR))
        }
        if (cancelled != null) {
            runExecService.cancelActiveRun(id)
            // A cancel can win the CAS before the run coroutine unwinds — push CANCELLED now to both parties
            // so a watching tab reflects it at once (best-effort; the coroutine's terminal push + the poll cover it).
            taskCompletionHub?.publish(listOf(req.principal, req.decidedBy).filterNotNull(), TaskEvent(id, "CANCELLED"))
            accessStore.getRequest(id)?.let { notifications?.enqueueTerminal(it) }
        }
        val updated = accessStore.getRequest(id)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        call.respond(updated)
    }

    // ---- Execute under R ---------------------------------------------------------------

    post("/api/approvals/{id}/execute") {
        if (!call.requireApi(config)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val executor = call.userSession()?.principal ?: "debug-user"
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) {
            return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        }
        // Authorize (task.approve) BEFORE disclosing task state: a caller who cannot approve this task gets a
        // uniform 403 regardless of its status, so the 409 already_executed/not_approved distinctions below are
        // never a state oracle for a non-approver. The approver-of-record identity is still pinned further down.
        if (!mayDecide(call, AuthzAction.TASK_APPROVE, req)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))
        }
        if (req.status in setOf("EXECUTING", "EXECUTED", "FAILED", "CANCELLED")) {
            return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_executed"))
        }
        if (req.status != "APPROVED") {
            return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.not_approved"))
        }
        // The approver of record must be the one who executes. This pins executedBy = decided_by = the
        // approver, so the run's identity (run(principal = executor)) always falls inside the task.assume
        // permit (requester or approver) and the saved result stays readable by its parties — no need to
        // add executedBy to the permit. An eligible approver who did not approve THIS task cannot run it.
        // No authDebug bypass: this is an identity invariant, enforced in development too.
        if (req.decidedBy != executor) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.not_the_approver"))
        }
        val store = queryResultStore
            ?: return@post call.respond(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))
        val ds = req.datasourceId?.let(datasourceStore::get)
            ?: return@post call.respond(HttpStatusCode.Conflict, ApiError("common.not_found", mapOf("resource" to "datasource")))
        val sql = req.sql ?: return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.no_sql"))
        val requesterIp = call.httpRequesterIp(config)
        // Only LIVE execute-as roles: a role soft-deleted since approval grants nothing, so it drops out of
        // the run's ceiling here (and an all-deleted snapshot fails closed at the empty check below).
        val executeAs = policyStore.liveRoleNames(req.executeAs)
        // Fail closed on a task with no execute-as role set — there is no R to enforce the run under. Only
        // a row with no elevation role can be empty (every new request carries R), so this never rejects a
        // current request; without it the run would fall through to the proxy Decide under the requester's
        // own roles, silently reinterpreting the authorization. Mirrors the view path's empty-{R} deny.
        if (executeAs.isEmpty()) {
            return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.no_execute_role"))
        }

        // Claim (APPROVED→EXECUTING) and start the child (NULL→RUNNING) in ONE transaction: a cancel can
        // then never land in a gap where the parent is EXECUTING but no RUNNING child exists yet (which
        // would no-op the cancel and let the query run). Before the commit the task is still APPROVED
        // (cancel → not_cancelable); after it, EXECUTING with a RUNNING child a cancel can catch.
        if (store.claimAndStartRun(id, executor) { c -> accessStore.claimExecution(id, c) } == null) {
            return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_executed"))
        }

        appScope.launch {
            runApprovedTask(
                id = id, executor = executor, ds = ds, sql = sql, executeAs = executeAs,
                requesterIp = requesterIp, requesterPrincipal = req.principal, req = req,
                config = config, accessStore = accessStore, store = store, auditStore = auditStore,
                runExecService = runExecService, taskCompletionHub = taskCompletionHub,
                notifications = notifications, log = call.application.environment.log,
            )
        }
        call.respond(HttpStatusCode.Accepted, ExecuteApprovalResponse(decision = "EXECUTING"))
    }

    // The decrypted rows: task.assume gates the viewer, then the stored result is re-decided live under
    // exactly the task's execute-as role set in the viewer's workflow-viewer context. Every successful
    // view and live-decision denial is audited; a deactivated viewer is hidden and an expired result is Gone.
    get("/api/approvals/{id}/result") {
        if (!call.requireApi(config)) return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val principal = call.userSession()?.principal ?: "debug-user"
        val req = accessStore.getRequest(id)
        if (req == null || !req.isWorkflowApproval) return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        // Deprovisioning gate applies before result lookup. The live decideQuery path repeats this gate as
        // defense in depth. Fail-closed as NotFound — no result-existence oracle for a deprovisioned principal.
        if (userGroupStore.isDeactivated(principal)) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        }
        // One read captures the row's ciphertext + meta together; the payload is decrypted lazily on the
        // first read of access.decrypted below, which happens only AFTER authorization passes — an
        // unauthorized caller never triggers a decrypt. Reading both in one shot also keeps a concurrent
        // re-execute from swapping the row between the authz check and the decrypt (TOCTOU).
        val access = queryResultStore?.accessFor(id)
            ?: return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        val meta = access.meta
        if (!mayReadResult(call, req)) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "query approval request")))
        }
        if (meta.status != "DONE") {
            return@get call.respond(HttpStatusCode.Conflict, ApiError("approval.result_not_ready"))
        }
        val decrypted = access.decrypted
            ?: return@get call.respond(HttpStatusCode.Gone, ApiError("approval.result_expired"))

        // No raw side-channel: EVERY view re-decides under exactly the task's execute-as role set {R}
        // (approval-execute-view-model). A row with an empty {R} — which a new request can never produce,
        // since it must name its role — has no basis to re-decide under, so decideResultView denies it
        // fail-closed rather than returning the stored bytes unmasked.
        val viewDecision = when {
            req.datasourceId == null -> ResultViewDecision.Denied("approval request has no datasource")
            // Bind the re-decision to the SAME child whose bytes were just decrypted (access.sql), not the
            // task's first-child req.sql — the two diverge once a task holds plural children.
            access.sql == null -> ResultViewDecision.Denied("saved result child has no SQL")
            else -> {
                val ds = datasourceStore.get(req.datasourceId)
                if (ds == null) {
                    ResultViewDecision.Denied("approval request datasource no longer exists")
                } else {
                    decideResultView(
                        viewer = principal,
                        req = req,
                        childSql = access.sql,
                        ds = ds,
                        decrypted = decrypted,
                        callerContext = call.httpAuthzContext(config),
                        datasourceStore = datasourceStore,
                        policyStore = policyStore,
                        accessStore = accessStore,
                        userGroupStore = userGroupStore,
                        roleResolver = roleResolver,
                        authz = authz,
                        systemClassification = systemClassification,
                    )
                }
            }
        }
        when (viewDecision) {
            is ResultViewDecision.Denied -> {
                call.application.environment.log.warn(
                    "query approval result view denied request={} viewer={} reason={}",
                    id,
                    principal,
                    viewDecision.reason,
                )
                auditStore.insert(e3Record(principal, req, "result-view-denied", Channel.WORKFLOW_VIEWER))
                call.respond(HttpStatusCode.Forbidden, ApiError("approval.result_view_denied"))
            }
            is ResultViewDecision.Allowed -> {
                // Classify by the viewer's relationship to the task, not requester-vs-everyone-else: a
                // system:auditor (or any operator-defined task.assume principal) is neither party, so it must
                // not be miscredited to the approver. The exact actor is always record.principal regardless.
                val viewEvent = when (principal) {
                    req.principal -> "result-viewed-by-requester"
                    req.decidedBy -> "result-viewed-by-approver"
                    else -> "result-viewed-by-assumer"
                }
                // Audit the view BEFORE returning rows — a failed audit insert propagates (500) so PII is never
                // returned without a durable record.
                auditStore.insert(e3Record(principal, req, viewEvent, Channel.WORKFLOW_VIEWER))
                call.respond(
                    QueryResultView(
                        meta, viewDecision.columns, viewDecision.rows,
                        // The stored bytes are R's execution output, but this VIEW re-decides under the
                        // viewer's own context and may narrow further — so the label describes the release,
                        // not the execution that produced it.
                        decision = if (viewDecision.maskedColumns.isEmpty()) Decision.ALLOW else Decision.MASK,
                        maskedColumns = viewDecision.maskedColumns,
                    ),
                )
            }
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
    sql: String,
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

    val failureCode = try {
        val response = runExecService.run(
            principal = executor,
            ds = ds,
            sql = sql,
            maxRows = 5000,
            approverExec = true,
            assumeRoles = executeAs,
            requesterIp = requesterIp,
            taskId = id,
            preflight = { store.meta(id)?.status == "RUNNING" },
            exchangeTimeoutMs = config.queryExchangeTimeoutMs,
        )
        if (response.decision == EnfAction.DENY) {
            "approval.execute_denied"
        } else {
            val result = DecryptedResult(response.columns, response.rows)
            // Child DONE, parent EXECUTED, and the execution audit all commit in ONE transaction: a crash can
            // never leave a readable DONE child under a non-EXECUTED task. If the parent has left EXECUTING
            // (e.g. a restart already reconciled it to FAILED), the flip fails and aborts the whole commit —
            // the child stays RUNNING and the failure path below transitions both consistently.
            val completed = store.completeRun(id, result, QueryResultStore.RESULT_RETENTION_SEC) { conn, _ ->
                if (!accessStore.markExecuted(id, conn)) {
                    throw IllegalStateException("task $id left EXECUTING before completion")
                }
                auditStore.insert(conn, lifecycleRecord("result-executed", Channel.WORKFLOW_EXECUTOR))
            }
            if (completed != null) {
                log.info(
                    "query approval executed request={} requester={} executor={} rows={}",
                    id, requesterPrincipal, executor, result.rows.size,
                )
                null
            } else {
                "approval.query_failed"
            }
        }
    } catch (_: RunCanceledBeforeStartException) {
        null
    } catch (_: NoProxyAttachedException) {
        "query.no_proxy_attached"
    } catch (_: ProxyRunTimeoutException) {
        "query.proxy_timeout"
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
        runCatching { store.failRun(id, failureCode) { conn, _ -> accessStore.markFailed(id, conn) } }
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
