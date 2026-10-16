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
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable

/** What the caller may do on a request's thread, with the thread itself. */
@Serializable
data class RequestThread(
    val requestId: Long,
    val ccs: List<String>,
    // Approvers who were notified or acted, and CCs. A comment by anyone else is marked as such.
    val participants: List<String>,
    val timeline: List<RequestEvent>,
    val canComment: Boolean,
    val canCc: Boolean,
    // Closing a request that has not started; a running query is stopped through the approval routes.
    val canClose: Boolean,
    val canDecide: Boolean,
)

/**
 * The parts every workflow request shares, whatever it asks for: comments, LGTMs, CCs, the timeline, closing it, and
 * the list of requests a person took part in. Each action is a Cedar decision on the Request.
 */
class RequestThreads(
    private val accessStore: AccessStore,
    private val datasourceStore: DatasourceStore,
    private val roleResolver: RoleResolver,
    private val userGroupStore: UserGroupStore,
    private val authz: Authz,
    private val recorder: ManagementAuditRecorder,
    private val notifications: NotificationService?,
) {
    fun may(
        principal: String,
        requesterIp: String?,
        action: AuthzAction,
        req: AccessRequest,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): Boolean = authz.authorizeWithContext(
        principal,
        action,
        req.toApprovalResource(),
        AuthzContext(requesterIp = requesterIp, channel = channel.contextValue),
        req.datasourceName,
        req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
    ) !is AuthzDecision.Deny

    /** A workflow request: a query approval or a role request (or a past rate reset). */
    fun request(id: Long): AccessRequest = accessStore.getRequest(id)?.takeIf { it.isWorkflowRequest } ?: throw serviceNotFound(REQUEST)

    fun thread(principal: String, requesterIp: String?, id: Long, channel: Channel = Channel.WORKFLOW_VIEWER): RequestThread {
        val req = request(id)
        if (!may(principal, requesterIp, AuthzAction.TASK_READ, req, channel)) throw serviceNotFound(REQUEST)
        return RequestThread(
            requestId = id,
            ccs = req.ccs,
            participants = accessStore.dataSource.connection.use { RequestParticipants.list(it, id) },
            timeline = RequestEvents.list(accessStore.dataSource, id),
            canComment = may(principal, requesterIp, AuthzAction.TASK_COMMENT, req, channel),
            canCc = may(principal, requesterIp, AuthzAction.TASK_CC, req, channel),
            canClose = req.closable && may(principal, requesterIp, AuthzAction.TASK_CANCEL, req, channel),
            canDecide = req.status == "PENDING" && may(principal, requesterIp, AuthzAction.TASK_APPROVE, req, channel),
        )
    }

    /**
     * Requests the caller filed or took part in, from the participant list rather than a Cedar check per row.
     * Another person's statement shows only when it carries no protected literal, as in a Slack channel.
     */
    fun involved(principal: String): List<AccessRequest> =
        accessStore.listInvolvedRequests(principal, INVOLVED_LIMIT).map { req ->
            if (req.principal == principal || req.statementCarriesProtectedLiteral == false) req else req.copy(sql = null)
        }

    /** Add a comment, or with [lgtm] an LGTM, which is shown but never approves. */
    fun comment(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        body: String?,
        lgtm: Boolean = false,
        channel: Channel = Channel.WORKFLOW_VIEWER,
        sourceThread: String? = null,
        slackRef: String? = null,
    ): RequestEvent {
        val text = body?.trim()?.takeIf { it.isNotEmpty() }
        if (!lgtm && text == null) {
            throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "body")))
        }
        if (text != null && text.length > COMMENT_MAX_CHARS) {
            throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.comment_too_long", mapOf("max" to "$COMMENT_MAX_CHARS")))
        }
        val req = request(id)
        if (!may(principal, requesterIp, AuthzAction.TASK_COMMENT, req, channel)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.comment_forbidden"))
        }
        val kind = if (lgtm) RequestEventKind.LGTM else RequestEventKind.COMMENT
        val event = accessStore.dataSource.inTx { c ->
            RequestEvents.record(c, id, kind, principal, actor.channel, text, sourceThread, slackRef)
        } ?: throw serviceNotFound(REQUEST)
        notifications?.wake()
        return event
    }

    /** Add or remove a CC. [who] is a principal or an email of an active user. */
    fun setCc(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        who: String,
        add: Boolean,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = request(id)
        if (!may(principal, requesterIp, AuthzAction.TASK_CC, req, channel)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.cc_forbidden"))
        }
        val cc = who.trim().takeIf { it in roleResolver.listActivePrincipals() }
            ?: userGroupStore.activePrincipalByEmail(who.trim())
            ?: if (add) throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.unknown_user")) else who.trim()
        if (add && cc == req.principal) throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.cc_requester"))
        accessStore.dataSource.inTx { c ->
            val changed = if (add) {
                cc !in req.ccs && run { RequestParticipants.add(c, id, listOf(cc), ParticipantKind.CC); true }
            } else {
                RequestParticipants.remove(c, id, cc, ParticipantKind.CC)
            }
            if (changed) {
                RequestEvents.record(c, id, if (add) RequestEventKind.CC_ADDED else RequestEventKind.CC_REMOVED, principal, actor.channel, cc)
                if (add) accessStore.getRequest(id, c)?.let { notifications?.emitCcAdded(c, it, cc) }
            }
        }
        if (add) notifications?.wake()
        return request(id)
    }

    /** End a request that has not started as CANCELLED. A running query is stopped by the approval service. */
    fun close(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = request(id)
        if (!may(principal, requesterIp, AuthzAction.TASK_CANCEL, req, channel)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        if (!req.closable) throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
        accessStore.closeRequest(id, actor, recorder) { c, closed -> notifications?.emit(c, NotificationEvent.TASK_CANCELLED, closed) }
            ?: throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.not_cancelable"))
        notifications?.wake()
        return request(id)
    }

    companion object {
        private const val REQUEST = "request"
        private const val INVOLVED_LIMIT = 200
        const val COMMENT_MAX_CHARS = 4000
    }
}

/** A workflow request, as opposed to the editor's or the wire proxy's own task row in the same table. */
val AccessRequest.isWorkflowRequest: Boolean get() = creatorKind == "WORKFLOW"

/** Not started, so closing it undoes nothing: pending, or an approved query that has not run. A pull request's
 *  request closes with its pull request. */
val AccessRequest.closable: Boolean get() =
    !fromPullRequest && (status == "PENDING" || (kind == "QUERY" && status == "APPROVED"))

@Serializable data class CommentInput(val body: String? = null, val lgtm: Boolean = false)

@Serializable data class CcInput(val principal: String)

/** The routes every request shares, whatever its kind. */
fun Route.requestRoutes(config: Config, threads: RequestThreads) {
    get("/api/requests/involved") {
        val principal = call.requireApi() ?: return@get
        call.respond(threads.involved(principal))
    }

    get("/api/requests/{id}/thread") {
        val principal = call.requireApi() ?: return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(threads.thread(principal, call.httpRequesterIp(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/requests/{id}/comments") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<CommentInput>()
        try {
            call.respond(
                HttpStatusCode.Created,
                threads.comment(principal, call.httpRequesterIp(config), call.auditActor(config), id, input.body, input.lgtm),
            )
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/requests/{id}/ccs") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<CcInput>()
        try {
            call.respond(threads.setCc(principal, call.httpRequesterIp(config), call.auditActor(config), id, input.principal, add = true))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    delete("/api/requests/{id}/ccs/{principal}") {
        val principal = call.requireApi() ?: return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val cc = call.parameters["principal"] ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(threads.setCc(principal, call.httpRequesterIp(config), call.auditActor(config), id, cc, add = false))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/requests/{id}/close") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(threads.close(principal, call.httpRequesterIp(config), call.auditActor(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}
