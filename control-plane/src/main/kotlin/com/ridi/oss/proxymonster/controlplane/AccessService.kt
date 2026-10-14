package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import io.ktor.http.HttpStatusCode
import java.sql.Connection

/**
 * JIT role requests, rate resets and grants, shared by the REST access routes and the MCP access tools. Each
 * Cedar decision runs on the same context REST builds. Failures throw [TaskServiceException].
 */
class AccessService(
    private val accessStore: AccessStore,
    private val datasourceStore: DatasourceStore,
    private val auditStore: AuditStore,
    private val roleResolver: RoleResolver,
    private val authz: Authz,
    private val recorder: ManagementAuditRecorder,
    // Null when no notification transport is configured.
    private val notifications: NotificationService? = null,
) {
    /** Forward-filtered by task.read: every row is decided, so no listing answers the whole table. */
    fun listRequests(principal: String, status: String?): List<AccessRequest> =
        accessStore.listRequests(status).filter {
            authz.authorize(principal, AuthzAction.TASK_READ, it.toApprovalResource()) is AuthzDecision.Allow
        }

    /** A datasource-less request has no Datasource resource to decide, so authentication alone admits it. */
    fun createRequest(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        input: AccessRequestInput,
        source: String = "console",
    ): AccessRequest {
        val ds = input.datasourceId?.let(datasourceStore::get)
        // A tombstoned id still satisfies the FK, so the insert would otherwise skip the task.request gate.
        if (input.datasourceId != null && ds == null) throw serviceNotFound("datasource")
        if (ds != null && !mayRequestOn(authz, roleResolver, principal, requesterIp, ds)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.request_not_permitted"))
        }
        return accessStore.createRequest(principal, input, actor, recorder, source)
            .also { notifications?.emitRequestedEvent(it) }
    }

    fun requestRateReset(principal: String, actor: AuditActor, input: RateResetRequestInput): AccessRequest {
        if (input.reason.isBlank()) throw fieldRequired("reason")
        return accessStore.createRateResetRequest(principal, input, actor, recorder)
            .also { notifications?.emitRequestedEvent(it) }
    }

    fun approve(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        durationSec: Long?,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val before = requireApprover(principal, requesterIp, id, channel)
        val after = accessStore.approve(id, durationSec, principal, actor, recorder) ?: throw serviceNotFound("access request")
        return after.also { if (before.status != it.status) notifications?.emitEvent(NotificationEvent.TASK_DECIDED, it) }
    }

    fun reject(
        principal: String,
        requesterIp: String?,
        actor: AuditActor,
        id: Long,
        reason: String,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        requireApprover(principal, requesterIp, id, channel)
        return rejectApproved(principal, actor, id, reason)
    }

    /** The reject after [requireApprover] passed, so REST reads its body only once the request is decidable. */
    internal fun rejectApproved(principal: String, actor: AuditActor, id: Long, reason: String): AccessRequest {
        val before = accessStore.getRequest(id) ?: throw serviceNotFound("access request")
        val after = accessStore.reject(id, reason, principal, actor, recorder) ?: throw serviceNotFound("access request")
        return after.also { if (before.status != it.status) notifications?.emitEvent(NotificationEvent.TASK_DECIDED, it) }
    }

    // Self-approval is the shipped no-self-approval forbid, never an app rule. The Role:: resource lets a policy
    // scope approvers by the requested role.
    internal fun requireApprover(
        principal: String,
        requesterIp: String?,
        id: Long,
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ): AccessRequest {
        val req = accessStore.getRequest(id) ?: throw serviceNotFound("access request")
        if (req.kind == "QUERY") {
            throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.use_query_approval_endpoint"))
        }
        val decision = authz.authorizeWithContext(
            principal, AuthzAction.TASK_APPROVE,
            req.toApprovalResource(),
            AuthzContext(requesterIp = requesterIp, channel = channel.contextValue),
            req.datasourceName,
            req.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        if (decision is AuthzDecision.Deny) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.not_approver"))
        }
        return req
    }

    /** [principal] selects which rows to look for, never which the caller may see. */
    fun listGrants(caller: String, principal: String?, active: Boolean): List<AccessGrant> =
        accessStore.listGrants(principal, active).filter {
            authz.authorize(
                caller, AuthzAction.TASK_READ,
                AuthzResource.AccessGrant(owner = it.principal, id = it.id, roleName = it.roleName),
            ) is AuthzDecision.Allow
        }

    fun revokeGrant(principal: String, requesterIp: String?, actor: AuditActor, id: Long) {
        val grant = accessStore.getGrant(id) ?: throw serviceNotFound("access grant")
        val decision = authz.authorize(
            principal, AuthzAction.GRANT_REVOKE,
            AuthzResource.AccessGrant(owner = grant.principal, id = grant.id, roleName = grant.roleName),
            AuthzContext(requesterIp = requesterIp),
        )
        if (decision is AuthzDecision.Deny) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("common.forbidden", mapOf("detail" to decision.reason)))
        }
        if (!accessStore.revoke(id, actor, recorder)) throw serviceNotFound("access grant")
    }

    /** An admin's direct reset. The caller has already passed admin.identity. */
    fun resetRate(principal: String, reason: String, actor: AuditActor, c: Connection): RateReset {
        if (reason.isBlank()) throw fieldRequired("reason")
        return accessStore.resetRate(principal, reason, actor, recorder, c)
    }

    fun resetRate(principal: String, reason: String, actor: AuditActor): RateReset =
        accessStore.dataSource.inTx { resetRate(principal, reason, actor, it) }

    fun lastRateReset(principal: String): RateReset? = auditStore.lastRateReset(principal)

    private fun fieldRequired(field: String) =
        TaskServiceException(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to field)))
}
