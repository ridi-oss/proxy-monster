package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeNativeResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeInstructions
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.RequestAuthorizationResult
import io.grpc.Status
import io.grpc.StatusException
import java.time.Instant

/**
 * One request's caller, as the control plane sees it: the token's principal and kind, the channel and
 * assume-role set that kind implies, and the requester IP for the Cedar context. Roles and groups resolve lazily
 * (live, never from the token) so a deny before the role lookup costs nothing.
 */
internal class ResolvedRequestIdentity(
    val identity: WireIdentity,
    val kind: TokenKind,
    val channel: Channel,
    val providedRoles: Set<String>?,
    val httpRequesterIp: String?,
    val context: AuthzContext,
    resolveParents: () -> UserParents,
) {
    val effectiveParents: UserParents by lazy(resolveParents)
}

/** A token whose principal is still active; a deprovisioned user's surviving token row resolves to null. */
internal fun resolveActiveToken(tokenStore: TokenStore, users: UserGroupStore, token: String, allowRetired: Boolean = true): WireIdentity? =
    tokenStore.resolve(token, allowRetired)?.takeUnless { users.isDeactivated(it.principal) }

/**
 * The one place a wire token becomes a caller. Native tokens (SESSION, USER) are channel "wire" with the
 * proxy-reported client address; ephemeral tokens (EDITOR, APPROVER_EXEC) carry the HTTP requester IP
 * recorded at mint time and, when they hold a role set, run as exactly those roles. Fails UNAUTHENTICATED.
 */
internal fun ControlPlaneCore.resolveRequestIdentity(token: String, clientAddr: String?): ResolvedRequestIdentity {
    val identity = resolveActiveToken(tokenStore, userGroupStore, token)
        ?: throw StatusException(Status.UNAUTHENTICATED.withDescription("invalid, expired, revoked, or deactivated credential"))
    val kind = TokenKind.fromWire(identity.kind)
        ?: throw StatusException(Status.UNAUTHENTICATED.withDescription("unsupported token kind"))
    val ephemeral = kind == TokenKind.EDITOR || kind == TokenKind.APPROVER_EXEC
    val providedRoles = if (ephemeral) identity.roles.toSet().takeIf { it.isNotEmpty() } else null
    val channel = when (kind) {
        TokenKind.SESSION, TokenKind.USER -> Channel.WIRE
        TokenKind.EDITOR -> Channel.EDITOR
        TokenKind.APPROVER_EXEC -> if (providedRoles == null) Channel.EDITOR else Channel.WORKFLOW_EXECUTOR
        TokenKind.WORKLOAD -> throw StatusException(Status.UNAUTHENTICATED.withDescription("unsupported token kind"))
    }
    val httpIp = if (ephemeral) runRequesterIps.get(tokenHash(token)) else null
    return ResolvedRequestIdentity(
        identity, kind, channel, providedRoles, httpIp,
        AuthzContext(channel = channel.contextValue, requesterIp = if (channel == Channel.WIRE) parseRequesterIp(clientAddr) else httpIp),
    ) {
        providedRoles?.let { UserParents(policyStore.liveRoleNames(it)) }
            ?: roleResolver.resolveParents(identity.principal)
    }
}

sealed interface RequestAdmission {
    data class Denied(val denyCode: String) : RequestAdmission
    /** [instructions] is the engine's own message for a native operation; null for a metadata read. */
    data class Allowed(val instructions: NativeInstructions? = null) : RequestAdmission
}

/** What the proxy must do with an admitted native call, one arm per engine (RequestAuthorizationResult.instructions). */
sealed interface NativeInstructions {
    fun applyTo(result: RequestAuthorizationResult.Builder)
    data class Athena(val instructions: AthenaNativeInstructions) : NativeInstructions {
        override fun applyTo(result: RequestAuthorizationResult.Builder) { result.athena = instructions }
    }
}

/** What a request without SQL touches, as its engine reads it; [authorizeRequest] asks Cedar about it. */
sealed interface RequestAccess {
    /** The engine refuses the request before Cedar runs, e.g. `native.invalid_descriptor`. */
    data class Denied(val denyCode: String) : RequestAccess

    /** A catalog or table-metadata read of the datasource's own catalog; only the connect gate applies. */
    data object Metadata : RequestAccess

    /** A native API call: each of [resources] needs native.invoke as [operation] (`athena:GetWorkGroup`), then the proxy follows [instructions]. */
    data class Native(val operation: String, val resources: List<NativeResourceRef>, val instructions: NativeInstructions) : RequestAccess
}

/** One resource a native call touches, e.g. kind `workgroup`, id `primary`; [owner] when the target reports one. */
data class NativeResourceRef(val kind: String, val id: String, val owner: String? = null)

internal val RequestAuthorization.isNative: Boolean
    get() = operationCase != RequestAuthorization.OperationCase.READ_CATALOG &&
        operationCase != RequestAuthorization.OperationCase.READ_TABLE_METADATA

internal fun RequestAuthorization.deniedAdmission() =
    RequestAdmission.Denied(if (isNative) "native.not_authorized" else "datasource.not_connectable")

/**
 * Decides one request that carries no SQL statement: the engine reads what it touches, then Cedar runs the
 * connect gate and native.invoke on each resource. A request naming another datasource or no operation is refused.
 */
internal fun Authz.authorizeRequest(
    request: RequestAuthorization,
    datasource: Datasource,
    principal: String,
    parents: UserParents,
    context: AuthzContext,
    now: Instant = Instant.now(),
): RequestAdmission {
    if (request.datasourceName.isBlank() || request.datasourceName != datasource.name) return request.deniedAdmission()
    if (request.operationCase == RequestAuthorization.OperationCase.OPERATION_NOT_SET) return request.deniedAdmission()
    val access = datasource.engine.definition.requestAccess(request, datasource, principal, now)
    if (access is RequestAccess.Denied) return RequestAdmission.Denied(access.denyCode)
    if ((access is RequestAccess.Native) != request.isNative) return request.deniedAdmission()
    val raw = context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null)
    if (!authorizeMetadata(this, principal, parents, datasource, raw)) return request.deniedAdmission()
    if (access !is RequestAccess.Native) return RequestAdmission.Allowed()
    val allowed = access.resources.all { ref ->
        val resource = AuthzResource.NativeResource(datasource.name, ref.kind, ref.id, ref.owner, datasource.tags)
        authorizeNativeResource(principal, parents, resource, access.operation, raw) is AuthzDecision.Allow
    }
    return if (allowed) RequestAdmission.Allowed(access.instructions) else request.deniedAdmission()
}

/** A MySQL or PostgreSQL catalog or table-metadata read whose selector names [datasource]'s catalog; anything else is denied. */
internal fun metadataRequestAccess(request: RequestAuthorization, datasource: Datasource): RequestAccess {
    val denied = RequestAccess.Denied(request.deniedAdmission().denyCode)
    val catalog = when (request.operationCase) {
        RequestAuthorization.OperationCase.READ_CATALOG -> {
            val namespace = request.readCatalog.namespace
            if (namespace.catalog.isBlank() || namespace.schema.isBlank()) return denied
            namespace.catalog
        }
        RequestAuthorization.OperationCase.READ_TABLE_METADATA -> {
            val table = request.readTableMetadata.table
            if (table.catalog.isBlank() || table.schema.isBlank() || table.table.isBlank()) return denied
            table.catalog
        }
        else -> return denied
    }
    try {
        datasource.requireCatalog(catalog)
    } catch (_: ManagementException) {
        return denied
    }
    return RequestAccess.Metadata
}

/** The same datasource.connect gate the HTTP metadata routes use, with context tags derived here. */
internal fun authorizeMetadata(authz: Authz, principal: String, parents: UserParents, datasource: Datasource, context: AuthzContext): Boolean {
    val raw = context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null)
    val tags = authz.resolveContextTags(principal, parents, datasource.name, raw, datasource.tags)
    return authz.authorizeDatasourceAction(
        principal, parents, AuthzAction.DATASOURCE_CONNECT, datasource.name, raw.copy(tags = tags), datasource.tags,
    ) is AuthzDecision.Allow
}
