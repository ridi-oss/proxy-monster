package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeInstructions
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.RequestAuthorizationResult
import io.grpc.Status
import io.grpc.StatusException

/**
 * One request's caller, as the control plane sees it: the token's principal and kind, the channel and
 * assume-role set that kind implies, and the requester IP for the Cedar context. Roles resolve lazily
 * (live, never from the token) so a deny before the role lookup costs nothing.
 */
internal class ResolvedRequestIdentity(
    val identity: WireIdentity,
    val kind: TokenKind,
    val channel: Channel,
    val providedRoles: Set<String>?,
    val httpRequesterIp: String?,
    val context: AuthzContext,
    resolveRoles: () -> Set<String>,
) {
    val effectiveRoles: Set<String> by lazy(resolveRoles)
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
    }
    val httpIp = if (ephemeral) runRequesterIps.get(tokenHash(token)) else null
    return ResolvedRequestIdentity(
        identity, kind, channel, providedRoles, httpIp,
        AuthzContext(channel = channel.contextValue, requesterIp = if (channel == Channel.WIRE) parseRequesterIp(clientAddr) else httpIp),
    ) { providedRoles?.let(policyStore::liveRoleNames) ?: roleResolver.resolve(identity.principal) }
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

/**
 * Decides one request that carries no SQL statement. Deny by default: an operation the engine does not
 * recognize, a blank selector, or a datasource the request does not name is refused before Cedar runs.
 */
fun interface RequestAuthorizer {
    fun authorize(request: RequestAuthorization, datasource: Datasource, principal: String, roles: Set<String>, context: AuthzContext, authz: Authz): RequestAdmission
}

internal val RequestAuthorization.isNative: Boolean
    get() = operationCase != RequestAuthorization.OperationCase.READ_CATALOG &&
        operationCase != RequestAuthorization.OperationCase.READ_TABLE_METADATA

internal fun RequestAuthorization.deniedAdmission() =
    RequestAdmission.Denied(if (isNative) "native.not_authorized" else "datasource.not_connectable")

internal fun RequestAuthorizer.authorizeBounded(
    request: RequestAuthorization,
    datasource: Datasource,
    principal: String,
    roles: Set<String>,
    context: AuthzContext,
    authz: Authz,
): RequestAdmission {
    if (request.datasourceName.isBlank() || request.datasourceName != datasource.name) return request.deniedAdmission()
    if (request.operationCase == RequestAuthorization.OperationCase.OPERATION_NOT_SET) return request.deniedAdmission()
    val admission = authorize(request, datasource, principal, roles, context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null), authz)
    // A native operation is admitted only with instructions; a metadata read never carries any.
    if (admission is RequestAdmission.Allowed && request.isNative != (admission.instructions != null)) return request.deniedAdmission()
    return admission
}

/** Catalog and table-metadata reads: the selector must name this datasource's catalog, then the connect gate applies. */
internal object MetadataRequestAuthorizer : RequestAuthorizer {
    override fun authorize(
        request: RequestAuthorization,
        datasource: Datasource,
        principal: String,
        roles: Set<String>,
        context: AuthzContext,
        authz: Authz,
    ): RequestAdmission {
        if (request.datasourceName.isBlank() || request.datasourceName != datasource.name) return request.deniedAdmission()
        val catalog = when (request.operationCase) {
            RequestAuthorization.OperationCase.READ_CATALOG -> {
                val namespace = request.readCatalog.namespace
                if (namespace.catalog.isBlank() || namespace.schema.isBlank()) return request.deniedAdmission()
                namespace.catalog
            }
            RequestAuthorization.OperationCase.READ_TABLE_METADATA -> {
                val table = request.readTableMetadata.table
                if (table.catalog.isBlank() || table.schema.isBlank() || table.table.isBlank()) return request.deniedAdmission()
                table.catalog
            }
            else -> return request.deniedAdmission()
        }
        try {
            datasource.requireCatalog(catalog)
        } catch (_: ManagementException) {
            return request.deniedAdmission()
        }
        return if (authorizeMetadata(authz, principal, roles, datasource, context)) RequestAdmission.Allowed() else request.deniedAdmission()
    }
}

/** The same datasource.connect gate the HTTP metadata routes use, with context tags derived here. */
internal fun authorizeMetadata(authz: Authz, principal: String, roles: Set<String>, datasource: Datasource, context: AuthzContext): Boolean {
    val raw = context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null)
    val tags = authz.resolveContextTags(principal, roles, datasource.name, raw, datasource.tags)
    return authz.authorizeDatasourceAction(
        principal, roles, AuthzAction.DATASOURCE_CONNECT, datasource.name, raw.copy(tags = tags), datasource.tags,
    ) is AuthzDecision.Allow
}
