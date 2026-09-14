package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import io.grpc.Status
import io.grpc.StatusException

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

internal fun resolveActiveToken(tokenStore: TokenStore, users: UserGroupStore, token: String): WireIdentity? =
    tokenStore.resolve(token)?.takeUnless { users.isDeactivated(it.principal) }

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

fun interface RequestAuthorizer {
    fun authorize(request: RequestAuthorization, datasource: Datasource, principal: String, roles: Set<String>, context: AuthzContext, authz: Authz): Boolean
}

internal object MetadataRequestAuthorizer : RequestAuthorizer {
    override fun authorize(
        request: RequestAuthorization,
        datasource: Datasource,
        principal: String,
        roles: Set<String>,
        context: AuthzContext,
        authz: Authz,
    ): Boolean {
        if (request.datasourceName.isBlank() || request.datasourceName != datasource.name) return false
        val catalog = when (request.operationCase) {
            RequestAuthorization.OperationCase.READ_CATALOG -> {
                val namespace = request.readCatalog.namespace
                if (namespace.catalog.isBlank() || namespace.schema.isBlank()) return false
                namespace.catalog
            }
            RequestAuthorization.OperationCase.READ_TABLE_METADATA -> {
                val table = request.readTableMetadata.table
                if (table.catalog.isBlank() || table.schema.isBlank() || table.table.isBlank()) return false
                table.catalog
            }
            else -> return false
        }
        try {
            datasource.resolveCatalog(catalog)
        } catch (_: ManagementException) {
            return false
        }
        return authorizeMetadata(authz, principal, roles, datasource, context)
    }
}

internal fun authorizeMetadata(authz: Authz, principal: String, roles: Set<String>, datasource: Datasource, context: AuthzContext): Boolean {
    val raw = context.copy(tags = emptySet(), stmtKind = null)
    val tags = authz.resolveContextTags(principal, roles, datasource.name, raw, datasource.tags)
    return authz.authorizeDatasourceAction(
        principal, roles, AuthzAction.DATASOURCE_CONNECT, datasource.name, raw.copy(tags = tags), datasource.tags,
    ) is AuthzDecision.Allow
}
