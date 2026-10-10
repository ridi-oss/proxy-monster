package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
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

/** The same datasource.connect gate the HTTP metadata routes use, with context tags derived here. */
internal fun authorizeMetadata(authz: Authz, principal: String, roles: Set<String>, datasource: Datasource, context: AuthzContext): Boolean {
    val raw = context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null)
    val tags = authz.resolveContextTags(principal, roles, datasource.name, raw, datasource.tags)
    return authz.authorizeDatasourceAction(
        principal, roles, AuthzAction.DATASOURCE_CONNECT, datasource.name, raw.copy(tags = tags), datasource.tags,
    ) is AuthzDecision.Allow
}
