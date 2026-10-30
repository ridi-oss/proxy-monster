package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import io.grpc.Status
import io.grpc.StatusException

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
    val context: AuthzContext,
    resolveParents: () -> UserParents,
) {
    val effectiveParents: UserParents by lazy(resolveParents)
}

/** A token whose principal is still active; a deprovisioned user's surviving token row resolves to null. */
internal fun resolveActiveToken(tokenStore: TokenStore, users: UserGroupStore, token: String, allowRetired: Boolean = true): WireIdentity? =
    tokenStore.resolve(token, allowRetired)?.takeUnless { users.isDeactivated(it.principal) }

/**
 * The one place a wire token becomes a caller. Native tokens (SESSION, USER) are channel "wire"; ephemeral
 * tokens (EDITOR, APPROVER_EXEC), when they hold a role set, run as exactly those roles. The requester IP is
 * the client address goproxy reports for every channel: a wire client's socket, or the requester an
 * EditorQuery carried. Fails UNAUTHENTICATED.
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
    return ResolvedRequestIdentity(
        identity, kind, channel, providedRoles,
        AuthzContext(channel = channel.contextValue, requesterIp = parseRequesterIp(clientAddr)),
    ) {
        providedRoles?.let { UserParents(policyStore.liveRoleNames(it)) }
            ?: roleResolver.resolveParents(identity.principal)
    }
}

/** The same datasource.connect gate the HTTP metadata routes use, with context tags derived here. */
internal fun authorizeMetadata(authz: Authz, principal: String, parents: UserParents, datasource: Datasource, context: AuthzContext): Boolean {
    val raw = context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null)
    val tags = authz.resolveContextTags(principal, parents, datasource.name, raw, datasource.tags)
    return authz.authorizeDatasourceAction(
        principal, parents, AuthzAction.DATASOURCE_CONNECT, datasource.name, raw.copy(tags = tags), datasource.tags,
    ) is AuthzDecision.Allow
}
