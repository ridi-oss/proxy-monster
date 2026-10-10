package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_MINT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_REVOKE
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode

/**
 * USER wire tokens for the MCP token tools: list, mint and revoke, each a Cedar decision on the Token
 * resource. Failures throw [TaskServiceException].
 */
class TokenService(
    private val store: TokenStore,
    private val userGroupStore: UserGroupStore,
    private val authz: Authz,
    private val authAudit: AuthAuditRecorder,
) {
    /** Metadata only; a secret is exposed once at mint and never re-readable. */
    fun list(caller: String, requesterIp: String?, target: String?): List<WireTokenInfo> {
        val owner = target ?: caller
        authorize(caller, requesterIp, AuthzAction.TOKEN_LIST, AuthzResource.Token(owner, kind = null))
        return store.list(owner)
    }

    /** The owner is always [caller]. The TTL is clamped inside [TokenStore.issue]. */
    fun mintUser(
        caller: String,
        requesterIp: String?,
        roles: List<String>,
        actor: AuditActor,
        name: String?,
        ttlSeconds: Long?,
    ): IssuedToken {
        authorize(caller, requesterIp, AuthzAction.TOKEN_MINT, AuthzResource.Token(caller, TokenKind.USER))
        val ttl = ttlSeconds ?: store.defaultUserTtlSeconds
        // The active check and the INSERT share one locked transaction, so no deprovision revoke can race between them.
        return store.dataSource.mintForActivePrincipalLocked(caller, userGroupStore) { c ->
            store.issue(TokenKind.USER, caller, roles, name?.ifBlank { null }, ttl, c).also { token ->
                authAudit.success(c, actor, ACTION_TOKEN_MINT, auditEntity("Token", token.id.toString()), "Minted USER wire token")
            }
        } ?: throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("auth.principal_deprovisioned"))
    }

    /** [actor] is the caller, never the owner: an oversight revoke must not name the victim as the actor. */
    fun revoke(caller: String, requesterIp: String?, actor: AuditActor, id: Long): Boolean {
        val token = store.get(id) ?: throw serviceNotFound("token")
        authorize(caller, requesterIp, AuthzAction.TOKEN_REVOKE, AuthzResource.Token(token.principal, TokenKind.fromWire(token.kind)))
        val revoked = store.dataSource.inTx { c ->
            store.revoke(id, token.principal, c).also { changed ->
                if (changed) {
                    authAudit.success(
                        c, actor, ACTION_TOKEN_REVOKE, auditEntity("Token", id.toString()),
                        "Revoked ${token.kind} wire token owned by ${token.principal}",
                    )
                }
            }
        }
        if (!revoked) throw serviceNotFound("token")
        return true
    }

    private fun authorize(caller: String, requesterIp: String?, action: AuthzAction, resource: AuthzResource) {
        val decision = authz.authorize(caller, action, resource, AuthzContext(requesterIp = requesterIp))
        if (decision is AuthzDecision.Deny) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("common.forbidden", mapOf("detail" to decision.reason)))
        }
    }
}
