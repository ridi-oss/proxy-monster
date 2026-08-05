package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import java.sql.Connection

private const val MAX_AUDITED_VALUE_CHARS = 200

/**
 * Bound a caller-supplied value before it reaches an audit row. Rejection paths run before any validation,
 * and several of them (the OIDC callback, wire-token validation) are reachable unauthenticated — without a
 * bound the caller chooses how much of a tamper-evident, SIEM-exported chain each attempt consumes.
 */
internal fun auditedValue(raw: String): String = raw.take(MAX_AUDITED_VALUE_CHARS)

/**
 * Writes a `kind="auth"` authentication/session-lifecycle event through the one [AuditStore] chain
 * chokepoint, alongside [com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder]'s
 * `kind="admin"` config-change events.
 *
 * Pass the caller's transaction as `c` whenever the event accompanies a state change (a session minted,
 * a token revoked) so the two commit or roll back together. `c = null` writes standalone, which is for
 * the stateless rejections — a bad `state` parameter, an invalid wire token — that change nothing and so
 * have no transaction to join.
 *
 * Successful wire-token validation is deliberately NOT recorded here: it runs on every connection and
 * query, the per-query decision is already audited by the data plane, and the volume would bury the
 * rejected attempts this trail exists to surface.
 */
class AuthAuditRecorder(private val auditStore: AuditStore) {
    private val log = org.slf4j.LoggerFactory.getLogger(AuthAuditRecorder::class.java)

    fun success(
        c: Connection?,
        actor: AuditActor,
        action: String,
        resource: String,
        summary: String,
        detail: String? = null,
    ) {
        record(c, actor, action, resource, summary, detail, Decision.ALLOW, OUTCOME_SUCCESS)
    }

    fun failure(
        c: Connection?,
        actor: AuditActor,
        action: String,
        resource: String,
        summary: String,
        detail: String? = null,
    ) {
        record(c, actor, action, resource, summary, detail, Decision.DENY, OUTCOME_FAILURE)
    }

    /**
     * Record a standalone rejection/failure event best-effort. A rejection accompanies no state change, so a
     * failed audit insert must never change the caller's outcome — turn an UNAUTHENTICATED into an INTERNAL,
     * or a redirect into a 500. Logs and swallows an insert failure. For `c == null` events only; an event
     * that accompanies a committed mutation MUST use [success]/[failure] on the caller's transaction so the
     * two commit or roll back together.
     */
    fun failureBestEffort(
        actor: AuditActor,
        action: String,
        resource: String,
        summary: String,
        detail: String? = null,
    ) {
        runCatching { record(null, actor, action, resource, summary, detail, Decision.DENY, OUTCOME_FAILURE) }
            .onFailure { log.warn("best-effort auth failure audit insert failed (action={})", action, it) }
    }

    private fun record(
        c: Connection?,
        actor: AuditActor,
        action: String,
        resource: String,
        summary: String,
        detail: String?,
        decision: Decision,
        outcome: String,
    ) {
        val event = AuditEvent(
            principal = actor.principal,
            roles = actor.roles,
            datasource = DATASOURCE,
            clientAddr = actor.clientAddr,
            statement = summary,
            decision = decision,
            detail = detail,
            channel = actor.channel,
            authzAction = action,
            authzResource = resource,
            outcome = outcome,
            kind = KIND_AUTH,
        )
        if (c == null) auditStore.insert(event) else auditStore.insert(c, event)
    }

    companion object {
        const val KIND_AUTH = "auth"
        const val OUTCOME_SUCCESS = "SUCCESS"
        const val OUTCOME_FAILURE = "FAILURE"

        /** The `principal` of an event no identity can be attributed to — a credential that did not resolve,
         *  or a grant redeemed by a client rather than a user. `principal` is NOT NULL, so absence needs a
         *  value; one shared literal keeps "unattributed" a queryable state instead of a per-site spelling. */
        const val PRINCIPAL_UNATTRIBUTED = "unknown"

        const val CHANNEL_OIDC = "oidc"
        const val CHANNEL_WIRE = "wire"
        const val CHANNEL_DEVICE = "device"
        const val CHANNEL_PMON = "pmon"
        const val CHANNEL_OAUTH = "oauth"
        const val CHANNEL_SESSION = "session"

        const val ACTION_OIDC_LOGIN = "auth.oidc.login"
        const val ACTION_LOGOUT = "auth.logout"
        const val ACTION_DEVICE_APPROVE = "auth.device.approve"
        const val ACTION_DEVICE_MINT = "auth.device.mint"
        const val ACTION_SESSION_RENEW = "auth.session.renew"
        const val ACTION_SESSION_EXPIRE = "auth.session.expire"
        const val ACTION_WIRE_VALIDATE = "auth.wire.validate"
        const val ACTION_TOKEN_MINT = "auth.token.mint"
        const val ACTION_TOKEN_REVOKE = "auth.token.revoke"
        const val ACTION_OAUTH_CONSENT = "auth.oauth.consent"
        const val ACTION_OAUTH_TOKEN = "auth.oauth.token"
        const val ACTION_OAUTH_REVOKE = "auth.oauth.revoke"

        private const val DATASOURCE = "control-plane"
    }
}
