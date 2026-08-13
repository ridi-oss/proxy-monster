package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.toApprovalResource
import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import org.slf4j.LoggerFactory

/**
 * Turns a Slack button click into a task decision (docs/notifications.md, "Approving from Slack").
 *
 * This is an ADAPTER, not a second lifecycle: authorization is the same `task.approve` Cedar decision the
 * HTTP route makes, and the transition goes through the same [AccessStore.decideQueryRequest] CAS — so two
 * people tapping at once resolve exactly as two console users would, and the loser is told what actually
 * happened.
 *
 * A click is a weaker assertion than a console session — no OIDC session, no attested address — so it is made
 * visible to policy rather than hidden behind a flag: it decides on [Channel.SLACK], which an operator can
 * scope or forbid per datasource or role. `requester_ip` is absent, so any policy conditioning on it denies,
 * matching how the system already treats an unknown attribute.
 *
 * Replies are ephemeral and carry no result data — an outcome, never rows.
 */
class SlackDecisionHandler(
    private val accessStore: AccessStore,
    private val datasourceStore: DatasourceStore,
    private val authz: Authz,
    private val auditRecorder: ManagementAuditRecorder,
    private val notifications: NotificationService,
    private val defaultLocale: String,
    private val onApproved: suspend (AccessRequest) -> Unit,
) {
    private val log = LoggerFactory.getLogger(SlackDecisionHandler::class.java)
    private val catalog = MessageCatalog(NotificationRenderer.DOMAIN)

    /** Handle one click. The returned string is shown privately to the clicker; empty means say nothing. */
    suspend fun handle(interaction: SlackInteraction): String {
        // Ephemeral replies render in the CLICKER's own saved language, like the notifications themselves.
        val locale = notifications.localeOf(interaction.principal) ?: defaultLocale
        fun reply(key: String) = catalog.text("reply.$key", locale)

        val req = accessStore.getRequest(interaction.taskId)
        if (req == null || req.kind != "QUERY" || req.creatorKind != "WORKFLOW") {
            return reply("request_gone")
        }
        if (req.status != "PENDING") {
            // Someone else won the race, or it was decided in the console. Say what actually happened rather
            // than reporting a failure — the message itself is rewritten by the decision's own notification.
            return catalog.text("reply.already_status", locale, mapOf("status" to req.status.lowercase()))
        }

        val ds = req.datasourceId?.let(datasourceStore::getIncludingDeleted)
        if (!mayDecide(interaction.principal, req, ds)) {
            return reply("not_authorized")
        }

        val approve = interaction.actionId == SlackTransport.ACTION_APPROVE
        val actor = AuditActor(
            principal = interaction.principal,
            clientAddr = null,
            channel = Channel.SLACK.contextValue,
        )
        val updated = accessStore.decideQueryRequest(
            interaction.taskId,
            approved = approve,
            rejectionReason = if (approve) null else SLACK_REJECT_REASON,
            decidedBy = interaction.principal,
            actor = actor,
            recorder = auditRecorder,
            onDecided = { c, decided -> notifications.emit(c, NotificationEvent.TASK_DECIDED, decided) },
        ) ?: return reply("already_done")
        // The decide committed; deliver the "decided/running" message edit now rather than on the next poll.
        // This is what removes the buttons the user just clicked, so a slow update never invites a re-click.
        notifications.wake()

        log.info(
            "query approval {} from slack request={} requester={} decider={}",
            if (approve) "approved" else "rejected", req.id, req.principal, interaction.principal,
        )
        if (!approve) return ""

        // Approving from Slack also runs it: whoever approves is the one who must execute, so offering
        // approve-without-run here would strand the task waiting for a console visit.
        return runCatching { onApproved(updated); "" }
            .getOrElse { t ->
                log.warn("slack-approved execution failed request={}", req.id, t)
                reply("run_failed")
            }
    }

    private fun mayDecide(principal: String, req: AccessRequest, ds: Datasource?): Boolean {
        val decision = authz.authorizeWithContext(
            principal,
            AuthzAction.TASK_APPROVE,
            req.toApprovalResource(),
            // No attested address: a Slack click carries none, so a policy requiring one denies. That is the
            // same fail-closed posture the system takes for any unknown attribute, and the reason `slack` is
            // its own channel rather than a flag.
            AuthzContext(channel = Channel.SLACK.contextValue),
            req.datasourceName,
            ds?.tags.orEmpty(),
        )
        return decision !is AuthzDecision.Deny
    }

    companion object {
        /** Recorded as the rejection reason; the console requires one and a click supplies no text. */
        const val SLACK_REJECT_REASON = "Denied from Slack"
    }
}
