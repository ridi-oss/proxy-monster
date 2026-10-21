package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessService
import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.TaskServiceException
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.isWorkflowRequest
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import org.slf4j.LoggerFactory

/**
 * Turns a Slack button click into a task action (docs/notifications.md, "Approving from Slack").
 *
 * This is an ADAPTER, not a second lifecycle: every click goes through [ApprovalService], the same Cedar
 * decisions and CAS transitions the console makes, on [Channel.SLACK]. A click carries no OIDC session and no
 * attested address, so it is visible to policy as its own channel, and `requester_ip` is absent.
 *
 * Replies are ephemeral and carry no result data — an outcome, never rows.
 */
class SlackDecisionHandler(
    private val accessStore: AccessStore,
    private val approvals: () -> ApprovalService,
    private val access: () -> AccessService,
    private val notifications: NotificationService,
    private val defaultLocale: String,
    private val deepLink: (Long) -> String = { "" },
    private val run: (principal: String, taskId: Long) -> Unit = { principal, taskId ->
        approvals().execute(principal, null, taskId, Channel.SLACK)
    },
) {
    private val log = LoggerFactory.getLogger(SlackDecisionHandler::class.java)
    private val catalog = MessageCatalog(NotificationRenderer.DOMAIN)
    private val reviewView = SlackReviewView(catalog, NotificationRenderer(catalog))

    /** The socket's entry: Review opens a modal, a click inside one redraws it, any other click replies privately. */
    suspend fun respond(interaction: SlackInteraction): SlackReply {
        val locale = notifications.localeOf(interaction.principal) ?: defaultLocale
        if (interaction.actionId == SlackTransport.ACTION_REVIEW) {
            val view = runCatching {
                reviewView.forDetail(review(interaction.principal, interaction.taskId), interaction.principal, deepLink(interaction.taskId), locale)
            }.getOrElse { e ->
                if (e !is TaskServiceException) throw e
                reviewView.message(catalog.text("modal.forbidden", locale), locale)
            }
            return SlackReply.OpenView(view)
        }
        val text = handle(interaction)
        if (interaction.viewId == null) return SlackReply.Ephemeral(text)
        val outcome = text.ifEmpty {
            val status = accessStore.getRequest(interaction.taskId)?.status?.lowercase() ?: "—"
            catalog.text("modal.done", locale, mapOf("status" to status))
        }
        return SlackReply.UpdateView(reviewView.message(outcome, locale))
    }

    private fun review(principal: String, id: Long): ReviewModel {
        val threads = approvals().threads
        val req = threads.request(id)
        if (req.kind == "QUERY") return ReviewModel(approvals().detail(principal, null, id, Channel.SLACK))
        val thread = threads.thread(principal, null, id, Channel.SLACK)
        return ReviewModel(
            req,
            canDecide = req.status == "PENDING" && threads.may(principal, null, AuthzAction.TASK_APPROVE, req, Channel.SLACK),
            canClose = thread.canClose,
            canComment = thread.canComment,
        )
    }

    /** Handle one click. The returned string is shown privately to the clicker; empty means say nothing. */
    suspend fun handle(interaction: SlackInteraction): String {
        // Ephemeral replies render in the CLICKER's own saved language, like the notifications themselves.
        val locale = notifications.localeOf(interaction.principal) ?: defaultLocale
        fun reply(key: String) = catalog.text("reply.$key", locale)

        val req = accessStore.getRequest(interaction.taskId)
        if (req == null || !req.isWorkflowRequest) {
            return reply("request_gone")
        }
        // An action is about the SQL the message showed, so a click from before an edit does nothing.
        if (req.revision != interaction.revision) return reply("request_changed")

        val principal = interaction.principal
        val actor = AuditActor(principal = principal, clientAddr = null, channel = Channel.SLACK.contextValue)
        val service = approvals()
        val decision = interaction.actionId in setOf(SlackTransport.ACTION_APPROVE_ONLY, SlackTransport.ACTION_DENY)
        if (req.kind != "QUERY" && decision && req.status != "PENDING") {
            return catalog.text("reply.already_status", locale, mapOf("status" to req.status.lowercase()))
        }
        val outcome = runCatching {
            // Approving a role is the whole action; there is nothing to run.
            if (req.kind != "QUERY" && decision) {
                if (interaction.actionId == SlackTransport.ACTION_DENY) {
                    access().reject(principal, null, actor, req.id, SLACK_REJECT_REASON, Channel.SLACK)
                } else {
                    access().approve(principal, null, actor, req.id, null, Channel.SLACK)
                }
            } else when (interaction.actionId) {
                SlackTransport.ACTION_APPROVE, SlackTransport.ACTION_APPROVE_ONLY ->
                    service.approve(principal, null, actor, req.id, req.revision, Channel.SLACK)
                SlackTransport.ACTION_DENY ->
                    service.reject(principal, null, actor, req.id, SLACK_REJECT_REASON, Channel.SLACK)
                SlackTransport.ACTION_UNAPPROVE -> service.unapprove(principal, null, actor, req.id, Channel.SLACK)
                // On a query this also stops a run already started from the same message.
                SlackTransport.ACTION_CLOSE -> if (req.kind == "QUERY") {
                    service.cancel(principal, null, actor, req.id, Channel.SLACK)
                } else {
                    service.threads.close(principal, null, actor, req.id, Channel.SLACK)
                }
                SlackTransport.ACTION_RUN -> run(principal, req.id)
                SlackTransport.ACTION_LGTM -> service.threads.comment(principal, null, actor, req.id, null, lgtm = true, Channel.SLACK)
                else -> return ""
            }
        }
        outcome.exceptionOrNull()?.let { e ->
            if (e !is TaskServiceException) throw e
            return when (e.error.code) {
                "approval.not_approver" -> reply("not_authorized")
                "approval.not_runner" -> reply("not_runner")
                "approval.cancel_forbidden" -> reply("not_closer")
                "approval.comment_forbidden" -> reply("not_commenter")
                "approval.request_changed" -> reply("request_changed")
                "approval.expired" -> reply("expired")
                else -> accessStore.getRequest(req.id)
                    ?.let { catalog.text("reply.already_status", locale, mapOf("status" to it.status.lowercase())) }
                    ?: reply("request_gone")
            }
        }
        log.info("slack {} request={} requester={} by={}", interaction.actionId, req.id, req.principal, principal)
        if (interaction.actionId == SlackTransport.ACTION_LGTM) return reply("lgtm_recorded")

        // A pull request's merge runs its request; an approve-only click never runs.
        if (interaction.actionId != SlackTransport.ACTION_APPROVE || req.fromPullRequest) return ""
        return runCatching { run(principal, req.id); "" }
            .getOrElse { t ->
                log.warn("slack-approved execution failed request={}", req.id, t)
                reply("run_failed")
            }
    }

    companion object {
        /** Recorded as the rejection reason; the console requires one and a click supplies no text. */
        const val SLACK_REJECT_REASON = "Denied from Slack"
    }
}
