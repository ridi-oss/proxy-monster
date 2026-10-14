package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.RequestEventKind
import com.ridi.oss.proxymonster.controlplane.RequestEvents
import com.ridi.oss.proxymonster.controlplane.inTx
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import org.slf4j.LoggerFactory

/**
 * Records a reply in a request's Slack thread as a comment on the request. A channel reply is already visible to
 * the whole channel, so it is recorded as written, under the author's Slack name when no active user matches them.
 * A DM reply is a comment by the DM's owner and needs their `task.comment`. Neither adds a participant.
 */
class SlackThreadHandler(
    private val store: NotificationStore,
    private val accessStore: AccessStore,
    private val approvals: () -> ApprovalService,
    private val notifications: NotificationService,
) {
    private val log = LoggerFactory.getLogger(SlackThreadHandler::class.java)

    suspend fun onMessage(m: SlackThreadMessage) {
        val ref = "${m.channel}:${m.ts}"
        if (m.kind != SlackThreadMessage.Kind.NEW) {
            val body = if (m.kind == SlackThreadMessage.Kind.DELETED) null else m.text?.take(COMMENT_MAX_CHARS).orEmpty()
            val event = accessStore.dataSource.inTx { c -> RequestEvents.editBySlackRef(c, ref, body) } ?: return
            notifications.propagate(event)
            return
        }
        val thread = store.threadAt("${m.channel}:${m.threadTs ?: return}", TRANSPORTS) ?: return
        val text = m.text?.trim()?.takeIf { it.isNotEmpty() }?.take(COMMENT_MAX_CHARS) ?: return
        if (thread.transport == SlackTransport.TRANSPORT_CHANNEL) {
            val author = m.principal ?: "slack:${m.name ?: "unknown"}"
            accessStore.dataSource.inTx { c ->
                RequestEvents.record(c, thread.taskId, RequestEventKind.COMMENT, author, ORIGIN, text, thread.externalRef, ref)
            }
            notifications.wake()
            return
        }
        val principal = m.principal ?: return
        runCatching {
            approvals().comment(
                principal, null, AuditActor(principal, channel = ORIGIN), thread.taskId, text,
                channel = Channel.SLACK, sourceThread = thread.externalRef, slackRef = ref,
            )
        }.onFailure { log.info("slack reply not recorded task={} by={}: {}", thread.taskId, principal, it.message) }
    }

    private companion object {
        val TRANSPORTS = setOf(SlackTransport.TRANSPORT, SlackTransport.TRANSPORT_CHANNEL)
        val ORIGIN = Channel.SLACK.contextValue
        const val COMMENT_MAX_CHARS = ApprovalService.COMMENT_MAX_CHARS
    }
}
