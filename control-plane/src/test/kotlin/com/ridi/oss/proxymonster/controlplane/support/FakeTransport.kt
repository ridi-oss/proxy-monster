package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.CodeReview
import com.ridi.oss.proxymonster.controlplane.notify.DeliveryResult
import com.ridi.oss.proxymonster.controlplane.notify.NotificationAction
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationMessage
import com.ridi.oss.proxymonster.controlplane.notify.NotificationTransport
import com.ridi.oss.proxymonster.controlplane.notify.RenderedStatement
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * An in-memory transport for testing [com.ridi.oss.proxymonster.controlplane.notify.NotificationService]
 * orchestration — drain, delivery ordering, retry/backoff, terminal announce — without any wire protocol.
 * Records what it was asked to deliver/update and returns whatever result the test programs.
 */
class FakeTransport(
    override val name: String = "fake",
    override val supportsUpdate: Boolean = true,
    // Set to act as a channel: every request goes to this one address, which everyone there reads.
    private val channel: String? = null,
    // Threads: each delivery gets its own ref, and replies into it are recorded.
    override val supportsReplies: Boolean = false,
) : NotificationTransport {
    /** (thread ref, text) for each reply posted into a thread, and (reply ref, new text or null) for each edit. */
    val replies: MutableList<Pair<String, String>> = Collections.synchronizedList(mutableListOf())
    val replyEdits: MutableList<Pair<String, String?>> = Collections.synchronizedList(mutableListOf())

    override suspend fun reply(threadRef: String, text: String): DeliveryResult {
        replies += threadRef to text
        return DeliveryResult.Sent("$threadRef/reply${replies.size}")
    }

    override suspend fun editReply(replyRef: String, text: String?): DeliveryResult {
        replyEdits += replyRef to text
        return DeliveryResult.Sent(replyRef)
    }

    override val addressesTasks: Boolean = channel != null
    override val sharedAudience: Boolean = channel != null

    override fun taskAddress(req: com.ridi.oss.proxymonster.controlplane.AccessRequest): String? = channel

    override val statementHardLimit: Int = 0

    /** Principal → address; return null to exercise the no-address drop. */
    @Volatile var address: (String) -> String? = { "addr:$it" }

    @Volatile var deliverResult: DeliveryResult = DeliveryResult.Sent("ref-fake")
    @Volatile var updateResult: DeliveryResult = DeliveryResult.Sent("ref-fake")

    /** When set, deliver() THROWS it — a deterministic render/transport bug, to exercise the poison-row bound. */
    @Volatile var deliverThrows: Throwable? = null

    data class Delivered(
        val to: String,
        val event: NotificationEvent,
        val actions: Set<NotificationAction>,
        // The result-derived fact carried to THIS recipient — null for a non-party (the row-count oracle gate).
        val rowCount: Int? = null,
        // The disclosure outcome and receipt list, so a drain test can see what actually rendered.
        val statement: RenderedStatement = RenderedStatement(null, false),
        val notifiedApprovers: List<String> = emptyList(),
        val approvers: List<String> = emptyList(),
        val ccs: List<String> = emptyList(),
    )
    data class Updated(
        val ref: String,
        val event: NotificationEvent,
        val statement: RenderedStatement = RenderedStatement(null, false),
        val actions: Set<NotificationAction> = emptySet(),
        val revision: Int = 1,
        val ccs: List<String> = emptyList(),
        val redraw: Boolean = false,
        val codeReviews: List<CodeReview> = emptyList(),
    )

    val delivered: MutableList<Delivered> = Collections.synchronizedList(mutableListOf())
    val updated: MutableList<Updated> = Collections.synchronizedList(mutableListOf())
    val addressCalls = AtomicInteger()

    private val deliverSignal = Channel<Unit>(Channel.UNLIMITED)

    override suspend fun addressOf(principal: String, email: String?): String? {
        addressCalls.incrementAndGet()
        return if (channel != null) principal else address(principal)
    }

    override suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult {
        delivered += Delivered(
            to, message.event, message.actions, message.rowCount, message.statement, message.notifiedApprovers,
            message.approvers, message.ccs,
        )
        deliverSignal.trySend(Unit)
        deliverThrows?.let { throw it }
        if (supportsReplies) return DeliveryResult.Sent("thread:$to:${message.event.wire}")
        return deliverResult
    }

    override suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult {
        updated += Updated(externalRef, message.event, message.statement, message.actions, message.revision, message.ccs, message.redraw, message.codeReviews)
        if (supportsReplies) return DeliveryResult.Sent(externalRef)
        return updateResult
    }

    /** Suspend until at least one deliver() call has happened, for testing wake latency. */
    suspend fun awaitDelivery(timeoutMs: Long = 5_000) = withTimeout(timeoutMs) { deliverSignal.receive() }
}
