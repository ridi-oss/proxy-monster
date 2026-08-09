package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.notify.DeliveryResult
import com.ridi.oss.proxymonster.controlplane.notify.NotificationAction
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationMessage
import com.ridi.oss.proxymonster.controlplane.notify.NotificationTransport
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
) : NotificationTransport {
    override val statementHardLimit: Int = 0

    /** Principal → address; return null to exercise the no-address drop. */
    @Volatile var address: (String) -> String? = { "addr:$it" }

    @Volatile var deliverResult: DeliveryResult = DeliveryResult.Sent("ref-fake")
    @Volatile var updateResult: DeliveryResult = DeliveryResult.Sent("ref-fake")

    data class Delivered(val to: String, val event: NotificationEvent, val actions: Set<NotificationAction>)
    data class Updated(val ref: String, val event: NotificationEvent)

    val delivered: MutableList<Delivered> = Collections.synchronizedList(mutableListOf())
    val updated: MutableList<Updated> = Collections.synchronizedList(mutableListOf())
    val addressCalls = AtomicInteger()

    private val deliverSignal = Channel<Unit>(Channel.UNLIMITED)

    override suspend fun addressOf(principal: String, email: String?): String? {
        addressCalls.incrementAndGet()
        return address(principal)
    }

    override suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult {
        delivered += Delivered(to, message.event, message.actions)
        deliverSignal.trySend(Unit)
        return deliverResult
    }

    override suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult {
        updated += Updated(externalRef, message.event)
        return updateResult
    }

    /** Suspend until at least one deliver() call has happened, for testing wake latency. */
    suspend fun awaitDelivery(timeoutMs: Long = 5_000) = withTimeout(timeoutMs) { deliverSignal.receive() }
}
