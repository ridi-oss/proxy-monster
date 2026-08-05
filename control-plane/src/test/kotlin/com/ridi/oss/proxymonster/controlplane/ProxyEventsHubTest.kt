package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.google.protobuf.ByteString
import kotlinx.coroutines.channels.Channel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A proxy whose stream is registered but unusable used to be reported as "no proxy is attached" — a different
 * problem with a different answer. A load balancer that resets the events stream on a transient health-check
 * blip leaves the control plane holding a channel the proxy has stopped reading, while its own log still says
 * the proxy is attached, so every query fails claiming nothing is there.
 */
class ProxyEventsHubTest {
    private fun openRun(hub: ProxyEventsHub, name: String) =
        hub.requestOpenRun(name, "session", "token", ByteString.copyFrom(ByteArray(16)), emptyList())

    @Test
    fun `a datasource with no stream is not attached`() {
        val hub = ProxyEventsHub()
        assertEquals(ProxyEventsHub.Dispatch.NOT_ATTACHED, openRun(hub, "absent"))
    }

    @Test
    fun `an open stream takes the event`() {
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)

        assertEquals(ProxyEventsHub.Dispatch.SENT, openRun(hub, "ds"))
        assertTrue(channel.tryReceive().isSuccess, "the event should be sitting in the channel")
    }

    @Test
    fun `a closed stream is WEDGED, not NOT_ATTACHED`() {
        // Registered, but the channel is dead. Distinguishing the two is the whole point: "no proxy attached"
        // sends an operator looking for a proxy that is in fact running.
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)
        channel.close()

        assertEquals(ProxyEventsHub.Dispatch.WEDGED, openRun(hub, "ds"))
    }

    @Test
    fun `a full buffer is WEDGED too`() {
        // A consumer that stopped draining looks the same to a non-blocking send as a closed channel does.
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(1)
        hub.register("ds", channel)

        assertEquals(ProxyEventsHub.Dispatch.SENT, openRun(hub, "ds"))
        assertEquals(ProxyEventsHub.Dispatch.WEDGED, openRun(hub, "ds"), "the single slot is taken")
    }

    @Test
    fun `a wedged stream is dropped so liveness stops claiming it`() {
        // Left registered, the channel cannot serve a later request either, and attached() would keep
        // reporting a reachable proxy until the stream's own close handler eventually ran.
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)
        assertEquals(setOf("ds"), hub.attached())

        channel.close()
        assertEquals(ProxyEventsHub.Dispatch.WEDGED, openRun(hub, "ds"))

        assertEquals(emptySet(), hub.attached(), "the dead stream should no longer count as attached")
        assertEquals(
            ProxyEventsHub.Dispatch.NOT_ATTACHED,
            openRun(hub, "ds"),
            "once dropped, the datasource genuinely has no proxy",
        )
    }

    @Test
    fun `a live replica serves the request even when another is wedged`() {
        // Eviction must not cost availability: with one dead and one healthy stream the request still goes
        // out, and only the dead one is dropped.
        val hub = ProxyEventsHub()
        val dead = Channel<ControlEvent>(Channel.BUFFERED)
        val live = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", dead)
        hub.register("ds", live)
        dead.close()

        assertEquals(ProxyEventsHub.Dispatch.SENT, openRun(hub, "ds"))
        assertTrue(live.tryReceive().isSuccess, "the healthy replica should have received it")
        assertEquals(setOf("ds"), hub.attached(), "the live stream keeps the datasource attached")
        assertEquals(ProxyEventsHub.Dispatch.SENT, openRun(hub, "ds"), "the dead one is gone, not retried")
    }

    @Test
    fun `a refresh push skips a wedged stream rather than counting it`() {
        val hub = ProxyEventsHub()
        val dead = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", dead)
        dead.close()

        assertEquals(0, hub.requestRefresh("ds"), "a dead stream notified nobody")
    }

    @Test
    fun `a scoped nudge carries exactly the due schemas, and an admin refresh carries none`() {
        // The two forms mean different things on the wire: an empty list asks for the whole server and is
        // the only reading that may establish which schemas exist, while a named set speaks only for the
        // schemas it lists. Sending an admin refresh where a nudge was meant costs a full catalog scan
        // every tick.
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)

        assertEquals(1, hub.requestRefresh("ds", listOf("app", "reporting")))
        val nudge = channel.tryReceive().getOrNull()!!
        assertEquals(listOf("app", "reporting"), nudge.refreshCatalog.schemasList)

        assertEquals(1, hub.requestRefresh("ds"))
        val adminRefresh = channel.tryReceive().getOrNull()!!
        assertTrue(adminRefresh.refreshCatalog.schemasList.isEmpty(), "an admin refresh must ask for the whole server")
    }
}
