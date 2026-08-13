package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.google.protobuf.ByteString
import kotlinx.coroutines.channels.Channel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
    fun `broadcastDraining signals then closes every open stream`() {
        val hub = ProxyEventsHub()
        val a = Channel<ControlEvent>(Channel.BUFFERED)
        val b = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds-a", a)
        hub.register("ds-b", b)

        assertEquals(2, hub.broadcastDraining(), "both open streams are signalled")

        for (channel in listOf(a, b)) {
            val signal = channel.tryReceive()
            assertTrue(signal.isSuccess, "the drain signal should be sitting in the channel")
            assertTrue(signal.getOrThrow().hasDraining(), "the signal is a Draining event")
            assertTrue(channel.tryReceive().isClosed, "the stream is closed right after the signal")
        }
    }

    @Test
    fun `awaitDrained returns true once every signalled stream deregisters`() {
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)
        hub.broadcastDraining()

        // A registered-but-not-yet-deregistered stream keeps the hub non-empty (the gRPC awaitClose that
        // deregisters runs off-thread; a plain Channel never fires it), so a bounded wait reports the drain
        // as incomplete rather than hanging.
        assertTrue(!hub.awaitDrained(50), "still attached until the stream deregisters")

        // Simulate the gRPC awaitClose firing after the close.
        hub.deregister("ds", channel)
        assertTrue(hub.awaitDrained(200), "empty once the stream deregisters")
    }

    @Test
    fun `once draining, a new register is refused and told to reconnect`() {
        val hub = ProxyEventsHub()
        hub.beginDraining()

        val late = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", late)

        // The late stream is signalled to reconnect and closed, never added — so a reconnecting proxy cannot
        // repopulate the hub behind awaitDrained and re-home onto this dying instance.
        val signal = late.tryReceive()
        assertTrue(signal.isSuccess && signal.getOrThrow().hasDraining(), "the refused stream is told it is draining")
        assertTrue(late.tryReceive().isClosed, "and its stream is closed")
        assertEquals(emptySet(), hub.attached(), "a refused stream never counts as attached")
    }

    @Test
    fun `once draining, dispatch stops returning SENT`() {
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)
        assertEquals(ProxyEventsHub.Dispatch.SENT, openRun(hub, "ds"), "healthy before draining")

        hub.beginDraining()

        // The stream is still open, but a query dispatched now must not be promised: it would ride behind the
        // Draining signal the proxy bails on and be silently dropped. NOT_ATTACHED fails it closed instead.
        assertEquals(ProxyEventsHub.Dispatch.NOT_ATTACHED, openRun(hub, "ds"), "no SENT once draining")
    }

    @Test
    fun `concurrent register cannot survive a drain`() {
        // The register barrier must be atomic with the drain: however registers interleave with
        // beginDraining + broadcastDraining, none may be left OPEN — an open, unsignalled stream would sit
        // behind awaitDrained. This stresses the check-then-insert window; the hub's lock is what holds it.
        repeat(30) {
            val hub = ProxyEventsHub()
            val channels = (1..12).map { Channel<ControlEvent>(Channel.BUFFERED) }
            val start = CountDownLatch(1)
            val threads = channels.mapIndexed { i, ch -> Thread { start.await(); hub.register("ds-$i", ch) } } +
                Thread { start.await(); hub.beginDraining(); hub.broadcastDraining() }
            threads.forEach(Thread::start)
            start.countDown()
            threads.forEach { it.join(5000) }
            assertTrue(threads.none(Thread::isAlive), "no thread should be stuck (a deadlock regression)")

            // close() returns false when the channel was already closed, so every channel must have been
            // closed by the drain — broadcast-closed if it was admitted, refuse-closed if it raced in after
            // the flag. A channel left open (a lost register) would return true here.
            channels.forEach { assertTrue(!it.close(), "every channel must be closed by the drain, none left open") }
        }
    }

    @Test
    fun `dispatch is serialized behind an in-progress drain`() {
        // dispatch() reporting SENT must be atomic with the drain, so a run can never be enqueued behind the
        // Draining signal (the proxy bails on Draining and would drop it). A scheduler-race version of this
        // was a false guard — mutation-testing showed it passing against the pre-lock code — so drive the
        // interleaving deterministically: a channel whose close() parks holds the hub lock inside
        // broadcastDraining, and a concurrent dispatch must then block until the drain releases it. Without
        // the lock on either path, the dispatch returns immediately instead of blocking.
        val hub = ProxyEventsHub()
        val inClose = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val delegate = Channel<ControlEvent>(Channel.UNLIMITED)
        val parkingChannel = object : Channel<ControlEvent> by delegate {
            override fun close(cause: Throwable?): Boolean {
                inClose.countDown()
                releaseClose.await()
                return delegate.close(cause)
            }
        }
        hub.register("ds", parkingChannel)

        val drainer = Thread { hub.beginDraining(); hub.broadcastDraining() }.apply { start() }
        try {
            assertTrue(inClose.await(2, TimeUnit.SECONDS), "broadcastDraining should reach close(), holding the lock")

            val dispatchReturned = CountDownLatch(1)
            Thread { openRun(hub, "ds"); dispatchReturned.countDown() }.start()
            assertFalse(
                dispatchReturned.await(300, TimeUnit.MILLISECONDS),
                "dispatch must block while a drain holds the lock — a run enqueued now would land behind Draining",
            )

            releaseClose.countDown()
            assertTrue(dispatchReturned.await(2, TimeUnit.SECONDS), "dispatch proceeds once the drain releases the lock")
        } finally {
            releaseClose.countDown() // idempotent: unpark the drainer on any failure path
            drainer.join(2000)
        }
    }

    @Test
    fun `once draining, requestRefresh notifies nobody`() {
        val hub = ProxyEventsHub()
        val channel = Channel<ControlEvent>(Channel.BUFFERED)
        hub.register("ds", channel)
        assertEquals(1, hub.requestRefresh("ds"), "notified while live")

        hub.beginDraining()
        assertEquals(0, hub.requestRefresh("ds"), "a refresh the drain is about to invalidate reports 0, not a lie")
    }
}
