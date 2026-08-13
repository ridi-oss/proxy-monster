package com.ridi.oss.proxymonster.controlplane

import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TaskCompletionHubTest {
    @Test
    fun `a subscriber receives an event published to its principal`() = runBlocking {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        hub.publish("alice", TaskEvent(7, "EXECUTED"))
        val got = withTimeout(1000) { events.receive() }
        assertEquals(TaskEvent(7, "EXECUTED"), got)
    }

    @Test
    fun `publish to a principal with no subscribers is a no-op`() {
        val hub = TaskCompletionHub()
        // Must not throw even though nobody is listening.
        hub.publish("nobody", TaskEvent(1, "FAILED"))
    }

    @Test
    fun `an event reaches every open stream of the same principal`() = runBlocking {
        val hub = TaskCompletionHub()
        val tabA = hub.subscribe("alice")
        val tabB = hub.subscribe("alice")
        hub.publish("alice", TaskEvent(9, "CANCELLED"))
        assertEquals(TaskEvent(9, "CANCELLED"), withTimeout(1000) { tabA.receive() })
        assertEquals(TaskEvent(9, "CANCELLED"), withTimeout(1000) { tabB.receive() })
    }

    @Test
    fun `a principal only receives its own events`() = runBlocking {
        val hub = TaskCompletionHub()
        val alice = hub.subscribe("alice")
        val bob = hub.subscribe("bob")
        hub.publish("alice", TaskEvent(3, "EXECUTED"))
        assertEquals(TaskEvent(3, "EXECUTED"), withTimeout(1000) { alice.receive() })
        // Bob's channel stays empty — no cross-principal leak.
        assertNull(bob.tryReceive().getOrNull())
    }

    @Test
    fun `publish to a party set delivers once per principal even when a principal repeats`() = runBlocking {
        val hub = TaskCompletionHub()
        val requester = hub.subscribe("carol")
        // carol is both requester and approver of a self-approved task: she must get exactly one event.
        hub.publish(listOf("carol", "carol"), TaskEvent(5, "EXECUTED"))
        assertEquals(TaskEvent(5, "EXECUTED"), withTimeout(1000) { requester.receive() })
        assertNull(requester.tryReceive().getOrNull())
    }

    @Test
    fun `unsubscribe removes and closes the channel`() = runBlocking<Unit> {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        hub.unsubscribe("alice", events)
        // The closed channel yields no more events; a publish after unsubscribe reaches nobody.
        hub.publish("alice", TaskEvent(2, "EXECUTED"))
        assertFailsWith<ClosedReceiveChannelException> { events.receive() }
    }

    @Test
    fun `a full subscriber buffer drops oldest and never blocks the publisher, keeping the newest event`() = runBlocking {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        // Far more than the 64-slot buffer, with nobody draining: every publish must return without suspending
        // (DROP_OLDEST), so the run coroutine is never blocked by a stuck client.
        withTimeout(1000) {
            for (i in 1..500) hub.publish("alice", TaskEvent(i.toLong(), "EXECUTED"))
        }
        val drained = buildList { while (true) { add(events.tryReceive().getOrNull() ?: break) } }
        assertTrue(drained.size <= 64, "buffer must stay bounded, got ${drained.size}")
        assertTrue(drained.isNotEmpty())
        // The most recent event is always retained; the oldest are the ones dropped.
        assertEquals(500L, drained.last().taskId)
    }

    @Test
    fun `isDraining is false until beginDraining`() {
        val hub = TaskCompletionHub()
        assertFalse(hub.isDraining())
        hub.beginDraining()
        assertTrue(hub.isDraining())
    }

    @Test
    fun `broadcastDraining closes every open stream and returns the count`() {
        val hub = TaskCompletionHub()
        val alice = hub.subscribe("alice")
        val bobTab1 = hub.subscribe("bob")
        val bobTab2 = hub.subscribe("bob")

        assertEquals(3, hub.broadcastDraining(), "every open stream across principals is closed")

        // A closed stream ends its SSE handler, which the browser's EventSource then reconnects.
        for (stream in listOf(alice, bobTab1, bobTab2)) {
            assertTrue(stream.tryReceive().isClosed, "the stream is closed by the drain")
        }
    }

    @Test
    fun `awaitDrained blocks until the closed streams deregister, then reports drained`() {
        val hub = TaskCompletionHub()
        val stream = hub.subscribe("alice")
        hub.beginDraining()
        hub.broadcastDraining()

        // broadcastDraining closes the channel but the subscriber map only empties when the handler's `finally`
        // unsubscribes (off-thread in production). Until then the hub is not drained: the wait must report that
        // rather than return early, so shutdown keeps the process alive for the reconnect hint to flush.
        assertFalse(hub.awaitDrained(50), "still holding a closed-but-not-yet-deregistered stream")

        // Simulate the handler's finally running after it flushed its hint.
        hub.unsubscribe("alice", stream)
        assertTrue(hub.awaitDrained(200), "drained once the last stream deregisters")
    }

    @Test
    fun `once draining, a new subscribe is refused with an already-closed channel`() {
        val hub = TaskCompletionHub()
        hub.beginDraining()

        val late = hub.subscribe("alice")
        // Handed back closed so its handler ends at once (and the browser re-homes), and never registered —
        // so a browser reconnecting onto this draining instance is bounced straight back off it.
        assertTrue(late.tryReceive().isClosed, "a subscribe during drain is handed a closed channel")
        hub.publish("alice", TaskEvent(1, "EXECUTED"))
        assertTrue(late.tryReceive().isClosed, "and it was never registered, so nothing is delivered")
    }

    @Test
    fun `concurrent subscribe cannot survive a drain`() {
        // The subscribe barrier must be atomic with the drain: however subscribes interleave with
        // beginDraining + broadcastDraining, none may be left OPEN (registered but unclosed) — such a stream
        // would linger on the draining instance, never told to reconnect. Without subscribe()'s lock, a check
        // that reads shuttingDown as false can insert its (open) channel after broadcastDraining already swept.
        // subscribe() owns the channel it returns (the SSE handler does not supply one, unlike a proxy Events
        // stream), so the deterministic parking-close ProxyEventsHubTest uses is not available here — this
        // stresses the check-then-insert window across many interleavings instead.
        repeat(200) {
            val hub = TaskCompletionHub()
            val start = CountDownLatch(1)
            val streams = ConcurrentLinkedQueue<ReceiveChannel<TaskEvent>>()
            val subscribers = (1..12).map { i ->
                Thread { start.await(); streams.add(hub.subscribe("p-$i")) }
            }
            val drainer = Thread { start.await(); hub.beginDraining(); hub.broadcastDraining() }
            val threads = subscribers + drainer
            threads.forEach(Thread::start)
            start.countDown()
            threads.forEach { it.join(5000) }
            assertTrue(threads.none(Thread::isAlive), "no thread should be stuck (a deadlock regression)")

            assertEquals(12, streams.size, "every subscribe returned a stream")
            // Each stream must be closed — broadcast-closed if it registered before the drain, refuse-closed if
            // it raced in after the flag. An OPEN (empty, not closed) stream is a lost subscribe that would sit
            // on the dying instance forever.
            streams.forEach { assertTrue(it.tryReceive().isClosed, "every stream must be closed by the drain, none left open") }
        }
    }
}
