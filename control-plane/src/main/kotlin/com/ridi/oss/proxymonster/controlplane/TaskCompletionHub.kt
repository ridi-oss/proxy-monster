package com.ridi.oss.proxymonster.controlplane

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** A terminal transition of one task, pushed to the parties watching it so their web tab updates without
 *  waiting for the next poll. [status] is the task's new state (EXECUTED / FAILED / CANCELLED). */
@Serializable
data class TaskEvent(val taskId: Long, val status: String)

/**
 * In-process per-principal fan-out of task terminal transitions, so a watching web tab is pushed the state
 * change instead of discovering it on its next poll. Single-replica by design: the run coroutine that
 * terminalizes a task and the SSE stream that serves the principal live in the same process, so a plain
 * in-memory map suffices. A multi-replica LISTEN/NOTIFY fan-out is a separate follow-up (docs/backlog.md).
 *
 * The push is a pure accelerator: the web still polls the task to a terminal state, so a dropped or missed
 * event only delays the update to the next poll — it is never the source of truth. Accordingly [publish] is
 * non-blocking (a full subscriber buffer drops the oldest event rather than suspending the run coroutine),
 * and delivery is best-effort.
 */
class TaskCompletionHub {
    private val log = LoggerFactory.getLogger(TaskCompletionHub::class.java)

    // principal -> its open SSE subscriber channels (one per browser tab/connection). CopyOnWriteArrayList so
    // publish iterates without locking against concurrent subscribe/unsubscribe.
    private val subscribers = ConcurrentHashMap<String, CopyOnWriteArrayList<Channel<TaskEvent>>>()

    // Serializes the drain transition against subscribe(), so a read of [shuttingDown] and the map mutation
    // that follows it are one atomic step: a subscribe racing the drain either registers before it (and is
    // then closed by [broadcastDraining]) or sees the flag and is refused — never lands after the broadcast
    // and lingers on the draining instance. publish() stays lock-free (the query hot path, best-effort).
    private val lock = Any()

    // Set once on shutdown, under [lock], before closing the open streams: a fresh subscribe is refused so a
    // browser reconnecting onto this draining instance is bounced straight back off it.
    private var shuttingDown = false

    /** Enter drain mode: refuse new subscribers. Idempotent; call before [broadcastDraining]. */
    fun beginDraining() = synchronized(lock) { shuttingDown = true }

    /** True once the process is draining — the SSE handler reads it on a closed channel to decide whether the
     *  close is a shutdown (send the reconnect hint) or an ordinary end. */
    fun isDraining(): Boolean = synchronized(lock) { shuttingDown }

    /** Open a subscription for [principal]; the caller must [unsubscribe] it (a `finally`) when the stream ends. */
    fun subscribe(principal: String): ReceiveChannel<TaskEvent> {
        // Bounded + DROP_OLDEST: a slow/stuck client can never make publish() suspend or grow memory unbounded;
        // it just loses the oldest pushes and catches up on its next poll.
        val channel = Channel<TaskEvent>(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)
        synchronized(lock) {
            // Draining: hand back an already-closed channel so the handler ends at once and re-homes, without
            // registering it (which would leave a stream behind the broadcast, never told to leave).
            if (shuttingDown) channel.close() else subscribers.compute(principal) { _, list ->
                (list ?: CopyOnWriteArrayList()).apply { add(channel) }
            }
        }
        return channel
    }

    fun unsubscribe(principal: String, channel: ReceiveChannel<TaskEvent>) {
        subscribers.computeIfPresent(principal) { _, list ->
            list.remove(channel)
            list.ifEmpty { null }
        }
        (channel as? Channel<TaskEvent>)?.close()
    }

    /** Best-effort push of [event] to every open stream of [principal]. Never blocks the caller. */
    fun publish(principal: String, event: TaskEvent) {
        val channels = subscribers[principal] ?: return
        for (channel in channels) channel.trySend(event)
    }

    /** Push [event] to a set of parties (e.g. a workflow task's requester + approver), de-duplicated. */
    fun publish(principals: Collection<String>, event: TaskEvent) {
        for (principal in principals.toSet()) publish(principal, event)
    }

    /**
     * On shutdown, close every open SSE stream. The close is the guarantee: it ends the handler, which ends the
     * Ktor response, so the browser's EventSource reconnects — re-homing to the replacement instance (a rolling
     * restart) instead of waiting out the LB's connection drain on the departing one. Before ending, the handler
     * sees [isDraining] and writes a short `retry` so that reconnect is prompt rather than on the ~3s default;
     * that hint is best-effort (it must flush before the HTTP server stops — see [awaitDrained] — and a straggler
     * simply reconnects on the default, which the console's poll covers). Returns the number of streams closed.
     * Call after [beginDraining].
     */
    fun broadcastDraining(): Int = synchronized(lock) {
        var closed = 0
        for ((_, channels) in subscribers) {
            for (channel in channels) {
                channel.close()
                closed++
            }
        }
        return closed
    }

    /**
     * Block up to [timeoutMs] for every stream closed by [broadcastDraining] to run its handler's close path —
     * the `send(retry)` then the `finally` that unsubscribes, which is what empties [subscribers]. This is what
     * keeps the process (and so Netty's I/O threads) alive long enough for the retry to flush before shutdown
     * tears the HTTP server down; a straggler just falls through to the browser's default reconnect, which the
     * console's poll then covers. Returns true if the hub emptied in time.
     */
    fun awaitDrained(timeoutMs: Long): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (subscribers.isNotEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(20)
        }
        return subscribers.isEmpty()
    }
}
