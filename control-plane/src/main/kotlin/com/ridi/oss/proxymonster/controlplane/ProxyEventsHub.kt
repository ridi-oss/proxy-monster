package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.ridi.oss.proxymonster.grpc.Refetch
import com.ridi.oss.proxymonster.grpc.controlEvent
import com.ridi.oss.proxymonster.grpc.openRunChannel
import com.ridi.oss.proxymonster.grpc.openTableDetailChannel
import com.ridi.oss.proxymonster.grpc.proxyCommand
import com.ridi.oss.proxymonster.grpc.refreshCatalog
import kotlinx.coroutines.channels.SendChannel
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Tracks the open proxy→control-plane `Events` streams (docs/datasource-registration.md). Two jobs on
 * one channel: **liveness** (an open stream == a proxy is attached to that datasource) and **refresh push**
 * (an admin "re-introspect now" is fanned out to the datasource's open stream(s) as a `RefreshCatalog`).
 *
 * The direction invariant holds: the control-plane never dials *into* a proxy — it only ever writes back
 * down a stream the proxy itself opened. Shared (via [ControlPlaneCore]) between the gRPC `events` handler
 * that registers streams and the HTTP admin route that requests a refresh.
 */
class ProxyEventsHub {
    private val log = LoggerFactory.getLogger(ProxyEventsHub::class.java)

    // datasource name -> the send channel of each currently-open Events stream (one per attached replica).
    private val streams = ConcurrentHashMap<String, CopyOnWriteArrayList<SendChannel<ControlEvent>>>()

    fun register(name: String, channel: SendChannel<ControlEvent>) {
        // Add INSIDE compute so it's atomic with deregister's remove-and-evict — otherwise a register that
        // creates the list, then adds outside the lock, could have its list evicted (empty) by a concurrent
        // deregister before the add, losing the registration.
        val open = streams.compute(name) { _, list -> (list ?: CopyOnWriteArrayList()).apply { add(channel) } }!!.size
        log.info("proxy attached to datasource '{}' ({} stream(s) open)", name, open)
    }

    fun deregister(name: String, channel: SendChannel<ControlEvent>) {
        // Remove the channel and drop the map entry entirely when its last stream closes, so a churn of
        // distinct names can't accumulate empty lists forever.
        streams.compute(name) { _, list ->
            list?.remove(channel)
            if (list.isNullOrEmpty()) null else list
        }
        log.info("proxy detached from datasource '{}' ({} stream(s) remaining)", name, streams[name]?.size ?: 0)
    }

    /**
     * Fan a `RefreshCatalog` out to every open stream for [name]. Returns the number of streams notified
     * (0 == no proxy currently attached — the admin's refresh is a no-op, reported honestly). A full send
     * buffer (a wedged proxy) is skipped, not blocked on.
     */
    fun requestRefresh(name: String): Int {
        val event = controlEvent { refreshCatalog = refreshCatalog {} }
        val channels = streams[name] ?: return 0
        var notified = 0
        for (channel in channels) if (channel.trySend(event).isSuccess) notified++
        return notified
    }

    /**
     * The outcome of asking a proxy to open a stream. NOT_ATTACHED and WEDGED look identical to a caller
     * that only gets a boolean, and they need different answers: the first means no proxy is there, the
     * second means one is registered but its channel will not take an event — a stream already closed by
     * a reset the server has not finished tearing down, or a consumer that stopped draining. Reporting
     * both as "no proxy attached" sends whoever debugs it looking for a proxy that is in fact running.
     */
    enum class Dispatch { SENT, NOT_ATTACHED, WEDGED }

    /**
     * Hand [event] to exactly one attached replica. The first non-blocking send that succeeds wins;
     * broadcasting would make every replica open a backend connection for the same request.
     *
     * A channel that refuses the event is deregistered here rather than left in place. It cannot serve a
     * later request either, and leaving it registered means `attached()` keeps reporting a proxy that
     * cannot be reached — the liveness view would lie until the stream's own close handler eventually ran.
     */
    private fun dispatch(name: String, what: String, event: ControlEvent): Dispatch {
        val channels = streams[name] ?: return Dispatch.NOT_ATTACHED
        val refused = mutableListOf<SendChannel<ControlEvent>>()
        for (channel in channels) {
            if (channel.trySend(event).isSuccess) {
                refused.forEach { deregisterWedged(name, it, what) }
                return Dispatch.SENT
            }
            refused += channel
        }
        refused.forEach { deregisterWedged(name, it, what) }
        return if (refused.isEmpty()) Dispatch.NOT_ATTACHED else Dispatch.WEDGED
    }

    private fun deregisterWedged(name: String, channel: SendChannel<ControlEvent>, what: String) {
        log.warn(
            "proxy stream for datasource '{}' would not accept {} (closed or its buffer is full); dropping it",
            name, what,
        )
        deregister(name, channel)
    }

    /**
     * Ask exactly one attached proxy replica to dial a run stream. The first successful non-blocking
     * send wins; broadcasting would make every replica open a backend connection for the same CP request.
     */
    fun requestOpenRun(
        name: String,
        sessionId: String,
        ephemeralToken: String,
        connectionId: com.google.protobuf.ByteString,
        onOpen: List<Refetch>,
    ): Dispatch {
        val event = controlEvent {
            openRunChannel = openRunChannel {
                this.sessionId = sessionId
                this.ephemeralToken = ephemeralToken
                this.connectionId = connectionId
                this.onOpen.addAll(onOpen.map { proxyCommand { refetch = it } })
            }
        }
        return dispatch(name, "an open-run request", event)
    }

    /** Ask exactly one attached proxy replica to dial an on-demand table-detail stream. */
    fun requestOpenTableDetail(name: String, sessionId: String, schema: String, table: String): Dispatch {
        val event = controlEvent {
            openTableDetailChannel = openTableDetailChannel {
                this.sessionId = sessionId
                this.schema = schema
                this.table = table
            }
        }
        return dispatch(name, "a table-detail request", event)
    }

    /** Datasource names with at least one open Events stream — the admin "which have a proxy attached". */
    fun attached(): Set<String> = streams.entries.filter { it.value.isNotEmpty() }.map { it.key }.toSet()
}
