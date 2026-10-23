package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.RequestEvents
import java.sql.Connection
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource

/** A delivered message that later timeline entries are posted into as replies. */
data class MessageThread(
    val taskId: Long,
    val transport: String,
    val recipient: String,
    val externalRef: String,
    val lastEventId: Long,
    val kind: NotificationKind = NotificationKind.APPROVER,
)

/** One queued delivery, as the drainer sees it. */
data class OutboxRow(
    val id: Long,
    val taskId: Long,
    val event: NotificationEvent,
    val transport: String,
    val recipient: String,
    val kind: NotificationKind,
    val attempts: Int,
)

/**
 * The durable notification queue (docs/notifications.md, "Delivery").
 *
 * [enqueue] takes a caller-supplied [Connection] so the row commits in the SAME transaction as the task state
 * change it describes: a crash can never leave a request approved with nobody told. Everything after that is
 * best-effort — a delivery failure never touches the task, because the console is the system of record and a
 * notification is a courtesy.
 */
class NotificationStore(private val dataSource: DataSource) {

    /**
     * Queue one delivery, in the caller's transaction. Idempotent per (task, event, transport, recipient,
     * kind): an event emitted twice for one recipient+kind collapses onto the existing row rather than sending
     * twice — but the same recipient's requester-side and approver-side threads ([kind]) stay separate.
     */
    fun enqueue(
        c: Connection,
        taskId: Long,
        event: NotificationEvent,
        transport: String,
        recipient: String,
        kind: NotificationKind,
    ) {
        // An update redraws the message from the request's current state, so a repeat (a second edit, or a
        // decision after an edit) re-queues its row instead of collapsing onto it.
        val onConflict = if (event.isUpdate) {
            "DO UPDATE SET status = 'PENDING', attempts = 0, next_attempt_at = now(), last_error = NULL, updated_at = now()"
        } else {
            "DO NOTHING"
        }
        c.prepareStatement(
            """INSERT INTO notification_outbox (task_id, event, transport, recipient, kind)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (task_id, event, transport, recipient, kind) $onConflict""",
        ).use { ps ->
            ps.setLong(1, taskId)
            ps.setString(2, event.wire)
            ps.setString(3, transport)
            ps.setString(4, recipient)
            ps.setString(5, kind.wire)
            ps.executeUpdate()
        }
    }

    /**
     * Claim up to [limit] due rows for delivery.
     *
     * `FOR UPDATE SKIP LOCKED` so a second drainer (or a restart overlapping the previous process) never
     * double-sends: a row being worked on is invisible to the other claimant rather than blocking it. The
     * claim only reserves — it does not advance `attempts`, which [markSent]/[markFailed] own, so a crash
     * mid-delivery leaves the row claimable again rather than silently consuming a retry.
     */
    fun claimDue(limit: Int): List<OutboxRow> = dataSource.inTxLocal { c ->
        c.prepareStatement(
            """SELECT id, task_id, event, transport, recipient, kind, attempts
               FROM notification_outbox
               WHERE status = 'PENDING' AND next_attempt_at <= now()
               ORDER BY id
               LIMIT ?
               FOR UPDATE SKIP LOCKED""",
        ).use { ps ->
            ps.setInt(1, limit)
            val out = ArrayList<OutboxRow>()
            val poison = ArrayList<Pair<Long, String>>()
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    val wire = rs.getString("event")
                    val event = NotificationEvent.fromWire(wire)
                    if (event == null) {
                        // An unknown event wire value can never be delivered; dead-letter it in the claim
                        // transaction rather than skip it, or it stays PENDING and is re-selected every drain.
                        poison += rs.getLong("id") to wire
                        continue
                    }
                    out += OutboxRow(
                        id = rs.getLong("id"),
                        taskId = rs.getLong("task_id"),
                        event = event,
                        transport = rs.getString("transport"),
                        recipient = rs.getString("recipient"),
                        kind = NotificationKind.fromWire(rs.getString("kind")),
                        attempts = rs.getInt("attempts"),
                    )
                }
            }
            for ((id, wire) in poison) {
                c.prepareStatement("UPDATE notification_outbox SET status = 'DEAD', last_error = ? WHERE id = ?").use { u ->
                    u.setString(1, "unknown event: $wire")
                    u.setLong(2, id)
                    u.executeUpdate()
                }
            }
            out
        }
    }

    fun markSent(id: Long) = update(id, "SENT", null, null)

    /** Terminal failure: the row is done and its last error kept for an operator to read. */
    fun markDead(id: Long, error: String) = update(id, "DEAD", error, null)

    /** Transient failure: stay PENDING, burn an attempt, and come back after [backoff]. */
    fun markRetry(id: Long, error: String, backoff: java.time.Duration) =
        update(id, "PENDING", error, Instant.now().plus(backoff))

    /**
     * Push a waiting row's next attempt out WITHOUT burning an attempt. Used when an update must wait for an
     * earlier pending sibling: a bare skip would leave the row due, and the ordered `claimDue` LIMIT would
     * re-select these low-id no-ops every poll, starving newer notifications while an earlier row is backed
     * off. Deferring takes the waiter out of the due set until it is worth re-checking.
     */
    fun defer(id: Long, backoff: java.time.Duration) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                "UPDATE notification_outbox SET next_attempt_at = ?, updated_at = now() WHERE id = ?",
            ).use { ps ->
                ps.setTimestamp(1, Timestamp.from(Instant.now().plus(backoff)))
                ps.setLong(2, id)
                ps.executeUpdate()
            }
        }
    }

    private fun update(id: Long, status: String, error: String?, nextAttempt: Instant?) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE notification_outbox
                   SET status = ?, last_error = ?, attempts = attempts + 1,
                       next_attempt_at = COALESCE(?, next_attempt_at), updated_at = now()
                   WHERE id = ?""",
            ).use { ps ->
                ps.setString(1, status)
                ps.setString(2, error?.take(500))
                if (nextAttempt == null) ps.setNull(3, java.sql.Types.TIMESTAMP) else ps.setTimestamp(3, Timestamp.from(nextAttempt))
                ps.setLong(4, id)
                ps.executeUpdate()
            }
        }
    }

    /**
     * True when an earlier event for this (task, transport, recipient) is still queued.
     *
     * An update must not overtake the message it edits, so a decided/finished event waits while its
     * `task.requested` is still pending. Ordering is by id, which is insertion order.
     */
    fun hasEarlierPending(row: OutboxRow): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT 1 FROM notification_outbox
               WHERE task_id = ? AND transport = ? AND recipient = ? AND kind = ? AND status = 'PENDING' AND id < ?
               LIMIT 1""",
        ).use { ps ->
            ps.setLong(1, row.taskId)
            ps.setString(2, row.transport)
            ps.setString(3, row.recipient)
            ps.setString(4, row.kind.wire)
            ps.setLong(5, row.id)
            ps.executeQuery().use { it.next() }
        }
    }

    /** The last of [events] delivered to [row]'s thread, the one its message now shows. */
    fun lastDrawn(row: OutboxRow, events: List<NotificationEvent>): NotificationEvent? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT event FROM notification_outbox
               WHERE task_id = ? AND transport = ? AND recipient = ? AND kind = ? AND status = 'SENT' AND event = ANY (?)
               ORDER BY updated_at DESC, id DESC LIMIT 1""",
        ).use { ps ->
            ps.setLong(1, row.taskId)
            ps.setString(2, row.transport)
            ps.setString(3, row.recipient)
            ps.setString(4, row.kind.wire)
            ps.setArray(5, c.createArrayOf("text", events.map { it.wire }.toTypedArray()))
            ps.executeQuery().use { rs -> if (rs.next()) NotificationEvent.fromWire(rs.getString(1)) else null }
        }
    }

    /** The handle a delivered message left behind for this thread, or null when nothing has been delivered. */
    fun externalRef(taskId: Long, transport: String, recipient: String, kind: NotificationKind): String? =
        dataSource.connection.use { c ->
            c.prepareStatement(
                "SELECT external_ref FROM notification_message WHERE task_id = ? AND transport = ? AND recipient = ? AND kind = ?",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.setString(2, transport)
                ps.setString(3, recipient)
                ps.setString(4, kind.wire)
                ps.executeQuery().use { if (it.next()) it.getString(1) else null }
            }
        }

    /**
     * Everyone the "needs approval" notification for [taskId] was enqueued to. A later event edits exactly
     * these messages in place — so an approver whose role was revoked after they were notified still has their
     * live "needs approval" buttons removed, instead of a recompute silently skipping them. Reads on the
     * caller's connection [c] since a later event runs inside the decide/terminal transaction.
     */
    fun recipientsOfRequest(c: Connection, taskId: Long): Set<String> =
        c.prepareStatement("SELECT DISTINCT recipient FROM notification_outbox WHERE task_id = ? AND event = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.setString(2, NotificationEvent.TASK_REQUESTED.wire)
            ps.executeQuery().use { rs ->
                val out = LinkedHashSet<String>()
                while (rs.next()) out += rs.getString(1)
                out
            }
        }

    /** Threads on [transports] with timeline entries past their cursor. */
    fun threadsBehind(transports: Set<String>): List<MessageThread> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT m.task_id, m.transport, m.recipient, m.external_ref, m.last_event_id, m.kind FROM notification_message m
               WHERE m.transport = ANY (?) AND EXISTS (
                   SELECT 1 FROM request_event e WHERE e.request_id = m.task_id AND e.id > m.last_event_id)
               ORDER BY m.task_id, m.id""",
        ).use { ps ->
            ps.setArray(1, c.createArrayOf("text", transports.toTypedArray()))
            ps.executeQuery().use { rs ->
                val out = ArrayList<MessageThread>()
                while (rs.next()) {
                    out += MessageThread(
                        rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5),
                        NotificationKind.fromWire(rs.getString(6)),
                    )
                }
                out
            }
        }
    }

    /** The thread whose first message is [externalRef], on one of [transports]. */
    fun threadAt(externalRef: String, transports: Set<String>): MessageThread? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT task_id, transport, recipient, external_ref, last_event_id FROM notification_message
               WHERE external_ref = ? AND transport = ANY (?) LIMIT 1""",
        ).use { ps ->
            ps.setString(1, externalRef)
            ps.setArray(2, c.createArrayOf("text", transports.toTypedArray()))
            ps.executeQuery().use { rs ->
                if (rs.next()) MessageThread(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5)) else null
            }
        }
    }

    fun eventsAfter(taskId: Long, afterId: Long) = dataSource.connection.use { RequestEvents.after(it, taskId, afterId) }

    fun advanceThread(thread: MessageThread, eventId: Long) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                "UPDATE notification_message SET last_event_id = ? WHERE external_ref = ? AND transport = ? AND last_event_id < ?",
            ).use { ps ->
                ps.setLong(1, eventId)
                ps.setString(2, thread.externalRef)
                ps.setString(3, thread.transport)
                ps.setLong(4, eventId)
                ps.executeUpdate()
            }
        }
    }

    fun addPost(eventId: Long, externalRef: String) = dataSource.connection.use { RequestEvents.addPost(it, eventId, externalRef) }

    fun postsOf(eventId: Long): List<String> = dataSource.connection.use { RequestEvents.postsOf(it, eventId) }

    /** Who may approve [taskId], as recorded when it was filed, without its requester. */
    fun approversOf(taskId: Long): List<String> = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT principal FROM request_participant WHERE request_id = ? AND kind = 'approver' ORDER BY created_at, principal",
        ).use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> val o = ArrayList<String>(); while (rs.next()) o += rs.getString(1); o }
        }
    }

    /** [recipientsOfRequest] on the store's own connection, for a delivery-time read outside any transaction. */
    fun recipientsOfRequest(taskId: Long): Set<String> =
        dataSource.connection.use { c -> recipientsOfRequest(c, taskId) }

    /** Record where a message landed, so a later event edits that thread in place. */
    fun rememberMessage(taskId: Long, transport: String, recipient: String, kind: NotificationKind, externalRef: String) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO notification_message (task_id, transport, recipient, kind, external_ref, last_event_id)
                   VALUES (?, ?, ?, ?, ?, (SELECT coalesce(max(id), 0) FROM request_event WHERE request_id = ?))
                   ON CONFLICT (task_id, transport, recipient, kind)
                   DO UPDATE SET external_ref = EXCLUDED.external_ref, updated_at = now()""",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.setString(2, transport)
                ps.setString(3, recipient)
                ps.setString(4, kind.wire)
                ps.setString(5, externalRef)
                ps.setLong(6, taskId)
                ps.executeUpdate()
            }
        }
    }

    /** Run [body] in one transaction — for a caller that has no transaction of its own to join. */
    fun <T> inTransaction(body: (Connection) -> T): T = dataSource.inTxLocal(body)

    /** The recipient's saved language, or null when they have never expressed one. */
    fun localeOf(principal: String): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT locale FROM app_user WHERE principal = ?").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { if (it.next()) it.getString(1) else null }
        }
    }

    fun emailOf(principal: String): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT email FROM app_user WHERE principal = ?").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { if (it.next()) it.getString(1) else null }
        }
    }

    /** Set the caller's own language. Returns false when no directory row exists for them. */
}

/** Local transaction helper — the claim needs its row locks held to the commit. */
internal inline fun <T> DataSource.inTxLocal(body: (Connection) -> T): T = connection.use { c ->
    c.autoCommit = false
    try {
        val result = body(c)
        c.commit()
        result
    } catch (e: Throwable) {
        runCatching { c.rollback() }
        throw e
    } finally {
        runCatching { c.autoCommit = true }
    }
}
