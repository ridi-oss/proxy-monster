package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import org.slf4j.LoggerFactory
import java.sql.Connection
import java.time.Duration

/**
 * The notification layer's one entry point (docs/notifications.md).
 *
 * The workflow calls [emit] inside the transaction that changes a task; [runDrainLoop] delivers what was
 * queued. Nothing here can fail a task: the console is the system of record and a notification is a courtesy,
 * so every failure path logs and moves on.
 */
class NotificationService(
    private val store: NotificationStore,
    private val recipients: RecipientResolver,
    private val transports: List<NotificationTransport>,
    private val accessStore: AccessStore,
    private val queryResultStore: QueryResultStore?,
    private val webBaseUrl: String,
    private val disclosure: StatementDisclosure,
    private val defaultLocale: String,
) {
    private val log = LoggerFactory.getLogger(NotificationService::class.java)

    val enabled: Boolean get() = transports.isNotEmpty()

    // A wake so a queued notification delivers in ~ms instead of on the next poll tick. Conflated: many
    // wakes between two drains collapse into one, since a drain claims the whole due batch regardless.
    // The poll in [runDrainLoop] stays as a backstop, so a missed wake only delays, never loses. This is
    // the in-process form of the LISTEN/NOTIFY the multi-instance follow-up will use (docs/backlog.md).
    private val wakeSignal = Channel<Unit>(Channel.CONFLATED)

    /**
     * Nudge the drainer to run now. Call this AFTER the transaction that enqueued a row has COMMITTED —
     * `enqueue` runs inside the caller's transaction, so an earlier wake would race a row a separate
     * connection cannot yet see. A wake before commit is not wrong, only wasted: the drain finds nothing
     * and the backstop poll picks the row up on its next tick.
     */
    fun wake() {
        if (enabled) wakeSignal.trySend(Unit)
    }

    /**
     * Drain on every wake, and on a timer as a backstop. The timer covers a wake dropped by a crash or a
     * wake that raced a not-yet-committed row; the wake covers the latency a bare timer would add to an
     * interactive click, where a user is watching the message and re-clicks if it does not move.
     */
    suspend fun runDrainLoop(pollInterval: Duration) {
        if (!enabled) return
        while (true) {
            // withTimeoutOrNull returns null on the poll deadline, Unit on a wake — either way, drain.
            try {
                withTimeoutOrNull(pollInterval.toMillis()) { wakeSignal.receive() }
            } catch (_: TimeoutCancellationException) {
                // Defensive: a receive cancelled by the timeout still falls through to a drain.
            }
            runCatching { drainOnce() }.onFailure { log.warn("notification drain failed", it) }
        }
    }

    /**
     * Queue [event] for everyone who should hear it, in the caller's transaction [c] — so the rows commit
     * with the task change itself and a crash cannot leave a request decided with nobody told.
     *
     * Never throws: a routing or enqueue failure must not roll back the task the caller is committing.
     */
    fun emit(c: Connection, event: NotificationEvent, req: AccessRequest) {
        if (!enabled) return
        runCatching {
            val targets: List<Pair<String, NotificationKind>> = when (event) {
                // emit() only carries later events; a pending request is enqueued by emitRequested. Kept total.
                NotificationEvent.TASK_REQUESTED -> recipients.recipientsFor(req).map { it to NotificationKind.APPROVER }
                // Every later event edits the threads of exactly the people who were TOLD about the request —
                // the approver side is those who got it (recomputing eligibility would skip an approver whose
                // role was revoked since, stranding their live buttons), the requester side is the requester's
                // own receipt. A self-approving requester holds both threads and both are updated.
                else -> buildList {
                    for (r in store.recipientsOfRequest(c, req.id)) add(r to NotificationKind.APPROVER)
                    for (r in listOfNotNull(req.decidedBy, req.executedBy).filter { it.isNotBlank() }) {
                        add(r to NotificationKind.APPROVER)
                    }
                    add(req.principal to NotificationKind.REQUESTER)
                }
            }
            for (transport in transports) {
                for ((recipient, kind) in targets) {
                    store.enqueue(c, req.id, event, transport.name, recipient, kind)
                }
            }
        }.onFailure { log.warn("notification emit failed task={} event={}", req.id, event.wire, it) }
    }

    /**
     * Queue the "needs approval" notification for a request being CREATED, in the caller's transaction.
     *
     * The row is not yet visible to another connection, so routing is given the facts we already hold rather
     * than a re-read: requester, datasource, and the role are all the eligibility decision needs.
     */
    fun emitRequested(
        c: Connection,
        taskId: Long,
        requester: String,
        ds: com.ridi.oss.proxymonster.controlplane.Datasource,
        roleName: String?,
    ) {
        if (!enabled) return
        runCatching {
            val subject = AccessRequest(
                id = taskId,
                principal = requester,
                datasourceId = ds.id,
                datasourceName = ds.name,
                roleName = roleName,
                requestedDurationSec = 0,
                status = "PENDING",
                createdAt = "",
            )
            val approvers = recipients.recipientsFor(subject)
            for (transport in transports) {
                for (recipient in approvers) {
                    store.enqueue(c, taskId, NotificationEvent.TASK_REQUESTED, transport.name, recipient, NotificationKind.APPROVER)
                }
                // The requester always gets their own receipt. When they are also an approver it is a separate
                // thread from their approver message (distinct kind), so both are delivered, not deduped.
                store.enqueue(c, taskId, NotificationEvent.TASK_SUBMITTED, transport.name, requester, NotificationKind.REQUESTER)
            }
        }.onFailure { log.warn("notification emit failed task={} event=task.requested", taskId, it) }
    }

    /**
     * Announce a task that has reached a terminal state. Unlike [emit] this owns its own transaction: the
     * run settles outside the execution commit, so there is no caller transaction to join.
     */
    fun enqueueTerminal(req: AccessRequest) {
        if (!enabled) return
        val event = NotificationEvent.forTerminalStatus(req.status) ?: return
        runCatching { store.inTransaction { c -> emit(c, event, req) } }
            .onFailure { log.warn("notification terminal emit failed task={}", req.id, it) }
        // The transaction above has committed, so the "finished" update is safe to deliver now rather than
        // on the next poll — this is the second half of an approve-and-run the user is watching for.
        wake()
    }

    /** Claim and deliver one batch. Returns how many rows were attempted. */
    suspend fun drainOnce(batch: Int = DRAIN_BATCH): Int {
        if (!enabled) return 0
        val rows = runCatching { store.claimDue(batch) }.getOrElse {
            log.warn("notification claim failed", it)
            return 0
        }
        for (row in rows) {
            runCatching { deliver(row) }
                .onFailure {
                    // retryOrGiveUp, not a raw markRetry: a DETERMINISTIC throw (a malformed Slack payload,
                    // a render bug) would otherwise stay PENDING forever, and an ordered claim of such rows
                    // starves every newer notification behind them. Bound it by MAX_ATTEMPTS like any failure.
                    log.warn("notification delivery threw task={} event={}", row.taskId, row.event.wire, it)
                    retryOrGiveUp(row, "unhandled: ${it.message}")
                }
        }
        return rows.size
    }

    private suspend fun deliver(row: OutboxRow) {
        val transport = transports.firstOrNull { it.name == row.transport }
            ?: return store.markDead(row.id, "no such transport")

        // An update must not overtake the message it edits. Defer it (without burning an attempt) so it leaves
        // the due set instead of re-filling the ordered claim batch every poll while the earlier event is
        // backed off — otherwise low-id waiters can starve newer notifications under a Slack outage.
        if (row.event.isUpdate && store.hasEarlierPending(row)) return store.defer(row.id, Duration.ofSeconds(BACKOFF_BASE_SEC))

        val req = accessStore.getRequest(row.taskId)
            ?: return store.markDead(row.id, "task no longer exists")

        val locale = store.localeOf(row.recipient) ?: defaultLocale
        val message = buildMessage(row, req, transport)
        val existingRef = store.externalRef(row.taskId, transport.name, row.recipient, row.kind)

        // A non-update row that already left a ref was delivered by a prior attempt whose markSent did not
        // commit (the post succeeded, then the bookkeeping failed). Re-posting would double-send and strand
        // the first message's live approve/deny buttons — adopt the ref and finish the row instead.
        if (!row.event.isUpdate && existingRef != null) return store.markSent(row.id)

        // Editing an existing message needs only its ref, not the recipient's address — so an update skips
        // the address lookup entirely. For Slack that is two saved round-trips per update
        // (users.lookupByEmail + conversations.open), which is most of an interactive click's felt latency:
        // the "running" and "finished" edits are the ones a user is watching for.
        val editingExisting = row.event.isUpdate && existingRef != null && transport.supportsUpdate
        val result = if (editingExisting) {
            transport.update(existingRef!!, message, locale)
        } else {
            // A transient address-resolution failure (a network blip, a rate limit) is THROWN, not returned —
            // retry the recipient rather than dead-letter them. A null is a genuine no-address and drops.
            val address = try {
                transport.addressOf(row.recipient, store.emailOf(row.recipient))
            } catch (e: Exception) {
                return retryOrGiveUp(row, "address lookup: ${e.message}")
            } ?: return store.markDead(row.id, "no address on ${transport.name}")
            transport.deliver(address, message, locale)
        }

        when (result) {
            is DeliveryResult.Sent -> {
                store.rememberMessage(row.taskId, transport.name, row.recipient, row.kind, result.externalRef)
                store.markSent(row.id)
            }
            is DeliveryResult.Drop -> store.markDead(row.id, result.reason)
            is DeliveryResult.Retry -> retryOrGiveUp(row, result.reason)
        }
    }

    /** Retry [row] with backoff, or dead-letter it once [MAX_ATTEMPTS] is reached. */
    private fun retryOrGiveUp(row: OutboxRow, reason: String?) {
        if (row.attempts + 1 >= MAX_ATTEMPTS) {
            store.markDead(row.id, "gave up after ${row.attempts + 1}: $reason")
        } else {
            store.markRetry(row.id, reason ?: "unknown", backoffFor(row.attempts))
        }
    }

    /** The recipient's saved language, for localizing a Slack click reply (null → the caller's default). */
    fun localeOf(principal: String): String? = store.localeOf(principal)

    private fun buildMessage(row: OutboxRow, req: AccessRequest, transport: NotificationTransport): NotificationMessage {
        // The disclosure decision: mode × event × hint. The hint (statementCarriesProtectedLiteral) flags a
        // predicate comparing a literal against a CLASSIFIED column — a protected value sitting in the query
        // text, where masking never reaches it; NULL (never analyzed) counts as "might carry one". AUTO shows
        // only a cleared statement. FULL shows it to PENDING approvers regardless, then — once the task is
        // handled (every other event) — falls back to AUTO, so a PII value does not persist in the channel.
        // The requester's own receipt (SUBMITTED) never carries the statement: they authored it, and keeping
        // it out leaves that message disclosure-free.
        val cleared = req.statementCarriesProtectedLiteral == false
        // `pending` is the LIVE task state, not merely the request event: a backed-off task.requested that
        // finally delivers after the task was decided must not be the first to surface a flagged statement
        // under FULL. Once the status leaves PENDING, FULL falls back to the hint like every handled message.
        val pending = row.event == NotificationEvent.TASK_REQUESTED && req.status == "PENDING"
        val show = row.event != NotificationEvent.TASK_SUBMITTED &&
            discloseStatement(disclosure, pending = pending, cleared = cleared)
        val statement = renderStatement(req.sql, show, transport.statementHardLimit)
        // The requester's receipt names who was actually asked — the durable task.requested recipients, not a
        // fresh eligibility recompute that role churn between enqueue and delivery could drift from (and that
        // would re-run Cedar per candidate). Plain identities, resolved to display by the transport without an
        // `<@id>` ping, since each already got their own message.
        val notifiedApprovers = if (row.event == NotificationEvent.TASK_SUBMITTED) {
            store.recipientsOfRequest(req.id).filter { it != req.principal }.sorted()
        } else {
            emptyList()
        }
        // Result-derived facts (row count, error code) are a cardinality/existence oracle, so they go only to
        // the two identities that authored the run — the requester and the principal who actually executed it.
        // A merely eligible co-approver hears that the task finished, never how many rows it returned.
        val meta = queryResultStore
            ?.takeIf { row.recipient == req.principal || row.recipient == req.executedBy }
            ?.meta(req.id)
        return NotificationMessage(
            event = row.event,
            taskId = req.id,
            requester = req.principal,
            datasource = req.datasourceName ?: "—",
            roleName = req.roleName,
            reason = req.reason,
            statement = statement,
            decidedBy = req.decidedBy,
            approved = when (req.status) {
                "REJECTED" -> false
                "APPROVED", "EXECUTING", "EXECUTED" -> true
                else -> null
            },
            rowCount = meta?.rowCount,
            errorCode = meta?.errorCode,
            deepLink = URLBuilder(webBaseUrl).appendPathSegments("workflows", req.id.toString()).buildString(),
            actions = actionsFor(row.event, req, statement),
            notifiedApprovers = notifiedApprovers,
        )
    }

    /**
     * What the recipient may do from the message.
     *
     * `[open]` is always there. `[approve and run]` is offered ONLY while the task is still pending AND the
     * message carries the WHOLE statement — approving is vouching for a specific statement, and a truncated
     * one is worse than none, since the elided tail is exactly where a dangerous predicate would sit. The
     * test is what was rendered, never which mode the operator configured. `[deny]` needs no such gate:
     * refusing something you have not fully read is always safe.
     */
    private fun actionsFor(
        event: NotificationEvent,
        req: AccessRequest,
        statement: RenderedStatement,
    ): Set<NotificationAction> = buildSet {
        add(NotificationAction.OPEN)
        if (event == NotificationEvent.TASK_REQUESTED && req.status == "PENDING") {
            add(NotificationAction.DENY)
            // Approve-and-run also RUNS the query, which needs result storage — without it the click would
            // approve but never start the run, so the button is not offered when it cannot be honored.
            if (statement.complete && queryResultStore != null) add(NotificationAction.APPROVE_AND_RUN)
        }
    }

    /** Exponential, capped. A transient Slack outage should not hammer it every tick. */
    private fun backoffFor(attempts: Int): Duration =
        Duration.ofSeconds(minOf(BACKOFF_CAP_SEC, BACKOFF_BASE_SEC shl minOf(attempts, 6)))

    companion object {
        const val DRAIN_BATCH = 32
        const val MAX_ATTEMPTS = 6
        private const val BACKOFF_BASE_SEC = 15L
        private const val BACKOFF_CAP_SEC = 900L
    }
}
