package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The durable outbox on real PostgreSQL. The load-bearing cases are the ones a unit test with an in-memory
 * queue cannot reach: `FOR UPDATE SKIP LOCKED` so a second drainer never double-sends, the backoff that keeps
 * a retried row out of the claim until it is due, and the earlier-pending check that stops a "decided" edit
 * from overtaking the "requested" message it edits.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationStoreTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var store: NotificationStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        store = NotificationStore(fx.dataSource)
    }

    // claimDue's LIMIT is global, so a leftover row from another test would pollute a claim. Start each test
    // with an empty outbox; the access_request rows the FKs need are left in place.
    @BeforeEach
    fun clean() {
        fx.dataSource.connection.use { c ->
            c.createStatement().use {
                it.executeUpdate("DELETE FROM notification_message")
                it.executeUpdate("DELETE FROM notification_outbox")
            }
        }
    }

    /** A fresh access_request the outbox rows can FK to. */
    private fun newTask(principal: String = "req@example.com"): Long =
        fx.accessStore.createQueryRequest(
            principal = principal, datasourceId = fx.datasource.id, statements = listOf("SELECT 1"),
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "ALLOW",
        ).id

    private fun attemptsOf(id: Long): Int = fx.dataSource.connection.use { c ->
        c.prepareStatement("SELECT attempts FROM notification_outbox WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { it.next(); it.getInt(1) }
        }
    }

    private fun statusOf(id: Long): String = fx.dataSource.connection.use { c ->
        c.prepareStatement("SELECT status FROM notification_outbox WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { it.next(); it.getString(1) }
        }
    }

    @Test
    fun `enqueue is idempotent per task-event-transport-recipient`() {
        val task = newTask()
        fx.dataSource.connection.use { c ->
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "a@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "a@x", NotificationKind.APPROVER)
        }
        assertEquals(1, store.claimDue(10).count { it.taskId == task }, "the second enqueue collapsed onto the first")
    }

    @Test
    fun `claimDue returns due pending rows in id order up to the limit`() {
        val task = newTask()
        fx.dataSource.connection.use { c ->
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "one@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "two@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "three@x", NotificationKind.APPROVER)
        }
        val claimed = store.claimDue(2).filter { it.taskId == task }
        assertEquals(2, claimed.size, "the limit is honored")
        assertEquals(claimed.map { it.id }.sorted(), claimed.map { it.id }, "returned in id (insertion) order")
    }

    /**
     * The claim a second drainer would run must skip a row the first is holding, not block on it or return it.
     * Hold a row's lock in one open transaction, then claim from the pool: the locked row is invisible.
     */
    @Test
    fun `claimDue skips a row another transaction holds locked`() {
        val task = newTask()
        fx.dataSource.connection.use { c ->
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "locked@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "free@x", NotificationKind.APPROVER)
        }
        val rows = store.claimDue(10).filter { it.taskId == task }.sortedBy { it.id }
        val lockedId = rows.first().id
        val freeId = rows.last().id

        val holder = fx.dataSource.connection
        try {
            holder.autoCommit = false
            holder.prepareStatement("SELECT id FROM notification_outbox WHERE id = ? FOR UPDATE").use { ps ->
                ps.setLong(1, lockedId); ps.executeQuery().use { it.next() }
            }
            // Another claimant runs now, while the lock above is held.
            val claimedIds = store.claimDue(10).map { it.id }
            assertFalse(lockedId in claimedIds, "the locked row must be skipped, never double-claimed")
            assertTrue(freeId in claimedIds, "the unlocked sibling is still claimable")
        } finally {
            holder.rollback(); holder.autoCommit = true; holder.close()
        }
    }

    @Test
    fun `markSent is terminal and increments attempts`() {
        val task = newTask()
        fx.dataSource.connection.use { c -> store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "s@x", NotificationKind.APPROVER) }
        val row = store.claimDue(10).first { it.taskId == task }
        store.markSent(row.id)
        assertEquals("SENT", statusOf(row.id))
        assertEquals(1, attemptsOf(row.id))
        assertTrue(store.claimDue(10).none { it.id == row.id }, "a SENT row is never claimed again")
    }

    @Test
    fun `markRetry keeps the row pending but out of the claim until it is due`() {
        val task = newTask()
        fx.dataSource.connection.use { c -> store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "r@x", NotificationKind.APPROVER) }
        val row = store.claimDue(10).first { it.taskId == task }

        store.markRetry(row.id, "ratelimited", Duration.ofHours(1))
        assertEquals("PENDING", statusOf(row.id))
        assertTrue(store.claimDue(10).none { it.id == row.id }, "a backed-off row is not due yet")

        // A backoff already in the past makes it claimable again — the retry actually happens.
        store.markRetry(row.id, "ratelimited", Duration.ofSeconds(-1))
        assertTrue(store.claimDue(10).any { it.id == row.id }, "once due, the row is reclaimable")
    }

    @Test
    fun `markDead is terminal`() {
        val task = newTask()
        fx.dataSource.connection.use { c -> store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "d@x", NotificationKind.APPROVER) }
        val row = store.claimDue(10).first { it.taskId == task }
        store.markDead(row.id, "channel_not_found")
        assertEquals("DEAD", statusOf(row.id))
        assertTrue(store.claimDue(10).none { it.id == row.id })
    }

    @Test
    fun `an update waits while an earlier event for the same recipient is still pending`() {
        val task = newTask()
        fx.dataSource.connection.use { c ->
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "slack", "u@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_DECIDED, "slack", "u@x", NotificationKind.APPROVER)
        }
        val rows = store.claimDue(10).filter { it.taskId == task }.sortedBy { it.id }
        val requested = rows.first { it.event == NotificationEvent.TASK_REQUESTED }
        val decided = rows.first { it.event == NotificationEvent.TASK_DECIDED }

        assertTrue(store.hasEarlierPending(decided), "the decided edit must wait for the requested message")
        store.markSent(requested.id)
        assertFalse(store.hasEarlierPending(decided), "once the requested is delivered, the edit may go")
    }

    @Test
    fun `rememberMessage upserts the external ref`() {
        val task = newTask()
        assertNull(store.externalRef(task, "slack", "m@x", NotificationKind.APPROVER), "nothing delivered yet")
        store.rememberMessage(task, "slack", "m@x", NotificationKind.APPROVER, "C1:100")
        assertEquals("C1:100", store.externalRef(task, "slack", "m@x", NotificationKind.APPROVER))
        store.rememberMessage(task, "slack", "m@x", NotificationKind.APPROVER, "C1:200")
        assertEquals("C1:200", store.externalRef(task, "slack", "m@x", NotificationKind.APPROVER), "a later delivery overwrites the handle")
    }

    @Test
    fun `locale and email round-trip for a directory user, and setLocale reports a missing one`() {
        assertFalse(store.setLocale("nobody@example.com", "ko"), "no directory row to set a preference on")

        fx.dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO app_user (principal, email) VALUES (?, ?)").use { ps ->
                ps.setString(1, "dir@example.com"); ps.setString(2, "dir-mail@example.com"); ps.executeUpdate()
            }
        }
        assertNull(store.localeOf("dir@example.com"), "no preference expressed yet")
        assertEquals("dir-mail@example.com", store.emailOf("dir@example.com"))
        assertTrue(store.setLocale("dir@example.com", "ko"))
        assertEquals("ko", store.localeOf("dir@example.com"))
    }
}
