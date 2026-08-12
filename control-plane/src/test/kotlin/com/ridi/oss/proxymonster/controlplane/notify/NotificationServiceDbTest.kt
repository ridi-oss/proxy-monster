package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.DecryptedResult
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import com.ridi.oss.proxymonster.controlplane.ResultCrypto
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.FakeTransport
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Duration
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The drain orchestration on real PostgreSQL, with an in-memory transport so the assertions are about the
 * SERVICE — deliver vs edit-in-place, the ordering gate, retry/drop/exhaustion, terminal announce, and the
 * wake that makes an interactive click's edit land in ~ms rather than on the next poll. Routing itself is
 * pinned separately (NotificationRoutingDbTest); here the candidate source is empty so recipients come only
 * from the events' own always-include parties, keeping the drain assertions deterministic.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationServiceDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var store: NotificationStore
    private lateinit var transport: FakeTransport
    private lateinit var svc: NotificationService

    @BeforeAll
    fun setupClass() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    @BeforeEach
    fun setup() {
        fx.dataSource.connection.use { c ->
            c.createStatement().use {
                it.executeUpdate("DELETE FROM notification_message")
                it.executeUpdate("DELETE FROM notification_outbox")
            }
        }
        store = NotificationStore(fx.dataSource)
        transport = FakeTransport()
        svc = NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(transport),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            defaultLocale = "en",
        )
    }

    private fun newTask(principal: String = "req@example.com"): AccessRequest =
        fx.accessStore.createQueryRequest(
            principal = principal, datasourceId = fx.datasource.id, sql = "SELECT 1",
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "ALLOW",
        )

    private fun enqueue(task: Long, event: NotificationEvent, recipient: String, transportName: String = "fake") {
        fx.dataSource.connection.use { c -> store.enqueue(c, task, event, transportName, recipient) }
    }

    private fun statusOf(task: Long, event: NotificationEvent, recipient: String): String =
        fx.dataSource.connection.use { c ->
            c.prepareStatement("SELECT status FROM notification_outbox WHERE task_id=? AND event=? AND recipient=?").use { ps ->
                ps.setLong(1, task); ps.setString(2, event.wire); ps.setString(3, recipient)
                ps.executeQuery().use { it.next(); it.getString(1) }
            }
        }

    private fun setAttempts(task: Long, event: NotificationEvent, attempts: Int) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE notification_outbox SET attempts=? WHERE task_id=? AND event=?").use { ps ->
                ps.setInt(1, attempts); ps.setLong(2, task); ps.setString(3, event.wire); ps.executeUpdate()
            }
        }
    }

    private fun countRows(task: Long, event: NotificationEvent, recipient: String): Int =
        fx.dataSource.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM notification_outbox WHERE task_id=? AND event=? AND recipient=?").use { ps ->
                ps.setLong(1, task); ps.setString(2, event.wire); ps.setString(3, recipient)
                ps.executeQuery().use { it.next(); it.getInt(1) }
            }
        }

    private fun setHint(task: Long, value: Boolean?) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET statement_carries_protected_literal = ? WHERE id = ?").use { ps ->
                if (value == null) ps.setNull(1, java.sql.Types.BOOLEAN) else ps.setBoolean(1, value)
                ps.setLong(2, task); ps.executeUpdate()
            }
        }
    }

    private fun setStatus(task: Long, status: String) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = ? WHERE id = ?").use { ps ->
                ps.setString(1, status); ps.setLong(2, task); ps.executeUpdate()
            }
        }
    }

    private fun adminRoleId(): Long = fx.policyStore.listRoles().first { it.name == "system:admin" }.id

    private fun serviceWith(disclosure: StatementDisclosure, candidates: List<String> = emptyList()) =
        NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { candidates },
            transports = listOf(transport),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = disclosure,
            defaultLocale = "en",
        )

    @Test
    fun `emitRequested sends the requester a receipt and never routes them the approver message`() {
        val task = newTask(principal = "req@example.com").id
        fx.dataSource.connection.use { c ->
            svc.emitRequested(c, task, "req@example.com", fx.datasource, roleName = null)
        }
        // The requester always gets a task.submitted receipt (here with no approvers, the candidate source is
        // empty) — and never a task.requested addressed to themselves, whatever routing would resolve.
        assertEquals("PENDING", statusOf(task, NotificationEvent.TASK_SUBMITTED, "req@example.com"))
        assertEquals(0, countRows(task, NotificationEvent.TASK_REQUESTED, "req@example.com"))
    }

    @Test
    fun `an eligible requester is still dropped from the approver message and only gets the receipt`() {
        // Make the requester resolve as a genuine approver candidate, so the exclusion filter has something to
        // drop — without it they would receive both task.requested and task.submitted.
        val requester = "self@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(requester, adminRoleId()))
        val routing = serviceWith(StatementDisclosure.AUTO, candidates = listOf(requester))
        val task = newTask(principal = requester).id
        fx.dataSource.connection.use { c -> routing.emitRequested(c, task, requester, fx.datasource, roleName = null) }
        assertEquals(0, countRows(task, NotificationEvent.TASK_REQUESTED, requester))
        assertEquals("PENDING", statusOf(task, NotificationEvent.TASK_SUBMITTED, requester))
    }

    @Test
    fun `the requester receipt lists the durable task-requested recipients and carries no statement`() = runBlocking {
        val task = newTask(principal = "req@example.com").id
        setHint(task, true) // even a flagged task: the receipt stays disclosure-free
        // Two approvers were actually asked (durable rows). The candidate source is empty, so a receipt that
        // recomputed eligibility would list nobody — asserting bob+carol proves it reads the outbox instead.
        enqueue(task, NotificationEvent.TASK_REQUESTED, "bob@x")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "carol@x")
        enqueue(task, NotificationEvent.TASK_SUBMITTED, "req@example.com")
        svc.drainOnce()
        val receipt = transport.delivered.single { it.event == NotificationEvent.TASK_SUBMITTED }
        assertEquals(listOf("bob@x", "carol@x"), receipt.notifiedApprovers, "the receipt names who was actually asked")
        assertNull(receipt.statement.text, "the requester's receipt never carries the statement")
    }

    @Test
    fun `full shows a flagged statement while pending and hides it once the task is handled`() = runBlocking {
        val task = newTask().id
        setHint(task, true) // flagged: auto would withhold this
        enqueue(task, NotificationEvent.TASK_REQUESTED, "bob@x")
        svc.drainOnce() // svc is FULL
        assertNotNull(transport.delivered.single().statement.text, "full shows a pending approver even a flagged statement")

        // The same request, now handled, on a fresh (late/replayed) task.requested row: full falls back to the
        // hint and withholds it, so a protected literal never surfaces for the first time after the decision.
        setStatus(task, "REJECTED")
        transport.delivered.clear()
        enqueue(task, NotificationEvent.TASK_REQUESTED, "carol@x")
        svc.drainOnce()
        assertNull(transport.delivered.single().statement.text, "once handled, full hides a flagged statement even on a task.requested")
    }

    @Test
    fun `drain delivers a pending notification and records its handle`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()

        assertEquals(1, transport.delivered.size)
        assertEquals("addr:sam@x", transport.delivered.first().to)
        assertEquals(NotificationEvent.TASK_REQUESTED, transport.delivered.first().event)
        assertEquals("SENT", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"))
        assertEquals("ref-fake", store.externalRef(task, "fake", "sam@x"), "the handle is remembered for later edits")
    }

    @Test
    fun `an update edits by stored handle and skips the address lookup`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()
        transport.addressCalls.set(0)

        enqueue(task, NotificationEvent.TASK_DECIDED, "sam@x")
        svc.drainOnce()

        assertEquals(1, transport.updated.size, "the decided event edits the existing message")
        assertEquals("ref-fake", transport.updated.first().ref)
        assertEquals(0, transport.addressCalls.get(), "editing needs only the handle — no addressOf round-trip")
    }

    @Test
    fun `an update waits while the requested message it edits is still pending`() = runBlocking {
        val task = newTask().id
        transport.deliverResult = DeliveryResult.Retry("ratelimited") // the requested stays pending
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        enqueue(task, NotificationEvent.TASK_DECIDED, "sam@x")
        svc.drainOnce()

        assertEquals(1, transport.delivered.size, "only the requested was attempted")
        assertTrue(transport.updated.isEmpty(), "the decided edit must not overtake the message it edits")
        assertEquals("PENDING", statusOf(task, NotificationEvent.TASK_DECIDED, "sam@x"), "it waits for the next drain")
    }

    @Test
    fun `a permanent drop marks the row dead`() = runBlocking {
        val task = newTask().id
        transport.deliverResult = DeliveryResult.Drop("channel_not_found")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()
        assertEquals("DEAD", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"))
    }

    @Test
    fun `a retry that exhausts the attempt budget dies rather than looping forever`() = runBlocking {
        val task = newTask().id
        transport.deliverResult = DeliveryResult.Retry("ratelimited")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        setAttempts(task, NotificationEvent.TASK_REQUESTED, NotificationService.MAX_ATTEMPTS - 1)
        svc.drainOnce()
        assertEquals("DEAD", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"), "gave up after the last attempt")
    }

    @Test
    fun `a deterministic delivery exception is bounded by the attempt budget, not retried forever`() = runBlocking {
        val task = newTask().id
        transport.deliverThrows = IllegalStateException("malformed payload")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        setAttempts(task, NotificationEvent.TASK_REQUESTED, NotificationService.MAX_ATTEMPTS - 1)
        svc.drainOnce()
        assertEquals(
            "DEAD",
            statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"),
            "an unhandled throw goes through retryOrGiveUp — it dies instead of pinning the row PENDING and starving the claim",
        )
    }

    @Test
    fun `a requested row whose ref was already recorded is adopted, not re-posted`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        // A prior attempt posted (ref recorded) but its markSent did not commit: the row is still PENDING, yet
        // a delivery handle already exists. Re-posting would double-send and strand the first message's buttons.
        store.rememberMessage(task, "fake", "sam@x", "ref-prior")
        svc.drainOnce()

        assertTrue(transport.delivered.isEmpty(), "the existing ref is adopted; the message is not sent again")
        assertEquals("SENT", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"), "the row is finished, not left pending")
        assertEquals("ref-prior", store.externalRef(task, "fake", "sam@x"), "the original handle is kept for later edits")
    }

    @Test
    fun `a recipient with no address is dropped as dead, not retried forever`() = runBlocking {
        val task = newTask().id
        transport.address = { null }
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()
        assertEquals("DEAD", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"))
        assertTrue(transport.delivered.isEmpty(), "no address means nothing was delivered")
    }

    @Test
    fun `a row for an unknown transport is dead`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x", transportName = "ghost")
        svc.drainOnce()
        assertEquals("DEAD", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"))
    }

    @Test
    fun `result facts reach the requester and executor but never a mere co-approver`() = runBlocking {
        // A finished task with a stored 3-row result. startRun records executed_by on the query_result child;
        // AccessRequest.executedBy is derived from it, so owner@x becomes both requester and executor.
        val req = newTask(principal = "owner@x")
        val resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        resultStore.startRun(req.id, "owner@x")
        resultStore.completeRun(req.id, DecryptedResult(listOf("id"), listOf(listOf("1"), listOf("2"), listOf("3"))), retentionSec = 3600)

        val svcWithResults = NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(transport),
            accessStore = fx.accessStore,
            queryResultStore = resultStore,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            defaultLocale = "en",
        )
        // The terminal event goes to the requester AND a mere co-approver who neither requested nor ran it.
        enqueue(req.id, NotificationEvent.TASK_EXECUTED, "owner@x")
        enqueue(req.id, NotificationEvent.TASK_EXECUTED, "coapprover@x")
        svcWithResults.drainOnce()

        val toOwner = transport.delivered.first { it.to == "addr:owner@x" }
        val toCoApprover = transport.delivered.first { it.to == "addr:coapprover@x" }
        assertEquals(3, toOwner.rowCount, "the requester/executor sees the row count")
        assertEquals(null, toCoApprover.rowCount, "a co-approver gets no row-count oracle — it is a cardinality leak")
    }

    @Test
    fun `emit queues the always-include parties in the caller's transaction`() = runBlocking {
        val task = newTask(principal = "owner@x")
        fx.dataSource.connection.use { c -> svc.emit(c, NotificationEvent.TASK_DECIDED, task) }
        // candidateSource is empty, so the requester is here only because a decided event always includes them.
        assertEquals("PENDING", statusOf(task.id, NotificationEvent.TASK_DECIDED, "owner@x"))
    }

    @Test
    fun `enqueueTerminal announces a terminal event and it drains`() = runBlocking {
        val created = newTask(principal = "owner@x")
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='EXECUTED' WHERE id=?").use { ps ->
                ps.setLong(1, created.id); ps.executeUpdate()
            }
        }
        svc.enqueueTerminal(fx.accessStore.getRequest(created.id)!!)
        svc.drainOnce()

        assertEquals(NotificationEvent.TASK_EXECUTED, transport.delivered.single().event)
        assertEquals("addr:owner@x", transport.delivered.single().to)
    }

    @Test
    fun `a wake drains immediately rather than waiting for the poll`() = runBlocking {
        val task = newTask().id
        val loop = launch(Dispatchers.IO) { svc.runDrainLoop(Duration.ofSeconds(30)) } // poll far longer than the test
        try {
            enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
            svc.wake()
            transport.awaitDelivery(timeoutMs = 5_000) // completes well under the 30s poll
            assertEquals("addr:sam@x", transport.delivered.first().to)
        } finally {
            loop.cancel()
        }
    }
}
