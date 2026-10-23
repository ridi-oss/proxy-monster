package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.DecryptedResult
import com.ridi.oss.proxymonster.controlplane.ParticipantKind
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import com.ridi.oss.proxymonster.controlplane.RequestEdit
import com.ridi.oss.proxymonster.controlplane.RequestEventKind
import com.ridi.oss.proxymonster.controlplane.RequestEvents
import com.ridi.oss.proxymonster.controlplane.RequestParticipants
import com.ridi.oss.proxymonster.controlplane.ResultCrypto
import com.ridi.oss.proxymonster.controlplane.requestNotifier
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
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
import kotlin.test.assertFalse
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
            principal = principal, datasourceId = fx.datasource.id, statements = listOf("SELECT 1"),
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "ALLOW",
        )

    private fun enqueue(
        task: Long,
        event: NotificationEvent,
        recipient: String,
        kind: NotificationKind = NotificationKind.APPROVER,
        transportName: String = "fake",
    ) {
        fx.dataSource.connection.use { c -> store.enqueue(c, task, event, transportName, recipient, kind) }
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
    fun `a self-approving requester gets BOTH the approver message and their own receipt`() = runBlocking {
        // Policy lets the requester approve their own request, so recipientsFor (Cedar) returns them — never
        // post-filtered. They are a plain recipient of both threads, and both are delivered, not deduped.
        val requester = "self@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(requester, adminRoleId()))
        val routing = serviceWith(StatementDisclosure.AUTO, candidates = listOf(requester))
        val task = newTask(principal = requester).id
        fx.dataSource.connection.use { c -> routing.emitRequested(c, task, requester, fx.datasource, roleName = null) }
        routing.drainOnce()
        val toRequester = transport.delivered.filter { it.to == "addr:$requester" }.map { it.event }.toSet()
        assertEquals(
            setOf(NotificationEvent.TASK_REQUESTED, NotificationEvent.TASK_SUBMITTED),
            toRequester,
            "the requester receives BOTH the approver message and their receipt — neither is deduped away",
        )
    }

    @Test
    fun `a terminal event updates both threads of a self-approving requester`() = runBlocking {
        val requester = "self@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(requester, adminRoleId()))
        val routing = serviceWith(StatementDisclosure.AUTO, candidates = listOf(requester))
        val task = newTask(principal = requester).id
        fx.dataSource.connection.use { c -> routing.emitRequested(c, task, requester, fx.datasource, roleName = null) }
        routing.drainOnce() // both threads delivered, both refs remembered
        transport.updated.clear()
        val req = fx.accessStore.getRequest(task)!!
        fx.dataSource.connection.use { c -> routing.emit(c, NotificationEvent.TASK_DECIDED, req) }
        routing.drainOnce()
        assertEquals(
            2,
            transport.updated.count { it.event == NotificationEvent.TASK_DECIDED },
            "the decision edits both the approver-side message and the requester's receipt",
        )
    }

    @Test
    fun `the requester receipt lists the durable task-requested recipients and carries no statement`() = runBlocking {
        val task = newTask(principal = "req@example.com").id
        setHint(task, true) // even a flagged task: the receipt stays disclosure-free
        // Two approvers were actually asked (durable rows). The candidate source is empty, so a receipt that
        // recomputed eligibility would list nobody — asserting bob+carol proves it reads the outbox instead.
        enqueue(task, NotificationEvent.TASK_REQUESTED, "bob@x")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "carol@x")
        enqueue(task, NotificationEvent.TASK_SUBMITTED, "req@example.com", NotificationKind.REQUESTER)
        svc.drainOnce()
        val receipt = transport.delivered.single { it.event == NotificationEvent.TASK_SUBMITTED }
        assertEquals(listOf("bob@x", "carol@x"), receipt.notifiedApprovers, "the receipt names who was actually asked")
        assertNull(receipt.statement.text, "the requester's receipt never carries the statement")
    }

    @Test
    fun `only a cleared statement carries its whole text for a thread`() = runBlocking {
        for ((hint, full) in listOf(false to "SELECT 1", true to null, null to null)) {
            val task = newTask().id
            setHint(task, hint)
            transport.delivered.clear()
            enqueue(task, NotificationEvent.TASK_REQUESTED, "bob@x")
            svc.drainOnce() // svc is FULL, so every pending statement is shown
            val statement = transport.delivered.single().statement
            assertNotNull(statement.text, "hint=$hint")
            assertEquals(full, statement.full, "hint=$hint")
        }
    }

    @Test
    fun `the requester's later messages carry no statement for a thread their receipt never had`() = runBlocking {
        val task = newTask().id
        setHint(task, false)
        enqueue(task, NotificationEvent.TASK_DECIDED, "req@example.com", NotificationKind.REQUESTER)
        svc.drainOnce()
        val statement = transport.delivered.single().statement
        assertNotNull(statement.text)
        assertNull(statement.full)
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
        assertEquals("ref-fake", store.externalRef(task, "fake", "sam@x", NotificationKind.APPROVER), "the handle is remembered for later edits")
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
    fun `a repeated decision redraws the message again`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()
        repeat(2) {
            enqueue(task, NotificationEvent.TASK_DECIDED, "sam@x")
            svc.drainOnce()
        }
        assertEquals(2, transport.updated.count { it.event == NotificationEvent.TASK_DECIDED })
    }

    @Test
    fun `a channel message offers Review, withholds a flagged statement even under full, and names approvers and CCs`() = runBlocking {
        val channel = FakeTransport(name = "chan", channel = "C123")
        val shared = NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(transport, channel),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            defaultLocale = "en",
        )
        val task = newTask().id
        fx.dataSource.connection.use { c ->
            RequestParticipants.add(c, task, listOf("sam@x"), ParticipantKind.APPROVER)
            RequestParticipants.add(c, task, listOf("cc@x"), ParticipantKind.CC)
            shared.emitRequested(c, task, "req@example.com", fx.datasource, null)
        }
        shared.drainOnce()

        val posted = channel.delivered.single()
        assertEquals("C123", posted.to)
        assertEquals(setOf(NotificationAction.OPEN, NotificationAction.REVIEW), posted.actions)
        assertNull(posted.statement.text, "a channel never gets the full-disclosure statement of a flagged request")
        assertEquals(listOf("sam@x"), posted.approvers)
        assertEquals(listOf("cc@x"), posted.ccs)
    }

    @Test
    fun `a comment is posted into every other thread, never back into the one it came from, and edits follow`() = runBlocking {
        val threads = FakeTransport(name = "threads", supportsReplies = true)
        val svc = NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(threads),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.AUTO,
            defaultLocale = "en",
        )
        val task = newTask().id
        fx.dataSource.connection.use { c -> store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "threads", "sam@x", NotificationKind.APPROVER) }
        fx.dataSource.connection.use { c -> store.enqueue(c, task, NotificationEvent.TASK_SUBMITTED, "threads", "req@example.com", NotificationKind.REQUESTER) }
        svc.drainOnce()
        assertTrue(threads.replies.isEmpty(), "the request itself is not replayed into a new thread")

        val samThread = "thread:addr:sam@x:task.requested"
        val reqThread = "thread:addr:req@example.com:task.submitted"
        val comment = fx.dataSource.connection.use { c ->
            RequestEvents.record(c, task, RequestEventKind.COMMENT, "sam@x", "slack", "why the join?", samThread, "D1:9.9")
        }!!
        svc.drainOnce()
        assertEquals(listOf(reqThread to "*sam@x*: why the join?"), threads.replies)

        val edited = fx.dataSource.connection.use { c -> RequestEvents.editBySlackRef(c, "D1:9.9", "why this join?") }!!
        assertEquals(comment.id, edited.id)
        svc.propagate(edited)
        assertEquals(listOf<Pair<String, String?>>("$reqThread/reply1" to "*sam@x*: why this join?"), threads.replyEdits.toList())

        svc.drainOnce()
        assertEquals(1, threads.replies.size, "a drained entry is not posted twice")

        // A CC who is removed stops getting new entries in their thread.
        fx.dataSource.connection.use { c ->
            RequestParticipants.add(c, task, listOf("cc@x"), ParticipantKind.CC)
            store.enqueue(c, task, NotificationEvent.TASK_CC_ADDED, "threads", "cc@x", NotificationKind.CC)
        }
        svc.drainOnce()
        fx.dataSource.connection.use { c ->
            RequestParticipants.remove(c, task, "cc@x", ParticipantKind.CC)
            RequestEvents.record(c, task, RequestEventKind.COMMENT, "sam@x", "console", "after removal")
        }
        svc.drainOnce()
        assertTrue(threads.replies.none { (ref, text) -> "cc@x" in ref && "after removal" in text }, "got: ${threads.replies}")
        assertTrue(threads.replies.any { (ref, text) -> ref == samThread && "after removal" in text })
    }

    @Test
    fun `a CC change redraws every delivered message with the new list, and only a mention goes unannounced`() = runBlocking {
        val threads = FakeTransport(name = "threads", supportsReplies = true)
        val svc = NotificationService(
            store = store,
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(threads),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.AUTO,
            defaultLocale = "en",
        )
        val task = newTask().id
        fx.dataSource.connection.use { c ->
            store.enqueue(c, task, NotificationEvent.TASK_REQUESTED, "threads", "sam@x", NotificationKind.APPROVER)
            store.enqueue(c, task, NotificationEvent.TASK_SUBMITTED, "threads", "req@example.com", NotificationKind.REQUESTER)
        }
        svc.drainOnce()
        val samThread = "thread:addr:sam@x:task.requested"
        val reqThread = "thread:addr:req@example.com:task.submitted"
        // A decider who was never asked holds a message of their own, and sam's now shows the decision.
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'APPROVED', decided_by = 'dee@x' WHERE id = ?").use { it.setLong(1, task); it.executeUpdate() }
            svc.emit(c, NotificationEvent.TASK_DECIDED, fx.accessStore.getRequest(task, c)!!)
        }
        svc.drainOnce()
        val deeThread = "thread:addr:dee@x:task.decided"
        threads.updated.clear()

        fx.dataSource.connection.use { c ->
            RequestParticipants.add(c, task, listOf("cc@x"), ParticipantKind.CC)
            RequestEvents.record(c, task, RequestEventKind.CC_ADDED, "sam@x", "slack", "cc@x")
            val req = fx.accessStore.getRequest(task, c)!!
            svc.emitCcAdded(c, req, "cc@x")
            svc.emitCcChanged(c, req)
        }
        svc.drainOnce()
        assertEquals(
            setOf(
                samThread to NotificationEvent.TASK_DECIDED,
                reqThread to NotificationEvent.TASK_DECIDED,
                deeThread to NotificationEvent.TASK_DECIDED,
                "thread:addr:cc@x:task.cc_added" to NotificationEvent.TASK_CC_ADDED,
            ),
            threads.updated.map { it.ref to it.event }.toSet(),
            "each message is redrawn as its last event drew it",
        )
        assertTrue(threads.updated.all { it.redraw && it.ccs == listOf("cc@x") }, "got: ${threads.updated}")
        assertTrue(threads.replies.isEmpty(), "the mention already says who was added: ${threads.replies}")

        threads.updated.clear()
        fx.dataSource.connection.use { c ->
            RequestParticipants.remove(c, task, "cc@x", ParticipantKind.CC)
            RequestEvents.record(c, task, RequestEventKind.CC_REMOVED, "sam@x", "console", "cc@x")
        }
        assertTrue(requestNotifier(fx.accessStore, svc)(task, "cc-removed", null))
        svc.drainOnce()
        assertEquals(setOf(samThread, reqThread, deeThread), threads.updated.map { it.ref }.toSet())
        assertTrue(threads.updated.all { it.ccs.isEmpty() })
        assertEquals(setOf(samThread, reqThread, deeThread), threads.replies.map { it.first }.toSet(), "a console change is announced")
    }

    @Test
    fun `cp-go's request-notified signal enqueues a close and a new CC's thread`() {
        val task = newTask()
        val notify = requestNotifier(fx.accessStore, svc)
        assertTrue(notify(task.id, "cancelled", null))
        assertEquals(1, countRows(task.id, NotificationEvent.TASK_CANCELLED, task.principal))
        assertTrue(notify(task.id, "cc-added", "cc@x"))
        assertEquals(1, countRows(task.id, NotificationEvent.TASK_CC_ADDED, "cc@x"))
        assertFalse(notify(task.id, "cc-added", null), "a CC signal names the CC")
        assertTrue(notify(task.id, "cc-removed", null))
        assertTrue(notify(task.id, "commented", null))
        assertFalse(notify(task.id, "bogus", null))
    }

    @Test
    fun `role requests are announced and decided through AccessService, with role text`() = runBlocking {
        val approver = "role-approver@example.com"
        val roles = fx.policyStore.listRoles().associateBy { it.name }
        fx.policyStore.createAssignment(com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput(approver, roles.getValue("system:admin").id))
        val recorder = ManagementAuditRecorder(fx.auditStore)
        val access = com.ridi.oss.proxymonster.controlplane.AccessService(
            fx.accessStore, fx.datasourceStore, fx.auditStore, fx.roleResolver, fx.authz, recorder, svc,
        )
        val actor = AuditActor("req@example.com", channel = "console")
        val role = fx.policyStore.createRole(com.ridi.oss.proxymonster.controlplane.RoleInput("notify-role-${System.nanoTime()}"))
        val req = access.createRequest(
            "req@example.com", null, actor,
            com.ridi.oss.proxymonster.controlplane.AccessRequestInput(roleId = role.id, reason = "on call", requestedDurationSec = 1800),
        )
        val reset = access.createRequest(
            "req@example.com", null, actor,
            com.ridi.oss.proxymonster.controlplane.AccessRequestInput(roleId = role.id, reason = "again", requestedDurationSec = 1800),
        )
        assertEquals("PENDING", statusOf(req.id, NotificationEvent.TASK_SUBMITTED, "req@example.com"))
        assertEquals("PENDING", statusOf(reset.id, NotificationEvent.TASK_SUBMITTED, "req@example.com"))
        enqueue(req.id, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()

        val delivered = transport.delivered.filter { it.event in setOf(NotificationEvent.TASK_REQUESTED, NotificationEvent.TASK_SUBMITTED) }
        val open = NotificationAction.OPEN
        assertEquals(setOf(open, NotificationAction.APPROVE, NotificationAction.DENY), delivered.single { it.to == "addr:sam@x" }.actions)
        assertTrue(delivered.filter { it.to == "addr:req@example.com" }.all { it.actions == setOf(open, NotificationAction.CLOSE) })

        access.approve(approver, null, AuditActor(approver, channel = "console"), req.id, null)
        access.reject(approver, null, AuditActor(approver, channel = "console"), reset.id, "not now")
        assertEquals("PENDING", statusOf(req.id, NotificationEvent.TASK_DECIDED, "req@example.com"))
        assertEquals("PENDING", statusOf(reset.id, NotificationEvent.TASK_DECIDED, "req@example.com"))

        val text = NotificationRenderer().summary(
            NotificationMessage(
                event = NotificationEvent.TASK_REQUESTED, taskId = req.id, revision = 1, requester = "req@example.com",
                datasource = "", roleName = role.name, reason = null, statement = RenderedStatement(null, false),
                deepLink = "x", actions = emptySet(), requestKind = "ROLE", durationSec = 1800,
            ),
            "en",
        )
        assertEquals("*req@example.com* asks for the *${role.name}* role on *any datasource* for 30 minutes.", text)
        val resetText = NotificationRenderer().summary(
            NotificationMessage(
                event = NotificationEvent.TASK_REQUESTED, taskId = reset.id, revision = 1, requester = "req@example.com",
                datasource = "", roleName = null, reason = null, statement = RenderedStatement(null, false),
                deepLink = "x", actions = emptySet(), requestKind = "RATE_RESET", spentRate = "10000 rows / 1h",
            ),
            "en",
        )
        assertEquals("*req@example.com* asks to reset their spent result rates.\nSpent rate: 10000 rows / 1h", resetText)
    }

    @Test
    fun `an approved request offers unapprove and deny to approvers and close to the requester`() = runBlocking {
        val task = newTask().id
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'APPROVED', decided_by = 'sam@x', approved_at = now() WHERE id = ?")
                .use { ps -> ps.setLong(1, task); ps.executeUpdate() }
        }
        enqueue(task, NotificationEvent.TASK_DECIDED, "sam@x")
        enqueue(task, NotificationEvent.TASK_DECIDED, "req@example.com", NotificationKind.REQUESTER)
        svc.drainOnce()

        val byRecipient = transport.delivered.filter { it.event == NotificationEvent.TASK_DECIDED }.associateBy { it.to }
        val open = NotificationAction.OPEN
        // No result store here, so Run is not offered to anyone.
        assertEquals(setOf(open, NotificationAction.UNAPPROVE, NotificationAction.DENY), byRecipient.getValue("addr:sam@x").actions)
        assertEquals(setOf(open, NotificationAction.CLOSE), byRecipient.getValue("addr:req@example.com").actions)
    }

    @Test
    fun `every edit redraws the message with the new SQL and its approve buttons`() = runBlocking {
        val task = newTask().id
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()
        val recorder = ManagementAuditRecorder(fx.auditStore)
        val actor = AuditActor("req@example.com", clientAddr = null, channel = "console")
        for (sql in listOf("SELECT 2", "SELECT 3")) {
            fx.accessStore.editQueryRequest(task, listOf(sql), RequestEdit("h", null, "ALLOW", false), actor, recorder) { c, r ->
                svc.emit(c, NotificationEvent.TASK_EDITED, r)
            }
            svc.drainOnce()
        }

        val edits = transport.updated.filter { it.event == NotificationEvent.TASK_EDITED && it.ref == "ref-fake" }
        assertEquals(listOf("SELECT 2", "SELECT 3"), edits.map { it.statement.text }.distinct())
        assertEquals(listOf(2, 3), edits.map { it.revision }.distinct())
        // The requester's own receipt is redrawn too, with Close instead of the decision.
        assertTrue(
            listOf(2, 3).all { rev -> edits.any { it.revision == rev && NotificationAction.DENY in it.actions } },
            "a pending edit offers the decision again",
        )
    }

    @Test
    fun `an alert posts fresh and leaves the request message as the one later events edit`() = runBlocking {
        val task = newTask().id
        transport.deliverResult = DeliveryResult.Sent("ref-request")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()

        transport.deliverResult = DeliveryResult.Sent("ref-alert")
        enqueue(task, NotificationEvent.TASK_MERGED_WITHOUT_FILE, "sam@x")
        svc.drainOnce()
        assertEquals(NotificationEvent.TASK_MERGED_WITHOUT_FILE, transport.delivered.last().event, "the alert is a fresh post")
        assertEquals("ref-request", store.externalRef(task, "fake", "sam@x", NotificationKind.APPROVER))

        enqueue(task, NotificationEvent.TASK_EXECUTED, "sam@x")
        svc.drainOnce()
        assertEquals(listOf("ref-request"), transport.updated.map { it.ref })
    }

    @Test
    fun `an approval after a force-run edits the request message, not the force-run alert`() = runBlocking {
        val task = newTask().id
        transport.deliverResult = DeliveryResult.Sent("ref-request")
        enqueue(task, NotificationEvent.TASK_REQUESTED, "sam@x")
        svc.drainOnce()

        transport.deliverResult = DeliveryResult.Sent("ref-force-run")
        enqueue(task, NotificationEvent.TASK_FORCE_RUN, "sam@x")
        svc.drainOnce()
        assertEquals("ref-request", store.externalRef(task, "fake", "sam@x", NotificationKind.APPROVER))

        enqueue(task, NotificationEvent.TASK_DECIDED, "sam@x")
        svc.drainOnce()
        assertEquals(listOf("ref-request"), transport.updated.map { it.ref }, "the decision clears the request's buttons")
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
        store.rememberMessage(task, "fake", "sam@x", NotificationKind.APPROVER, "ref-prior")
        svc.drainOnce()

        assertTrue(transport.delivered.isEmpty(), "the existing ref is adopted; the message is not sent again")
        assertEquals("SENT", statusOf(task, NotificationEvent.TASK_REQUESTED, "sam@x"), "the row is finished, not left pending")
        assertEquals("ref-prior", store.externalRef(task, "fake", "sam@x", NotificationKind.APPROVER), "the original handle is kept for later edits")
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
        resultStore.startNextRun(req.id, "owner@x")
        val decisionId = fx.auditStore.insert(
            AuditEvent(principal = "owner@x", datasource = fx.datasource.name, statement = "select 1", decision = Decision.ALLOW),
        )
        resultStore.completeRun(req.id, DecryptedResult(listOf("id"), listOf(listOf("1"), listOf("2"), listOf("3"))), retentionSec = 3600, decisionId = decisionId)

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
