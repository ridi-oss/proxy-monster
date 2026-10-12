package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.PullRequestRef
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.source.Repo
import com.ridi.oss.proxymonster.controlplane.support.FakeSourceAdapter
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PullRequestCommentTransportTest {
    private val adapter = FakeSourceAdapter()
    private val transport = PullRequestCommentTransport(adapter)

    private fun request(source: String, repository: String? = null, pr: Int? = null) = AccessRequest(
        id = 9, principal = "alice@example.com", requestedDurationSec = 0, status = "PENDING", createdAt = "",
        kind = "QUERY", source = source, revision = 1,
        pullRequest = if (repository != null && pr != null) PullRequestRef(repository, pr) else null,
    )

    private fun message(
        event: NotificationEvent,
        failure: String? = null,
        failedStatement: FailedStatement? = null,
    ) = NotificationMessage(
        event = event, taskId = 9, revision = 1, requester = "alice@example.com", datasource = "shop-mysql", roleName = "migrator",
        reason = null, statement = RenderedStatement("SELECT 1", true), decidedBy = "bob@example.com", approved = true,
        rowCount = 4242, deepLink = "https://console.example.com/workflows/9", actions = emptySet(),
        source = "github", path = "db/orders/00042_backfill.sql", schema = "orders", statementCount = 2, failure = failure,
        failedStatement = failedStatement,
    )

    @Test
    fun `only a pull-request request has a task address`() {
        assertNull(transport.taskAddress(request("console")))
        assertNull(transport.taskAddress(request("github")))
        assertEquals("acme/shop#7", transport.taskAddress(request("github", "acme/shop", 7)))
        assertTrue(transport.addressesTasks)
    }

    @Test
    fun `an alert gets its own comment that a later update leaves alone`() {
        runBlocking {
            transport.deliver("acme/shop#7", message(NotificationEvent.TASK_MERGED_WITHOUT_FILE), "en")
            transport.update("acme/shop#7", message(NotificationEvent.TASK_EXECUTED), "en")
        }
        assertEquals(listOf("task-9-task.merged_without_file", "task-9"), adapter.upserts.map { it.marker })
    }

    @Test
    fun `deliver upserts one marked comment per task and never carries a row count`() {
        val result = runBlocking { transport.deliver("acme/shop#7", message(NotificationEvent.TASK_EXECUTED), "en") }
        assertEquals(DeliveryResult.Sent("acme/shop#7"), result)
        val upsert = adapter.upserts.single()
        assertEquals(Repo("acme", "shop"), upsert.repo)
        assertEquals(7, upsert.pr)
        assertEquals("task-9", upsert.marker)
        assertTrue(upsert.body.contains("00042_backfill.sql") && upsert.body.contains("shop-mysql/orders"), upsert.body)
        assertTrue(upsert.body.contains("Statements run: 2"), upsert.body)
        assertFalse(upsert.body.contains("4242"), upsert.body)

        runBlocking { transport.update("acme/shop#7", message(NotificationEvent.TASK_FAILED, failure = "ERROR 1062"), "en") }
        assertEquals("task-9", adapter.upserts.last().marker)
        assertTrue(adapter.upserts.last().body.contains("ERROR 1062"))
    }

    @Test
    fun `a failure names the failed statement and quotes its SQL before the error`() {
        val failed = FailedStatement(1, "ALTER TABLE orders ADD COLUMN note TEXT")
        val body = transport.body(message(NotificationEvent.TASK_FAILED, "ERROR 1146 (42S02)", failed), "en")
        assertTrue(body.contains("failed at statement 2 of 2"), body)
        val sqlAt = body.indexOf("```sql\nALTER TABLE orders ADD COLUMN note TEXT\n```")
        assertTrue(sqlAt >= 0 && sqlAt < body.indexOf("ERROR 1146 (42S02)"), body)
        assertFalse(body.contains("4242"), body)

        val ko = transport.body(message(NotificationEvent.TASK_FAILED, "ERROR 1146", failed), "ko")
        assertFalse(ko.contains("comment."), ko)
        assertTrue(ko.contains("구문 2개 중 2번째") && ko.contains("ALTER TABLE orders"), ko)
    }

    @Test
    fun `a long failed statement is truncated`() {
        val long = "INSERT INTO t VALUES " + "(1),".repeat(400)
        val body = transport.body(message(NotificationEvent.TASK_FAILED, "ERROR", FailedStatement(0, long)), "en")
        assertTrue(body.contains("failed at statement 1 of 2"), body)
        assertTrue(body.contains(long.take(PullRequestCommentTransport.STATEMENT_MAX_CHARS) + "…"), body)
        assertFalse(body.contains(long), body)
    }

    @Test
    fun `a malformed address drops`() {
        val result = runBlocking { transport.deliver("not-an-address", message(NotificationEvent.TASK_EXECUTED), "en") }
        assertTrue(result is DeliveryResult.Drop)
    }

    @Test
    fun `every comment key resolves in both locales`() {
        for (locale in MessageCatalog.LOCALES) {
            for (event in NotificationEvent.entries) {
                assertFalse(transport.body(message(event), locale).contains("comment."), "$event/$locale")
            }
        }
    }
}
