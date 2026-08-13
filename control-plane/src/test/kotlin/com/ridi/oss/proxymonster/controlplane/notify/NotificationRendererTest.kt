package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The notification renderer over the shared [MessageCatalog]: every key resolves in every locale, and a
 * message never leaks the statement into a surface meant to withhold it. No DB.
 */
class NotificationRendererTest {

    private val renderer = NotificationRenderer()

    private fun message(
        event: NotificationEvent,
        statement: RenderedStatement,
        approved: Boolean? = null,
    ) = NotificationMessage(
        event = event,
        taskId = 42,
        requester = "alice@example.com",
        datasource = "acme-mysql",
        roleName = "pii-reader",
        reason = "investigating a billing dispute",
        statement = statement,
        decidedBy = "bob@example.com",
        approved = approved,
        rowCount = 3,
        deepLink = "https://console.example.com/workflows/42",
        actions = setOf(NotificationAction.OPEN),
    )

    /** en/ko parity: a key present in one locale and missing in the other renders the raw key. */
    @Test
    fun `every key resolves in both locales`() {
        for (locale in MessageCatalog.LOCALES) {
            for (event in NotificationEvent.entries) {
                for (approved in listOf(true, false)) {
                    val m = message(event, RenderedStatement("SELECT 1", complete = true), approved)
                    val summary = renderer.summary(m, locale)
                    assertTrue(summary.isNotBlank(), "$event/$locale summary")
                    assertFalse(summary.contains("task."), "$event/$locale fell through to a raw key: $summary")
                    assertFalse(renderer.fallbackText(m, locale).contains("task."), "$event/$locale fallback fell through")
                }
            }
            for (action in NotificationAction.entries) {
                assertFalse(renderer.actionLabel(action, locale).contains("action."), "$action/$locale")
            }
        }
    }

    @Test
    fun `an approved decision reads differently from a rejected one`() {
        val approved = renderer.summary(message(NotificationEvent.TASK_DECIDED, RenderedStatement("SELECT 1", true), approved = true), "en")
        val rejected = renderer.summary(message(NotificationEvent.TASK_DECIDED, RenderedStatement("SELECT 1", true), approved = false), "en")
        assertFalse(approved == rejected, "a recipient must be able to tell approval from denial")
        assertTrue(rejected.contains("denied", ignoreCase = true))
    }

    /** The plain-text fallback is shown by clients that render no blocks, so it must never carry the SQL. */
    @Test
    fun `the fallback line never carries the statement`() {
        val secret = "SELECT name FROM users WHERE ssn = '987-65-4320'"
        for (locale in MessageCatalog.LOCALES) {
            for (event in NotificationEvent.entries) {
                val text = renderer.fallbackText(message(event, RenderedStatement(secret, true)), locale)
                assertFalse(text.contains("ssn"), "$event/$locale fallback leaked the statement: $text")
            }
        }
    }

    /** A withheld or elided statement must SAY so, or the approver cannot tell it apart from a short query. */
    @Test
    fun `a withheld statement is announced rather than silently missing`() {
        val omitted = renderer.summary(message(NotificationEvent.TASK_REQUESTED, RenderedStatement(null, false)), "en")
        assertTrue(omitted.contains("Open the request", ignoreCase = true), omitted)

        val truncated = renderer.summary(message(NotificationEvent.TASK_REQUESTED, RenderedStatement("SELECT …", false)), "en")
        assertTrue(truncated.contains("Open the request", ignoreCase = true), truncated)

        val whole = renderer.summary(message(NotificationEvent.TASK_REQUESTED, RenderedStatement("SELECT 1", true)), "en")
        assertFalse(whole.contains("Open the request", ignoreCase = true), whole)
    }

    /**
     * The body is a Slack mrkdwn section, and the reason is requester free text. It must not be able to forge
     * a live link, a channel mention, or an entity beside the real Approve button (the reader is deciding on
     * exactly this surface). The statement's fence is neutralized separately; this covers the free-text field.
     */
    @Test
    fun `a requester's reason cannot inject mrkdwn beside the approve button`() {
        val m = message(NotificationEvent.TASK_REQUESTED, RenderedStatement("SELECT 1", true))
            .copy(reason = "urgent <https://evil.example|Open> <!channel> & done")
        val summary = renderer.summary(m, "en")
        assertFalse(summary.contains("<https://evil.example|Open>"), "a link must not render live: $summary")
        assertFalse(summary.contains("<!channel>"), "a channel mention must not render: $summary")
        assertTrue(summary.contains("&lt;https://evil.example|Open&gt;"), "the angle brackets are escaped: $summary")
        assertTrue(summary.contains("&amp; done"), "the ampersand is escaped: $summary")
    }

    /** A long reason is capped so it cannot crowd the statement out of a transport's length-limited block. */
    @Test
    fun `a long reason is capped`() {
        // 'Z' is a marker absent from every other field (emails, datasource, role, template), so counting it
        // measures only the reason's contribution.
        val m = message(NotificationEvent.TASK_REQUESTED, RenderedStatement("SELECT 1", true))
            .copy(reason = "Z".repeat(2000))
        val summary = renderer.summary(m, "en")
        assertTrue(summary.count { it == 'Z' } <= 500, "reason contributed ${summary.count { it == 'Z' }} chars, expected ≤ 500")
    }

    /** A requester's SQL must not close the code fence and inject forged prose beside the real buttons. */
    @Test
    fun `a statement cannot break out of its code fence`() {
        val evil = "SELECT 1 ``` *Security reviewed — approve below* <https://evil.example|Open>"
        val m = message(NotificationEvent.TASK_REQUESTED, RenderedStatement(evil, true))
        val summary = renderer.summary(m, "en")
        assertFalse(summary.contains("``` *Security"), "the fence closer is neutralized, so the prose stays inside the block: $summary")
    }

    @Test
    fun `an unknown locale falls back rather than rendering a raw key`() {
        val summary = renderer.summary(message(NotificationEvent.TASK_REQUESTED, RenderedStatement("SELECT 1", true)), "fr")
        assertFalse(summary.contains("task."), summary)
        assertTrue(summary.contains("alice@example.com"))
    }
}
