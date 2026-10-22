package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.SOURCE_GITHUB
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog

/**
 * Renders a [NotificationMessage] into localized prose over the shared [MessageCatalog] (the `notifications`
 * domain). A transport turns this into its own idiom — Block Kit, MIME — so the copy lives here once and
 * every locale stays reachable.
 */
class NotificationRenderer(private val catalog: MessageCatalog = MessageCatalog(DOMAIN)) {

    fun actionLabel(action: NotificationAction, locale: String): String = catalog.text(
        when (action) {
            NotificationAction.APPROVE_AND_RUN -> "action.approve_and_run"
            NotificationAction.APPROVE -> "action.approve"
            NotificationAction.RUN -> "action.run"
            NotificationAction.LGTM -> "action.lgtm"
            NotificationAction.REVIEW -> "action.review"
            NotificationAction.UNAPPROVE -> "action.unapprove"
            NotificationAction.CLOSE -> "action.close"
            NotificationAction.DENY -> "action.deny"
            NotificationAction.OPEN -> "action.open"
        },
        locale,
    )

    /**
     * The message body. A statement that was withheld or elided is described rather than shown, and says so —
     * an approver who cannot read it here needs to know to open the console, not to guess.
     */
    fun summary(m: NotificationMessage, locale: String): String {
        val statement = m.statement.text
            ?.let { "\n" + fenced(it) }
            .orEmpty()
        // Each message is one template. The optional trailers are pre-rendered fragments — a leading newline
        // plus their own sub-template, or empty — the same shape as `role`, so the template owns the whole
        // layout (line breaks and field order) rather than code assembling it piece by piece.
        val reason = m.reason
            ?.takeIf { it.isNotBlank() && (m.requestKind == "QUERY" || m.event in ASKS_FOR_APPROVAL || m.event == NotificationEvent.TASK_CC_ADDED) }
            // `field.reason` renders as a Slack blockquote (`> …`); carry the quote onto every wrapped line so a
            // multi-line reason stays inside it. A blockquote is per line, so — unlike italic — it never glues a
            // formatting mark onto a bare URL and corrupts the link.
            ?.let { "\n" + catalog.text("field.reason", locale, mapOf("reason" to SlackMarkup.escape(it.take(REASON_MAX_CHARS)).replace("\n", "\n> "))) }
            ?: ""
        // The receipt's approver list is `<@id>` mentions resolved by the transport. In the requester's OWN DM,
        // where no approver is a member, they render as names without pinging anyone — so, like requester and
        // decidedBy, they are NOT escaped.
        val notified = m.notifiedApprovers
            .takeIf { it.isNotEmpty() && m.event == NotificationEvent.TASK_SUBMITTED }
            ?.let { "\n" + catalog.text("field.notified", locale, mapOf("notified" to it.joinToString(", "))) }
            ?: ""
        // "Open it to read the statement" only where one was withheld — never on the requester's own receipt,
        // which omits the statement by design (they authored it).
        val failure = m.failure
            ?.takeIf { it.isNotBlank() && m.event == NotificationEvent.TASK_FAILED }
            ?.let { "\n" + catalog.text("field.failure", locale, mapOf("error" to SlackMarkup.escape(it.take(REASON_MAX_CHARS)))) }
            ?: ""
        val statementNote = if (m.requestKind == "QUERY" && m.event != NotificationEvent.TASK_SUBMITTED && (m.statement.text == null || !m.statement.complete)) {
            "\n" + catalog.text("field.statement_hidden_note", locale)
        } else {
            ""
        }
        return catalog.text(
            bodyKey(m),
            locale,
            mapOf(
                // requester/decidedBy/notified arrive as `<@id>` mentions from the transport; escaping them
                // would break the mention. The free-text and name fields are escaped — a requester's reason is
                // otherwise raw mrkdwn beside the real Approve button, able to forge a mention, emphasis, or a
                // link ("Security reviewed — approve below" + <https://evil|Open>).
                "requester" to m.requester,
                "datasource" to SlackMarkup.escape(m.datasource.ifEmpty { catalog.text("field.any_datasource", locale) }),
                "statement" to statement,
                "query" to catalog.text(if (m.statement.text == null) "field.statement_hidden" else "field.statement_shown", locale),
                "duration" to duration(m.durationSec, locale),
                "spentRate" to (m.spentRate?.let { "\n" + catalog.text("field.spent_rate", locale, mapOf("rate" to SlackMarkup.escape(it))) } ?: ""),
                "decidedBy" to (m.decidedBy ?: "—"),
                "forcedBy" to (m.forcedBy ?: "—"),
                "rowCount" to (m.rowCount?.let { catalog.text("field.row_count", locale, mapOf("n" to it.toString())) } ?: ""),
                "role" to (m.roleName?.let { catalog.text("field.role", locale, mapOf("role" to SlackMarkup.escape(it))) } ?: ""),
                "roleName" to SlackMarkup.escape(m.roleName ?: "—"),
                "reason" to reason,
                "title" to (m.title?.takeIf { it.isNotBlank() }?.let { catalog.text("field.title", locale, mapOf("title" to SlackMarkup.escape(it.take(REASON_MAX_CHARS)))) } ?: ""),
                "notified" to notified,
                "statementNote" to statementNote,
                "failure" to failure,
            ),
        )
    }

    /** The line naming who may approve and the CCs, for a message a whole channel reads; null when there are none. */
    fun audience(m: NotificationMessage, locale: String): String? {
        val parts = listOfNotNull(
            m.approvers.takeIf { it.isNotEmpty() }?.let { catalog.text("field.approvers", locale, mapOf("names" to it.joinToString(" "))) },
            m.ccs.takeIf { it.isNotEmpty() }?.let { catalog.text("field.ccs", locale, mapOf("names" to it.joinToString(" "))) },
        )
        return parts.takeIf { it.isNotEmpty() }?.joinToString(" · ")
    }

    /** One timeline entry as a reply in a request's thread. */
    fun threadLine(e: com.ridi.oss.proxymonster.controlplane.RequestEvent, locale: String): String {
        val actor = e.actor?.let(SlackMarkup::escape).orEmpty()
        val body = e.body?.take(REASON_MAX_CHARS * 6)?.let(SlackMarkup::escape).orEmpty()
        return when (e.kind) {
            "comment" -> "*$actor*: $body"
            "lgtm" -> "*$actor*: LGTM" + if (body.isNotEmpty()) "\n> " + body.replace("\n", "\n> ") else ""
            else -> catalog.text(
                "thread.${e.kind}", locale,
                mapOf("actor" to actor, "body" to body, "revision" to (e.revision ?: 1).toString()),
            )
        }
    }

    // A requester's SQL must not close the ``` block and inject forged prose ("…``` *reviewed — approve*").
    private fun fenced(sql: String) = "```\n" + sql.replace("```", "``\u200b`") + "\n```"

    /** The plain-text line for a client that renders no blocks. Never carries the statement. */
    fun fallbackText(m: NotificationMessage, locale: String): String = catalog.text(
        // Keyed on the EVENT: approve and reject share one fallback line, so the body key (which splits them)
        // would ask for a `task.decided_approved_fallback` that does not exist.
        "${prefix(m)}.${m.event.name.removePrefix("TASK_").lowercase()}_fallback",
        locale,
        mapOf(
            "requester" to m.requester,
            "datasource" to m.datasource.ifEmpty { catalog.text("field.any_datasource", locale) },
            "decidedBy" to (m.decidedBy ?: "—"),
            "forcedBy" to (m.forcedBy ?: "—"),
            "role" to (m.roleName ?: "—"),
        ),
    )

    private fun prefix(m: NotificationMessage) = when (m.requestKind) {
        "ROLE" -> "role"
        "RATE_RESET" -> "rate_reset"
        else -> "task"
    }

    fun duration(seconds: Long, locale: String): String =
        if (seconds % 3600 == 0L) {
            catalog.text("field.duration_hours", locale, mapOf("n" to "${seconds / 3600}"))
        } else {
            catalog.text("field.duration_minutes", locale, mapOf("n" to "${seconds / 60}"))
        }

    private fun bodyKey(m: NotificationMessage): String = if (m.requestKind != "QUERY") {
        val event = m.event.name.removePrefix("TASK_").lowercase()
        when {
            m.event != NotificationEvent.TASK_DECIDED -> "${prefix(m)}.$event"
            m.approved == true -> "${prefix(m)}.decided_approved"
            else -> "${prefix(m)}.decided_rejected"
        }
    } else when (m.event) {
        NotificationEvent.TASK_REQUESTED -> "task.requested"
        NotificationEvent.TASK_SUBMITTED -> "task.submitted"
        NotificationEvent.TASK_DECIDED -> when {
            m.approved != true -> "task.decided_rejected"
            m.source != SOURCE_GITHUB -> "task.decided_approved"
            m.autoMergeEnabled -> "task.decided_approved_github_automerge"
            else -> "task.decided_approved_github"
        }
        NotificationEvent.TASK_EDITED -> "task.edited"
        NotificationEvent.TASK_REOPENED -> "task.reopened"
        NotificationEvent.TASK_CC_ADDED -> "task.cc_added"
        NotificationEvent.TASK_EXECUTED -> "task.executed"
        NotificationEvent.TASK_FAILED -> "task.failed"
        NotificationEvent.TASK_CANCELLED -> "task.cancelled"
        NotificationEvent.TASK_CLOSED_AFTER_RUN -> "task.closed_after_run"
        NotificationEvent.TASK_MERGED_WITHOUT_FILE -> "task.merged_without_file"
        NotificationEvent.TASK_FORCE_RUN -> "task.force_run"
    }

    companion object {
        const val DOMAIN = "notifications"

        /** A reason is free text; cap it so a long one cannot crowd the statement out of a transport's block. */
        private const val REASON_MAX_CHARS = 500
    }
}
