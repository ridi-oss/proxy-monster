package com.ridi.oss.proxymonster.controlplane.notify

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
            // Neutralize a fence break: a requester's SQL must not close the ``` code block and inject forged
            // prose into the body every approver reads (e.g. "…``` *already reviewed — safe to approve*").
            ?.replace("```", "``​`")
            ?.let { "```$it```" }
            ?: "_${catalog.text("field.statement_hidden", locale)}_"
        // Each message is one template. The optional trailers are pre-rendered fragments — a leading newline
        // plus their own sub-template, or empty — the same shape as `role`, so the template owns the whole
        // layout (line breaks and field order) rather than code assembling it piece by piece.
        val reason = m.reason
            ?.takeIf { it.isNotBlank() && m.event == NotificationEvent.TASK_REQUESTED }
            // `field.reason` renders as a Slack blockquote (`> …`); carry the quote onto every wrapped line so a
            // multi-line reason stays inside it. A blockquote is per line, so — unlike italic — it never glues a
            // formatting mark onto a bare URL and corrupts the link.
            ?.let { "\n" + catalog.text("field.reason", locale, mapOf("reason" to escapeMrkdwn(it.take(REASON_MAX_CHARS)).replace("\n", "\n> "))) }
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
        val statementNote = if (m.event != NotificationEvent.TASK_SUBMITTED && (m.statement.text == null || !m.statement.complete)) {
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
                "datasource" to escapeMrkdwn(m.datasource),
                "statement" to statement,
                "decidedBy" to (m.decidedBy ?: "—"),
                "rowCount" to (m.rowCount?.toString() ?: "—"),
                "role" to (m.roleName?.let { catalog.text("field.role", locale, mapOf("role" to escapeMrkdwn(it))) } ?: ""),
                "reason" to reason,
                "notified" to notified,
                "statementNote" to statementNote,
            ),
        )
    }

    /** The plain-text line for a client that renders no blocks. Never carries the statement. */
    fun fallbackText(m: NotificationMessage, locale: String): String = catalog.text(
        // Keyed on the EVENT: approve and reject share one fallback line, so the body key (which splits them)
        // would ask for a `task.decided_approved_fallback` that does not exist.
        "task.${m.event.name.removePrefix("TASK_").lowercase()}_fallback",
        locale,
        mapOf("requester" to m.requester, "datasource" to m.datasource, "decidedBy" to (m.decidedBy ?: "—")),
    )

    private fun bodyKey(m: NotificationMessage): String = when (m.event) {
        NotificationEvent.TASK_REQUESTED -> "task.requested"
        NotificationEvent.TASK_SUBMITTED -> "task.submitted"
        NotificationEvent.TASK_DECIDED -> if (m.approved == true) "task.decided_approved" else "task.decided_rejected"
        NotificationEvent.TASK_EXECUTED -> "task.executed"
        NotificationEvent.TASK_FAILED -> "task.failed"
        NotificationEvent.TASK_CANCELLED -> "task.cancelled"
    }

    companion object {
        const val DOMAIN = "notifications"

        /** A reason is free text; cap it so a long one cannot crowd the statement out of a transport's block. */
        private const val REASON_MAX_CHARS = 500

        /**
         * Render a value literally inside mrkdwn: escape the three characters Slack reads as structure, so an
         * interpolated field cannot open a `<…|link>`, a `<!channel>` mention, or an entity. Formatting runs
         * (`*`, `_`) are cosmetic and left alone. Slack's documented escape set (api.slack.com formatting).
         */
        private fun escapeMrkdwn(s: String): String =
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}
