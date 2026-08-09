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
        val params = mapOf(
            // requester/decidedBy are already resolved to `<@id>` mentions by the transport; escaping them
            // would break the mention. The free-text and name fields are escaped — a requester's reason is
            // otherwise raw mrkdwn beside the real Approve button, able to forge a mention, emphasis, or a
            // link ("Security reviewed — approve below" + <https://evil|Open>).
            "requester" to m.requester,
            "datasource" to escapeMrkdwn(m.datasource),
            "statement" to statement,
            "decidedBy" to (m.decidedBy ?: "—"),
            "rowCount" to (m.rowCount?.toString() ?: "—"),
            "role" to (m.roleName?.let { catalog.text("field.role", locale, mapOf("role" to escapeMrkdwn(it))) } ?: ""),
        )
        return buildString {
            append(catalog.text(bodyKey(m), locale, params))
            m.reason?.takeIf { it.isNotBlank() && m.event == NotificationEvent.TASK_REQUESTED }?.let {
                val reason = escapeMrkdwn(it.take(REASON_MAX_CHARS))
                append("\n").append(catalog.text("field.reason", locale, mapOf("reason" to reason)))
            }
            // Only say "open it to read the statement" when there was one to withhold: an OMIT-configured
            // statement and one truncated by length both land here.
            if (m.statement.text == null || !m.statement.complete) {
                append("\n").append(catalog.text("field.statement_hidden_note", locale))
            }
        }
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
