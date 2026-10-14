package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.QueryRequestDetail
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The Review modal a channel message opens: private to the person who clicked, so it carries the whole statement
 * they may read and only the buttons Cedar allows them. Its buttons send the same action ids as a DM's.
 */
internal class SlackReviewView(private val catalog: MessageCatalog, private val renderer: NotificationRenderer) {

    fun forDetail(d: QueryRequestDetail, principal: String, deepLink: String, locale: String): JsonObject {
        val req = d.request
        // Measured after escaping, which is what Slack counts.
        val sql = escape(req.sql.orEmpty()).replace("```", "``​`")
        val complete = sql.isNotEmpty() && sql.length <= STATEMENT_LIMIT
        val actions = buildList {
            if (d.canDecide) {
                if (complete) {
                    if (d.canApproveAndRun) add(NotificationAction.APPROVE_AND_RUN)
                    add(NotificationAction.APPROVE)
                }
                add(NotificationAction.DENY)
            }
            if (d.canExecute) add(NotificationAction.RUN)
            if (d.canUnapprove) add(NotificationAction.UNAPPROVE)
            if (d.canReject && req.status == "APPROVED") add(NotificationAction.DENY)
            if (d.canClose) add(NotificationAction.CLOSE)
            if (d.canComment && req.principal != principal && req.status in setOf("PENDING", "APPROVED")) {
                add(NotificationAction.LGTM)
            }
        }.distinct()
        return view(locale) {
            add(section(catalog.text("modal.summary", locale, mapOf(
                "requester" to escape(req.principal),
                "datasource" to escape(req.datasourceName ?: "—"),
                "role" to escape(req.roleName ?: "—"),
                "status" to req.status.lowercase(),
            ))))
            add(section("```" + sql.take(STATEMENT_LIMIT) + "```"))
            if (!complete) add(context(catalog.text("field.statement_hidden_note", locale)))
            req.reason?.takeIf { it.isNotBlank() }?.let { add(section("> " + escape(it.take(500)).replace("\n", "\n> "))) }
            if (actions.isEmpty()) add(context(catalog.text("modal.no_actions", locale)))
            add(
                buildJsonObject {
                    put("type", "actions")
                    putJsonArray("elements") {
                        for (action in actions) add(button(action, req.id, req.revision, locale, actions))
                        add(
                            buildJsonObject {
                                put("type", "button")
                                putJsonObject("text") { put("type", "plain_text"); put("text", renderer.actionLabel(NotificationAction.OPEN, locale)) }
                                put("url", deepLink)
                            },
                        )
                    }
                },
            )
            add(context(catalog.text("modal.comment_hint", locale)))
        }
    }

    /** A modal that only says [text]: a refusal, or the outcome of a button pressed inside it. */
    fun message(text: String, locale: String): JsonObject = view(locale) { add(section(text)) }

    private fun view(locale: String, blocks: kotlinx.serialization.json.JsonArrayBuilder.() -> Unit) = buildJsonObject {
        put("type", "modal")
        putJsonObject("title") { put("type", "plain_text"); put("text", catalog.text("modal.title", locale)) }
        putJsonObject("close") { put("type", "plain_text"); put("text", catalog.text("modal.close", locale)) }
        put("blocks", buildJsonArray(blocks))
    }

    private fun button(
        action: NotificationAction,
        id: Long,
        revision: Int,
        locale: String,
        all: List<NotificationAction>,
    ) = buildJsonObject {
        put("type", "button")
        putJsonObject("text") { put("type", "plain_text"); put("text", renderer.actionLabel(action, locale)) }
        put("action_id", SlackTransport.ACTION_IDS.getValue(action))
        put("value", "$id:$revision")
        when (action) {
            NotificationAction.APPROVE_AND_RUN, NotificationAction.RUN -> put("style", "primary")
            NotificationAction.APPROVE -> if (NotificationAction.APPROVE_AND_RUN !in all) put("style", "primary")
            NotificationAction.DENY -> put("style", "danger")
            else -> Unit
        }
    }

    private fun section(text: String) = buildJsonObject {
        put("type", "section")
        putJsonObject("text") { put("type", "mrkdwn"); put("text", text) }
    }

    private fun context(text: String) = buildJsonObject {
        put("type", "context")
        putJsonArray("elements") { add(buildJsonObject { put("type", "mrkdwn"); put("text", text) }) }
    }

    private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private companion object {
        // A section's text caps at 3000 characters, with room left for the code fence.
        const val STATEMENT_LIMIT = 2900
    }
}
