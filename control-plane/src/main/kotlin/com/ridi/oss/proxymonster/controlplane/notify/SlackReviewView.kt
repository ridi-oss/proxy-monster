package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
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
/** What the person who opened Review may do, from their own Cedar decisions. */
internal data class ReviewModel(
    val request: AccessRequest,
    val canDecide: Boolean,
    val canApproveAndRun: Boolean = false,
    val canExecute: Boolean = false,
    val canUnapprove: Boolean = false,
    val canReject: Boolean = false,
    val canClose: Boolean = false,
    val canComment: Boolean = false,
) {
    constructor(d: QueryRequestDetail) : this(
        d.request, d.canDecide, d.canApproveAndRun, d.canExecute, d.canUnapprove, d.canReject, d.canClose, d.canComment,
    )
}

internal class SlackReviewView(private val catalog: MessageCatalog, private val renderer: NotificationRenderer) {

    fun forDetail(d: ReviewModel, principal: String, deepLink: String, locale: String): JsonObject {
        val req = d.request
        val query = req.kind == "QUERY"
        // Measured after escaping, which is what Slack counts.
        val sql = escape(req.sql.orEmpty()).replace("```", "``​`")
        val complete = !query || (sql.isNotEmpty() && sql.length <= STATEMENT_LIMIT)
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
                "datasource" to escape(req.datasourceName ?: if (req.kind == "QUERY") "—" else catalog.text("field.any_datasource", locale)),
                "role" to escape(req.roleName ?: "—"),
                "status" to req.status.lowercase(),
            ))))
            when (req.kind) {
                "QUERY" -> add(section("```" + sql.take(STATEMENT_LIMIT) + "```"))
                "ROLE" -> add(section(catalog.text("modal.role", locale, mapOf(
                    "role" to escape(req.roleName ?: "—"),
                    "datasource" to escape(req.datasourceName ?: catalog.text("field.any_datasource", locale)),
                    "duration" to renderer.duration(req.requestedDurationSec, locale),
                ))))
                else -> add(section(catalog.text("modal.rate_reset", locale, mapOf("rate" to escape(req.denyReason ?: "—")))))
            }
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
