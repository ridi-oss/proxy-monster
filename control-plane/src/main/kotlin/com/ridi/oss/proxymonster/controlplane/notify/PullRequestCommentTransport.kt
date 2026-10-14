package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.source.GitHubException
import com.ridi.oss.proxymonster.controlplane.source.Repo
import com.ridi.oss.proxymonster.controlplane.source.SourceAdapter

/**
 * Reports a pull request's requests on the pull request itself: one comment per request, edited in place as the
 * request moves. Addresses the task (`owner/name#N`), not a person. Carries the outcome, never rows.
 */
class PullRequestCommentTransport(
    private val adapter: SourceAdapter,
    private val catalog: MessageCatalog = MessageCatalog(DOMAIN),
) : NotificationTransport {
    override val name = TRANSPORT

    override val supportsUpdate = true

    override val addressesTasks = true

    override fun taskAddress(req: AccessRequest): String? {
        if (!req.fromPullRequest) return null
        val ref = req.pullRequest ?: return null
        return "${ref.repository}#${ref.pr}"
    }

    override suspend fun addressOf(principal: String, email: String?): String? = principal

    override suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult =
        post(to, message, locale)

    override suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult =
        post(externalRef, message, locale)

    private suspend fun post(address: String, message: NotificationMessage, locale: String): DeliveryResult {
        val (repo, pr) = parseAddress(address) ?: return DeliveryResult.Drop("malformed pull request address")
        return try {
            adapter.upsertComment(repo, pr, marker(message), body(message, locale))
            DeliveryResult.Sent(address)
        } catch (e: GitHubException.NotFound) {
            DeliveryResult.Drop(e.message ?: "not found")
        } catch (e: GitHubException.Forbidden) {
            DeliveryResult.Drop(e.message ?: "forbidden")
        } catch (e: GitHubException.Unprocessable) {
            DeliveryResult.Drop(e.message ?: "unprocessable")
        } catch (e: Exception) {
            DeliveryResult.Retry(e.message ?: e.javaClass.simpleName)
        }
    }

    // An alert gets a comment of its own, so the request's comment moving on never overwrites it.
    private fun marker(m: NotificationMessage): String =
        if (m.event.isCreation || m.event.isUpdate) "task-${m.taskId}" else "task-${m.taskId}-${m.event.wire}"

    internal fun body(m: NotificationMessage, locale: String): String {
        val key = when (m.event) {
            NotificationEvent.TASK_REQUESTED, NotificationEvent.TASK_SUBMITTED, NotificationEvent.TASK_EDITED,
            NotificationEvent.TASK_REOPENED -> "comment.requested"
            NotificationEvent.TASK_DECIDED -> if (m.approved == true) "comment.decided_approved" else "comment.decided_rejected"
            NotificationEvent.TASK_EXECUTED -> "comment.executed"
            NotificationEvent.TASK_FAILED -> if (m.failedStatement != null) "comment.failed_at" else "comment.failed"
            NotificationEvent.TASK_CANCELLED -> "comment.cancelled"
            NotificationEvent.TASK_CLOSED_AFTER_RUN -> "comment.closed_after_run"
            NotificationEvent.TASK_MERGED_WITHOUT_FILE -> "comment.merged_without_file"
            NotificationEvent.TASK_FORCE_RUN -> "comment.force_run"
        }
        val target = m.schema?.let { "${m.datasource}/$it" } ?: m.datasource
        return catalog.text(
            key,
            locale,
            mapOf(
                "path" to (m.path ?: "#${m.taskId}"),
                "datasource" to m.datasource,
                "schema" to target,
                "decidedBy" to (m.decidedBy ?: "—"),
                "forcedBy" to (m.forcedBy ?: "—"),
                "statementCount" to m.statementCount.toString(),
                "error" to (m.failure?.let(::fenceSafe) ?: "—"),
                "ordinal" to ((m.failedStatement?.ordinal ?: 0) + 1).toString(),
                "statement" to (m.failedStatement?.sql?.let { fenceSafe(truncate(it.trim())) } ?: ""),
                "link" to m.deepLink,
            ),
        )
    }

    companion object {
        const val TRANSPORT = "github"
        const val DOMAIN = "github"

        const val STATEMENT_MAX_CHARS = 500

        private fun fenceSafe(text: String) = text.replace("```", "``\u200b`")

        private fun truncate(sql: String) =
            if (sql.length <= STATEMENT_MAX_CHARS) sql else sql.take(STATEMENT_MAX_CHARS).trimEnd() + "…"

        fun parseAddress(address: String): Pair<Repo, Int>? {
            val repository = address.substringBeforeLast('#', "")
            val pr = address.substringAfterLast('#', "").toIntOrNull()?.takeIf { it > 0 } ?: return null
            return Repo.parse(repository)?.let { it to pr }
        }
    }
}
