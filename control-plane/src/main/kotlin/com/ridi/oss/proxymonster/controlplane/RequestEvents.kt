package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.Serializable
import java.sql.Connection
import java.sql.ResultSet
import javax.sql.DataSource

/** The origin of an event the system made rather than a person. */
const val SYSTEM_ORIGIN = "system"

enum class RequestEventKind(val wire: String) {
    REQUESTED("requested"), EDITED("edited"), APPROVED("approved"), REJECTED("rejected"),
    UNAPPROVED("unapproved"), EXPIRED("expired"), WITHDRAWN("withdrawn"), CLOSED("closed"),
    RAN("ran"), EXECUTED("executed"), FAILED("failed"), CANCELLED("cancelled"),
    COMMENT("comment"), LGTM("lgtm"), CC_ADDED("cc_added"), CC_REMOVED("cc_removed"),
    CODE_APPROVED("code_approved"), CODE_CHANGES_REQUESTED("code_changes_requested"),
    CODE_REVIEW_DISMISSED("code_review_dismissed"),
}

/** A reviewer's standing code review; [name] is a principal when [principal], else their GitHub login. */
data class CodeReview(val name: String, val principal: Boolean, val approved: Boolean)

/** One timeline entry. [actor] is null for an event the system made. */
@Serializable
data class RequestEvent(
    val id: Long,
    val kind: String,
    val actor: String? = null,
    val body: String? = null,
    val revision: Int? = null,
    val origin: String,
    val createdAt: String,
    val editedAt: String? = null,
    val deleted: Boolean = false,
)

/** A workflow request's timeline. The editor's and the wire proxy's own task rows get none. */
object RequestEvents {
    fun record(
        c: Connection,
        requestId: Long,
        kind: RequestEventKind,
        actor: String?,
        origin: String,
        body: String? = null,
        // A Slack reply: the thread it was written in, and the reply itself.
        sourceThread: String? = null,
        slackRef: String? = null,
        githubReviewId: String? = null,
    ): RequestEvent? =
        c.prepareStatement(
            """INSERT INTO request_event (request_id, kind, actor, body, revision, origin, source_thread, slack_ref, github_review_id)
               SELECT id, ?, ?, ?, revision, ?, ?, ?, ? FROM access_request
               WHERE id = ? AND creator_kind = 'WORKFLOW'
               ON CONFLICT DO NOTHING
               RETURNING $COLUMNS""",
        ).use { ps ->
            ps.setString(1, kind.wire)
            ps.setString(2, actor)
            ps.setString(3, body)
            ps.setString(4, origin)
            ps.setString(5, sourceThread)
            ps.setString(6, slackRef)
            ps.setString(7, githubReviewId)
            ps.setLong(8, requestId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toEvent() else null }
        }?.also {
            if (actor != null && kind in DECISIONS && !actor.startsWith(SYSTEM_PREFIX)) {
                RequestParticipants.add(c, requestId, listOf(actor), ParticipantKind.APPROVER)
            }
        }

    /** Entries of [requestId] after [afterId], each with the thread it came from, for posting into threads. */
    fun after(c: Connection, requestId: Long, afterId: Long): List<Pair<RequestEvent, String?>> =
        c.prepareStatement(
            "SELECT $COLUMNS, source_thread FROM request_event WHERE request_id = ? AND id > ? ORDER BY id",
        ).use { ps ->
            ps.setLong(1, requestId)
            ps.setLong(2, afterId)
            ps.executeQuery().use { rs ->
                val out = ArrayList<Pair<RequestEvent, String?>>()
                while (rs.next()) out += rs.toEvent() to rs.getString(10)
                out
            }
        }

    /** The GitHub reviews recorded on each of [requestIds], as (request, kind, review) triples. */
    fun githubReviews(c: Connection, requestIds: List<Long>): Set<Triple<Long, String, String>> =
        c.prepareStatement(
            "SELECT request_id, kind, github_review_id FROM request_event WHERE request_id = ANY(?) AND github_review_id IS NOT NULL",
        ).use { ps ->
            ps.setArray(1, c.createArrayOf("bigint", requestIds.toTypedArray()))
            ps.executeQuery().use { rs ->
                buildSet { while (rs.next()) add(Triple(rs.getLong(1), rs.getString(2), rs.getString(3))) }
            }
        }

    /** Each reviewer's latest GitHub review of [requestId] that still stands, in the order they reviewed. */
    fun codeReviews(c: Connection, requestId: Long): List<CodeReview> =
        c.prepareStatement(
            """SELECT actor, body, kind FROM (
                 SELECT DISTINCT ON (COALESCE(actor, body)) actor, body, kind, id, github_review_id FROM request_event
                 WHERE request_id = ? AND github_review_id IS NOT NULL AND kind <> 'code_review_dismissed'
                 ORDER BY COALESCE(actor, body), id DESC
               ) latest
               WHERE NOT EXISTS (
                 SELECT 1 FROM request_event d
                 WHERE d.request_id = ? AND d.github_review_id = latest.github_review_id AND d.kind = 'code_review_dismissed')
               ORDER BY id""",
        ).use { ps ->
            ps.setLong(1, requestId)
            ps.setLong(2, requestId)
            ps.executeQuery().use { rs ->
                val out = ArrayList<CodeReview>()
                while (rs.next()) {
                    val actor = rs.getString(1)
                    out += CodeReview(actor ?: rs.getString(2), actor != null, rs.getString(3) != RequestEventKind.CODE_CHANGES_REQUESTED.wire)
                }
                out
            }
        }

    /** Replace or, with a null [body], delete the comment written as Slack reply [slackRef]. Null when there is none. */
    fun editBySlackRef(c: Connection, slackRef: String, body: String?): RequestEvent? =
        c.prepareStatement(
            """UPDATE request_event
               SET body = ?, edited_at = CASE WHEN ? THEN now() ELSE edited_at END,
                   deleted_at = CASE WHEN ? THEN NULL ELSE now() END
               WHERE slack_ref = ? AND deleted_at IS NULL
               RETURNING $COLUMNS""",
        ).use { ps ->
            ps.setString(1, body)
            ps.setBoolean(2, body != null)
            ps.setBoolean(3, body != null)
            ps.setString(4, slackRef)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toEvent() else null }
        }

    fun addPost(c: Connection, eventId: Long, externalRef: String) {
        c.prepareStatement("INSERT INTO request_event_post (event_id, external_ref) VALUES (?, ?) ON CONFLICT DO NOTHING").use { ps ->
            ps.setLong(1, eventId)
            ps.setString(2, externalRef)
            ps.executeUpdate()
        }
    }

    fun postsOf(c: Connection, eventId: Long): List<String> =
        c.prepareStatement("SELECT external_ref FROM request_event_post WHERE event_id = ?").use { ps ->
            ps.setLong(1, eventId)
            ps.executeQuery().use { rs -> val o = ArrayList<String>(); while (rs.next()) o += rs.getString(1); o }
        }

    fun list(dataSource: DataSource, requestId: Long): List<RequestEvent> = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT $COLUMNS FROM request_event WHERE request_id = ? ORDER BY id",
        ).use { ps ->
            ps.setLong(1, requestId)
            ps.executeQuery().use { rs ->
                val out = ArrayList<RequestEvent>()
                while (rs.next()) out += rs.toEvent()
                out
            }
        }
    }

    // A system actor, such as an automatic reviewer, is never listed as a participant.
    private const val SYSTEM_PREFIX = "system:"

    // Acting on a request makes the actor a participant; commenting does not.
    private val DECISIONS = setOf(
        RequestEventKind.APPROVED, RequestEventKind.REJECTED, RequestEventKind.UNAPPROVED, RequestEventKind.RAN,
    )

    private const val COLUMNS = "id, kind, actor, body, revision, origin, created_at, edited_at, deleted_at"

    private fun ResultSet.toEvent() = RequestEvent(
        id = getLong(1),
        kind = getString(2),
        actor = getString(3),
        body = getString(4),
        revision = getInt(5).takeUnless { wasNull() },
        origin = getString(6),
        createdAt = getTimestamp(7).toInstant().toString(),
        editedAt = getTimestamp(8)?.toInstant()?.toString(),
        deleted = getTimestamp(9) != null,
    )
}
