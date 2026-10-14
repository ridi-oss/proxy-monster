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
}

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

/** A query request's timeline. Only human workflow requests get one; editor and wire tasks are skipped. */
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
    ): RequestEvent? =
        c.prepareStatement(
            """INSERT INTO request_event (request_id, kind, actor, body, revision, origin, source_thread, slack_ref)
               SELECT id, ?, ?, ?, revision, ?, ?, ? FROM access_request WHERE id = ? AND creator_kind = 'WORKFLOW'
               ON CONFLICT (slack_ref) WHERE slack_ref IS NOT NULL DO NOTHING
               RETURNING $COLUMNS""",
        ).use { ps ->
            ps.setString(1, kind.wire)
            ps.setString(2, actor)
            ps.setString(3, body)
            ps.setString(4, origin)
            ps.setString(5, sourceThread)
            ps.setString(6, slackRef)
            ps.setLong(7, requestId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toEvent() else null }
        }?.also { if (actor != null && kind in DECISIONS) RequestParticipants.add(c, requestId, listOf(actor), ParticipantKind.APPROVER) }

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
