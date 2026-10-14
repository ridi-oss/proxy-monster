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
    ): RequestEvent? =
        c.prepareStatement(
            """INSERT INTO request_event (request_id, kind, actor, body, revision, origin)
               SELECT id, ?, ?, ?, revision, ? FROM access_request WHERE id = ? AND creator_kind = 'WORKFLOW'
               RETURNING $COLUMNS""",
        ).use { ps ->
            ps.setString(1, kind.wire)
            ps.setString(2, actor)
            ps.setString(3, body)
            ps.setString(4, origin)
            ps.setLong(5, requestId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toEvent() else null }
        }?.also { if (actor != null && kind in DECISIONS) RequestParticipants.add(c, requestId, listOf(actor), ParticipantKind.APPROVER) }

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

    private const val COLUMNS = "id, kind, actor, body, revision, origin, created_at"

    private fun ResultSet.toEvent() = RequestEvent(
        id = getLong(1),
        kind = getString(2),
        actor = getString(3),
        body = getString(4),
        revision = getInt(5).takeUnless { wasNull() },
        origin = getString(6),
        createdAt = getTimestamp(7).toInstant().toString(),
    )
}
