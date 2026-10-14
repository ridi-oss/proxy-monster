package com.ridi.oss.proxymonster.controlplane

import java.sql.Connection

enum class ParticipantKind(val wire: String) { APPROVER("approver"), CC("cc") }

/**
 * Who besides the requester took part in a query request. CC rows are the request's CCs, read by Cedar as
 * `resource.ccs`. APPROVER rows only drive the history list: a stale row lists a request its holder can no
 * longer open, and opening it is still a live `task.read`.
 */
object RequestParticipants {
    fun add(c: Connection, requestId: Long, principals: Collection<String>, kind: ParticipantKind) {
        if (principals.isEmpty()) return
        c.prepareStatement(
            """INSERT INTO request_participant (request_id, principal, kind)
               SELECT ?, ?, ? WHERE ? <> (SELECT principal FROM access_request WHERE id = ?)
               ON CONFLICT DO NOTHING""",
        ).use { ps ->
            for (principal in principals.toSet()) {
                ps.setLong(1, requestId)
                ps.setString(2, principal)
                ps.setString(3, kind.wire)
                ps.setString(4, principal)
                ps.setLong(5, requestId)
                ps.addBatch()
            }
            ps.executeBatch()
        }
    }

    fun list(c: Connection, requestId: Long): List<String> =
        c.prepareStatement("SELECT DISTINCT principal FROM request_participant WHERE request_id = ? ORDER BY principal").use { ps ->
            ps.setLong(1, requestId)
            ps.executeQuery().use { rs -> val o = ArrayList<String>(); while (rs.next()) o += rs.getString(1); o }
        }

    fun remove(c: Connection, requestId: Long, principal: String, kind: ParticipantKind): Boolean =
        c.prepareStatement("DELETE FROM request_participant WHERE request_id = ? AND principal = ? AND kind = ?").use { ps ->
            ps.setLong(1, requestId)
            ps.setString(2, principal)
            ps.setString(3, kind.wire)
            ps.executeUpdate() > 0
        }
}
