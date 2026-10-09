package com.ridi.oss.proxymonster.controlplane.support

import javax.sql.DataSource

/** An ACTIVE DAEMON `principal_session` row as a pmon login leaves it; returns its id. */
fun DataSource.seedDaemonSession(principal: String, windowSeconds: Long = 3600, ttlSeconds: Long = 900): Long =
    connection.use { c ->
        c.prepareStatement(
            """INSERT INTO principal_session (principal, ttl_seconds, absolute_expires_at, liveness_status, kind, scopes)
               VALUES (?, ?, now() + make_interval(secs => ?), 'ACTIVE', 'DAEMON', 'mcp:query mcp:read')
               RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setLong(2, ttlSeconds)
            ps.setDouble(3, windowSeconds.toDouble())
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

/** Whether [principal]'s newest DAEMON session is still inside its renewal window. */
fun DataSource.daemonWithinWindow(principal: String): Boolean = connection.use { c ->
    c.prepareStatement(
        """SELECT absolute_expires_at > now() FROM principal_session
           WHERE principal = ? AND kind = 'DAEMON' ORDER BY created_at DESC, id DESC LIMIT 1""",
    ).use { ps ->
        ps.setString(1, principal)
        ps.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }
    }
}

fun DataSource.daemonLiveness(id: Long): String = connection.use { c ->
    c.prepareStatement("SELECT liveness_status FROM principal_session WHERE id = ? AND kind = 'DAEMON'").use { ps ->
        ps.setLong(1, id)
        ps.executeQuery().use { rs -> check(rs.next()); rs.getString(1) }
    }
}
