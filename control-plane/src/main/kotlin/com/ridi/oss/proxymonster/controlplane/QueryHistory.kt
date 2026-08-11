package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import kotlinx.serialization.Serializable
import javax.sql.DataSource

/** One recalled query from a principal's editor history. */
@Serializable
data class QueryHistoryEntry(val sql: String, val datasourceId: Long? = null, val ranAt: String)

class QueryHistoryStore(private val dataSource: DataSource) {
    /** Append a run to the principal's history. Blank SQL is ignored. */
    fun add(principal: String, datasourceId: Long?, sql: String) {
        val trimmed = sql.trim()
        if (trimmed.isEmpty()) return
        dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO query_history (principal, datasource_id, sql) VALUES (?, ?, ?)",
            ).use { ps ->
                ps.setString(1, principal)
                if (datasourceId != null) ps.setLong(2, datasourceId) else ps.setNull(2, java.sql.Types.BIGINT)
                ps.setString(3, trimmed)
                ps.executeUpdate()
            }
        }
    }

    /** The principal's most recent DISTINCT queries (latest occurrence wins), newest first. */
    fun recent(principal: String, limit: Int): List<QueryHistoryEntry> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT sql, datasource_id, created_at FROM (
                   SELECT DISTINCT ON (sql) sql, datasource_id, created_at
                   FROM query_history WHERE principal = ?
                   ORDER BY sql, created_at DESC
               ) q
               ORDER BY created_at DESC
               LIMIT ?""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setInt(2, limit)
            ps.executeQuery().use { rs ->
                val out = ArrayList<QueryHistoryEntry>()
                while (rs.next()) {
                    val dsId = rs.getLong("datasource_id").let { if (rs.wasNull()) null else it }
                    out += QueryHistoryEntry(rs.getString("sql"), dsId, rs.getTimestamp("created_at").toInstant().toString())
                }
                out
            }
        }
    }

    fun clear(principal: String) = dataSource.connection.use { c ->
        c.prepareStatement("DELETE FROM query_history WHERE principal = ?").use { ps ->
            ps.setString(1, principal)
            ps.executeUpdate()
        }
    }
}

fun Route.queryHistoryRoutes(config: Config, store: QueryHistoryStore) {
    get("/api/query-history") {
        val principal = call.requireApi() ?: return@get
        val limit = (call.request.queryParameters["limit"]?.toIntOrNull() ?: 50).coerceIn(1, 200)
        call.respond(store.recent(principal, limit))
    }
    delete("/api/query-history") {
        val principal = call.requireApi() ?: return@delete
        store.clear(principal)
        call.respond(HttpStatusCode.NoContent)
    }
}
