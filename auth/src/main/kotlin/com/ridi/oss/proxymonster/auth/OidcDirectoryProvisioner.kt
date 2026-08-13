package com.ridi.oss.proxymonster.auth

import java.sql.Connection
import javax.sql.DataSource

/**
 * Shared OIDC JIT directory reconciler used by every control-plane login surface, so
 * app_user/app_group/group_member semantics cannot drift between web, device, and MCP OAuth flows.
 */
class OidcDirectoryProvisioner(private val dataSource: DataSource) {
    fun provision(
        principal: String,
        email: String?,
        idpGroups: List<String>,
        mapping: OidcGroupMapping = OidcGroupMapping(emptyMap(), null),
    ): Long = dataSource.connection.use { connection ->
        connection.autoCommit = false
        try {
            connection.prepareStatement(
                """INSERT INTO app_user (principal, email, source, active)
                   VALUES (?, ?, 'OIDC', TRUE)
                   ON CONFLICT (principal) DO UPDATE
                   SET email = COALESCE(EXCLUDED.email, app_user.email), source = EXCLUDED.source
                   WHERE app_user.source <> 'SCIM'""",
            ).use { statement ->
                statement.setString(1, principal)
                statement.setString(2, email)
                statement.executeUpdate()
            }
            val userId = connection.userId(principal)
                ?: error("OIDC provision did not leave an app_user row for '$principal'")
            val targetGroups = mapping.resolve(idpGroups).mapTo(LinkedHashSet()) { connection.ensureGroup(it) }
            val currentGroups = connection.groupIds(userId)
            connection.prepareStatement(
                "INSERT INTO group_member (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
            ).use { statement ->
                for (groupId in targetGroups - currentGroups) {
                    statement.setLong(1, groupId)
                    statement.setLong(2, userId)
                    statement.addBatch()
                }
                statement.executeBatch()
            }
            connection.prepareStatement("DELETE FROM group_member WHERE group_id = ? AND user_id = ?").use { statement ->
                for (groupId in currentGroups - targetGroups) {
                    statement.setLong(1, groupId)
                    statement.setLong(2, userId)
                    statement.addBatch()
                }
                statement.executeBatch()
            }
            connection.commit()
            userId
        } catch (e: Exception) {
            connection.rollback()
            throw e
        } finally {
            connection.autoCommit = true
        }
    }

    private fun Connection.userId(principal: String): Long? =
        prepareStatement("SELECT id FROM app_user WHERE principal = ?").use { statement ->
            statement.setString(1, principal)
            statement.executeQuery().use { result -> if (result.next()) result.getLong(1) else null }
        }

    private fun Connection.ensureGroup(name: String): Long =
        prepareStatement(
            """INSERT INTO app_group (name, source) VALUES (?, 'OIDC')
               ON CONFLICT (name) WHERE deleted_at IS NULL DO UPDATE SET name = EXCLUDED.name
               RETURNING id""",
        ).use { statement ->
            statement.setString(1, name)
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }

    private fun Connection.groupIds(userId: Long): Set<Long> =
        prepareStatement("SELECT group_id FROM group_member WHERE user_id = ?").use { statement ->
            statement.setLong(1, userId)
            statement.executeQuery().use { result ->
                buildSet { while (result.next()) add(result.getLong(1)) }
            }
        }
}
