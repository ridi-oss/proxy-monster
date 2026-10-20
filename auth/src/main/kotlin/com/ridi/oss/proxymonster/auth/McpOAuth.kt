package com.ridi.oss.proxymonster.auth

import kotlinx.serialization.Serializable
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.sql.DataSource

fun sha256Hex(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(StandardCharsets.UTF_8))
    .joinToString("") { "%02x".format(it) }

@Serializable
data class McpAccessIdentity(
    val principal: String,
    val clientId: String,
    val resource: String,
    val scopes: Set<String>,
    val consentId: Long,
)

class McpTokenStore(private val dataSource: DataSource) {
    fun resolveAccess(token: String, expectedResource: String): McpAccessIdentity? = dataSource.connection.use { connection ->
        connection.prepareStatement(
            """SELECT t.principal, t.client_id, t.resource, t.scope, t.consent_id
               FROM proxy_token t
               JOIN oauth_consent c ON c.id = t.consent_id
                 AND c.principal = t.principal AND c.client_id = t.client_id
                 AND c.resource = t.resource AND c.scope = t.scope
               WHERE t.token_hash = ? AND t.kind = 'MCP_ACCESS' AND t.resource = ?
                 AND t.revoked_at IS NULL AND t.expires_at > now()
                 AND c.revoked_at IS NULL""",
        ).use { statement ->
            statement.setString(1, sha256Hex(token))
            statement.setString(2, expectedResource)
            statement.executeQuery().use { result ->
                if (!result.next()) return@use null
                McpAccessIdentity(
                    principal = result.getString("principal"),
                    clientId = result.getString("client_id"),
                    resource = result.getString("resource"),
                    scopes = result.getString("scope").split(' ').filter(String::isNotBlank).toSet(),
                    consentId = result.getLong("consent_id"),
                )
            }
        }
    }
}
