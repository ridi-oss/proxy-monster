package com.ridi.oss.proxymonster.auth

import kotlinx.serialization.Serializable
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Connection
import java.sql.Types
import java.time.Instant
import java.util.Base64
import javax.sql.DataSource

const val MCP_ACCESS_KIND = "MCP_ACCESS"
const val MCP_REFRESH_KIND = "MCP_REFRESH"
const val TOKEN_MIN_TTL_SECONDS = 60L
const val TOKEN_MAX_TTL_SECONDS = 24 * 3600L

fun clampTtlSeconds(ttlSeconds: Long): Long = ttlSeconds.coerceIn(TOKEN_MIN_TTL_SECONDS, TOKEN_MAX_TTL_SECONDS)

fun canonicalScopes(scopes: Collection<String>): String = scopes.map(String::trim).filter(String::isNotEmpty).toSortedSet().joinToString(" ")

fun sha256Hex(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(StandardCharsets.UTF_8))
    .joinToString("") { "%02x".format(it) }

fun pkceS256(verifier: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
    MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)),
)

fun isValidPkceChallenge(challenge: String): Boolean = challenge.length == 43 && challenge.all {
    it.isLetterOrDigit() || it == '-' || it == '_'
}

fun isValidPkceVerifier(verifier: String): Boolean = verifier.length in 43..128 && verifier.all {
    it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' || it == '~'
}

private val secureRandom = SecureRandom()

fun randomSecret(prefix: String, bytes: Int = 32): String {
    val raw = ByteArray(bytes).also(secureRandom::nextBytes)
    return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
}

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

@Serializable
data class OAuthTokenPair(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long,
    val scope: String,
)

@Serializable
data class OAuthConsent(
    val id: Long,
    val principal: String,
    val clientId: String,
    val resource: String,
    val scope: String,
    val createdAt: String,
    val updatedAt: String,
)

data class AuthorizationCodeInput(
    val clientId: String,
    val principal: String,
    val redirectUri: String,
    val resource: String,
    val scopes: Collection<String>,
    val codeChallenge: String,
    val ttlSeconds: Long = 300,
    val consentId: Long,
)

data class ConsumeAuthorizationCodeInput(
    val code: String,
    val clientId: String,
    val redirectUri: String,
    val resource: String,
    val codeVerifier: String,
    val accessTtlSeconds: Long,
    val refreshTtlSeconds: Long,
)

data class RefreshTokenInput(
    val refreshToken: String,
    val clientId: String,
    val resource: String,
    val accessTtlSeconds: Long,
    val refreshTtlSeconds: Long,
)

class OAuthAuthorizationStore(private val dataSource: DataSource) {
    fun createAuthorizationCode(input: AuthorizationCodeInput): String {
        require(isValidPkceChallenge(input.codeChallenge)) { "invalid PKCE challenge" }
        val code = randomSecret("pmc_")
        val canonicalScope = canonicalScopes(input.scopes)
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                "DELETE FROM oauth_authorization_code WHERE expires_at <= now() OR used_at IS NOT NULL",
            ).use { statement -> statement.executeUpdate() }
            connection.prepareStatement(
                """INSERT INTO oauth_authorization_code
                   (code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge, expires_at, consent_id)
                   SELECT ?, ?, ?, ?, ?, ?, ?, now() + (?::bigint * interval '1 second'), id
                   FROM oauth_consent
                   WHERE id = ? AND principal = ? AND client_id = ? AND resource = ? AND scope = ?
                     AND revoked_at IS NULL""",
            ).use { statement ->
                statement.setString(1, sha256Hex(code))
                statement.setString(2, input.clientId)
                statement.setString(3, input.principal)
                statement.setString(4, input.redirectUri)
                statement.setString(5, input.resource)
                statement.setString(6, canonicalScope)
                statement.setString(7, input.codeChallenge)
                statement.setLong(8, input.ttlSeconds.coerceIn(60, 600))
                statement.setLong(9, input.consentId)
                statement.setString(10, input.principal)
                statement.setString(11, input.clientId)
                statement.setString(12, input.resource)
                statement.setString(13, canonicalScope)
                require(statement.executeUpdate() == 1) { "authorization code consent is absent, revoked, or mismatched" }
            }
        }
        return code
    }

    /**
     * [onCommit] runs inside this transaction after the grant succeeds and before commit, so a caller can
     * write an audit row that commits or rolls back WITH the grant — a rejected audit leaves the code
     * unconsumed and the client retries cleanly.
     */
    fun consumeAuthorizationCode(
        input: ConsumeAuthorizationCodeInput,
        onCommit: ((Connection) -> Unit)? = null,
    ): OAuthTokenPair? = inTransaction { connection ->
        val row = connection.prepareStatement(
            """SELECT id, principal, client_id, redirect_uri, resource, scope, code_challenge, consent_id
               FROM oauth_authorization_code
               WHERE code_hash = ? FOR UPDATE""",
        ).use { statement ->
            statement.setString(1, sha256Hex(input.code))
            statement.executeQuery().use { result ->
                if (!result.next()) return@inTransaction null
                CodeRow(
                    id = result.getLong("id"),
                    principal = result.getString("principal"),
                    clientId = result.getString("client_id"),
                    redirectUri = result.getString("redirect_uri"),
                    resource = result.getString("resource"),
                    scope = result.getString("scope"),
                    challenge = result.getString("code_challenge"),
                    consentId = result.getLong("consent_id"),
                )
            }
        }
        val usable = connection.prepareStatement(
            "SELECT used_at IS NULL AND expires_at > now() FROM oauth_authorization_code WHERE id = ?",
        ).use { statement ->
            statement.setLong(1, row.id)
            statement.executeQuery().use { result -> result.next() && result.getBoolean(1) }
        }
        if (!usable || row.clientId != input.clientId || row.redirectUri != input.redirectUri ||
            row.resource != input.resource || !isValidPkceVerifier(input.codeVerifier) ||
            pkceS256(input.codeVerifier) != row.challenge
        ) return@inTransaction null
        connection.prepareStatement("UPDATE oauth_authorization_code SET used_at = now() WHERE id = ? AND used_at IS NULL").use { statement ->
            statement.setLong(1, row.id)
            if (statement.executeUpdate() != 1) return@inTransaction null
        }
        if (!consentActive(connection, row.consentId, row.principal, row.clientId, row.resource, row.scope)) {
            return@inTransaction null
        }
        val pair = issuePair(
            connection = connection,
            principal = row.principal,
            clientId = row.clientId,
            resource = row.resource,
            scope = row.scope,
            consentId = row.consentId,
            family = randomSecret("pmf_", 24),
            accessTtlSeconds = input.accessTtlSeconds,
            refreshTtlSeconds = input.refreshTtlSeconds,
            rotatedFrom = null,
        )
        onCommit?.invoke(connection)
        pair
    }

    /**
     * [onCommit] runs inside this transaction on the SUCCESS (rotation) path; [onReplayRevoke] runs when a
     * replayed (already-rotated) refresh token forces its family to be revoked — a real revocation that
     * commits, so its audit row must commit with it. Both are invoked before commit, keyed by the presented
     * token's id.
     */
    fun rotateRefresh(
        input: RefreshTokenInput,
        onCommit: ((Connection) -> Unit)? = null,
        onReplayRevoke: ((Connection, Long) -> Unit)? = null,
    ): OAuthTokenPair? = inTransaction { connection ->
        val row = connection.prepareStatement(
            """SELECT id, kind, principal, client_id, resource, scope, refresh_family, consent_id,
                      revoked_at, expires_at, rotated_at
               FROM proxy_token WHERE token_hash = ? FOR UPDATE""",
        ).use { statement ->
            statement.setString(1, sha256Hex(input.refreshToken))
            statement.executeQuery().use { result ->
                if (!result.next() || result.getString("kind") != MCP_REFRESH_KIND) return@inTransaction null
                RefreshRow(
                    id = result.getLong("id"),
                    principal = result.getString("principal"),
                    clientId = result.getString("client_id"),
                    resource = result.getString("resource"),
                    scope = result.getString("scope"),
                    family = result.getString("refresh_family"),
                    consentId = result.getLong("consent_id"),
                    revoked = result.getTimestamp("revoked_at") != null,
                    expired = result.getTimestamp("expires_at").toInstant() <= Instant.now(),
                    rotated = result.getTimestamp("rotated_at") != null,
                )
            }
        }
        if (row.clientId != input.clientId || row.resource != input.resource) return@inTransaction null
        if (row.rotated) {
            if (revokeFamily(connection, row.family) > 0) onReplayRevoke?.invoke(connection, row.id)
            return@inTransaction null
        }
        if (row.revoked || row.expired ||
            !consentActive(connection, row.consentId, row.principal, row.clientId, row.resource, row.scope)
        ) return@inTransaction null
        connection.prepareStatement("UPDATE proxy_token SET revoked_at = now(), rotated_at = now() WHERE id = ? AND revoked_at IS NULL").use { statement ->
            statement.setLong(1, row.id)
            if (statement.executeUpdate() != 1) return@inTransaction null
        }
        val pair = issuePair(
            connection = connection,
            principal = row.principal,
            clientId = row.clientId,
            resource = row.resource,
            scope = row.scope,
            consentId = row.consentId,
            family = row.family,
            accessTtlSeconds = input.accessTtlSeconds,
            refreshTtlSeconds = input.refreshTtlSeconds,
            rotatedFrom = row.id,
        )
        onCommit?.invoke(connection)
        pair
    }

    /** [onCommit] runs inside this transaction with the consent id, so a caller's consent-grant audit commits
     *  or rolls back with the consent. */
    fun rememberConsent(
        principal: String,
        clientId: String,
        resource: String,
        scopes: Collection<String>,
        onCommit: ((Connection, Long) -> Unit)? = null,
    ): OAuthConsent =
        inTransaction { connection ->
            val canonical = canonicalScopes(scopes)
            val id = connection.prepareStatement(
                """INSERT INTO oauth_consent (principal, client_id, resource, scope)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL
                   DO UPDATE SET updated_at = now()
                   RETURNING id""",
            ).use { statement ->
                statement.setString(1, principal)
                statement.setString(2, clientId)
                statement.setString(3, resource)
                statement.setString(4, canonical)
                statement.executeQuery().use { result -> result.next(); result.getLong(1) }
            }
            consent(connection, id)!!.also { onCommit?.invoke(connection, id) }
        }

    fun findActiveConsent(principal: String, clientId: String, resource: String, scopes: Collection<String>): OAuthConsent? =
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                """SELECT id, principal, client_id, resource, scope, created_at, updated_at
                   FROM oauth_consent
                   WHERE principal = ? AND client_id = ? AND resource = ? AND scope = ? AND revoked_at IS NULL""",
            ).use { statement ->
                statement.setString(1, principal)
                statement.setString(2, clientId)
                statement.setString(3, resource)
                statement.setString(4, canonicalScopes(scopes))
                statement.executeQuery().use { result -> if (result.next()) result.toConsent() else null }
            }
        }

    fun listConsents(principal: String): List<OAuthConsent> = dataSource.connection.use { connection ->
        connection.prepareStatement(
            """SELECT id, principal, client_id, resource, scope, created_at, updated_at
               FROM oauth_consent WHERE principal = ? AND revoked_at IS NULL ORDER BY updated_at DESC""",
        ).use { statement ->
            statement.setString(1, principal)
            statement.executeQuery().use { result -> buildList { while (result.next()) add(result.toConsent()) } }
        }
    }

    /** [onCommit] runs inside this transaction with the consent id when the revocation actually transitions a
     *  row, so a caller's revoke audit commits with the consent + token revocation. */
    fun revokeConsent(id: Long, principal: String, onCommit: ((Connection, Long) -> Unit)? = null): Boolean = inTransaction { connection ->
        val updated = connection.prepareStatement(
            "UPDATE oauth_consent SET revoked_at = now(), updated_at = now() WHERE id = ? AND principal = ? AND revoked_at IS NULL",
        ).use { statement ->
            statement.setLong(1, id)
            statement.setString(2, principal)
            statement.executeUpdate()
        }
        if (updated == 0) return@inTransaction false
        connection.prepareStatement(
            "UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now()) WHERE consent_id = ? AND kind IN ('MCP_ACCESS', 'MCP_REFRESH')",
        ).use { statement -> statement.setLong(1, id); statement.executeUpdate() }
        onCommit?.invoke(connection, id)
        true
    }

    /**
     * RFC 7009: access closes only itself; refresh closes its entire rotation family. Returns the presented
     * token's id when this call actually closed something, null when it resolved to nothing or to a token
     * already revoked. The caller answers 200 either way (RFC 7009 §2.2 forbids distinguishing the cases to
     * the client), but the endpoint is unauthenticated, so a caller replaying one once-valid token must not
     * be able to append a revocation record per call.
     */
    fun revoke(token: String, onCommit: ((Connection, Long) -> Unit)? = null): Long? = inTransaction { connection ->
        val (id, kind, family) = connection.prepareStatement(
            "SELECT id, kind, refresh_family FROM proxy_token WHERE token_hash = ? FOR UPDATE",
        ).use { statement ->
            statement.setString(1, sha256Hex(token))
            statement.executeQuery().use { result ->
                if (result.next()) Triple(result.getLong(1), result.getString(2), result.getString(3)) else null
            }
        } ?: return@inTransaction null
        val closed = when (kind) {
            MCP_REFRESH_KIND -> revokeFamily(connection, family)
            MCP_ACCESS_KIND -> connection.prepareStatement(
                "UPDATE proxy_token SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL",
            ).use { statement -> statement.setLong(1, id); statement.executeUpdate() }
            else -> 0
        }
        // [onCommit] runs inside this transaction only when a token actually closed, so the revoke audit
        // commits with the revocation (RFC 7009 still answers 200 regardless — the caller absorbs a throw).
        id.takeIf { closed > 0 }?.also { onCommit?.invoke(connection, it) }
    }

    private fun issuePair(
        connection: Connection,
        principal: String,
        clientId: String,
        resource: String,
        scope: String,
        consentId: Long,
        family: String,
        accessTtlSeconds: Long,
        refreshTtlSeconds: Long,
        rotatedFrom: Long?,
    ): OAuthTokenPair {
        val access = randomSecret("pma_")
        val refresh = randomSecret("pmr_")
        insertToken(connection, access, MCP_ACCESS_KIND, principal, clientId, resource, scope, family, consentId, accessTtlSeconds, null)
        insertToken(connection, refresh, MCP_REFRESH_KIND, principal, clientId, resource, scope, family, consentId, refreshTtlSeconds, rotatedFrom)
        return OAuthTokenPair(access, refresh, expiresIn = clampTtlSeconds(accessTtlSeconds), scope = scope)
    }

    private fun insertToken(
        connection: Connection,
        token: String,
        kind: String,
        principal: String,
        clientId: String,
        resource: String,
        scope: String,
        family: String,
        consentId: Long,
        ttlSeconds: Long,
        rotatedFrom: Long?,
    ) {
        connection.prepareStatement(
            """INSERT INTO proxy_token
               (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, rotated_from)
               VALUES (?, ?, ?, '[]'::jsonb, now() + (?::bigint * interval '1 second'), ?, ?, ?, ?, ?, ?)""",
        ).use { statement ->
            statement.setString(1, sha256Hex(token))
            statement.setString(2, kind)
            statement.setString(3, principal)
            statement.setLong(4, clampTtlSeconds(ttlSeconds))
            statement.setString(5, resource)
            statement.setString(6, clientId)
            statement.setString(7, scope)
            statement.setString(8, family)
            statement.setLong(9, consentId)
            statement.setNullableLong(10, rotatedFrom)
            statement.executeUpdate()
        }
    }

    /** Closes every still-open token in [family] and returns how many that was — an already-closed family
     *  keeps its original timestamps and reports 0, which is how a caller tells a real revocation from a replay. */
    private fun revokeFamily(connection: Connection, family: String?): Int {
        if (family == null) return 0
        return connection.prepareStatement(
            """UPDATE proxy_token SET revoked_at = now()
               WHERE refresh_family = ? AND kind IN ('MCP_ACCESS', 'MCP_REFRESH') AND revoked_at IS NULL""",
        ).use { statement -> statement.setString(1, family); statement.executeUpdate() }
    }

    private fun consentActive(
        connection: Connection,
        id: Long,
        principal: String,
        clientId: String,
        resource: String,
        scope: String,
    ): Boolean {
        return connection.prepareStatement(
            """SELECT revoked_at IS NULL FROM oauth_consent
               WHERE id = ? AND principal = ? AND client_id = ? AND resource = ? AND scope = ?""",
        ).use { statement ->
            statement.setLong(1, id)
            statement.setString(2, principal)
            statement.setString(3, clientId)
            statement.setString(4, resource)
            statement.setString(5, scope)
            statement.executeQuery().use { result -> result.next() && result.getBoolean(1) }
        }
    }

    private fun consent(connection: Connection, id: Long): OAuthConsent? = connection.prepareStatement(
        "SELECT id, principal, client_id, resource, scope, created_at, updated_at FROM oauth_consent WHERE id = ?",
    ).use { statement ->
        statement.setLong(1, id)
        statement.executeQuery().use { result -> if (result.next()) result.toConsent() else null }
    }

    private fun java.sql.ResultSet.toConsent() = OAuthConsent(
        id = getLong("id"),
        principal = getString("principal"),
        clientId = getString("client_id"),
        resource = getString("resource"),
        scope = getString("scope"),
        createdAt = getTimestamp("created_at").toInstant().toString(),
        updatedAt = getTimestamp("updated_at").toInstant().toString(),
    )

    private fun <T> inTransaction(block: (Connection) -> T): T = dataSource.connection.use { connection ->
        connection.autoCommit = false
        try {
            val result = block(connection)
            connection.commit()
            result
        } catch (e: Exception) {
            connection.rollback()
            throw e
        } finally {
            connection.autoCommit = true
        }
    }

    private data class CodeRow(
        val id: Long,
        val principal: String,
        val clientId: String,
        val redirectUri: String,
        val resource: String,
        val scope: String,
        val challenge: String,
        val consentId: Long,
    )

    private data class RefreshRow(
        val id: Long,
        val principal: String,
        val clientId: String,
        val resource: String,
        val scope: String,
        val family: String,
        val consentId: Long,
        val revoked: Boolean,
        val expired: Boolean,
        val rotated: Boolean,
    )
}

private fun java.sql.PreparedStatement.setNullableLong(index: Int, value: Long?) {
    if (value == null) setNull(index, Types.BIGINT) else setLong(index, value)
}
