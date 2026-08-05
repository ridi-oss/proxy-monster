package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.AuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.ConsumeAuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.McpTokenStore
import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.OAuthTokenPair
import com.ridi.oss.proxymonster.auth.RefreshTokenInput
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpOAuthStoreDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: OAuthAuthorizationStore
    private lateinit var tokens: McpTokenStore

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_oauth"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = OAuthAuthorizationStore(dataSource)
        tokens = McpTokenStore(dataSource)
    }

    @AfterAll
    fun close() {
        (dataSource as? AutoCloseable)?.close()
    }

    @Test
    fun `authorization code is one-time PKCE-bound and access tokens are audience-bound`() {
        val principal = "oauth-audience@example.com"
        val consent = store.rememberConsent(principal, CLIENT_ID, RESOURCE, SCOPES)
        val code = store.createAuthorizationCode(
            AuthorizationCodeInput(
                CLIENT_ID, principal, REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                consentId = consent.id,
            ),
        )

        assertNull(store.consumeAuthorizationCode(consume(code, resource = "$RESOURCE/wrong")))
        assertNull(store.consumeAuthorizationCode(consume(code, verifier = "b".repeat(43))))
        val pair = assertNotNull(store.consumeAuthorizationCode(consume(code)))
        assertNull(store.consumeAuthorizationCode(consume(code)), "an authorization code must be single-use")

        val identity = assertNotNull(tokens.resolveAccess(pair.accessToken, RESOURCE))
        assertEquals(principal, identity.principal)
        assertEquals(CLIENT_ID, identity.clientId)
        assertEquals(SCOPES, identity.scopes)
        assertEquals(consent.id, identity.consentId)
        assertNull(tokens.resolveAccess(pair.accessToken, "$RESOURCE/wrong"))

        dataSource.connection.use { connection ->
            connection.prepareStatement("SELECT token_hash, roles FROM proxy_token WHERE kind='MCP_ACCESS' AND principal=?").use { statement ->
                statement.setString(1, principal)
                statement.executeQuery().use { result ->
                    assertTrue(result.next())
                    assertFalse(result.getString("token_hash").contains(pair.accessToken), "the plaintext token must never be stored")
                    assertEquals("[]", result.getString("roles"))
                }
            }
        }
    }

    @Test
    fun `refresh rotates once and replay revokes the complete token family`() {
        val first = issue("oauth-rotation@example.com")
        val second = assertNotNull(store.rotateRefresh(refresh(first.refreshToken)))
        assertNotNull(tokens.resolveAccess(second.accessToken, RESOURCE))

        assertNull(store.rotateRefresh(refresh(first.refreshToken)), "a rotated refresh token is replay, not a second rotation")
        assertNull(tokens.resolveAccess(first.accessToken, RESOURCE))
        assertNull(tokens.resolveAccess(second.accessToken, RESOURCE))
        assertNull(store.rotateRefresh(refresh(second.refreshToken)), "replay must revoke the new refresh token too")
    }

    @Test
    fun `revoked consent blocks code exchange and revokes access plus refresh`() {
        val principal = "oauth-consent@example.com"
        val consent = store.rememberConsent(principal, CLIENT_ID, RESOURCE, SCOPES)
        val code = store.createAuthorizationCode(
            AuthorizationCodeInput(
                CLIENT_ID, principal, REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                consentId = consent.id,
            ),
        )
        val active = issue(principal, consent.id)

        assertTrue(store.revokeConsent(consent.id, principal))
        assertFalse(store.revokeConsent(consent.id, principal))
        assertNull(store.consumeAuthorizationCode(consume(code)))
        assertNull(tokens.resolveAccess(active.accessToken, RESOURCE))
        assertNull(store.rotateRefresh(refresh(active.refreshToken)))
    }

    @Test
    fun `RFC 7009 access revocation is local while refresh revocation closes the family`() {
        val accessOnly = issue("oauth-revoke-access@example.com")
        assertNotNull(store.revoke(accessOnly.accessToken))
        assertNull(tokens.resolveAccess(accessOnly.accessToken, RESOURCE))
        val afterAccessRevoke = assertNotNull(store.rotateRefresh(refresh(accessOnly.refreshToken)))
        assertNotNull(tokens.resolveAccess(afterAccessRevoke.accessToken, RESOURCE))

        assertNotNull(store.revoke(afterAccessRevoke.refreshToken))
        assertNull(tokens.resolveAccess(afterAccessRevoke.accessToken, RESOURCE))
        assertNull(store.rotateRefresh(refresh(afterAccessRevoke.refreshToken)))
    }

    /**
     * Revocation reports the token it CLOSED, not merely one that resolved. The endpoint in front of this is
     * unauthenticated (RFC 7009 answers 200 for an unknown token), so a caller replaying one once-valid token
     * must not be able to append a revocation record per call.
     */
    @Test
    fun `revoke reports a transition once and an unknown token never`() {
        val pair = issue("oauth-revoke-replay@example.com")

        assertNotNull(store.revoke(pair.accessToken), "the first revoke closes the access token")
        assertNull(store.revoke(pair.accessToken), "replaying the same access token closes nothing")

        assertNotNull(store.revoke(pair.refreshToken), "the refresh token's family is still open")
        assertNull(store.revoke(pair.refreshToken), "replaying the refresh token closes nothing")

        assertNull(store.revoke("pma_never-issued"))
    }

    @Test
    fun `authorization codes cannot borrow a mismatched or revoked consent`() {
        val consent = store.rememberConsent("consent-owner@example.com", CLIENT_ID, RESOURCE, SCOPES)
        assertFailsWith<IllegalArgumentException> {
            store.createAuthorizationCode(
                AuthorizationCodeInput(
                    CLIENT_ID, "different-principal@example.com", REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                    consentId = consent.id,
                ),
            )
        }
        assertTrue(store.revokeConsent(consent.id, "consent-owner@example.com"))
        assertFailsWith<IllegalArgumentException> {
            store.createAuthorizationCode(
                AuthorizationCodeInput(
                    CLIENT_ID, "consent-owner@example.com", REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                    consentId = consent.id,
                ),
            )
        }
    }

    @Test
    fun `issuing a code prunes expired and already-used authorization codes`() {
        val principal = "oauth-pruning@example.com"
        val consent = store.rememberConsent(principal, CLIENT_ID, RESOURCE, SCOPES)
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                """INSERT INTO oauth_authorization_code
                   (code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge,
                    consent_id, expires_at, used_at)
                   VALUES ('expired-code', ?, ?, ?, ?, ?, ?, ?, now() - interval '1 minute', NULL),
                          ('used-code', ?, ?, ?, ?, ?, ?, ?, now() + interval '1 minute', now())""",
            ).use { statement ->
                for (offset in listOf(0, 7)) {
                    statement.setString(1 + offset, CLIENT_ID)
                    statement.setString(2 + offset, principal)
                    statement.setString(3 + offset, REDIRECT_URI)
                    statement.setString(4 + offset, RESOURCE)
                    statement.setString(5 + offset, canonicalScopesForTest())
                    statement.setString(6 + offset, CHALLENGE)
                    statement.setLong(7 + offset, consent.id)
                }
                statement.executeUpdate()
            }
        }

        store.createAuthorizationCode(
            AuthorizationCodeInput(
                CLIENT_ID, principal, REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                consentId = consent.id,
            ),
        )

        dataSource.connection.use { connection ->
            connection.prepareStatement(
                "SELECT count(*) FROM oauth_authorization_code WHERE code_hash IN ('expired-code', 'used-code')",
            ).use { statement ->
                statement.executeQuery().use { result -> result.next(); assertEquals(0, result.getInt(1)) }
            }
        }
    }

    private fun issue(principal: String, consentId: Long? = null): OAuthTokenPair {
        val consent = consentId ?: store.rememberConsent(principal, CLIENT_ID, RESOURCE, SCOPES).id
        val code = store.createAuthorizationCode(
            AuthorizationCodeInput(
                CLIENT_ID, principal, REDIRECT_URI, RESOURCE, SCOPES, CHALLENGE,
                consentId = consent,
            ),
        )
        return assertNotNull(store.consumeAuthorizationCode(consume(code)))
    }

    private fun consume(
        code: String,
        resource: String = RESOURCE,
        verifier: String = VERIFIER,
    ) = ConsumeAuthorizationCodeInput(code, CLIENT_ID, REDIRECT_URI, resource, verifier, 600, 3_600)

    private fun refresh(token: String) = RefreshTokenInput(token, CLIENT_ID, RESOURCE, 600, 3_600)

    private fun canonicalScopesForTest() = SCOPES.sorted().joinToString(" ")

    private companion object {
        const val CLIENT_ID = "https://client.example/mcp.json"
        const val REDIRECT_URI = "http://127.0.0.1:43110/callback"
        const val RESOURCE = "https://proxy.example/mcp"
        val SCOPES = setOf("mcp:read", "mcp:policies:write")
        val VERIFIER = "a".repeat(43)
        val CHALLENGE = pkceS256(VERIFIER)
    }
}
