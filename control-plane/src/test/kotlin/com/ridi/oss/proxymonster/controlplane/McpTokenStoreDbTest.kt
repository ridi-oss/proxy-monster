package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.McpTokenStore
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_RESOURCE
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The MCP server's bearer lookup: a live access token under a live consent, for exactly this resource. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpTokenStoreDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: McpTokenStore
    private lateinit var tokens: McpTokens

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_mcp_token_store"))
        store = McpTokenStore(dataSource)
        tokens = McpTokens(dataSource)
    }

    @AfterAll
    fun close() {
        (dataSource as? AutoCloseable)?.close()
    }

    @Test
    fun `an access token resolves only for its resource while it and its consent are live`() {
        val token = tokens.token("mcp-user@example.com", setOf("mcp:read", "mcp:query"))
        val identity = assertNotNull(store.resolveAccess(token, MCP_TEST_RESOURCE))
        assertEquals("mcp-user@example.com", identity.principal)
        assertEquals(setOf("mcp:read", "mcp:query"), identity.scopes)
        assertNull(store.resolveAccess(token, "$MCP_TEST_RESOURCE/wrong"))
        assertNull(store.resolveAccess("pma_unknown", MCP_TEST_RESOURCE))

        execute("UPDATE oauth_consent SET revoked_at = now() WHERE id = ${identity.consentId}")
        assertNull(store.resolveAccess(token, MCP_TEST_RESOURCE), "a revoked consent must close its tokens")

        val expired = tokens.token("mcp-user@example.com", setOf("mcp:read"))
        execute("UPDATE proxy_token SET expires_at = now() - interval '1 second' WHERE token_hash = '${sha256Hex(expired)}'")
        assertNull(store.resolveAccess(expired, MCP_TEST_RESOURCE))

        val revoked = tokens.token("mcp-user@example.com", setOf("mcp:tokens"))
        execute("UPDATE proxy_token SET revoked_at = now() WHERE token_hash = '${sha256Hex(revoked)}'")
        assertNull(store.resolveAccess(revoked, MCP_TEST_RESOURCE))
    }

    private fun execute(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }
}
