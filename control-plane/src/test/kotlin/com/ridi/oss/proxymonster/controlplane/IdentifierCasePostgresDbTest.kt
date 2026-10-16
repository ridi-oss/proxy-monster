package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.NAME_ADMIN
import com.ridi.oss.proxymonster.controlplane.support.NAME_SENTINEL
import com.ridi.oss.proxymonster.controlplane.support.NameCaseStack
import com.ridi.oss.proxymonster.controlplane.support.NameCaseTarget
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

private const val QUOTED_SENTINEL = "quoted.table@example.com"

/** Postgres: unquoted names fold to lowercase, quoted names keep their case; "Users" and users are two tables. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdentifierCasePostgresDbTest {
    private lateinit var stack: NameCaseStack

    private val lowerReads = listOf("SELECT email FROM users", "SELECT EMAIL FROM Users", "SELECT email FROM \"users\"")
    private val quotedReads = listOf("SELECT email FROM \"Users\"", "SELECT EMAIL FROM public.\"Users\"")

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        stack = NameCaseStack.create()
    }

    private fun target(): NameCaseTarget = stack.postgres { st ->
        st.execute("CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT)")
        st.execute("INSERT INTO users VALUES (1, '$NAME_SENTINEL')")
        st.execute("CREATE TABLE \"Users\" (id BIGINT PRIMARY KEY, email TEXT)")
        st.execute("INSERT INTO \"Users\" VALUES (1, '$QUOTED_SENTINEL')")
    }

    private fun assertOnlyLowerMasked(t: NameCaseTarget) {
        lowerReads.forEach { t.assertMasked(it) }
        quotedReads.forEach { t.assertCleartext(it, QUOTED_SENTINEL) }
    }

    private fun assertOnlyQuotedMasked(t: NameCaseTarget) {
        quotedReads.forEach { t.assertMasked(it, QUOTED_SENTINEL) }
        lowerReads.forEach { t.assertCleartext(it) }
    }

    @Test
    fun `HTTP classification Users means users`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        client.login(NAME_ADMIN)
        assertEquals(HttpStatusCode.OK, t.httpClassify(client, t.schema, "Users", "email").status)
        assertOnlyLowerMasked(t)
    }

    @Test
    fun `HTTP classification users means users`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        client.login(NAME_ADMIN)
        assertEquals(HttpStatusCode.OK, t.httpClassify(client, t.schema, "users", "email").status)
        assertOnlyLowerMasked(t)
    }

    @Test
    fun `MCP classification quoted Users means Users`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        t.mcpClassify(client, stack.adminToken(), t.schema, "\"Users\"", "email").ok()
        assertOnlyQuotedMasked(t)
    }

    @Test
    fun `MCP classification Users means users`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        t.mcpClassify(client, stack.adminToken(), t.schema, "Users", "EMAIL").ok()
        assertOnlyLowerMasked(t)
    }
}
