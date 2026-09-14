package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.CapResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ResultCap
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.resolveResultCaps
import java.sql.Connection
import java.time.Duration
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Pure, no-DB proof of [resolveResultCaps] and [ResultCap.parse]: a forbid lifts, else min, and nothing is granted. */
class ResultCapAuthzTest {
    private val seedPolicies = listOf(
        1L to """@cap("5000, 50MB, 100MB/1h") permit(principal, action == Action::"result.cap", resource);""",
        2L to """@cap("500, 5MB, 10000/1h, 50000/1d") permit(principal, action == Action::"result.cap", resource)
                 when { resource is Column && resource.tagged && context has masked && !context.masked };""",
        3L to """@cap("9") permit(principal in Role::"tight", action == Action::"result.cap", resource == Datasource::"acme-pg");""",
        4L to """forbid(principal in Role::"dump", action == Action::"result.cap", resource == Datasource::"acme-pg");""",
        5L to """permit(principal in Role::"quiet", action == Action::"result.cap", resource);""",
    )

    private object UnusedDataSource : DataSource {
        override fun getConnection(): Connection = error("not used by this test")
        override fun getConnection(username: String?, password: String?): Connection = error("not used by this test")
        override fun getLogWriter() = error("not used by this test")
        override fun setLogWriter(out: java.io.PrintWriter?) = error("not used by this test")
        override fun setLoginTimeout(seconds: Int) = error("not used by this test")
        override fun getLoginTimeout() = error("not used by this test")
        override fun getParentLogger(): Logger = error("not used by this test")
        override fun <T : Any?> unwrap(iface: Class<T>?): T = error("not used by this test")
        override fun isWrapperFor(iface: Class<*>?): Boolean = false
    }

    private val authz = Authz(CedarEngine(seedPolicies), CedarPolicyStore(UnusedDataSource), RoleSource { emptySet() })
    private val ssnRef = ColumnRef("acme.public.users.ssn", "acme", "public", "users", "ssn", listOf("pii"))
    private val ssnClear = CapResource.Column(ssnRef, null, masked = false)
    private val ssnMasked = CapResource.Column(ssnRef, null, masked = true)
    private val id = CapResource.Column(ColumnRef("acme.public.users.id", "acme", "public", "users", "id"), null, masked = false)

    private fun resolve(roles: Set<String>, vararg resources: CapResource) =
        authz.resolveResultCaps("alice", roles, "acme-pg", resources.toList())

    @Test
    fun `the datasource ask alone yields the general row`() {
        val caps = resolve(emptySet())
        assertEquals(false, caps.unbounded)
        assertEquals(5_000L to 50_000_000L, caps.rows to caps.bytes)
        assertEquals(listOf("100MB/1h"), caps.rates.map { it.spec })
    }

    @Test
    fun `a tagged column in the clear tightens, masked or untagged it does not`() {
        assertEquals(500L to 5_000_000L, resolve(emptySet(), ssnClear).let { it.rows to it.bytes })
        assertEquals(5_000L to 50_000_000L, resolve(emptySet(), ssnMasked).let { it.rows to it.bytes })
        assertEquals(5_000L to 50_000_000L, resolve(emptySet(), id).let { it.rows to it.bytes })
        assertEquals(500L to 5_000_000L, resolve(emptySet(), id, ssnClear).let { it.rows to it.bytes })
        // The tight row's rates ride along only when it matched.
        assertTrue(resolve(emptySet(), ssnClear).rates.any { it.spec == "10000/1h" })
        assertTrue(resolve(emptySet(), ssnMasked).rates.none { it.spec == "10000/1h" })
    }

    @Test
    fun `a role-scoped row folds in by minimum on its dimension only`() {
        assertEquals(9L to 5_000_000L, resolve(setOf("tight"), ssnClear).let { it.rows to it.bytes })
    }

    @Test
    fun `a forbid wins over every number and drops every rate`() {
        val lifted = resolve(setOf("tight", "dump"), ssnClear)
        assertEquals(true, lifted.unbounded)
        assertEquals(null, lifted.rows)
        assertTrue(lifted.rates.isEmpty())
    }

    @Test
    fun `an unannotated result cap permit contributes nothing`() {
        assertEquals(5_000L to 50_000_000L, resolve(setOf("quiet"), id).let { it.rows to it.bytes })
    }

    @Test
    fun `permitting result cap is not a read grant`() {
        assertIs<AuthzDecision.Deny>(
            authz.authorizeDatasourceAction("alice", setOf("dump"), AuthzAction.DATASOURCE_CONNECT, "acme-pg"),
        )
    }

    @Test
    fun `the cap grammar is one list of amounts and rates`() {
        val cap = ResultCap.parse(mapOf("cap" to "500, 5MB, 10000/1h, 50MB/1d, 7/10m"))
        assertEquals(500L, cap.rows)
        assertEquals(5_000_000L, cap.bytes)
        assertEquals(listOf(10_000L to null, null to 50_000_000L, 7L to null), cap.rates.map { it.rows to it.bytes })
        assertEquals(listOf(Duration.ofHours(1), Duration.ofDays(1), Duration.ofMinutes(10)), cap.rates.map { it.window })
        assertEquals(200L, ResultCap.parse(mapOf("cap" to "500, 200")).rows, "two cap entries fold to the tightest")
        for (bad in listOf("2K", "3M", "1G", "abc", "0", "5MB/", "/1h", "10/32d", "10/1x", "1,,2", "")) {
            assertFailsWith<IllegalArgumentException>(bad) { ResultCap.parse(mapOf("cap" to bad)) }
        }
        assertTrue(ResultCap.parse(emptyMap()).isEmpty)
    }
}
