package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ColumnVerdict
import com.ridi.oss.proxymonster.controlplane.authz.FilterVerdict
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumnFilters
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumns
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pure, no-DB proof of the `result.filter.literal` opt-in (docs/authz-model.md, "Opting in to literal
 * filters"). The action is asked only for a column the analyzer marked ALLOW_LITERAL_FILTER whose read verdict
 * is MASKED; this pins the Cedar decision itself: deny by default, scoped like a read permit, independent of
 * the read actions in both directions, and overridden by a `forbid`. Same in-memory engine pattern as
 * [ColumnAuthzTest].
 */
class ColumnFilterAuthzTest {
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

    private fun authz(vararg policies: String): Authz =
        Authz(
            CedarEngine(policies.mapIndexed { i, src -> (i + 1).toLong() to src }),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )

    private val filterPii =
        """permit(principal in Role::"analyst", action == Action::"result.filter.literal", resource in Datasource::"acme-pg") when { resource in Tag::"pii" };"""
    private val readMaskedPii =
        """permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Datasource::"acme-pg") when { resource in Tag::"pii" };"""

    private val email = ColumnRef("acme.public.users.email", "acme", "public", "users", "email", listOf("pii"))
    private val region = ColumnRef("acme.public.users.region", "acme", "public", "users", "region")
    private val analyst = UserParents(setOf("analyst"))

    private fun filters(authz: Authz, vararg columns: ColumnRef, parents: UserParents = analyst) =
        authz.authorizeColumnFilters("alice", parents, "acme-pg", columns.toList())

    @Test
    fun `without a permit a masked column cannot be filtered on`() {
        assertEquals(mapOf(email.key to FilterVerdict.DENIED), filters(authz(readMaskedPii), email))
    }

    @Test
    fun `a permit scoped to the pii tag allows filtering on a pii column`() {
        assertEquals(mapOf(email.key to FilterVerdict.ALLOWED), filters(authz(filterPii), email))
    }

    @Test
    fun `the permit does not reach a column outside its tag`() {
        assertEquals(
            mapOf(email.key to FilterVerdict.ALLOWED, region.key to FilterVerdict.DENIED),
            filters(authz(filterPii), email, region),
        )
    }

    @Test
    fun `the permit does not reach a principal without the role`() {
        assertEquals(
            mapOf(email.key to FilterVerdict.DENIED),
            filters(authz(filterPii), email, parents = UserParents(setOf("someone-else"))),
        )
    }

    @Test
    fun `a read permit never implies the filter permit`() {
        val authz = authz(readMaskedPii)
        assertEquals(
            mapOf(email.key to ColumnVerdict.MASKED),
            authz.authorizeColumns("alice", analyst, "acme-pg", listOf(email)),
        )
        assertEquals(mapOf(email.key to FilterVerdict.DENIED), filters(authz, email))
    }

    @Test
    fun `the filter permit never implies a read`() {
        val authz = authz(filterPii)
        assertEquals(mapOf(email.key to FilterVerdict.ALLOWED), filters(authz, email))
        assertEquals(
            mapOf(email.key to ColumnVerdict.DENIED),
            authz.authorizeColumns("alice", analyst, "acme-pg", listOf(email)),
        )
    }

    @Test
    fun `a forbid overrides the permit`() {
        val forbid =
            """forbid(principal in Role::"analyst", action == Action::"result.filter.literal", resource == Column::"acme-pg/acme/public/users/email");"""
        assertEquals(mapOf(email.key to FilterVerdict.DENIED), filters(authz(filterPii, forbid), email))
    }

    @Test
    fun `an identity carrying a delimiter builds no entity and is denied`() {
        val odd = ColumnRef("acme.public.users.e/mail", "acme", "public", "users", "e/mail", listOf("pii"))
        assertEquals(mapOf(odd.key to FilterVerdict.DENIED), filters(authz(filterPii), odd))
    }
}
