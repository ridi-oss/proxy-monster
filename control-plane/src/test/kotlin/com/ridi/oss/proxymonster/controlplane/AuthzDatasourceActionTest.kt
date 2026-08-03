package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Pure, no-DB proof of the two once-per-query gates (docs/authz-model.md) —
 * `datasource.connect` and `sql.<kind>` — pinned at the Cedar-decision level, independent of Query.kt's
 * wiring. In particular this pins the NAME-keying of the Datasource resource EUID
 * ([Authz.authorizeDatasourceAction] must NOT go through [Authz.authorize]'s id-keyed
 * `marshalResource`, which would silently deny every query) and deny-by-default (an ungranted action,
 * an ungranted datasource name, and an empty role set are all DENIED, never absent-equals-allow).
 * Mirrors ColumnAuthzTest's in-memory-CedarEngine + UnusedDataSource pattern to stay off JDBC/Docker.
 */
class AuthzDatasourceActionTest {
    // A role granted datasource.connect + sql.select + sql.insert on acme-mysql specifically — NOT
    // sql.delete, and NOT any other datasource name.
    private val seedPolicies = listOf(
        1L to """permit(
            principal in Role::"batch-writer",
            action in [Action::"datasource.connect", Action::"sql.select", Action::"sql.insert"],
            resource in Datasource::"acme-mysql"
        );""",
        2L to """permit(
            principal,
            action == Action::"sql.unmaskable",
            resource
        ) when { resource in Tag::"system:development" };""",
    )

    /** A [DataSource] that's never actually connected to — [authorizeDatasourceAction] never touches
     *  its [CedarPolicyStore] parameter, only [CedarEngine] does, and this test's engine is built from
     *  an in-memory policy list (mirrors ColumnAuthzTest's UnusedDataSource). */
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

    private fun authz(): Authz {
        val engine = CedarEngine(seedPolicies)
        val policyStore = CedarPolicyStore(UnusedDataSource)
        // authorizeDatasourceAction takes roles explicitly and never calls this — it's only here
        // because Authz's constructor requires a RoleSource for its own (unrelated) authorize() path.
        val roleSource = RoleSource { emptySet() }
        return Authz(engine, policyStore, roleSource)
    }

    @Test
    fun `a granted role may connect to the named datasource`() {
        val decision = authz().authorizeDatasourceAction(
            principal = "alice",
            roles = setOf("batch-writer"),
            action = AuthzAction.DATASOURCE_CONNECT,
            datasource = "acme-mysql",
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `a granted role may run a granted sql kind on the named datasource`() {
        val decision = authz().authorizeDatasourceAction(
            principal = "alice",
            roles = setOf("batch-writer"),
            action = AuthzAction.SQL_INSERT,
            datasource = "acme-mysql",
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `sql-unmaskable follows the preset-development datasource tag`() {
        val authz = authz()
        assertEquals(
            AuthzDecision.Allow,
            authz.authorizeDatasourceAction(
                principal = "alice",
                roles = setOf("batch-writer"),
                action = AuthzAction.SQL_UNMASKABLE,
                datasource = "acme-mysql",
                datasourceTags = listOf("system:development"),
            ),
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorizeDatasourceAction(
                principal = "alice",
                roles = setOf("batch-writer"),
                action = AuthzAction.SQL_UNMASKABLE,
                datasource = "acme-mysql",
                datasourceTags = emptyList(),
            ),
        )
    }

    @Test
    fun `an ungranted sql kind is denied — deny-by-default, not absent-equals-allow`() {
        val decision = authz().authorizeDatasourceAction(
            principal = "alice",
            roles = setOf("batch-writer"),
            action = AuthzAction.SQL_DELETE,
            datasource = "acme-mysql",
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `the same grant on a different datasource name does not apply — NAME-keyed, not blanket`() {
        val decision = authz().authorizeDatasourceAction(
            principal = "alice",
            roles = setOf("batch-writer"),
            action = AuthzAction.DATASOURCE_CONNECT,
            datasource = "other",
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `no roles at all is denied`() {
        val decision = authz().authorizeDatasourceAction(
            principal = "nobody",
            roles = emptySet(),
            action = AuthzAction.DATASOURCE_CONNECT,
            datasource = "acme-mysql",
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `every datasource tag reaches policy as itself, whatever it is named`() {
        // Marshalling does not ask what a tag is called or what type carries it, so an operator's own
        // `pci` and a product `system:` name both match a policy written against them.
        val authz = Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal, action == Action::"sql.select", resource)
                             when { resource in Tag::"pci" };""",
                    2L to """permit(principal, action == Action::"sql.delete", resource)
                             when { resource in Tag::"system:critical" };""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        assertEquals(
            AuthzDecision.Allow,
            authz.authorizeDatasourceAction(
                principal = "alice",
                roles = setOf("anyone"),
                action = AuthzAction.SQL_SELECT,
                datasource = "acme-mysql",
                datasourceTags = listOf("pci"),
            ),
            "an ordinary datasource tag must reach Cedar as itself",
        )
        assertEquals(
            AuthzDecision.Allow,
            authz.authorizeDatasourceAction(
                principal = "alice",
                roles = setOf("anyone"),
                action = AuthzAction.SQL_DELETE,
                datasource = "acme-mysql",
                datasourceTags = listOf("system:critical"),
            ),
            "a product `system:` name is a tag too — no type-scoping drops it off a datasource",
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorizeDatasourceAction(
                principal = "alice",
                roles = setOf("anyone"),
                action = AuthzAction.SQL_SELECT,
                datasource = "acme-mysql",
                datasourceTags = emptyList(),
            ),
            "and the verdict comes from the tag: untagged, the same action is denied",
        )
    }

    @Test
    fun `the naming rule refuses an invented system name and admits the six the product defines`() {
        for (legal in DatasourceStore.SYSTEM_TAG_NAMES) {
            assertEquals(false, DatasourceStore.isReservedTagName(legal), "'$legal' is a product tag and must be writable")
        }
        for (invented in listOf("system:whatever", "system:", "system:Production", "system:critical-ish")) {
            assertEquals(true, DatasourceStore.isReservedTagName(invented), "'$invented' is not a product tag and must be refused")
        }
        for (ordinary in listOf("pci", "pii", "udf:output-vouched", "systematic", "SYSTEM:critical")) {
            assertEquals(false, DatasourceStore.isReservedTagName(ordinary), "'$ordinary' is an ordinary name and must be writable")
        }
    }
}
