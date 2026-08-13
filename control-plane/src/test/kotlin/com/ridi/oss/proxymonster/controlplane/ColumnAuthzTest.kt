package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ColumnVerdict
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumns
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pure, no-DB proof of the deny-by-default column-authz contract (docs/authz-model.md): every
 * touched column gets an EXPLICIT verdict from [authorizeColumns] — a column with no matching Cedar
 * grant is DENIED, never returned cleartext. A touched column ABSENT from a map must never fall through
 * to cleartext; these tests pin the deny-by-default verdict at the Cedar-decision level, independent of
 * Query.kt's wiring. Mirrors AuthzTest's
 * in-memory-CedarEngine + UnusedDataSource pattern to stay off JDBC/Docker.
 */
class ColumnAuthzTest {
    // The "read table except pii" pair from docs/authz-model.md's worked example, scoped to a
    // single fully-qualified table on a single datasource — analyst gets cleartext on every users
    // column NOT tagged pii, and the mask on the ones that are.
    private val seedPolicies = listOf(
        1L to """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Table::"acme-pg/acme/public/users") unless { resource in Tag::"pii" };""",
        2L to """permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Table::"acme-pg/acme/public/users") when { resource in Tag::"pii" };""",
        3L to """permit(principal in Role::"column-reader", action == Action::"result.read.unmasked", resource == Column::"acme-pg/acme/public/users/region");""",
    )

    /** A [DataSource] that's never actually connected to — [authorizeColumns] never touches its
     *  [CedarPolicyStore] parameter, only [CedarEngine] does, and this test's engine is built from an
     *  in-memory policy list (mirrors AuthzTest's UnusedDataSource). */
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
        // authorizeColumns takes roles explicitly and never calls this — it's only here because
        // Authz's constructor requires a RoleSource for its own (unrelated) authorize() path.
        val roleSource = RoleSource { emptySet() }
        return Authz(engine, policyStore, roleSource)
    }

    private fun column(
        key: String,
        table: String,
        name: String,
        catalog: String = "acme",
        schema: String = "public",
        tags: List<String> = emptyList(),
    ) = ColumnRef(key = key, catalog = catalog, schema = schema, table = table, column = name, tags = tags)

    @Test
    fun `an untagged column in the granted table is unmasked`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.users.region", "users", "region")),
        )
        assertEquals(mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED), verdicts)
    }

    @Test
    fun `a fully-qualified Column EUID grant matches its exact column`() {
        val verdicts = authz().authorizeColumns(
            principal = "bob",
            roles = setOf("column-reader"),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.users.region", "users", "region")),
        )
        assertEquals(mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED), verdicts)
    }

    @Test
    fun `an identifier containing a key delimiter is denied fail-closed`() {
        // '/' and '.' are legal in quoted SQL identifiers but are the Cedar-EUID and analyzer-key
        // delimiters, so a component containing one cannot render to an unambiguous key/EUID (schema
        // "public/a"+table "users" vs schema "public"+table "a/users" would collide). Such identities
        // are DENIED before Cedar — never a wrong-grant collision — and even a broad grant can't
        // authorize them: the key/EUID form joins components on the raw delimiter, so it cannot
        // represent such an identity unambiguously. Rejecting is the fail-closed answer for that
        // representation; an injective encoding would be the alternative, and is not what ships.
        val engine = CedarEngine(
            listOf(9L to """permit(principal in Role::"r", action == Action::"result.read.unmasked", resource);"""),
        )
        val authz = Authz(engine, CedarPolicyStore(UnusedDataSource), RoleSource { emptySet() })
        val verdicts = authz.authorizeColumns(
            "u", setOf("r"), "acme-pg",
            listOf(
                column("slash", table = "a/users", name = "ssn"),                 // '/' in table
                column("dot", table = "users", name = "ssn", schema = "pub.lic"),  // '.' in schema
                column("clean", table = "users", name = "ssn"),                    // no delimiter
            ),
        )
        assertEquals(ColumnVerdict.DENIED, verdicts["slash"], "a '/'-bearing identity must be denied")
        assertEquals(ColumnVerdict.DENIED, verdicts["dot"], "a '.'-bearing identity must be denied")
        assertEquals(ColumnVerdict.UNMASKED, verdicts["clean"], "the broad grant authorizes the clean identity")
    }

    @Test
    fun `a pii-tagged column in the granted table is masked, not unmasked`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.users.ssn", "users", "ssn", tags = listOf("pii"))),
        )
        assertEquals(mapOf("acme.public.users.ssn" to ColumnVerdict.MASKED), verdicts)
    }

    @Test
    fun `a column in an ungranted table is denied — deny-by-default, not absent-equals-cleartext`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.orders.amount", "orders", "amount")),
        )
        assertEquals(mapOf("acme.public.orders.amount" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `a pii-tagged column in an UNGRANTED table is denied, not masked — the masked grant is table-scoped`() {
        // The masked grant is scoped to Table::"acme-pg/acme/public/users", NOT a blanket
        // `resource in Tag::"pii"`. A pii column in a table this role has no grant on must be DENIED.
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.orders.card", "orders", "card", tags = listOf("pii"))),
        )
        assertEquals(mapOf("acme.public.orders.card" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `no roles at all is denied on every column`() {
        val verdicts = authz().authorizeColumns(
            principal = "nobody",
            roles = emptySet(),
            datasource = "acme-pg",
            columns = listOf(column("acme.public.users.region", "users", "region")),
        )
        assertEquals(mapOf("acme.public.users.region" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `a batch of columns resolves independent verdicts in one call`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(
                column("acme.public.users.region", "users", "region"),
                column("acme.public.users.ssn", "users", "ssn", tags = listOf("pii")),
                column("acme.public.orders.amount", "orders", "amount"),
            ),
        )
        assertEquals(
            mapOf(
                "acme.public.users.region" to ColumnVerdict.UNMASKED,
                "acme.public.users.ssn" to ColumnVerdict.MASKED,
                "acme.public.orders.amount" to ColumnVerdict.DENIED,
            ),
            verdicts,
        )
    }

    @Test
    fun `a permit on public users does not cover analytics users with the same table name`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("acme.analytics.users.region", "users", "region", schema = "analytics")),
        )
        assertEquals(mapOf("acme.analytics.users.region" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `a permit in one catalog does not cover the same schema and table in another catalog`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "acme-pg",
            columns = listOf(column("other.public.users.region", "users", "region", catalog = "other")),
        )
        assertEquals(mapOf("other.public.users.region" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `a different datasource with the same qualified table is not covered by the grant`() {
        val verdicts = authz().authorizeColumns(
            principal = "alice",
            roles = setOf("analyst"),
            datasource = "other-ds",
            columns = listOf(column("acme.public.users.region", "users", "region")),
        )
        assertEquals(mapOf("acme.public.users.region" to ColumnVerdict.DENIED), verdicts)
    }

    @Test
    fun `an operator's own datasource tag reaches a column through the datasource parent`() {
        // The transitive path is what a datasource tag is FOR: one tag on the datasource decides every
        // column under it.
        val authz = Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal, action == Action::"result.read.unmasked", resource)
                             when { resource in Tag::"pci" };""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        val col = listOf(column("acme.public.users.region", "users", "region"))
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("anyone"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = listOf("pci"),
            ),
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.DENIED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("anyone"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = emptyList(),
            ),
            "the verdict must come from the tag, not from something else in the policy",
        )
    }

    /**
     * A datasource tag is inherited by every column under it, so one named after a classification the
     * shipped presets key on decides for the whole datasource: `pii` flips an unclassified column from
     * cleartext to masked, whatever the column itself says.
     */
    @Test
    fun `a datasource tagged pii masks a column the shipped preset would otherwise read cleartext`() {
        val authz = Authz(
            CedarEngine(
                listOf(
                    // The shipped pair, verbatim in shape: -256 grants cleartext unless the resource is
                    // pii; -257 grants masked when it is.
                    1L to """permit(principal, action == Action::"result.read.unmasked", resource)
                             when { resource in Tag::"system:production" }
                             unless { resource in Tag::"pii" };""",
                    2L to """permit(principal, action == Action::"result.read.masked", resource)
                             when { resource in Tag::"system:production" && resource in Tag::"pii" };""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        // No classification of its own — every bit of the decision comes from the datasource's tags.
        val col = listOf(column("acme.public.users.region", "users", "region"))
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("anyone"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = listOf("system:production"),
            ),
            "an unclassified column on a production datasource reads cleartext",
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.MASKED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("anyone"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = listOf("system:production", "pii"),
            ),
            "adding pii to the DATASOURCE masks that same column, inherited through the datasource parent",
        )
    }

    /**
     * The other direction: a permit keyed on `resource in Tag::"pii"` — the `pii-reader` grant in
     * authz-model.md — reaches every column under a `pii`-tagged datasource, including columns nobody
     * classified.
     */
    @Test
    fun `a datasource tagged pii hands a pii-keyed permit every column under it`() {
        val authz = Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal in Role::"pii-reader", action == Action::"result.read.unmasked",
                                    resource in Tag::"pii");""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        val col = listOf(column("acme.public.users.region", "users", "region"))
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.DENIED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("pii-reader"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = emptyList(),
            ),
            "an unclassified column is not pii, so the pii-keyed permit does not reach it",
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED),
            authz.authorizeColumns(
                principal = "alice",
                roles = setOf("pii-reader"),
                datasource = "acme-pg",
                columns = col,
                datasourceTags = listOf("pii"),
            ),
            "tagging the DATASOURCE pii extends that same permit to a column that was never classified",
        )
    }

    /**
     * The shipped `system:catalog` permit is bare-principal cleartext, so a datasource carrying that name
     * opens every column under it. The widest reach any single tag has.
     */
    @Test
    fun `a datasource tagged system-catalog opens the bare-principal catalog permit for every column`() {
        val authz = Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal, action == Action::"result.read.unmasked", resource)
                             when { resource in Tag::"system:catalog" };""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        val col = listOf(column("acme.public.users.region", "users", "region"))
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.DENIED),
            authz.authorizeColumns("alice", emptySet(), "acme-pg", col, datasourceTags = emptyList()),
            "untagged, deny-by-default holds",
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED),
            authz.authorizeColumns("alice", emptySet(), "acme-pg", col, datasourceTags = listOf("system:catalog")),
            "on the datasource it reaches every column, no role required",
        )
    }

    /** A column's own `system:critical` reaches the shipped forbid, which overrides any read grant. */
    @Test
    fun `a column tagged system-critical is denied by the shipped forbid`() {
        val authz = Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal, action == Action::"result.read.unmasked", resource)
                             when { resource in Tag::"ok" };""",
                    2L to """forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
                             when { resource in Tag::"system:critical" };""",
                ),
            ),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.UNMASKED),
            authz.authorizeColumns(
                "alice", emptySet(), "acme-pg",
                listOf(column("acme.public.users.region", "users", "region", tags = listOf("ok"))),
                datasourceTags = listOf("ok"),
            ),
            "the read grant alone unmasks",
        )
        assertEquals(
            mapOf("acme.public.users.region" to ColumnVerdict.DENIED),
            authz.authorizeColumns(
                "alice", emptySet(), "acme-pg",
                listOf(column("acme.public.users.region", "users", "region", tags = listOf("ok", "system:critical"))),
                datasourceTags = listOf("ok"),
            ),
            "adding system:critical to the COLUMN reaches the forbid, which overrides the grant",
        )
    }
}
