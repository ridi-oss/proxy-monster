package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end (analyzer + Cedar + PostgreSQL): redact iff the principal can't read every column in
 * `diagnostic_leak_columns` unmasked.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DiagnosticRedactionDecideDbTest {
    private lateinit var fx: EnforcementFixture
    private val analyst = "analyst@example.com"
    private val inserter = "inserter@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private fun setTags(tagsJson: String) = fx.dataSource.connection.use { c ->
        c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
            ps.setString(1, tagsJson); ps.setLong(2, fx.datasource.id); ps.executeUpdate()
        }
    }

    private fun decide(sql: String, who: String = analyst) = decideQuery(
        principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = SystemClassificationService(),
    )

    @Test
    fun `a read leaks only its referenced columns`() {
        setTags("""["system:production"]""")
        // A read leaks only what it references — `select id` never puts ssn in a diagnostic.
        val idOnly = decide("select id from users order by id")
        assertEquals(EnfAction.ALLOW, idOnly.action)
        assertFalse(idOnly.sanitizeDiagnostics, "a read of only readable columns cannot leak a masked sibling")

        val withSsn = decide("select id, ssn from users order by id")
        assertEquals(EnfAction.MASK, withSsn.action)
        assertTrue(withSsn.sanitizeDiagnostics, "a MASK decision redacts — the masked column is in the leak set")

        setTags("""["system:development"]""")
    }

    @Test
    fun `a PostgreSQL write redacts its whole-row diagnostic for a writer who cannot read the whole row`() {
        // `insert into users (id)` can fail with `DETAIL: Failing row contains (1, <ssn>, …)` — the leak
        // set is every users column, and the inserter can't read ssn unmasked.
        setTags("""["system:production"]""")
        val write = decide("insert into users (id) values (1)", inserter)
        assertEquals(EnfAction.ALLOW, write.action, "the inserter's INSERT is allowed: ${write.denyReason}")
        assertTrue(write.sanitizeDiagnostics, "the whole-row leak set includes masked ssn → redact")
        setTags("""["system:development"]""")
    }

    @Test
    fun `the same write is not redacted for a full reader`() {
        // On dev (-200 preset) the inserter reads the whole row unmasked — nothing to protect.
        setTags("""["system:development"]""")
        val write = decide("insert into users (id) values (1)", inserter)
        assertEquals(EnfAction.ALLOW, write.action, "the inserter's INSERT is allowed: ${write.denyReason}")
        assertFalse(write.sanitizeDiagnostics, "a full reader of the whole target row has nothing to redact")
    }
}
