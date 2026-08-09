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
 * End-to-end through the real decision path (Cedar + PostgreSQL): the diagnostic-redaction flag on
 * DecisionContext is driven by the `result.read.unmasked`-on-datasource Cedar authorization, NOT a
 * datasource-tag check. On a `system:development` datasource the -200 preset permits unmasked reads, so no
 * redaction; on the production floor an ordinary principal is redacted. PostgreSQL is used because it leaks
 * on ALLOW, so the dev/prod difference shows on a plain SELECT.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DiagnosticRedactionDecideDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"

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

    private fun decide(sql: String) = decideQuery(
        principal = principal, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = SystemClassificationService(),
    )

    @Test
    fun `a system-development datasource never redacts (Cedar permits unmasked reads there)`() {
        setTags("""["system:development"]""")
        val r = decide("select id from users order by id")
        assertEquals(EnfAction.ALLOW, r.action)
        assertFalse(r.sanitizeDiagnostics, "dev holds no PII → the -200 unmasked permit fires → no redaction")
    }

    @Test
    fun `a production datasource redacts an ordinary principal, even on an ALLOW (Postgres whole-row leak)`() {
        setTags("""["system:production"]""")
        val allow = decide("select id from users order by id")
        assertEquals(EnfAction.ALLOW, allow.action)
        assertTrue(allow.sanitizeDiagnostics, "production + not a full-cleartext reader + PG leaks on ALLOW → redact")

        val mask = decide("select id, ssn from users order by id")
        assertEquals(EnfAction.MASK, mask.action)
        assertTrue(mask.sanitizeDiagnostics, "a MASK decision touches protected data → redact")
        setTags("""["system:development"]""")
    }
}
