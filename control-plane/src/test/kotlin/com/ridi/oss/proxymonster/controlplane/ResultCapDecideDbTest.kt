package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.InvalidCedarPolicyException
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The per-statement cap is folded from the `result.cap` permits that answer for the datasource and for every
 * column the statement returns (docs/result-caps.md). Shipped: -305 the general 5,000 / 50 MB on every ask,
 * -306 the 500 / 5 MB on a tagged column read in the clear, -307 the exporter's forbid.
 */
class ResultCapDecideDbTest {
    private fun EnforcementFixture.policy(name: String, src: String) =
        cedarPolicyStore.create(CedarPolicyInput(name, src), updatedBy = "test")

    private fun EnforcementFixture.unmaskedPii() = policy(
        "analyst-pii-unmasked",
        """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Tag::"pii");""",
    )

    private fun caps(d: DecisionContext) = d.maxRows to d.maxBytes

    @Test
    fun `MySQL caps follow what a statement returns and whether this principal reads it masked`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        val plain = fx.decide("select id from users")
        assertEquals(EnfAction.ALLOW, plain.action, plain.denyReason)
        assertEquals(5_000L to 50_000_000L, caps(plain))
        // A masked pii read is asked with masked = true: -306 matches only a read in the clear.
        val masked = fx.decide("select ssn from users")
        assertEquals(EnfAction.MASK, masked.action, masked.denyReason)
        assertEquals(5_000L to 50_000_000L, caps(masked))

        fx.unmaskedPii()
        val clear = fx.decide("select ssn from users")
        assertEquals(EnfAction.ALLOW, clear.action, clear.denyReason)
        assertEquals(500L to 5_000_000L, caps(clear))
        // A predicate-only read of ssn returns nothing to the client, so the column is not asked at all.
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("select id from users where ssn is not null")))
        assertEquals(500L to 5_000_000L, caps(fx.decide("select max(ssn) from users")))
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("select id from users")))
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("show databases")))
    }

    @Test
    fun `a masked read can be given its own cap through context masked`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("select ssn from users")))
        fx.policy(
            "masked-cap",
            """@cap("2000") permit(principal, action == Action::"result.cap", resource)
               when { resource is Column && resource.tagged && context has masked && context.masked };""",
        )
        assertEquals(2_000L to 50_000_000L, caps(fx.decide("select ssn from users")))
        // The masked row does not touch an untagged column or a read in the clear.
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("select id from users")))
        // exception.unmaskable lets the proxy relay the masked result raw, so the ask says clear.
        fx.policy(
            "unmaskable",
            """permit(principal in Role::"analyst", action == Action::"exception.unmaskable", resource == Datasource::"${fx.datasource.name}");""",
        )
        assertEquals(500L to 5_000_000L, caps(fx.decide("select ssn from users")))
        fx.unmaskedPii()
        assertEquals(500L to 5_000_000L, caps(fx.decide("select ssn from users")))
    }

    @Test
    fun `the tight row keys on any classification tag, not on the tag's name`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(schema = fx.datasource.engine.defaultSchema(fx.datasource.dbName), table = "users", column = "email", tags = listOf("contact"), maskFnId = null),
        )
        fx.policy(
            "analyst-contact-unmasked",
            """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Tag::"contact");""",
        )
        val clear = fx.decide("select email from users")
        assertEquals(EnfAction.ALLOW, clear.action, clear.denyReason)
        assertEquals(500L to 5_000_000L, caps(clear))
    }

    @Test
    fun `result cap entries fold to the tightest rows and the tightest bytes`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.unmaskedPii()
        fx.policy(
            "analyst-cap",
            """@cap("2000, 1MB") permit(principal in Role::"analyst", action == Action::"result.cap", resource);""",
        )
        fx.policy(
            "pii-rows-cap",
            """@cap("300") permit(principal, action == Action::"result.cap", resource in Tag::"pii");""",
        )
        val both = fx.decide("select id, ssn from users")
        assertEquals(EnfAction.ALLOW, both.action, both.denyReason)
        assertEquals(300L to 1_000_000L, caps(both))
        assertEquals(2_000L to 1_000_000L, caps(fx.decide("select id from users")))
    }

    @Test
    fun `permitting result cap grants nothing and forbidding it denies no read`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.policy("cap-everything", """permit(principal, action == Action::"result.cap", resource);""")
        assertEquals(EnfAction.MASK, fx.decide("select ssn from users").action)
        assertEquals(EnfAction.DENY, fx.decide("select id from orders").action)
        fx.policy("uncap-everything", """forbid(principal, action == Action::"result.cap", resource);""")
        val lifted = fx.decide("select ssn from users")
        assertEquals(EnfAction.MASK, lifted.action, "a result.cap forbid lifts caps, it never changes the read")
        assertNull(lifted.maxRows)
        assertEquals(EnfAction.DENY, fx.decide("select id from orders").action)
    }

    @Test
    fun `a forbid on result cap lifts every cap for the role it names`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.unmaskedPii()
        fx.policy(
            "other-uncapped",
            """forbid(principal in Role::"dump-runner", action == Action::"result.cap", resource == Datasource::"${fx.datasource.name}");""",
        )
        assertEquals(500L to 5_000_000L, caps(fx.decide("select ssn from users")))
        fx.policy(
            "analyst-uncapped",
            """forbid(principal in Role::"analyst", action == Action::"result.cap", resource == Datasource::"${fx.datasource.name}");""",
        )
        for (sql in listOf("select ssn from users", "select id from users", "show databases")) {
            val lifted = fx.decide(sql)
            assertNotEquals(EnfAction.DENY, lifted.action, "$sql: ${lifted.denyReason}")
            assertNull(lifted.maxRows, sql)
            assertNull(lifted.maxBytes, sql)
        }
    }

    // The shipped lift: system:production-exporter, held through a JIT grant or a workflow, is uncapped.
    @Test
    fun `the shipped production exporter role is uncapped`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.unmaskedPii()
        assertEquals(500L to 5_000_000L, caps(fx.decide("select ssn from users")))
        val lifted = fx.decide("select ssn from users", providedRoles = setOf("analyst", "system:production-exporter"))
        assertNotEquals(EnfAction.DENY, lifted.action, lifted.denyReason)
        assertNull(lifted.maxRows)
        assertNull(lifted.maxBytes)
    }

    @Test
    fun `with every shipped cap permit off the constant default still applies`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.unmaskedPii()
        fx.cedarPolicyStore.setEnabled(-305, false, "test")
        fx.cedarPolicyStore.setEnabled(-306, false, "test")
        try {
            assertEquals(DEFAULT_CAP_ROWS to DEFAULT_CAP_BYTES, caps(fx.decide("select ssn from users")))
            assertEquals(DEFAULT_CAP_ROWS to DEFAULT_CAP_BYTES, caps(fx.decide("show databases")))
        } finally {
            fx.cedarPolicyStore.setEnabled(-305, true, "test")
            fx.cedarPolicyStore.setEnabled(-306, true, "test")
        }
    }

    @Test
    fun `PostgreSQL RETURNING of a pii column read in the clear takes the tight cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.postgres()
        val masked = fx.decide("update users set id = id returning ssn", principal = "updater@example.com")
        assertEquals(EnfAction.DENY, masked.action)
        fx.policy(
            "updater-unmasked",
            """permit(principal in Role::"update-writer", action == Action::"result.read.unmasked", resource in Tag::"pii");""",
        )
        val clear = fx.decide("update users set id = id returning ssn", principal = "updater@example.com")
        assertEquals(EnfAction.ALLOW, clear.action, clear.denyReason)
        assertEquals(500L to 5_000_000L, caps(clear))
        assertEquals(5_000L to 50_000_000L, caps(fx.decide("update users set id = id returning id", principal = "updater@example.com")))
    }

    // A relay the exception gate lets through carries the datasource-level answer, never uncapped by
    // omission — the unanalyzable relay relays VERBATIM and UNMASKED, so an uncapped one is exactly the
    // dump the caps exist to bound.
    @Test
    fun `the analyzed, passthrough, and unanalyzable-relay exits each stamp a cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.policy(
            "dev-unanalyzable",
            """permit(principal, action == Action::"exception.unanalyzable", resource == Datasource::"${fx.datasource.name}");""",
        )
        fx.policy(
            "datasource-cap",
            """@cap("42") permit(principal, action == Action::"result.cap", resource == Datasource::"${fx.datasource.name}");""",
        )
        for (sql in listOf("select id from users", "show databases", "select missing_column from users")) {
            val decision = fx.decide(sql)
            assertNotEquals(EnfAction.DENY, decision.action, "$sql: ${decision.denyReason}")
            assertEquals(42L to 50_000_000L, caps(decision), sql)
        }
        assertTrue(fx.decide("select missing_column from users").passthrough)
    }

    @Test
    fun `a cap annotation is refused off a result cap policy and when malformed`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        val misplaced = assertFailsWith<InvalidCedarPolicyException> {
            fx.policy("misplaced", """@cap("500") permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);""")
        }
        assertTrue(misplaced.errors.any { "result.cap" in it }, misplaced.errors.toString())
        for (bad in listOf("abc", "0", "5XB", "-5", "2K", "3M", "1G", "500, ", "10/1x", "10/0h", "10/32d", "10/745h", "5MB/")) {
            val ex = assertFailsWith<InvalidCedarPolicyException>(bad) {
                fx.policy("bad-${System.nanoTime()}", """@cap("$bad") permit(principal, action == Action::"result.cap", resource);""")
            }
            assertTrue(ex.errors.any { "@cap" in it }, "$bad: ${ex.errors}")
        }
        fx.policy("kb-suffix", """@cap("2000, 3MB, 100KB/10m, 7GB/31d") permit(principal, action == Action::"result.cap", resource);""")
        assertEquals(2_000L to 3_000_000L, caps(fx.decide("select id from users")))
    }
}
