package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A rate entry on a `result.cap` permit denies a read once the principal's relayed volume over that window
 * is spent (docs/result-caps.md). Shipped: -305 rates everyone at 10000/1h, 50000/1d, 100MB/1h and
 * 500MB/1d; -306 carries no rate.
 */
class RateDecideDbTest {
    private fun EnforcementFixture.completion(
        rows: Long,
        bytes: Long,
        ageSeconds: Long = 60,
        principal: String = "analyst@example.com",
        kind: String = "completion",
    ) {
        auditStore.insert(
            AuditEvent(
                ts = Instant.now().minusSeconds(ageSeconds).toString(), principal = principal,
                datasource = "another-datasource", statement = "select id from users",
                decision = Decision.ALLOW, kind = kind, rowsReturned = rows, bytesReturned = bytes,
            ),
        )
    }

    private fun EnforcementFixture.policy(name: String, src: String) =
        cedarPolicyStore.create(CedarPolicyInput(name, src), updatedBy = "test")

    private fun EnforcementFixture.unmaskedPii() = policy(
        "analyst-pii-unmasked",
        """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Tag::"pii");""",
    )

    @Test
    fun `relayed volume sums only this principal's completions per window`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.completion(5, 50)
        fx.completion(7, 70, ageSeconds = 7200)
        fx.completion(10000, 10000, ageSeconds = 90000)
        fx.completion(10000, 10000, principal = "other@example.com")
        fx.completion(10000, 10000, kind = "decision")
        val volume = fx.auditStore.relayedVolume(
            "analyst@example.com", listOf(Duration.ofHours(1), Duration.ofDays(1), Duration.ofHours(1)), Instant.now(),
        )
        assertEquals(RelayedVolume(rows = 5, bytes = 50), volume.getValue(Duration.ofHours(1)))
        assertEquals(RelayedVolume(rows = 12, bytes = 120), volume.getValue(Duration.ofDays(1)))
        assertEquals(2, volume.size)
    }

    @Test
    fun `each shipped rate denies at its threshold, not below, naming the rate`() {
        requireDockerOrSkip()
        data class Rate(val dimension: String, val threshold: Long, val ageSeconds: Long, val spec: String)
        for ((dimension, threshold, ageSeconds, spec) in listOf(
            Rate("bytes", 100_000_000, 60, "100MB/1h"),
            Rate("bytes", 500_000_000, 7200, "500MB/1d"),
            Rate("rows", 10_000, 60, "10000/1h"),
            Rate("rows", 50_000, 7200, "50000/1d"),
        )) {
            val fx = EnforcementFixture.mysql()
            fx.unmaskedPii()
            fun add(value: Long) =
                fx.completion(if (dimension == "rows") value else 0, if (dimension == "bytes") value else 0, ageSeconds)
            // A rate counts everything the principal relays, so every read shape is bound by it alike.
            val queries = listOf("select id from users", "select ssn from users", "select count(*) from users")
            add(threshold - 1)
            for (sql in queries) {
                val decision = fx.decide(sql, auditStore = fx.auditStore)
                assertNotEquals(EnfAction.DENY, decision.action, "$spec below threshold: ${decision.denyReason}")
            }
            add(1)
            for (sql in queries) {
                val decision = fx.decide(sql, auditStore = fx.auditStore)
                assertEquals(EnfAction.DENY, decision.action, sql)
                assertEquals("$RATE_SPENT_DENY $spec spent", decision.denyReason, sql)
            }
            // A read the policy denies is denied by the read gate, before any rate is consulted.
            val unrelated = fx.decide("select id from orders", auditStore = fx.auditStore)
            assertEquals(EnfAction.DENY, unrelated.action)
            assertNotEquals("$RATE_SPENT_DENY $spec spent", unrelated.denyReason)
        }
    }

    @Test
    fun `an admin row declares its own window and a forbid lifts every rate`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.policy("three-hours", """@cap("20/3h") permit(principal in Role::"analyst", action == Action::"result.cap", resource);""")
        fx.completion(15, 0, ageSeconds = 7200)
        assertNotEquals(EnfAction.DENY, fx.decide("select id from users", auditStore = fx.auditStore).action)
        fx.completion(5, 0, ageSeconds = 3700)
        assertEquals("$RATE_SPENT_DENY 20/3h spent", fx.decide("select id from users", auditStore = fx.auditStore).denyReason)
        // The same rows fall outside a 1h window; a row scoped to another role changes nothing.
        fx.policy("other-uncapped", """forbid(principal in Role::"dump-runner", action == Action::"result.cap", resource);""")
        assertEquals("$RATE_SPENT_DENY 20/3h spent", fx.decide("select id from users", auditStore = fx.auditStore).denyReason)
        fx.policy("analyst-uncapped", """forbid(principal in Role::"analyst", action == Action::"result.cap", resource == Datasource::"${fx.datasource.name}");""")
        for (sql in listOf("select id from users", "select ssn from users", "select count(*) from users")) {
            val lifted = fx.decide(sql, auditStore = fx.auditStore)
            assertNotEquals(EnfAction.DENY, lifted.action, "$sql: ${lifted.denyReason}")
            assertNull(lifted.maxRows, sql)
        }
        // Access itself is unchanged: an ungranted table stays denied, uncapped or not.
        assertEquals(EnfAction.DENY, fx.decide("select id from orders", auditStore = fx.auditStore).action)
    }

    @Test
    fun `a reset clears every window at once and leaves the cap alone`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.unmaskedPii()
        fx.completion(10_000, 0, ageSeconds = 120)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", fx.decide("select ssn from users", auditStore = fx.auditStore).denyReason)
        val recorder = ManagementAuditRecorder(fx.auditStore)
        val reset = fx.accessStore.resetRate(
            "analyst@example.com", "false positive after a re-run", AuditActor("admin@example.com", channel = "console"), recorder,
        )
        assertEquals("admin@example.com", reset.resetBy)
        assertEquals(reset, fx.auditStore.lastRateReset("analyst@example.com"))
        val after = fx.decide("select ssn from users", auditStore = fx.auditStore)
        assertEquals(EnfAction.ALLOW, after.action, after.denyReason)
        assertEquals(500L, after.maxRows, "a reset never touches the statement cap")
        // Volume relayed AFTER the reset counts again.
        fx.completion(10_000, 0, ageSeconds = 0)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", fx.decide("select ssn from users", auditStore = fx.auditStore).denyReason)
        assertNotNull(fx.auditStore.recent(20).firstOrNull { it.kind == "admin" && it.principal == "admin@example.com" && "reset spent result rates" in it.statement })
    }

    @Test
    fun `approving a RATE_RESET request writes the reset`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.completion(0, 100_000_000, ageSeconds = 120)
        assertEquals("$RATE_SPENT_DENY 100MB/1h spent", fx.decide("select id from users", auditStore = fx.auditStore).denyReason)
        val recorder = ManagementAuditRecorder(fx.auditStore)
        val request = fx.accessStore.createRateResetRequest(
            "analyst@example.com", RateResetRequestInput("monthly export re-run", denyReason = "rate 100MB/1h spent"),
            AuditActor("analyst@example.com", channel = "console"), recorder,
        )
        assertEquals("RATE_RESET", request.kind)
        assertEquals("PENDING", request.status)
        assertEquals("rate 100MB/1h spent", request.denyReason)
        assertNull(fx.auditStore.lastRateReset("analyst@example.com"))
        val approved = fx.accessStore.approve(request.id, null, "approver@example.com", AuditActor("approver@example.com", channel = "console"), recorder)
        assertEquals("APPROVED", approved?.status)
        assertEquals("approver@example.com", fx.auditStore.lastRateReset("analyst@example.com")?.resetBy)
        assertNotEquals(EnfAction.DENY, fx.decide("select id from users", auditStore = fx.auditStore).action)
        // Approving twice changes nothing.
        assertEquals("APPROVED", fx.accessStore.approve(request.id, null, "approver@example.com", AuditActor("approver@example.com", channel = "console"), recorder)?.status)
        assertEquals(1, fx.accessStore.listRequests("APPROVED").count { it.kind == "RATE_RESET" })
    }
}
