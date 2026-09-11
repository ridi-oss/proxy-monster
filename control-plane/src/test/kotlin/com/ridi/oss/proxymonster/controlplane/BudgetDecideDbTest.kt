package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BudgetDecideDbTest {
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

    @Test
    fun `budget sums only this principal completions and reaches the connect gate`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.completion(5, 50)
        fx.completion(7, 70, ageSeconds = 7200)
        fx.completion(10000, 10000, ageSeconds = 90000)
        fx.completion(10000, 10000, principal = "other@example.com")
        fx.completion(10000, 10000, kind = "decision")
        assertEquals(
            CompletionBudget(rows1h = 5, bytes1h = 50, rows24h = 12, bytes24h = 120),
            fx.auditStore.completionBudget("analyst@example.com", Instant.now()),
        )
        fx.cedarPolicyStore.create(CedarPolicyInput("require-budgets", """
            forbid(principal, action == Action::"datasource.connect", resource) unless {
                context has budget_rows_1h && context.budget_rows_1h == 5 &&
                context has budget_bytes_1h && context.budget_bytes_1h == 50 &&
                context has budget_rows_24h && context.budget_rows_24h == 12 &&
                context has budget_bytes_24h && context.budget_bytes_24h == 120
            };
        """), updatedBy = "test")
        assertEquals(EnfAction.ALLOW, fx.decide("select id from users", auditStore = fx.auditStore).action)
        assertEquals(EnfAction.DENY, fx.decide("select id from users").action)
    }

    @Test
    fun `each shipped budget denies at its threshold for columns and table scans`() {
        requireDockerOrSkip()
        data class Budget(val dimension: String, val threshold: Long, val ageSeconds: Long, val window: String)
        for ((dimension, threshold, ageSeconds, window) in listOf(
            Budget("rows", 10000, 60, "1h"),
            Budget("bytes", 100000000, 60, "1h"),
            Budget("rows", 50000, 7200, "24h"),
            Budget("bytes", 500000000, 7200, "24h"),
        )) {
            val fx = EnforcementFixture.mysql()
            fun add(value: Long) =
                fx.completion(if (dimension == "rows") value else 0, if (dimension == "bytes") value else 0, ageSeconds)
            add(threshold - 1)
            val queries = listOf("select id from users", "select ssn from users", "select count(*) from users")
            for (sql in queries) {
                val decision = fx.decide(sql, auditStore = fx.auditStore)
                assertNotEquals(EnfAction.DENY, decision.action, "$dimension $window below threshold: ${decision.denyReason}")
            }
            add(1)
            for (sql in queries) {
                val decision = fx.decide(sql, auditStore = fx.auditStore)
                assertEquals(EnfAction.DENY, decision.action, sql)
                assertEquals("$BUDGET_SPENT_DENY ($window)", decision.denyReason, sql)
            }
            val unrelated = fx.decide("select id from orders", auditStore = fx.auditStore)
            assertEquals(EnfAction.DENY, unrelated.action)
            assertNotEquals("$BUDGET_SPENT_DENY ($window)", unrelated.denyReason)
        }
    }

    @Test
    fun `unbounded access removes caps and budget attributes without granting data access`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.completion(10000, 100000000)
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                "unbounded",
                """permit(principal in Role::"analyst", action == Action::"result.read.unbounded", resource);""",
            ),
            updatedBy = "test",
        )
        fx.cedarPolicyStore.create(CedarPolicyInput("no-budget-attrs", """
            forbid(principal, action == Action::"datasource.connect", resource) when {
                context has budget_rows_1h || context has budget_bytes_1h ||
                    context has budget_rows_24h || context has budget_bytes_24h
            };
        """), updatedBy = "test")
        for (sql in listOf("select id from users", "select ssn from users", "select 42", "show databases", "set @cap_test = 1")) {
            val decision = fx.decide(sql, auditStore = fx.auditStore)
            assertNotEquals(EnfAction.DENY, decision.action, "$sql: ${decision.denyReason}")
            assertTrue(decision.unbounded, sql)
        }
        assertEquals(EnfAction.DENY, fx.decide("select id from orders", auditStore = fx.auditStore).action)
    }
}
