package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * MySQL has no single-statement resolver that turns a row value into an object name (no `::regclass`
 * analog), so the only way a stored value could reach a diagnostic as an object name — and thus through an
 * allowlisted schema-name template (`Table 'db.<value>' doesn't exist`, `Unknown column '<value>'`) — is
 * dynamic SQL: load the value into a user variable, then `PREPARE` a statement text built from it. That path
 * is gated at its first step, which is the real barrier (not the error allowlist): `SET @v = (SELECT <col>)`
 * is a write to an unmaskable target, denied when `<col>` is masked or the table is ungranted. And if that
 * deny ever failed, `SELECT @v` would hand back the value as an ordinary result row — so the error channel
 * adds nothing. This locks that barrier for both a masked column and a denied (ungranted) column.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DynamicSqlNameExfilMySqlDbTest {
    private lateinit var fx: EnforcementFixture
    private val analyst = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    private fun decide(sql: String): com.ridi.oss.proxymonster.controlplane.DecisionContext = decideQuery(
        principal = analyst, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = SystemClassificationService(),
    )

    @Test
    fun `loading a masked column into a user variable is denied`() {
        // `ssn` is masked for analyst. Writing it into @v would launder the cleartext out of masking's reach
        // (SELECT @v, or a PREPARE built from @v) — the write to an unmaskable target denies.
        val r = decide("SET @v = (SELECT ssn FROM users LIMIT 1)")
        assertEquals(EnfAction.DENY, r.action, "SET @v = (SELECT ssn ...) must deny; reason=${r.denyReason}")
    }

    @Test
    fun `loading a denied column into a user variable is denied`() {
        // `orders` is ungranted (deny-by-default). Its value cannot reach @v either.
        val r = decide("SET @v = (SELECT amount FROM orders LIMIT 1)")
        assertEquals(EnfAction.DENY, r.action, "SET @v = (SELECT amount FROM orders ...) must deny; reason=${r.denyReason}")
    }

    @Test
    fun `dynamic execution of a prepared statement is denied for a restricted principal`() {
        // Even if a value somehow reached @v, PREPARE/EXECUTE run SQL the analyzer cannot see; analyst holds
        // no admin.exec grant, so the dynamic-SQL step the leak needs is unreachable.
        assertEquals(EnfAction.DENY, decide("PREPARE s FROM @v").action, "PREPARE must deny for analyst")
        assertEquals(EnfAction.DENY, decide("EXECUTE s").action, "EXECUTE must deny for analyst")
    }
}
