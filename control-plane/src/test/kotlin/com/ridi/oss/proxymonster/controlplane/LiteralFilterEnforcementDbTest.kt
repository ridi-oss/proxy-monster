package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The `result.filter.literal` opt-in end to end (docs/authz-model.md, "Opting in to literal filters"), against a
 * real target database. `analyst` has no such permit and is the control: a masked column in a WHERE is denied
 * exactly as before. `lookup` holds the permit on pii columns, so `col = literal` / `col IN (literals)` runs and
 * the column still comes back masked when it is also selected. Every other way of using the column in a
 * predicate stays denied under the same permit, because each can extract a value the caller does not hold.
 */
abstract class LiteralFilterEnforcementDbTest {
    protected lateinit var fx: EnforcementFixture

    private val lookup = "lookup@example.com"
    private val known = "987-65-4320"

    @Test
    fun `without the opt-in a filter on a masked column is denied as before`() {
        val r = fx.run("select id from users where ssn = '$known'")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
        assertTrue(r.denyReason!!.contains("cannot be masked") && r.denyReason!!.contains("ssn"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `with the opt-in an equality filter returns the matching rows`() {
        val r = fx.run("select id from users where ssn = '$known'", principal = lookup)
        assertEquals(EnfAction.ALLOW, r.decision, "deny reason: ${r.denyReason}")
        assertEquals(listOf(listOf("1")), r.rows)
    }

    @Test
    fun `with the opt-in an IN list of literals returns the matching rows`() {
        val r = fx.run("select id from users where ssn in ('$known', '987-65-4321') order by id", principal = lookup)
        assertEquals(EnfAction.ALLOW, r.decision, "deny reason: ${r.denyReason}")
        assertEquals(listOf(listOf("1"), listOf("2")), r.rows)
    }

    @Test
    fun `a filter that matches nothing is allowed and returns no rows`() {
        val r = fx.run("select id from users where ssn = '000-00-0000'", principal = lookup)
        assertEquals(EnfAction.ALLOW, r.decision, "deny reason: ${r.denyReason}")
        assertTrue(r.rows.isEmpty())
    }

    @Test
    fun `a count over a filtered masked column is allowed`() {
        val r = fx.run("select count(*) from users where ssn = '$known'", principal = lookup)
        assertEquals(EnfAction.ALLOW, r.decision, "deny reason: ${r.denyReason}")
        assertEquals(listOf(listOf("1")), r.rows)
    }

    @Test
    fun `the filtered column is still masked when it is also selected`() {
        val r = fx.run("select id, ssn from users where ssn = '$known'", principal = lookup)
        assertEquals(EnfAction.MASK, r.decision, "deny reason: ${r.denyReason}")
        val ssn = r.rows.map { it[1] }
        assertEquals(1, ssn.size)
        assertTrue(ssn.none { it == known }, "cleartext ssn leaked: $ssn")
        assertTrue(ssn.single()!!.startsWith("*") && ssn.single()!!.endsWith("4320"), "expected the last-4 mask, got $ssn")
    }

    @Test
    fun `a filter on a column that is not masked is unaffected`() {
        val r = fx.run("select id from users where region = 'KR' order by id", principal = lookup)
        assertEquals(EnfAction.ALLOW, r.decision, "deny reason: ${r.denyReason}")
        assertEquals(listOf(listOf("1"), listOf("2")), r.rows)
    }

    @Test
    fun `every other predicate shape on a masked column stays denied under the opt-in`() {
        val denied = listOf(
            "select id from users where ssn like '987%'",
            "select id from users where lower(ssn) = '$known'",
            "select id from users where ssn > '5'",
            "select id from users where ssn <> '$known'",
            "select id from users where not (ssn = '$known')",
            "select id from users where ssn not in ('$known')",
            "select id from users where ssn = '$known' or ssn = '987-65-4321'",
            "select id from users where ssn = '$known' order by ssn",
            "select ssn, count(*) from users where ssn = '$known' group by ssn",
            "select id from users where ssn = '$known' and lower(ssn) like '9%'",
            "select id from (select id, lower(ssn) as ssn from users) t where ssn = '$known'",
            "select id from (select id, ssn from users) t where ssn = '$known'",
            "select id from users where ssn in (select ssn from users)",
            "select id from users where ssn = region",
            "select id from users where ssn = '$known' union select id from users where ssn like '9%'",
        )
        for (sql in denied) {
            val r = fx.run(sql, principal = lookup)
            assertEquals(EnfAction.DENY, r.decision, "must be denied: $sql")
            assertTrue(r.rows.isEmpty(), "a DENY must not return rows: $sql")
        }
    }

    @Test
    fun `an EXPLAIN keeps the deny, because the plan's row estimates reflect the filter`() {
        val r = fx.run("explain select id from users where ssn = '$known'", principal = lookup)
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("cannot be masked") && r.denyReason!!.contains("ssn"), "deny reason: ${r.denyReason}")
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LiteralFilterEnforcementMysqlDbTest : LiteralFilterEnforcementDbTest() {
    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LiteralFilterEnforcementPostgresDbTest : LiteralFilterEnforcementDbTest() {
    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }
}
