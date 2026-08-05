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
 * SECURITY REGRESSION — a masked column must never be usable inside GROUP BY (or any result-shaping
 * position). This is NOT an over-conservative rule: a masked column reachable from GROUP BY can be fully
 * reconstructed, character by character, even though it is never selected. See issue #79.
 *
 * The test runs the ACTUAL reconstruction exploit two ways, so the guard can't be quietly relaxed:
 *   (1) against the RAW target DB (no proxy) it SUCCEEDS — proving the DENY is load-bearing, not paranoia;
 *   (2) through the enforcement engine every step is DENIED and the attacker recovers ZERO characters.
 *
 * The exploit uses only total functions the projection checker treats as safe (LOWER, SUBSTRING),
 * GROUP_CONCAT over the non-PII id, and inline constant rows as labels — NO explicit comparison, and it
 * never selects the masked cell. One GROUP BY per character position reconstructs every value (the inline
 * `#x` label lands in the same group as the ids whose p-th char is x).
 *
 * DO NOT relax this to allow masked columns in GROUP BY "when they aren't returned". If part (2) ever
 * fails, it fails by reconstructing real PII — the masking guarantee is broken, the test is not too strict.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MaskedColumnGroupByReconstructionDbTest {
    private lateinit var fx: EnforcementFixture

    // The fixture seeds users.rrn (pii, last4-masked) with exactly these two cleartext values.
    private val actual = mapOf(1L to "900101-1234567", 2L to "850202-2345678")
    private val alphabet = "0123456789-"   // the characters an rrn is built from
    private val maxLen = 16                 // rrn is 14 chars; probe a little past the end

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    /**
     * One reconstruction step: GROUP BY the p-th character of the masked rrn, with the alphabet inlined as
     * literal UNION rows so each `#x` label groups with the ids whose p-th char is x. Returns only
     * GROUP_CONCAT(id + labels) — the rrn cell is never selected, and there is no comparison against a value.
     */
    private fun attackQuery(p: Int): String {
        val labels = alphabet.toCharArray().joinToString(" ") { "UNION ALL SELECT '$it','#$it'" }
        return "SELECT GROUP_CONCAT(tag ORDER BY tag) FROM (" +
            "SELECT SUBSTRING(LOWER(rrn), $p, 1) AS ch, CAST(id AS CHAR) AS tag FROM users " +
            "$labels) t GROUP BY ch"
    }

    /** Drive the full O(length) reconstruction, reading each position's groups through [runGroups]. */
    private fun reconstruct(runGroups: (String) -> List<String>): Map<Long, String> {
        val chars = actual.keys.associateWith { CharArray(maxLen) { ' ' } }
        for (p in 1..maxLen) {
            for (group in runGroups(attackQuery(p))) {
                val toks = group.split(",")
                val label = toks.firstOrNull { it.startsWith("#") }?.getOrNull(1) ?: continue
                toks.filterNot { it.startsWith("#") }
                    .mapNotNull { it.toLongOrNull() }
                    .forEach { id -> chars[id]?.let { it[p - 1] = label } }
            }
        }
        return chars.mapValues { (_, cs) -> String(cs).trimEnd(' ') }
    }

    @Test
    fun `raw target DB - the GROUP BY exploit reconstructs the masked rrn (the DENY is load-bearing)`() {
        val recovered = reconstruct { sql -> fx.execOnTarget(sql).rows.map { it[0] ?: "" } }
        assertEquals(
            actual, recovered,
            "against the raw DB, one GROUP BY per character reconstructs every rrn — this is what the proxy must block",
        )
    }

    @Test
    fun `enforcement denies every step of the GROUP BY exploit - attacker recovers zero characters`() {
        for (p in 1..maxLen) {
            val r = fx.run(attackQuery(p))
            assertEquals(
                EnfAction.DENY, r.decision,
                "GROUP BY over the masked rrn must DENY (position $p) — reason: ${r.denyReason}",
            )
            assertTrue(r.rows.isEmpty(), "a DENY must return no rows (position $p)")
        }
        val throughProxy = reconstruct { sql ->
            fx.run(sql).let { if (it.decision == EnfAction.ALLOW) it.rows.map { row -> row[0] ?: "" } else emptyList() }
        }
        assertTrue(
            throughProxy.values.all { it.isEmpty() },
            "through enforcement the attacker must recover nothing, but got $throughProxy",
        )
        assertTrue(
            actual.none { (id, rrn) -> throughProxy[id] == rrn },
            "no real rrn may be reconstructed through the proxy",
        )
    }
}
