package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResultFingerprintRegistryTest {
    private val fingerprint = listOf("c2:cat.app.users.ssn:1", "t:cat.app.users")

    @Test
    fun `take consumes the entry so a stored result carries the digest exactly once`() {
        val reg = ResultFingerprintRegistry()
        reg.put(7, fingerprint)
        assertEquals(fingerprint, reg.take(7))
        assertTrue(reg.take(7).isEmpty(), "a second take must not re-yield the consumed digest")
    }

    @Test
    fun `a miss yields empty so the view fails closed rather than resurrecting stale lineage`() {
        assertTrue(ResultFingerprintRegistry().take(999).isEmpty())
    }

    @Test
    fun `an empty put is a no-op - a decision with no requirements carries nothing`() {
        val reg = ResultFingerprintRegistry()
        reg.put(1, emptyList())
        assertTrue(reg.take(1).isEmpty())
    }

    @Test
    fun `the registry is bounded - an unconsumed entry beyond capacity is evicted, never accumulated`() {
        val reg = ResultFingerprintRegistry(capacity = 4)
        for (id in 1L..10L) reg.put(id, fingerprint)
        assertTrue((1L..6L).all { reg.take(it).isEmpty() }, "evicted entries must be gone")
        assertTrue((7L..10L).all { reg.take(it) == fingerprint }, "the most recent entries are retained")
    }
}
