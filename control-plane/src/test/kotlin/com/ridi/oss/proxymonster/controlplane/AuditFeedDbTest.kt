package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Audit feeds expose all event kinds while applying principal ownership before the requested limit. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuditFeedDbTest {
    private lateinit var audit: AuditStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_audit"))
        audit = AuditStore(ds)
    }

    @Test
    fun `lifecycle rows are visible in recent and get`() {
        val normal = audit.insert(
            AuditEvent(principal = "bob", datasource = "d", statement = "select 1", decision = Decision.ALLOW),
        )
        val lifecycle = audit.insert(
            AuditEvent(
                principal = "alice",
                datasource = "d",
                statement = "approval #1 result-viewed-by-requester",
                decision = Decision.ALLOW,
                kind = "approval_lifecycle",
            ),
        )

        val recent = audit.recent(100)
        assertTrue(recent.any { it.id == normal })
        assertTrue(recent.any { it.id == lifecycle && it.kind == "approval_lifecycle" })
        assertNotNull(audit.get(normal))
        assertEquals("approval_lifecycle", audit.get(lifecycle)?.kind)
    }

    @Test
    fun `effective namespace round-trips through recent and get`() {
        val id = audit.insert(
            AuditEvent(
                principal = "namespace-audit",
                datasource = "d",
                statement = "select namespace_round_trip",
                decision = Decision.MASK,
                effectiveNamespace = listOf("a", "b"),
            ),
        )

        assertEquals(listOf("a", "b"), audit.get(id)?.effectiveNamespace)
        assertEquals(listOf("a", "b"), audit.recent(100).single { it.id == id }.effectiveNamespace)
    }

    @Test
    fun `principal-scoped feed includes owned lifecycle rows before applying the limit`() {
        val alice = "audit-scope-alice"
        val bob = "audit-scope-bob"
        audit.insert(
            AuditEvent(
                ts = "2099-01-01T00:00:00Z",
                principal = alice,
                datasource = "d",
                statement = "select alice_scope_normal",
                decision = Decision.ALLOW,
            ),
        )
        val aliceLifecycle = audit.insert(
            AuditEvent(
                ts = "2099-01-02T00:00:00Z",
                principal = alice,
                datasource = "d",
                statement = "approval #2 result-viewed-by-requester",
                decision = Decision.ALLOW,
                kind = "approval_lifecycle",
            ),
        )
        val bobNormal = audit.insert(
            AuditEvent(
                ts = "2099-01-03T00:00:00Z",
                principal = bob,
                datasource = "d",
                statement = "select bob_scope_normal",
                decision = Decision.ALLOW,
            ),
        )

        assertEquals(bobNormal, audit.recent(1).single().id)
        val recent = audit.recent(1, alice)
        assertEquals(aliceLifecycle, recent.single().id)
        assertEquals("approval_lifecycle", recent.single().kind)
        assertTrue(recent.all { it.principal == alice })
    }
}
