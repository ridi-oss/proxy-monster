package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * [CedarEngine]'s cached [com.cedarpolicy.model.policy.PolicySet] against a real, Flyway-migrated
 * Postgres: it must (a) invalidate the moment [CedarPolicyStore] mutates — disable/re-enable/delete
 * all take effect on the very next `isAuthorized()` call, never serving a stale decision — and (b)
 * actually be a cache, not rebuild on every call — the column-authz path calls `isAuthorized` once
 * per touched column per query, so an O(N) rebuild per call would defeat the point.
 *
 * Every policy/role name below is unique per test (`System.nanoTime()`) — this suite shares its
 * Postgres database with every other `@TestInstance(PER_CLASS)` DB test via [SharedPostgres], and the seed
 * seeds its own `system:admin`-scoped rows, so scoping by a fresh name/role avoids cross-test collisions
 * (mirrors [CedarPolicyStoreTest]'s name-scoping trick).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CedarEngineCacheTest {
    private lateinit var ds: DataSource
    private lateinit var store: CedarPolicyStore
    private lateinit var engine: CedarEngine
    private lateinit var authz: Authz

    /** Roles per principal, mutated per-test — backs the [RoleSource] the shared [authz] uses. */
    private val roles = mutableMapOf<String, Set<String>>()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_cedar_engine_cache"))
        store = CedarPolicyStore(ds)
        engine = CedarEngine(store)
        authz = Authz(engine, store, RoleSource { principal -> roles[principal] ?: emptySet() })
    }

    @Test
    fun `disable invalidates the cache, re-enable and delete both take effect on the next call`() {
        val principal = "cache-alice-${System.nanoTime()}"
        val role = "cache-role-${System.nanoTime()}"
        roles[principal] = setOf(role)
        val policy = store.create(
            CedarPolicyInput(
                name = "cache-test-toggle-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"$role", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = null,
        )

        assertEquals(
            AuthzDecision.Allow,
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "cache must warm to Allow with the policy enabled",
        )

        store.setEnabled(policy.id, enabled = false, updatedBy = null)
        assertIs<AuthzDecision.Deny>(
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "disabling must invalidate the cached PolicySet — the very next call must not serve a stale Allow",
        )

        store.setEnabled(policy.id, enabled = true, updatedBy = null)
        assertEquals(
            AuthzDecision.Allow,
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "re-enabling must invalidate the cache back to Allow",
        )

        store.delete(policy.id)
        assertIs<AuthzDecision.Deny>(
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "deleting the granting policy must invalidate the cache",
        )
    }

    @Test
    fun `isAuthorized only rebuilds the PolicySet when store state changes — O(1) per query`() {
        val principal = "cache-bob-${System.nanoTime()}"
        val role = "cache-role-o1-${System.nanoTime()}"
        roles[principal] = setOf(role)
        store.create(
            CedarPolicyInput(
                name = "cache-test-o1-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"$role", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = null,
        )

        // Warm the cache — this call (and only this call) is allowed to build.
        authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System)
        val buildsAfterWarmup = engine.buildCount

        repeat(25) {
            assertEquals(AuthzDecision.Allow, authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System))
        }

        assertEquals(
            buildsAfterWarmup,
            engine.buildCount,
            "25 more isAuthorized() calls with no CedarPolicyStore mutation must not rebuild the PolicySet again",
        )
    }
}
