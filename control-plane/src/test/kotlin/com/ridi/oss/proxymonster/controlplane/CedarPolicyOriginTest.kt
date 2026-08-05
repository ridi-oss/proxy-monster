package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.ReservedPolicyNameException
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.SystemPolicyImmutableException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Store-level proof for docs/policy-store.md: migration-owned SYSTEM source cannot be
 * updated or deleted even outside HTTP routes, the reserved name cannot enter through USER writes,
 * and the shipped sources at negative ids leave the effective Cedar decisions identical to the
 * [AuthzTest] oracle.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CedarPolicyOriginTest {
    private lateinit var ds: DataSource
    private lateinit var store: CedarPolicyStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_cedar_policy_origin"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = CedarPolicyStore(ds)
    }

    @Test
    fun `store rejects system mutation and reserved user names before touching state`() {
        val systemBefore = store.get(-1)!!
        val versionBefore = store.stateVersion()

        assertFailsWith<SystemPolicyImmutableException> {
            store.update(
                -1,
                CedarPolicyInput(name = "system:rewritten", cedarSrc = "not cedar", enabled = false),
                updatedBy = "operator@example.com",
            )
        }
        assertFailsWith<SystemPolicyImmutableException> { store.delete(-1) }
        assertEquals(systemBefore, store.get(-1), "failed system mutations must leave every field unchanged")
        assertEquals(versionBefore, store.stateVersion(), "rejected mutations must not invalidate the engine cache")

        assertFailsWith<ReservedPolicyNameException> {
            store.create(
                CedarPolicyInput("system:user-created", ADMIN_SOURCE),
                updatedBy = "operator@example.com",
            )
        }

        val user = store.create(
            CedarPolicyInput("origin-user-${System.nanoTime()}", TEST_ROLE_SOURCE),
            updatedBy = "operator@example.com",
        )
        val userBefore = store.get(user.id)!!
        assertFailsWith<ReservedPolicyNameException> {
            store.update(
                user.id,
                CedarPolicyInput("system:user-renamed", TEST_ROLE_SOURCE),
                updatedBy = "other@example.com",
            )
        }
        assertEquals(userBefore, store.get(user.id), "a rejected reserved rename must not alter the USER row")
        assertTrue(user.id > 0)
        assertEquals("USER", user.origin)
        assertEquals(null, user.systemKey)
    }

    @Test
    fun `system toggle changes only mutable fields`() {
        store.setEnabled(-1, enabled = true, updatedBy = "setup@example.com")
        val before = store.get(-1)!!
        val disabled = store.setEnabled(-1, enabled = false, updatedBy = "operator@example.com")
        assertNotNull(disabled)
        assertFalse(disabled.enabled)
        assertEquals("operator@example.com", disabled.updatedBy)
        assertEquals(before.id, disabled.id)
        assertEquals(before.origin, disabled.origin)
        assertEquals(before.systemKey, disabled.systemKey)
        assertEquals(before.name, disabled.name)
        assertEquals(before.cedarSrc, disabled.cedarSrc)
        assertTrue(store.setEnabled(-1, enabled = true, updatedBy = "operator@example.com")!!.enabled)
    }

    @Test
    fun `negative-id migration is decision-equivalent to the AuthzTest seed oracle`() {
        val roles = mapOf(
            "admin@example.com" to setOf("system:admin"),
            "analyst@example.com" to setOf("analyst"),
        )
        val roleSource = RoleSource { principal -> roles[principal] ?: emptySet() }
        val oracle = Authz(CedarEngine(ORACLE_SOURCES), store, roleSource)
        val migrated = Authz(CedarEngine(store), store, roleSource)
        val cases = listOf(
            DecisionCase("admin@example.com", AuthzAction.ADMIN_DATASOURCES, AuthzResource.System, true),
            DecisionCase("admin@example.com", AuthzAction.ADMIN_POLICIES, AuthzResource.System, true),
            DecisionCase("admin@example.com", AuthzAction.ADMIN_IDENTITY, AuthzResource.System, true),
            DecisionCase("nobody@example.com", AuthzAction.ADMIN_POLICIES, AuthzResource.System, false),
            DecisionCase("analyst@example.com", AuthzAction.ADMIN_POLICIES, AuthzResource.System, false),
            DecisionCase(
                "admin@example.com",
                AuthzAction.TASK_APPROVE,
                AuthzResource.ApprovalRequest(requester = "requester@example.com"),
                true,
            ),
            DecisionCase(
                "admin@example.com",
                AuthzAction.TASK_APPROVE,
                AuthzResource.ApprovalRequest(requester = "admin@example.com"),
                false,
            ),
            DecisionCase(
                "analyst@example.com",
                AuthzAction.AUDIT_READ,
                AuthzResource.AuditRecord(principal = "analyst@example.com"),
                true,
            ),
            DecisionCase(
                "analyst@example.com",
                AuthzAction.AUDIT_READ,
                AuthzResource.AuditRecord(principal = "other@example.com"),
                false,
            ),
            DecisionCase("analyst@example.com", AuthzAction.AUDIT_READ, AuthzResource.AuditLog, false),
            // system:admin reads the whole audit log by default; there is no separate `auditor` role.
            DecisionCase(
                "admin@example.com",
                AuthzAction.AUDIT_READ,
                AuthzResource.AuditRecord(principal = "other@example.com"),
                true,
            ),
            DecisionCase("admin@example.com", AuthzAction.AUDIT_READ, AuthzResource.AuditLog, true),
        )

        for (case in cases) {
            val expected = oracle.authorize(case.principal, case.action, case.resource).isAllowed()
            val actual = migrated.authorize(case.principal, case.action, case.resource).isAllowed()
            assertEquals(case.allowed, expected, "the AuthzTest oracle changed for $case")
            assertEquals(expected, actual, "V20 changed the effective decision for $case")
        }
    }

    private fun AuthzDecision.isAllowed(): Boolean = this == AuthzDecision.Allow

    private data class DecisionCase(
        val principal: String,
        val action: AuthzAction,
        val resource: AuthzResource,
        val allowed: Boolean,
    )

    private companion object {
        const val ADMIN_SOURCE =
            "permit(principal in Role::\"system:admin\", action in [Action::\"admin.datasources\",Action::\"admin.policies\",Action::\"admin.identity\"], resource);"
        const val TEST_ROLE_SOURCE =
            "permit(principal in Role::\"origin-test-role\", action == Action::\"admin.policies\", resource);"

        val ORACLE_SOURCES = listOf(
            1L to ADMIN_SOURCE,
            2L to "forbid(principal, action == Action::\"task.approve\", resource) when { principal == resource.requester };",
            3L to "permit(principal in Role::\"system:admin\", action == Action::\"task.approve\", resource);",
            4L to "permit(principal, action == Action::\"audit.read\", resource) when { resource is AuditRecord && resource.principal == principal };",
            5L to "permit(principal in Role::\"system:admin\", action == Action::\"audit.read\", resource);",
        )
    }
}
