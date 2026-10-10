package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The capabilities cp-go's /api/me/permissions reports, decided by Cedar. */
class MePermissionsTest {
    private val dataSource: DataSource by lazy {
        requireDockerOrSkip()
        SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_me_permissions"))
            .also { Flyway.configure().dataSource(it).load().migrate() }
    }

    private val authz: Authz by lazy {
        Authz(
            CedarEngine(
                listOf(
                    1L to """permit(principal in Role::"datasource-admin", action == Action::"admin.datasources", resource);""",
                    2L to """permit(principal in Role::"policy-admin", action == Action::"admin.policies", resource);""",
                    3L to """permit(principal in Role::"identity-admin", action == Action::"admin.identity", resource);""",
                    4L to """permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };""",
                    5L to """permit(principal in Role::"auditor", action == Action::"audit.read", resource);""",
                    6L to """permit(principal in Role::"edge-admin", action == Action::"admin.datasources", resource)
                        when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
                ),
            ),
            CedarPolicyStore(dataSource),
            RoleSource { p ->
                mapOf(
                    "datasource-only" to setOf("datasource-admin"),
                    "policy-only" to setOf("policy-admin"),
                    "identity-only" to setOf("identity-admin"),
                    "auditor-only" to setOf("auditor"),
                    "edge" to setOf("edge-admin"),
                )[p] ?: emptySet()
            },
        )
    }

    @Test
    fun `a principal holding no roles claims no capabilities`() {
        assertEquals(MePermissions(isAdmin = false, canReadAllAudit = false, canApprove = false), computeMePermissions("roleless", authz))
    }

    @Test
    fun `each independent admin action grants admin and approval but not audit collection access`() {
        for (principal in listOf("datasource-only", "policy-only", "identity-only")) {
            assertEquals(MePermissions(isAdmin = true, canReadAllAudit = false, canApprove = true), computeMePermissions(principal, authz), principal)
        }
    }

    @Test
    fun `auditor can read the audit collection without admin or approval capabilities`() {
        assertEquals(MePermissions(isAdmin = false, canReadAllAudit = true, canApprove = false), computeMePermissions("auditor-only", authz))
    }

    @Test
    fun `requester_ip reaches the admin decision`() {
        assertEquals(true, computeMePermissions("edge", authz, AuthzContext(requesterIp = "203.0.113.10")).isAdmin)
        assertEquals(false, computeMePermissions("edge", authz, AuthzContext(requesterIp = "198.51.100.10")).isAdmin)
        assertEquals(false, computeMePermissions("edge", authz).isAdmin)
    }
}
