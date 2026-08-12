package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Pure, no-DB proof that the seeded admin-gating and audit decisions hold at the Cedar-decision level: admin
 * routes require a real `system:admin` role (not "any session"), ROLE self-approval is denied even for an
 * admin, ordinary principals can read only their own audit records, and auditors can read the whole
 * collection. [CedarEngine]'s in-memory constructor and [Authz]'s unused [CedarPolicyStore] parameter
 * (a DataSource that's never actually queried — `authorize()` never touches it, see Authz.kt) keep
 * this fully off any JDBC/Docker dependency.
 */
class AuthzTest {
    private val seedPolicies = listOf(
        1L to """permit(principal in Role::"system:admin", action in [Action::"admin.datasources",Action::"admin.policies",Action::"admin.identity"], resource);""",
        2L to """forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester };""",
        3L to """permit(principal in Role::"system:admin", action == Action::"task.approve", resource);""",
        4L to """permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };""",
        5L to """permit(principal in Role::"auditor", action == Action::"audit.read", resource);""",
    )

    /** A [DataSource] that's never actually connected to — [Authz] never touches its [CedarPolicyStore]
     *  parameter, only [CedarEngine] does, and this test's engine is built from an in-memory policy list. */
    private object UnusedDataSource : DataSource {
        override fun getConnection(): Connection = error("not used by this test")
        override fun getConnection(username: String?, password: String?): Connection = error("not used by this test")
        override fun getLogWriter() = error("not used by this test")
        override fun setLogWriter(out: java.io.PrintWriter?) = error("not used by this test")
        override fun setLoginTimeout(seconds: Int) = error("not used by this test")
        override fun getLoginTimeout() = error("not used by this test")
        override fun getParentLogger(): Logger = error("not used by this test")
        override fun <T : Any?> unwrap(iface: Class<T>?): T = error("not used by this test")
        override fun isWrapperFor(iface: Class<*>?): Boolean = false
    }

    private fun authzWithRoles(roles: Map<String, Set<String>>): Authz {
        val engine = CedarEngine(seedPolicies)
        val policyStore = CedarPolicyStore(UnusedDataSource)
        val roleSource = RoleSource { principal -> roles[principal] ?: emptySet() }
        return Authz(engine, policyStore, roleSource)
    }

    @Test
    fun `system-admin is allowed on admin actions`() {
        val authz = authzWithRoles(mapOf("root" to setOf("system:admin")))
        assertEquals(AuthzDecision.Allow, authz.authorize("root", AuthzAction.ADMIN_POLICIES, AuthzResource.System))
        assertEquals(AuthzDecision.Allow, authz.authorize("root", AuthzAction.ADMIN_DATASOURCES, AuthzResource.System))
        assertEquals(AuthzDecision.Allow, authz.authorize("root", AuthzAction.ADMIN_IDENTITY, AuthzResource.System))
    }

    @Test
    fun `no roles is denied on admin actions — the 'admin = any session' hole stays closed`() {
        val authz = authzWithRoles(emptyMap())
        val decision = authz.authorize("nobody", AuthzAction.ADMIN_POLICIES, AuthzResource.System)
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `a role other than system-admin is still denied on admin actions`() {
        val authz = authzWithRoles(mapOf("analyst-alice" to setOf("analyst")))
        val decision = authz.authorize("analyst-alice", AuthzAction.ADMIN_POLICIES, AuthzResource.System)
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `the audit policies allow own records and grant auditors the whole collection`() {
        val authz = authzWithRoles(
            mapOf(
                "alice" to setOf("analyst"),
                "bob" to setOf("auditor"),
            ),
        )

        assertEquals(
            AuthzDecision.Allow,
            authz.authorize("alice", AuthzAction.AUDIT_READ, AuthzResource.AuditRecord(principal = "alice")),
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorize("alice", AuthzAction.AUDIT_READ, AuthzResource.AuditRecord(principal = "bob")),
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorize("alice", AuthzAction.AUDIT_READ, AuthzResource.AuditLog),
        )
        assertEquals(
            AuthzDecision.Allow,
            authz.authorize("bob", AuthzAction.AUDIT_READ, AuthzResource.AuditRecord(principal = "alice")),
        )
        assertEquals(
            AuthzDecision.Allow,
            authz.authorize("bob", AuthzAction.AUDIT_READ, AuthzResource.AuditLog),
        )
    }

    @Test
    fun `an approver may approve someone else's request`() {
        val authz = authzWithRoles(mapOf("approver1" to setOf("system:admin")))
        val decision = authz.authorize(
            "approver1",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `ROLE self-approval is denied even for a system-admin — the self-approval hole stays closed`() {
        val authz = authzWithRoles(mapOf("alice" to setOf("system:admin")))
        val decision = authz.authorize(
            "alice",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "alice"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `a non-admin approving someone else's request is still denied — no ambient permit`() {
        val authz = authzWithRoles(mapOf("bob" to emptySet()))
        val decision = authz.authorize(
            "bob",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    /** A Request scoped to a role (`ApprovalRequest.roleName`) attaches that Role as a Cedar PARENT
     *  (`Request in [Datasource, Role]`, schema.cedarschema), so `resource in Role::"..."` is a real
     *  entity-membership check — not a string comparison — letting a policy scope who may approve by
     *  the ROLE being requested, not just the requester's identity. */
    private fun authzForRoleScopedApproval(): Authz {
        val engine = CedarEngine(
            listOf(
                1L to """permit(principal in Role::"pii-reader", action == Action::"task.approve", resource) when { resource in Role::"pii-reader" };""",
            ),
        )
        val policyStore = CedarPolicyStore(UnusedDataSource)
        val roleSource = RoleSource { principal -> if (principal == "approver1") setOf("pii-reader") else emptySet() }
        return Authz(engine, policyStore, roleSource)
    }

    @Test
    fun `an approval request scoped to a role is matched via 'resource in Role' — Request carries the role as a Cedar parent`() {
        val authz = authzForRoleScopedApproval()
        val decision = authz.authorize(
            "approver1",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else", roleName = "pii-reader"),
        )
        assertEquals(AuthzDecision.Allow, decision)
    }

    @Test
    fun `a request scoped to a DIFFERENT role than the policy grants is denied — the Role parent is the request's, not ambient`() {
        val authz = authzForRoleScopedApproval()
        val decision = authz.authorize(
            "approver1",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else", roleName = "other-role"),
        )
        assertIs<AuthzDecision.Deny>(decision)
    }

    @Test
    fun `a request-specific policy cannot carry over to a later request with the same requester and datasource`() {
        // An operator permit scoped to one exact Request EUID must match only that persisted request, not a
        // later one that happens to share the requester and datasource — each durable request keys off its id.
        // Routed through `toApprovalResource`, the single persisted-path constructor every route funnels
        // through, so dropping the id there (the exact regression this closes) would fail here.
        val authz = Authz(
            CedarEngine(listOf(1L to """permit(principal, action == Action::"task.approve", resource == Request::"41");""")),
            CedarPolicyStore(UnusedDataSource),
            RoleSource { emptySet() },
        )
        fun row(id: Long) = AccessRequest(
            id = id, principal = "requester@example.com", datasourceName = "acme",
            requestedDurationSec = 3600, status = "PENDING", createdAt = "2026-01-01T00:00:00Z",
        )
        assertEquals(
            AuthzDecision.Allow,
            authz.authorize("approver@example.com", AuthzAction.TASK_APPROVE, row(41).toApprovalResource()),
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorize("approver@example.com", AuthzAction.TASK_APPROVE, row(42).toApprovalResource()),
        )
    }

    /** Regression: the Request's Datasource parent must be keyed by NAME (`Datasource::"acme-mysql"`),
     *  matching every other Datasource-keyed grant in the system — including this exact policy shape,
     *  straight from the doc's worked examples. Keyed by numeric id (`Datasource::"2"`) instead, a
     *  per-datasource approval policy silently never matches. */
    @Test
    fun `task lifecycle and grant revoke actions validate against the bundled schema`() {
        val sources = listOf(
            """permit(principal, action == Action::"task.request", resource);""",
            """permit(principal, action == Action::"task.approve", resource);""",
            """permit(principal, action == Action::"task.read", resource);""",
            """permit(principal, action == Action::"task.assume", resource);""",
            """permit(principal, action == Action::"task.cancel", resource);""",
            """permit(principal, action == Action::"task.delete", resource);""",
            """permit(principal, action == Action::"grant.revoke", resource);""",
        )
        sources.forEach { source -> assertTrue(CedarSchema.validate(source).isEmpty(), source) }
    }

    @Test
    fun `task assume seeds validate and allow only parties or auditor`() {
        val parties = """permit(principal, action == Action::"task.assume", resource) when { resource is Request && (resource.requester == principal || (resource has approver && resource.approver == principal)) };"""
        val auditor = """permit(principal in Role::"system:auditor", action == Action::"task.assume", resource) when { resource is Request };"""
        assertTrue(CedarSchema.validate(parties).isEmpty(), parties)
        assertTrue(CedarSchema.validate(auditor).isEmpty(), auditor)
        val engine = CedarEngine(listOf(21L to parties, 22L to auditor, 23L to """permit(principal in Role::"system:admin", action == Action::"task.read", resource);"""))
        val authz = Authz(
            engine,
            CedarPolicyStore(UnusedDataSource),
            RoleSource { principal ->
                when (principal) {
                    "auditor@example.com" -> setOf("system:auditor")
                    "admin@example.com" -> setOf("system:admin")
                    else -> emptySet()
                }
            },
        )
        val request = AuthzResource.ApprovalRequest(
            requester = "requester@example.com",
            approver = "approver@example.com",
            executedBy = "executor@example.com",
        )
        assertEquals(AuthzDecision.Allow, authz.authorize("requester@example.com", AuthzAction.TASK_ASSUME, request))
        assertEquals(AuthzDecision.Allow, authz.authorize("approver@example.com", AuthzAction.TASK_ASSUME, request))
        assertEquals(AuthzDecision.Allow, authz.authorize("auditor@example.com", AuthzAction.TASK_ASSUME, request))
        assertIs<AuthzDecision.Deny>(authz.authorize("admin@example.com", AuthzAction.TASK_ASSUME, request))
    }

    @Test
    fun `approval request marshals executedBy as a User attribute`() {
        val source = """permit(principal, action == Action::"task.assume", resource) when { resource has executedBy && resource.executedBy == principal };"""
        val authz = Authz(CedarEngine(listOf(1L to source)), CedarPolicyStore(UnusedDataSource), RoleSource { emptySet() })
        assertEquals(
            AuthzDecision.Allow,
            authz.authorize(
                "executor@example.com",
                AuthzAction.TASK_ASSUME,
                AuthzResource.ApprovalRequest(requester = "requester@example.com", executedBy = "executor@example.com"),
            ),
        )
    }

    @Test
    fun `retired workflow action ids are rejected by the bundled schema`() {
        listOf(
            "workflow.request", "workflow.approve", "workflow.read", "workflow.readResult", "workflow.revoke",
        ).forEach { action ->
            assertTrue(
                CedarSchema.validate("""permit(principal, action == Action::"$action", resource);""").isNotEmpty(),
                action,
            )
        }
    }

    @Test
    fun `an approval request scoped to a datasource is matched via 'resource in Datasource' by NAME`() {
        val engine = CedarEngine(
            listOf(
                1L to """permit(principal in Role::"acme-approver", action == Action::"task.approve", resource) when { resource in Datasource::"acme-mysql" };""",
            ),
        )
        val policyStore = CedarPolicyStore(UnusedDataSource)
        val roleSource = RoleSource { principal -> if (principal == "approver1") setOf("acme-approver") else emptySet() }
        val authz = Authz(engine, policyStore, roleSource)

        val matching = authz.authorize(
            "approver1",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else", datasourceName = "acme-mysql"),
        )
        assertEquals(AuthzDecision.Allow, matching)

        // A request for a DIFFERENT datasource must not match — the Datasource parent is the
        // request's, not ambient.
        val other = authz.authorize(
            "approver1",
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = "someone-else", datasourceName = "some-other-ds"),
        )
        assertIs<AuthzDecision.Deny>(other)
    }
}
