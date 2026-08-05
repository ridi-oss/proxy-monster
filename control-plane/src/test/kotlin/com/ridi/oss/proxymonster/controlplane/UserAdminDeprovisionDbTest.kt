package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed tests for local-admin `PUT`/`DELETE /api/users/{id}` teardown atomicity: a principal
 * rename or an active flip from true to false via [UserGroupStore.updateUser], and a
 * [UserGroupStore.deleteUser], must revoke the affected principal's active credentials — tokens,
 * JIT grants, AND daemon session windows — in the SAME transaction as the `app_user` mutation,
 * mirroring what [UserGroupStore.upsertScimUser]'s rename path (SCIM, [ProvisionMergeDbTest]) and
 * `Scim.kt`'s PATCH/DELETE paths already do, so the local-admin surface can't leave a live
 * token/grant/daemon-session behind a rename or a delete.
 * Store/primitive-level, not route-level (equivalent coverage, no HTTP/admin-gate scaffolding needed).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserAdminDeprovisionDbTest {
    private lateinit var ds: DataSource
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var policyStore: PolicyStore
    private lateinit var management: IdentityManagementService
    private val actor = AuditActor("admin@example.com", channel = AuditSource.CONSOLE)

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val dbName = SharedPostgres.freshDatabase("pm_user_admin_deprovision")
        ds = SharedPostgres.hikari(dbName)
        Flyway.configure().dataSource(ds).load().migrate()
        userGroupStore = UserGroupStore(ds)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        policyStore = PolicyStore(ds)
        management = IdentityManagementService(
            ds, userGroupStore, policyStore, tokenStore, accessStore, daemonSessionStore, ManagementAuditRecorder(AuditStore(ds)),
        )
    }

    /** Mint one of every credential class for [principal], including a live web session. */
    private fun seedCredentials(principal: String, roleName: String): IssuedToken {
        val token = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        val role = policyStore.createRole(RoleInput(roleName))
        val req = accessStore.createRequest(principal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")
        daemonSessionStore.create(principal, "dvc_$roleName", null, windowSeconds = 3600, ttlSeconds = 900)
        daemonSessionStore.mintWeb(principal, null, 3600, 900, "web-$roleName")
        assertTrue(daemonSessionStore.withinWindow(principal), "sanity: $principal is in-window before the teardown")
        return token
    }

    private fun assertWebEnded(principal: String) {
        val rows = ds.connection.use { c ->
            c.prepareStatement(
                """SELECT ended_reason, liveness_status FROM principal_session
                   WHERE principal = ? AND kind = 'WEB' ORDER BY id""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs ->
                    buildList { while (rs.next()) add(rs.getString(1) to rs.getString(2)) }
                }
            }
        }
        assertTrue(rows.isNotEmpty(), "sanity: $principal has a web session")
        assertTrue(rows.all { it.first == ENDED_DEACTIVATED && it.second == LIVENESS_INACTIVE })
    }

    private fun assertWebLive(principal: String) {
        val active = ds.connection.use { c ->
            c.prepareStatement(
                """SELECT count(*) FROM principal_session
                   WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
            }
        }
        assertEquals(1, active)
    }

    @Test
    fun `PUT rename atomically retires the old principal — tombstoned, token + grant + session revoked`() {
        val oldPrincipal = "admin-rename-old@example.com"
        val newPrincipal = "admin-rename-new@example.com"
        val user = userGroupStore.createUser(AppUserInput(principal = oldPrincipal, active = true), tokenStore, accessStore, daemonSessionStore)
        val token = seedCredentials(oldPrincipal, "admin-rename-role")

        val updated = userGroupStore.updateUser(
            user.id, AppUserInput(principal = newPrincipal, active = true), tokenStore, accessStore, daemonSessionStore,
        )
        assertEquals(newPrincipal, updated?.principal)

        assertTrue(userGroupStore.isDeactivated(oldPrincipal), "the renamed-away principal must be tombstoned")
        assertFalse(userGroupStore.isDeactivated(newPrincipal), "the current principal stays active")
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the old principal's token must be revoked by the rename")
        assertEquals(0, accessStore.listGrants(oldPrincipal, activeOnly = true).size, "the old principal's grant must be revoked")
        assertFalse(daemonSessionStore.withinWindow(oldPrincipal), "the old principal's daemon session window must be closed")
        assertWebEnded(oldPrincipal)
    }

    @Test
    fun `PUT active flip (true to false, no rename) revokes token + grant + session in the same transaction`() {
        val principal = "admin-deactivate@example.com"
        val user = userGroupStore.createUser(AppUserInput(principal = principal, active = true), tokenStore, accessStore, daemonSessionStore)
        val token = seedCredentials(principal, "admin-deactivate-role")

        val updated = userGroupStore.updateUser(
            user.id, AppUserInput(principal = principal, active = false), tokenStore, accessStore, daemonSessionStore,
        )
        assertEquals(false, updated?.active)
        assertTrue(userGroupStore.isDeactivated(principal))
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "flipping active to false must revoke the principal's tokens")
        assertEquals(0, accessStore.listGrants(principal, activeOnly = true).size, "flipping active to false must revoke the grant")
        assertFalse(daemonSessionStore.withinWindow(principal), "flipping active to false must close the daemon session window")
        assertWebEnded(principal)
    }

    @Test
    fun `PUT rename and deactivate revokes credentials held by both principal strings`() {
        // Row starts as `old` (active) with live creds. `new` is a SEPARATE identity that ALSO already
        // holds a live token/grant/session but has NO app_user row of its own. A PUT that renames
        // old->new AND deactivates (active=false) must retire `old` (tombstone + revoke) AND revoke
        // `new`'s pre-existing credentials — else reactivating the row later resurrects new's old token.
        val oldPrincipal = "combo-old@example.com"
        val newPrincipal = "combo-new@example.com"
        val user = userGroupStore.createUser(AppUserInput(principal = oldPrincipal, active = true), tokenStore, accessStore, daemonSessionStore)
        val oldToken = seedCredentials(oldPrincipal, "combo-old-role")
        val newToken = seedCredentials(newPrincipal, "combo-new-role") // new's creds exist, but no app_user row for new

        val updated = userGroupStore.updateUser(
            user.id, AppUserInput(principal = newPrincipal, active = false), tokenStore, accessStore, daemonSessionStore,
        )
        assertEquals(newPrincipal, updated?.principal)
        assertEquals(false, updated?.active)

        // Old principal fully retired.
        assertTrue(userGroupStore.isDeactivated(oldPrincipal), "old principal must be tombstoned")
        assertNotNull(tokenStore.get(oldToken.id)!!.revokedAt, "old principal's token must be revoked")
        assertEquals(0, accessStore.listGrants(oldPrincipal, activeOnly = true).size, "old principal's grant must be revoked")
        assertFalse(daemonSessionStore.withinWindow(oldPrincipal), "old principal's session window must be closed")
        assertWebEnded(oldPrincipal)
        // New (target) principal's PRE-EXISTING credentials must ALL be revoked.
        assertTrue(userGroupStore.isDeactivated(newPrincipal), "the renamed-to row is inactive")
        assertNotNull(tokenStore.get(newToken.id)!!.revokedAt, "the TARGET principal's pre-existing token must be revoked too")
        assertEquals(0, accessStore.listGrants(newPrincipal, activeOnly = true).size, "the TARGET principal's grant must be revoked too")
        assertFalse(daemonSessionStore.withinWindow(newPrincipal), "the TARGET principal's session window must be closed too")
        assertWebEnded(newPrincipal)
    }

    @Test
    fun `createUser with active=false revokes credentials held before the row existed`() {
        // A principal can accumulate a live wire token / grant / daemon session BEFORE any app_user
        // row exists for it at all (isDeactivated() is false with no row). Deliberately CREATING it
        // inactive must not leave those pre-existing credentials usable.
        val principal = "create-inactive-preexisting@example.com"
        assertFalse(userGroupStore.isDeactivated(principal), "sanity: no row yet, so not deactivated")
        val token = seedCredentials(principal, "create-inactive-role")

        val created = userGroupStore.createUser(AppUserInput(principal = principal, active = false), tokenStore, accessStore, daemonSessionStore)

        assertFalse(created.active)
        assertTrue(userGroupStore.isDeactivated(principal))
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "creating inactive must revoke the principal's pre-existing token")
        assertEquals(0, accessStore.listGrants(principal, activeOnly = true).size, "creating inactive must revoke the pre-existing grant")
        assertFalse(daemonSessionStore.withinWindow(principal), "creating inactive must close the pre-existing daemon session window")
        assertWebEnded(principal)
    }

    @Test
    fun `createUser with active=true does not touch an unrelated principal's credentials`() {
        val principal = "create-active-noop@example.com"
        val token = seedCredentials(principal, "create-active-noop-role")

        userGroupStore.createUser(AppUserInput(principal = principal, active = true), tokenStore, accessStore, daemonSessionStore)

        assertNull(tokenStore.get(token.id)!!.revokedAt, "creating active must not revoke pre-existing credentials")
        assertTrue(daemonSessionStore.withinWindow(principal))
        assertWebLive(principal)
    }

    @Test
    fun `PUT with no rename and no active flip does not revoke anything`() {
        val principal = "admin-noop-update@example.com"
        val user = userGroupStore.createUser(AppUserInput(principal = principal, active = true), tokenStore, accessStore, daemonSessionStore)
        val token = seedCredentials(principal, "admin-noop-role")

        userGroupStore.updateUser(
            user.id, AppUserInput(principal = principal, displayName = "New Display Name", active = true),
            tokenStore, accessStore, daemonSessionStore,
        )
        assertNull(tokenStore.get(token.id)!!.revokedAt, "an unrelated field update must not revoke live credentials")
        assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size, "an unrelated field update must not revoke the grant")
        assertTrue(daemonSessionStore.withinWindow(principal), "an unrelated field update must not close the session window")
        assertWebLive(principal)
    }

    @Test
    fun `DELETE tombstones (never hard-deletes) and revokes token + grant + session atomically`() {
        val principal = "admin-delete@example.com"
        val user = userGroupStore.createUser(AppUserInput(principal = principal, active = true), tokenStore, accessStore, daemonSessionStore)
        val token = seedCredentials(principal, "admin-delete-role")

        val deleted = userGroupStore.deleteUser(user.id, tokenStore, accessStore, daemonSessionStore)
        assertTrue(deleted)

        // Tombstoned, not hard-deleted: the row (and its audit trail) is still there, just inactive.
        assertNotNull(userGroupStore.getUser(user.id), "DELETE must tombstone, not hard-delete, the row")
        assertTrue(userGroupStore.isDeactivated(principal))
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "DELETE must revoke the principal's active tokens")
        assertEquals(0, accessStore.listGrants(principal, activeOnly = true).size, "DELETE must revoke the grant")
        assertFalse(daemonSessionStore.withinWindow(principal), "DELETE must close the daemon session window")
        assertWebEnded(principal)
    }

    @Test
    fun `DELETE on a nonexistent id returns false (404 at the route)`() {
        assertFalse(userGroupStore.deleteUser(999_999_999L, tokenStore, accessStore, daemonSessionStore))
    }

    @Test
    fun `REST-shaped ID deprovision still targets the original row after a principal rename`() {
        val original = userGroupStore.createUser(
            AppUserInput("id-stable-before@example.com", active = true), tokenStore, accessStore, daemonSessionStore,
        )
        userGroupStore.updateUser(
            original.id, AppUserInput("id-stable-after@example.com", active = true),
            tokenStore, accessStore, daemonSessionStore,
        )

        assertTrue(management.deprovisionUser(original.id, actor).deleted)
        val addressed = assertNotNull(userGroupStore.getUser(original.id))
        assertEquals("id-stable-after@example.com", addressed.principal)
        assertFalse(addressed.active)
    }

    @Test
    fun `concurrent REST-shaped group role additions retain both mappings`() {
        val group = userGroupStore.createGroup(AppGroupInput("concurrent-group-roles"))
        val first = policyStore.createRole(RoleInput("concurrent-role-first"))
        val second = policyStore.createRole(RoleInput("concurrent-role-second"))
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val futures = listOf(first, second).map { role ->
                executor.submit<Unit> { start.await(); management.addGroupRole(group.id, role.id, actor) }
            }
            start.countDown()
            futures.forEach { it.get() }
        } finally {
            executor.shutdownNow()
        }

        assertEquals(setOf(first.id, second.id), userGroupStore.listGroupRoles(group.id).map { it.roleId }.toSet())
    }
}
