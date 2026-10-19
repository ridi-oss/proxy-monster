package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.daemonLiveness
import com.ridi.oss.proxymonster.controlplane.support.daemonWithinWindow
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed tests for the deprovisioning backstop (docs/auth-model.md "Deprovisioning propagates
 * two ways"): [TokenStore.revokeAllForPrincipal] / [AccessStore.revokeAllForPrincipal] /
 * [PrincipalSessionStore.deactivateAllForPrincipal] / [revokeActiveCredentials] kill every
 * currently-active credential for a principal immediately — wire tokens, JIT grants, daemon
 * session windows, and live web sessions — and [RoleResolver.resolve]
 * fails closed to the empty set for a deactivated principal regardless of which role source
 * (direct/group/grant) would otherwise apply.
 *
 * NOTE: [RoleResolver.resolve] returning emptySet is necessary but NOT sufficient for fail-closed
 * enforcement — `decideQuery` only builds column MASK/DENY actions from role-attached policies, and
 * [PolicyEvaluator] ALLOWs when no masks result, so an empty role set alone actually flips a
 * deactivated principal's masked query to cleartext ALLOW (more access after deprovision). The
 * authoritative end-to-end fail-closed check — the explicit structural DENY [decideQuery] now emits
 * for a deactivated principal, exercised through [runEnforcedForTest] — lives in
 * [DeactivationEnforcementDbTest]; this file only covers the role-resolution and credential-revocation
 * layers below it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeprovisionDbTest {
    private lateinit var ds: DataSource
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var policyStore: PolicyStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var roleResolver: RoleResolver

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val dbName = SharedPostgres.freshDatabase("pm_deprovision")
        ds = SharedPostgres.hikari(dbName)
        Flyway.configure().dataSource(ds).load().migrate()
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        policyStore = PolicyStore(ds)
        userGroupStore = UserGroupStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)
    }

    @Test
    fun `revokeAllForPrincipal revokes every active token for that principal only`() {
        val principal = "revoke-tokens@example.com"
        val other = "someone-else@example.com"
        val t1 = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        val t2 = tokenStore.issue(TokenKind.USER, principal, emptyList(), name = "connect", ttlSeconds = 3600)
        val otherToken = tokenStore.issue(TokenKind.SESSION, other, emptyList(), name = null, ttlSeconds = 3600)

        val revoked = tokenStore.revokeAllForPrincipal(principal)
        assertEquals(2, revoked)
        assertNotNull(tokenStore.get(t1.id)!!.revokedAt)
        assertNotNull(tokenStore.get(t2.id)!!.revokedAt)
        assertNull(tokenStore.get(otherToken.id)!!.revokedAt, "a different principal's token must be untouched")
    }

    @Test
    fun `revokeAllForPrincipal is a no-op on an already-revoked or expired token`() {
        val principal = "revoke-idempotent@example.com"
        val t = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        assertEquals(1, tokenStore.revokeAllForPrincipal(principal))
        // Already revoked: the second sweep finds nothing left to revoke.
        assertEquals(0, tokenStore.revokeAllForPrincipal(principal))

        // An expired-but-not-yet-revoked token is excluded (fail-closed on the "active" definition,
        // not a target for this sweep — it's already unusable).
        val expiredPrincipal = "revoke-expired@example.com"
        ds.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at)
                   VALUES ('deadbeef', 'SESSION', ?, '[]'::jsonb, now() - interval '1 hour')""",
            ).use { ps -> ps.setString(1, expiredPrincipal); ps.executeUpdate() }
        }
        assertEquals(0, tokenStore.revokeAllForPrincipal(expiredPrincipal))
    }

    @Test
    fun `AccessStore revokeAllForPrincipal revokes every active grant for that principal only`() {
        val role = policyStore.createRole(RoleInput("deprovision-grant-role"))
        val principal = "revoke-grants@example.com"
        val other = "grant-untouched@example.com"

        val req1 = accessStore.createRequest(principal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req1.id, durationSec = 3600, decidedBy = "approver@example.com")
        val req2 = accessStore.createRequest(other, AccessRequestInput(roleId = role.id))
        accessStore.approve(req2.id, durationSec = 3600, decidedBy = "approver@example.com")

        val revoked = accessStore.revokeAllForPrincipal(principal)
        assertEquals(1, revoked)
        assertEquals(0, accessStore.listGrants(principal, activeOnly = true).size)
        assertEquals(1, accessStore.listGrants(other, activeOnly = true).size, "a different principal's grant must be untouched")
    }

    @Test
    fun `revokeActiveCredentials sums tokens grants daemon windows and web sessions`() {
        val role = policyStore.createRole(RoleInput("deprovision-combo-role"))
        val principal = "revoke-combo@example.com"
        val bystander = "revoke-combo-bystander@example.com"
        tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        tokenStore.issue(TokenKind.USER, principal, emptyList(), name = null, ttlSeconds = 3600)
        val req = accessStore.createRequest(principal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")
        ds.seedDaemonSession(principal)
        ds.seedDaemonSession(principal)
        val webId = daemonSessionStore.mintWeb(principal, null, 3600, 900, "combo-web-device")
        val bystanderWebId = daemonSessionStore.mintWeb(bystander, null, 3600, 900, "combo-bystander-device")

        assertEquals(6, revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore))
        assertNull(daemonSessionStore.resolveWeb(webId, "combo-web-device"))
        assertEquals(ENDED_DEACTIVATED, daemonSessionStore.webEndedReason(webId))
        assertNotNull(daemonSessionStore.resolveWeb(bystanderWebId, "combo-bystander-device"))
        assertEquals(0, revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore))
    }

    @Test
    fun `revokeActiveCredentials closes the principal's daemon session windows so a renewal secret can't survive`() {
        val principal = "revoke-daemon-session@example.com"
        val created = ds.seedDaemonSession(principal)
        assertTrue(ds.daemonWithinWindow(principal), "sanity: the session is in-window before revoke")

        revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore)

        assertEquals(LIVENESS_INACTIVE, ds.daemonLiveness(created), "revoke must mark the session INACTIVE")
        assertFalse(ds.daemonWithinWindow(principal), "revoke must close the renewal window (durable deprovision)")
    }

    @Test
    fun `RoleResolver resolve is fail-closed to empty for a deactivated principal, across every role source`() {
        val direct = policyStore.createRole(RoleInput("deprovision-direct-role"))
        val groupRole = policyStore.createRole(RoleInput("deprovision-group-role"))
        val grantRole = policyStore.createRole(RoleInput("deprovision-grant-role-2"))
        val principal = "deactivated-user@example.com"

        policyStore.createAssignment(RoleAssignmentInput(principal, direct.id))
        val user = userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        val group = userGroupStore.createGroup(AppGroupInput(name = "deprovision-test-group"))
        userGroupStore.addMember(group.id, user.id)
        userGroupStore.addGroupRole(group.id, groupRole.id)
        val req = accessStore.createRequest(principal, AccessRequestInput(roleId = grantRole.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")

        // Sanity: while active, all three sources contribute.
        assertEquals(setOf("deprovision-direct-role", "deprovision-group-role", "deprovision-grant-role-2"), roleResolver.resolve(principal))

        userGroupStore.setUserActive(principal, false)
        assertTrue(userGroupStore.isDeactivated(principal))
        assertEquals(emptySet(), roleResolver.resolve(principal), "a deactivated principal must resolve to zero roles from EVERY source")

        // Reactivating restores resolution (deprovisioning isn't a one-way local flag flip in this test,
        // just proving the gate is live, not baked into some other cached state).
        userGroupStore.setUserActive(principal, true)
        assertEquals(setOf("deprovision-direct-role", "deprovision-group-role", "deprovision-grant-role-2"), roleResolver.resolve(principal))
    }

    @Test
    fun `a principal with no app_user row at all is unaffected by the deactivation gate`() {
        val role = policyStore.createRole(RoleInput("deprovision-local-only-role"))
        val principal = "local-only-principal_role@example.com" // never synced into app_user
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        assertEquals(setOf("deprovision-local-only-role"), roleResolver.resolve(principal))
    }

    @Test
    fun `mintForActivePrincipalLocked refuses when a concurrent teardown deactivates first`() {
        val principal = "mint-toctou@example.com"
        userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore) // active

        // Sanity: an active principal mints (and the token validates).
        val ok = ds.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
            tokenStore.issue(TokenKind.USER, principal, emptyList(), name = null, ttlSeconds = 3600, c)
        }
        assertNotNull(ok, "an active principal mints")
        assertNotNull(tokenStore.validate(ok!!.token), "the minted token validates")

        // A concurrent teardown holds the advisory lock and commits active=false while a mint is in
        // flight. The mint must block on the lock, observe the committed deactivation, and mint
        // nothing because both operations use the same principal lock.
        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal); ps.executeQuery().use { it.next() }
        }
        holder.prepareStatement("UPDATE app_user SET active = FALSE WHERE principal = ?").use { ps ->
            ps.setString(1, principal); ps.executeUpdate()
        }
        try {
            runBlocking {
                coroutineScope {
                    val deferred = async(Dispatchers.IO) {
                        ds.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
                            tokenStore.issue(TokenKind.USER, principal, emptyList(), name = null, ttlSeconds = 3600, c)
                        }
                    }
                    delay(300)
                    assertFalse(deferred.isCompleted, "the mint must block behind the held advisory lock, not race ahead of the teardown")

                    holder.commit() // commit active=false + release the lock

                    val result = withTimeout(5_000) { deferred.await() }
                    assertNull(result, "once the teardown's deactivation commits, the locked mint must refuse (mint nothing)")
                }
            }
        } finally {
            holder.close()
        }
    }

    @Test
    fun `revokeActiveCredentials itself blocks behind a concurrent holder of the SAME principal's advisory lock`() {
        val principal = "revoke-serializes@example.com"
        val token = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)

        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal); ps.executeQuery().use { it.next() }
        }
        try {
            runBlocking {
                coroutineScope {
                    val revokeDeferred = async(Dispatchers.IO) {
                        revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore)
                    }
                    delay(300)
                    assertFalse(revokeDeferred.isCompleted, "revokeActiveCredentials must block behind the held advisory lock, not revoke ahead of the holder")
                    assertNull(tokenStore.get(token.id)!!.revokedAt, "the token must still be live while the teardown is blocked on the lock")

                    holder.commit()

                    val revoked = withTimeout(5_000) { revokeDeferred.await() }
                    assertTrue(revoked >= 1, "once the lock releases, the teardown proceeds and revokes at least the token")
                    assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the token must be revoked after the teardown completes")
                }
            }
        } finally {
            holder.close()
        }
    }
}
