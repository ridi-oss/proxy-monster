package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
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
 * DB-backed tests for OIDC JIT provisioning + SCIM reconciliation (docs/auth-model.md "SCIM vs
 * JIT (decision (c))"): JIT provisioning is additive-only and never clobbers a SCIM-owned user;
 * SCIM upsert reconciles a prior JIT row (matched by external_id -> email -> principal) instead of
 * duplicating it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProvisionMergeDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: UserGroupStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var policyStore: PolicyStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val dbName = SharedPostgres.freshDatabase("pm_provision_merge")
        ds = SharedPostgres.hikari(dbName)
        Flyway.configure().dataSource(ds).load().migrate()
        store = UserGroupStore(ds)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        policyStore = PolicyStore(ds)
    }

    @Test
    fun `provisionFromOidc creates a new source=OIDC user and mirrors the claim's groups`() {
        val user = store.provisionFromOidc("new-jit@example.com", "new-jit@example.com", listOf("eng", "on-call"))
        assertEquals("OIDC", user.source)
        assertEquals("new-jit@example.com", user.email)
        assertEquals(setOf("eng", "on-call"), user.groups.map { it.name }.toSet())

        // The groups were freshly created as source=OIDC (JIT-created, no SCIM push yet).
        val eng = store.listGroups().first { it.name == "eng" }
        assertEquals("OIDC", eng.source)
    }

    @Test
    fun `activePrincipalByEmail resolves a unique active email but refuses an ambiguous one`() {
        // email carries no uniqueness constraint, so two ACTIVE principals can share one. This method
        // authenticates a Slack click, so an ambiguous match must be refused, never resolved to an arbitrary
        // principal (which could hand the click the wrong Cedar authority).
        ds.connection.use { c ->
            c.prepareStatement("INSERT INTO app_user (principal, email, active) VALUES (?, ?, true)").use { ps ->
                ps.setString(1, "solo@principal"); ps.setString(2, "solo@example.com"); ps.executeUpdate()
                ps.setString(1, "dup-a@principal"); ps.setString(2, "shared@example.com"); ps.executeUpdate()
                ps.setString(1, "dup-b@principal"); ps.setString(2, "shared@example.com"); ps.executeUpdate()
            }
        }
        assertEquals("solo@principal", store.activePrincipalByEmail("solo@example.com"))
        assertEquals("solo@principal", store.activePrincipalByEmail("SOLO@example.com"), "case-insensitive match")
        assertNull(
            store.activePrincipalByEmail("shared@example.com"),
            "two active principals share this email — an ambiguous identity is refused, not guessed",
        )
    }

    @Test
    fun `re-provisioning SYNCS group membership to the latest claim (drops removed groups)`() {
        // OIDC is authoritative for an OIDC user's group membership, so a login with a
        // smaller claim REMOVES the groups no longer claimed (this is how dropping someone from the IdP
        // admin group revokes their system:admin on the next login).
        val principal = "additive@example.com"
        store.provisionFromOidc(principal, principal, listOf("group-a", "group-b"))
        val second = store.provisionFromOidc(principal, principal, listOf("group-c"))
        assertEquals(setOf("group-c"), second.groups.map { it.name }.toSet())
    }

    @Test
    fun `provisionFromOidc reuses an existing group's source, whatever it is`() {
        val group = store.createGroup(AppGroupInput(name = "already-local"))
        assertEquals("LOCAL", group.source)
        val user = store.provisionFromOidc("reuse-group@example.com", null, listOf("already-local"))
        assertEquals(setOf("already-local"), user.groups.map { it.name }.toSet())
        // The group's own source is untouched by JIT — group creation-vs-reuse is the only branch.
        assertEquals("LOCAL", store.getGroup(group.id)!!.source)
    }

    @Test
    fun `JIT never clobbers a source=SCIM user's fields`() {
        val principal = "scim-owned@example.com"
        val scimUser = store.upsertScimUser(
            externalId = "ext-1", principal = principal, email = "scim-owned@example.com",
            displayName = "SCIM Name", active = true,
        )
        assertEquals("SCIM", scimUser.source)

        // A JIT login for the same principal must not flip source back to OIDC or alter email.
        val afterJit = store.provisionFromOidc(principal, "attacker-supplied@evil.com", listOf("some-group"))
        assertEquals("SCIM", afterJit.source)
        assertEquals("scim-owned@example.com", afterJit.email, "JIT must not overwrite a SCIM-owned user's email")
    }

    @Test
    fun `upsertScimUser matches an existing JIT user by email and reconciles it to SCIM`() {
        val principal = "jit-then-scim@example.com"
        val jitUser = store.provisionFromOidc(principal, "jit-then-scim@example.com", emptyList())
        assertEquals("OIDC", jitUser.source)

        val reconciled = store.upsertScimUser(
            externalId = "ext-42", principal = principal, email = "jit-then-scim@example.com",
            displayName = "Reconciled", active = true,
        )
        assertEquals(jitUser.id, reconciled.id, "must reconcile the SAME row, not create a duplicate")
        assertEquals("SCIM", reconciled.source)
        assertEquals("ext-42", reconciled.externalId)
    }

    @Test
    fun `upsertScimUser matches by external_id first, even if principal or email changed at the IdP`() {
        val v1 = store.upsertScimUser(externalId = "ext-99", principal = "old-name@example.com", email = "old@example.com", displayName = "Old", active = true)
        val v2 = store.upsertScimUser(externalId = "ext-99", principal = "new-name@example.com", email = "new@example.com", displayName = "New", active = true)
        assertEquals(v1.id, v2.id)
        assertEquals("new-name@example.com", v2.principal)
        assertEquals("new@example.com", v2.email)
    }

    @Test
    fun `a SCIM rename retires the old principal string so it cannot keep authenticating`() {
        val v1 = store.upsertScimUser(externalId = "ext-rename", principal = "old-scim@example.com", email = "old-scim@example.com", displayName = "Old", active = true)
        assertFalse(store.isDeactivated("old-scim@example.com"))

        // The IdP renames the userName on the SAME identity (matched by external_id) — a supported
        // in-place rename (see the test above). Everything that authenticates/authorizes is keyed on
        // the principal STRING and every chokepoint gates on isDeactivated(principal), so the orphaned
        // old string must be left deprovisioned, else a rename-with-deactivate lets the old identity's
        // still-live token/session/roles sail past isDeactivated(old)=false.
        val v2 = store.upsertScimUser(externalId = "ext-rename", principal = "new-scim@example.com", email = "new-scim@example.com", displayName = "New", active = true)
        assertEquals(v1.id, v2.id)
        assertEquals("new-scim@example.com", v2.principal)

        assertTrue(store.isDeactivated("old-scim@example.com"), "the renamed-away principal must be deprovisioned (tombstoned)")
        assertFalse(store.isDeactivated("new-scim@example.com"), "the current principal stays active")
    }

    @Test
    fun `a SCIM rename atomically revokes the old principal's active credentials — tokens, grants, and daemon session window`() {
        val role = policyStore.createRole(RoleInput("provision-merge-rename-role"))
        val oldPrincipal = "rename-atomic-old@example.com"
        val newPrincipal = "rename-atomic-new@example.com"
        store.upsertScimUser(
            externalId = "ext-atomic-rename", principal = oldPrincipal, email = "atomic-old@example.com",
            displayName = "Old", active = true,
        )

        val token = tokenStore.issue(TokenKind.SESSION, oldPrincipal, emptyList(), name = null, ttlSeconds = 3600)
        val req = accessStore.createRequest(oldPrincipal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")
        daemonSessionStore.create(oldPrincipal, "dvc_atomic_rename", null, windowSeconds = 3600, ttlSeconds = 900)
        val webId = daemonSessionStore.mintWeb(oldPrincipal, null, 3600, 900, "atomic-rename-web")
        assertTrue(daemonSessionStore.withinWindow(oldPrincipal), "sanity: the old principal's daemon session is in-window before the rename")

        // The rename (matched by external_id, userName changes) goes through the stores-threaded
        // overload — the ONLY code path that atomically tears down the old principal's credentials.
        val renamed = store.upsertScimUser(
            externalId = "ext-atomic-rename", principal = newPrincipal, email = "atomic-new@example.com",
            displayName = "New", active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertEquals(newPrincipal, renamed.principal)

        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the old principal's token must be revoked by the atomic rename teardown")
        assertEquals(0, accessStore.listGrants(oldPrincipal, activeOnly = true).size, "the old principal's grant must be revoked")
        assertFalse(daemonSessionStore.withinWindow(oldPrincipal), "the old principal's daemon session window must be closed")
        assertNull(daemonSessionStore.resolveWeb(webId, "atomic-rename-web"))
        assertEquals(ENDED_DEACTIVATED, daemonSessionStore.webEndedReason(webId))
        assertTrue(store.isDeactivated(oldPrincipal), "the old principal remains tombstoned")
        assertFalse(store.isDeactivated(newPrincipal), "the renamed-to principal stays active")
    }

    @Test
    fun `the public 5-arg upsertScimUser rename revokes the old principal credentials`() {
        // Every other rename or deactivate test above drives the stores-threaded overload directly.
        // This test proves the public convenience overload delegates to the same atomic teardown path.
        val oldPrincipal = "rename-5arg-old@example.com"
        val newPrincipal = "rename-5arg-new@example.com"
        store.upsertScimUser(externalId = "ext-5arg-rename", principal = oldPrincipal, email = "old-5arg@example.com", displayName = "Old", active = true)

        val token = tokenStore.issue(TokenKind.SESSION, oldPrincipal, emptyList(), name = null, ttlSeconds = 3600)
        val role = policyStore.createRole(RoleInput("provision-merge-5arg-rename-role"))
        val req = accessStore.createRequest(oldPrincipal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")
        daemonSessionStore.create(oldPrincipal, "dvc_5arg_rename", null, windowSeconds = 3600, ttlSeconds = 900)
        val webId = daemonSessionStore.mintWeb(oldPrincipal, null, 3600, 900, "five-arg-rename-web")
        assertTrue(daemonSessionStore.withinWindow(oldPrincipal), "sanity: the old principal's daemon session is in-window before the rename")

        val renamed = store.upsertScimUser(externalId = "ext-5arg-rename", principal = newPrincipal, email = "new-5arg@example.com", displayName = "New", active = true)
        assertEquals(newPrincipal, renamed.principal)

        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the 5-arg overload's rename must still revoke the old principal's token")
        assertEquals(0, accessStore.listGrants(oldPrincipal, activeOnly = true).size, "the 5-arg overload's rename must still revoke the old principal's grant")
        assertFalse(daemonSessionStore.withinWindow(oldPrincipal), "the 5-arg overload's rename must still close the old principal's daemon session window")
        assertNull(daemonSessionStore.resolveWeb(webId, "five-arg-rename-web"))
        assertEquals(ENDED_DEACTIVATED, daemonSessionStore.webEndedReason(webId))
        assertTrue(store.isDeactivated(oldPrincipal), "the old principal remains tombstoned")
    }

    @Test
    fun `upsertScimUser active=false atomically revokes the principal credentials`() {
        val principal = "scim-deactivate-atomic@example.com"
        store.upsertScimUser(externalId = "ext-deact", principal = principal, email = "deact@example.com", displayName = "D", active = true)
        val token = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        val role = policyStore.createRole(RoleInput("scim-deactivate-atomic-role"))
        val req = accessStore.createRequest(principal, AccessRequestInput(roleId = role.id))
        accessStore.approve(req.id, durationSec = 3600, decidedBy = "approver@example.com")
        daemonSessionStore.create(principal, "dvc_scim_deact", null, windowSeconds = 3600, ttlSeconds = 900)
        val webId = daemonSessionStore.mintWeb(principal, null, 3600, 900, "scim-deactivate-web")
        assertTrue(daemonSessionStore.withinWindow(principal), "sanity: in-window before the deactivate")

        // The stores-threaded overload revokes in the same committed transaction as the app_user
        // active=false write, so a crash cannot leave an inactive principal with live credentials.
        val deactivated = store.upsertScimUser(
            externalId = "ext-deact", principal = principal, email = "deact@example.com", displayName = "D", active = false,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertFalse(deactivated.active)
        assertTrue(store.isDeactivated(principal))
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "deactivate must revoke the token")
        assertEquals(0, accessStore.listGrants(principal, activeOnly = true).size, "deactivate must revoke the grant")
        assertFalse(daemonSessionStore.withinWindow(principal), "deactivate must close the daemon session window")
        assertNull(daemonSessionStore.resolveWeb(webId, "scim-deactivate-web"))
        assertEquals(ENDED_DEACTIVATED, daemonSessionStore.webEndedReason(webId))
    }

    @Test
    fun `setActiveById deactivates and revokes atomically by id (SCIM PATCH SetActive false, and DELETE)`() {
        val principal = "scim-patch-delete@example.com"
        val user = store.upsertScimUser(externalId = "ext-patchdel", principal = principal, email = null, displayName = null, active = true)
        val token = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        daemonSessionStore.create(principal, "dvc_patchdel", null, windowSeconds = 3600, ttlSeconds = 900)
        val webId = daemonSessionStore.mintWeb(principal, null, 3600, 900, "patch-delete-web")
        assertTrue(daemonSessionStore.withinWindow(principal))

        val updated = store.setActiveById(user.id, false, tokenStore, accessStore, daemonSessionStore)

        assertEquals(false, updated?.active)
        assertTrue(store.isDeactivated(principal))
        assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the token must be revoked")
        assertFalse(daemonSessionStore.withinWindow(principal), "the daemon session window must be closed")
        assertNull(daemonSessionStore.resolveWeb(webId, "patch-delete-web"))
        assertEquals(ENDED_DEACTIVATED, daemonSessionStore.webEndedReason(webId))
    }

    @Test
    fun `setActiveById re-reads the current principal under the lock — deactivates the row's real identity, not a stale snapshot (SCIM PATCH-DELETE)`() {
        // A SCIM PATCH active=false / DELETE addresses a row BY ID. externalId Z starts as `old` (active);
        // a `mid` identity ALSO already holds a live token. A concurrent holder has the advisory lock AND
        // has renamed the row old -> mid (uncommitted), so setActiveById reads `old` as its snapshot then
        // blocks on the same lock. Once it acquires the lock it must RE-READ the row (now `mid`) and
        // deactivate+revoke THAT — not the stale `old` the route first saw — else mid's token stays live.
        // This is exactly the stale-route-snapshot class the SCIM PATCH/DELETE paths must not expose.
        val extId = "ext-setactive-reread"
        val row = store.upsertScimUser(externalId = extId, principal = "sa-old@example.com", email = null, displayName = null, active = true)
        val midToken = tokenStore.issue(TokenKind.SESSION, "sa-mid@example.com", emptyList(), name = null, ttlSeconds = 3600)

        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, "sa-old@example.com"); ps.executeQuery().use { it.next() }
        }
        holder.prepareStatement("UPDATE app_user SET principal = 'sa-mid@example.com' WHERE id = ?").use { ps ->
            ps.setLong(1, row.id); ps.executeUpdate()
        }
        try {
            runBlocking {
                coroutineScope {
                    val deferred = async(Dispatchers.IO) {
                        store.setActiveById(row.id, false, tokenStore, accessStore, daemonSessionStore)
                    }
                    delay(300)
                    assertFalse(deferred.isCompleted, "setActiveById must block behind the held advisory lock")

                    holder.commit() // row is now `mid`; lock released

                    val updated = withTimeout(5_000) { deferred.await() }
                    assertEquals("sa-mid@example.com", updated?.principal)
                    assertNotNull(
                        tokenStore.get(midToken.id)!!.revokedAt,
                        "the RE-READ current principal (mid) must be revoked, not the stale pre-lock snapshot (old)",
                    )
                    assertTrue(store.isDeactivated("sa-mid@example.com"), "mid (the row's real identity) must be deactivated")
                }
            }
        } finally {
            holder.close()
        }
    }

    @Test
    fun `a blocked rename retires the principal carried by the row after lock release`() {
        // externalId X starts as `old`; a `mid` identity holds a live token. A rename X -> `new` starts
        // while a concurrent holder has the advisory lock AND has already renamed the row old -> mid
        // (uncommitted, so the starting rename reads `old` as its snapshot, then blocks acquiring the same
        // lock). Once it acquires the lock it must RE-READ the row (now `mid`) and retire THAT, not the
        // stale `old` — otherwise mid's token stays live and isDeactivated(mid) remains false.
        val extId = "ext-reread-under-lock"
        store.upsertScimUser(externalId = extId, principal = "reread-old@example.com", email = null, displayName = null, active = true)
        val existingId = store.findUserByExternalId(extId)!!.id
        val midToken = tokenStore.issue(TokenKind.SESSION, "reread-mid@example.com", emptyList(), name = null, ttlSeconds = 3600)

        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, "reread-old@example.com"); ps.executeQuery().use { it.next() }
        }
        // A concurrent rename old -> mid, uncommitted: the blocked upsert reads `old` (committed) as its
        // snapshot, then blocks on the same advisory lock the holder holds.
        holder.prepareStatement("UPDATE app_user SET principal = 'reread-mid@example.com' WHERE id = ?").use { ps ->
            ps.setLong(1, existingId); ps.executeUpdate()
        }
        try {
            runBlocking {
                coroutineScope {
                    val renameDeferred = async(Dispatchers.IO) {
                        store.upsertScimUser(
                            externalId = extId, principal = "reread-new@example.com", email = null, displayName = null, active = true,
                            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
                        )
                    }
                    delay(300)
                    assertFalse(renameDeferred.isCompleted, "the rename must block behind the held advisory lock")

                    holder.commit() // row is now `mid`; lock released

                    val renamed = withTimeout(5_000) { renameDeferred.await() }
                    assertEquals("reread-new@example.com", renamed.principal)
                    assertNotNull(
                        tokenStore.get(midToken.id)!!.revokedAt,
                        "the RE-READ current principal (mid) must be retired, not the stale pre-lock snapshot (old)",
                    )
                    assertTrue(store.isDeactivated("reread-mid@example.com"), "mid must be tombstoned by the rename that observed it")
                }
            }
        } finally {
            holder.close()
        }
    }

    @Test
    fun `upsertScimGroup matches an existing group by external_id then by name`() {
        val g1 = store.upsertScimGroup(externalId = "gext-1", displayName = "eng-team")
        assertEquals("SCIM", g1.source)
        val g2 = store.upsertScimGroup(externalId = "gext-1", displayName = "eng-team-renamed")
        assertEquals(g1.id, g2.id)
        assertEquals("eng-team-renamed", g2.name)

        // A JIT-created group later claimed by SCIM (matched by name) is reconciled, not duplicated.
        val jitGroup = store.createGroup(AppGroupInput(name = "product-team"))
        val g3 = store.upsertScimGroup(externalId = "gext-2", displayName = "product-team")
        assertEquals(jitGroup.id, g3.id)
        assertEquals("SCIM", g3.source)
    }

    @Test
    fun `findUserByExternalId and findGroupByExternalId round-trip`() {
        val user = store.upsertScimUser(externalId = "find-me-user", principal = "find-me@example.com", email = null, displayName = null, active = true)
        val group = store.upsertScimGroup(externalId = "find-me-group", displayName = "findable-group")
        assertEquals(user.id, store.findUserByExternalId("find-me-user")?.id)
        assertEquals(group.id, store.findGroupByExternalId("find-me-group")?.id)
        assertNull(store.findUserByExternalId("no-such-external-id"))
        assertNull(store.findGroupByExternalId("no-such-external-id"))
    }

    @Test
    fun `setUserActive and isDeactivated`() {
        val principal = "toggle-active@example.com"
        store.provisionFromOidc(principal, null, emptyList())
        assertFalse(store.isDeactivated(principal))

        assertTrue(store.setUserActive(principal, false))
        assertTrue(store.isDeactivated(principal))

        assertTrue(store.setUserActive(principal, true))
        assertFalse(store.isDeactivated(principal))
    }

    @Test
    fun `isDeactivated is false for a principal with no app_user row at all`() {
        assertFalse(store.isDeactivated("no-directory-row@example.com"))
    }

    @Test
    fun `upsertScimUser matches by principal when external_id and email are both new`() {
        val existing = store.createUser(AppUserInput(principal = "local-admin-made@example.com", active = true), tokenStore, accessStore, daemonSessionStore)
        assertEquals("LOCAL", existing.source)
        val reconciled = store.upsertScimUser(
            externalId = "brand-new-ext", principal = "local-admin-made@example.com",
            email = "now-has-email@example.com", displayName = "Now SCIM", active = true,
        )
        assertEquals(existing.id, reconciled.id)
        assertEquals("SCIM", reconciled.source)
        assertNotNull(reconciled.externalId)
    }
}
