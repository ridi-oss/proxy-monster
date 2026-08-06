package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.Serializable
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.SQLException
import javax.sql.DataSource

// ---- DTOs — the wire contract for /api/users** + /api/groups** ---------------------------

@Serializable data class GroupRef(val id: Long, val name: String)

@Serializable
data class AppUser(
    val id: Long,
    val principal: String,
    val displayName: String? = null,
    val email: String? = null,
    val source: String,
    val externalId: String? = null,
    val active: Boolean,
    val createdAt: String,
    val groups: List<GroupRef> = emptyList(),
)

@Serializable
data class AppUserInput(
    val principal: String,
    val displayName: String? = null,
    val email: String? = null,
    val active: Boolean = true,
)

@Serializable
data class AppGroup(
    val id: Long,
    val name: String,
    val description: String? = null,
    val source: String,
    val externalId: String? = null,
    val memberCount: Int = 0,
    val roles: List<GroupRef> = emptyList(),
)

@Serializable data class AppGroupInput(val name: String, val description: String? = null)
@Serializable data class GroupMemberEntry(val userId: Long, val principal: String, val displayName: String? = null)
@Serializable data class GroupMemberInput(val userId: Long)
@Serializable data class GroupRoleEntry(val roleId: Long, val roleName: String)
@Serializable data class GroupRoleInput(val roleId: Long)

// ---- Store -------------------------------------------------------------------------------

/**
 * Thrown by [UserGroupStore.upsertScimGroup] when a SCIM POST would land on a SYSTEM-owned group
 * (e.g. the seeded `system:admin`). Raised INSIDE the resolve/check/mutate transaction so the check is
 * atomic with the write; the SCIM route catches it and returns a 409 `mutability` error.
 */
class SystemGroupImmutableException : RuntimeException("system-managed group is immutable")

class UserGroupStore(internal val dataSource: DataSource) {
    fun listUsers(): List<AppUser> {
        val groupsByUser = userGroups(null)
        return query("SELECT id, principal, display_name, email, source, external_id, active, created_at FROM app_user ORDER BY principal") {
            it.toUser(groupsByUser[it.getLong("id")].orEmpty())
        }
    }

    fun getUser(id: Long): AppUser? = dataSource.connection.use { getUser(id, it) }

    fun getUser(id: Long, c: Connection): AppUser? {
        val groups = userGroups(id, c)[id].orEmpty()
        return c.prepareStatement(
            "SELECT id, principal, display_name, email, source, external_id, active, created_at FROM app_user WHERE id=?",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toUser(groups) else null }
        }
    }

    fun getUserByPrincipal(principal: String): AppUser? = dataSource.connection.use { getUserByPrincipal(principal, it) }

    fun getUserByPrincipal(principal: String, c: Connection): AppUser? {
        val id = c.prepareStatement("SELECT id FROM app_user WHERE principal=?").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        } ?: return null
        return getUser(id, c)
    }

    /**
     * Create a NEW app_user row. Locked + tombstone-releasing like every other principal-mutating
     * write here — a stale [deactivatePrincipalTombstone] artifact must not permanently block
     * re-creating that principal (same fix as the rename paths). Creating a user with
     * `active=false` ALSO revokes any credentials that principal already holds: a
     * principal can accumulate a live wire token / daemon session BEFORE any app_user row exists for
     * it at all ([isDeactivated] is false with no row — see its kdoc), so deliberately creating it
     * inactive must not leave those pre-existing credentials usable.
     */
    fun createUser(
        input: AppUserInput,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
    ): AppUser {
        val id = dataSource.inTx { c -> createUser(input, tokenStore, accessStore, daemonSessionStore, c).id }
        return getUser(id)!!
    }

    fun createUser(
        input: AppUserInput,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): AppUser {
        releaseTombstone(c, input.principal, null)
        val id = c.prepareStatement(
            "INSERT INTO app_user (principal, display_name, email, active) VALUES (?, ?, ?, ?) RETURNING id",
        ).use { ps ->
            ps.setString(1, input.principal); ps.setString(2, input.displayName); ps.setString(3, input.email); ps.setBoolean(4, input.active)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        if (!input.active) revokeActiveCredentialsTx(input.principal, c, tokenStore, accessStore, daemonSessionStore)
        return getUser(id, c)!!
    }

    /**
     * Update an app_user row's fields. A principal RENAME retires the old principal string the same
     * way [upsertScimUser]'s rename path does: the app_user UPDATE, the old-principal
     * tombstone, and the old-principal credential revoke commit as ONE transaction under the
     * per-principal advisory lock, so this local-admin surface can't leave the pre-rename identity's
     * token/grant/daemon-session live. The retired principal is RE-READ under the lock, so it's the one
     * the row actually carries now, not a stale pre-lock snapshot. A deactivation
     * (`active=false`) revokes the TARGET principal's credentials in that SAME transaction too, and
     * INDEPENDENTLY of the rename branch — so a rename-and-deactivate onto a
     * principal that already holds credentials retires BOTH the old and the new string. Null if no such user.
     */
    fun updateUser(
        id: Long,
        input: AppUserInput,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
    ): AppUser? {
        if (getUser(id) == null) return null
        dataSource.inTx { c -> updateUser(id, input, tokenStore, accessStore, daemonSessionStore, c) }
        return getUser(id)
    }

    fun updateUser(
        id: Long,
        input: AppUserInput,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): AppUser? {
        if (getUser(id, c) == null) return null
        val current = lockCurrentPrincipal(c, id)
        releaseTombstone(c, input.principal, id)
        updateAppUserRow(c, id, input.principal, input.displayName, input.email, input.active)
        if (current != null && current != input.principal) {
            deactivatePrincipalTombstone(current, c)
            revokeActiveCredentialsTx(current, c, tokenStore, accessStore, daemonSessionStore)
        }
        if (!input.active) revokeActiveCredentialsTx(input.principal, c, tokenStore, accessStore, daemonSessionStore)
        return getUser(id, c)
    }

    /**
     * Deprovision (never hard-delete) an app_user row — mirrors SCIM DELETE (Scim.kt): tombstone
     * (active=false) + revoke active credentials commit as ONE transaction under the per-principal
     * advisory lock, so this local-admin surface can't leave a live credential behind. A thin BY-ID
     * wrapper over [setActiveById] so local-admin DELETE and SCIM DELETE share ONE id-stable teardown
     * (the revoked principal is RE-READ under the lock). False (404 at the route) if no such user.
     */
    fun deleteUser(id: Long, tokenStore: TokenStore, accessStore: AccessStore, daemonSessionStore: PrincipalSessionStore): Boolean =
        setActiveById(id, active = false, tokenStore, accessStore, daemonSessionStore) != null

    fun deleteUser(
        id: Long,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): Boolean {
        if (getUser(id, c) == null) return false
        val current = lockCurrentPrincipal(c, id) ?: return false
        c.prepareStatement("UPDATE app_user SET active = FALSE WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeUpdate()
        }
        revokeActiveCredentialsTx(current, c, tokenStore, accessStore, daemonSessionStore)
        return true
    }

    /**
     * Flip a user's active flag addressed BY ID, re-reading the row's CURRENT principal UNDER the
     * per-principal advisory lock — so a SCIM `PATCH replace:active` / `DELETE` (or a
     * local-admin DELETE) that resolved the row moments earlier can't act on a principal a concurrent
     * rename has since changed. An `active=false` additionally revokes THAT re-read principal's active
     * credentials — tokens, JIT grants, daemon-session windows — in the SAME committed transaction,
     * never a separate follow-up a crash could skip. Returns the updated user (whose
     * `principal` is the string the row actually carries now), or null (404) if no such row. This is
     * the id-stable teardown the SCIM PATCH SetActive(false)/DELETE routes and [deleteUser] all share.
     */
    fun setActiveById(
        id: Long,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
    ): AppUser? = dataSource.inTx { c -> setActiveById(id, active, tokenStore, accessStore, daemonSessionStore, c) }

    fun setActiveById(
        id: Long,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): AppUser? {
        if (getUser(id, c) == null) return null
        val current = lockCurrentPrincipal(c, id)
        c.prepareStatement("UPDATE app_user SET active = ? WHERE id = ?").use { ps ->
            ps.setBoolean(1, active); ps.setLong(2, id); ps.executeUpdate()
        }
        if (!active && current != null) revokeActiveCredentialsTx(current, c, tokenStore, accessStore, daemonSessionStore)
        return getUser(id, c)
    }

    private fun updateAppUserRow(c: Connection, id: Long, principal: String, displayName: String?, email: String?, active: Boolean) {
        c.prepareStatement("UPDATE app_user SET principal=?, display_name=?, email=?, active=? WHERE id=?").use { ps ->
            ps.setString(1, principal); ps.setString(2, displayName); ps.setString(3, email); ps.setBoolean(4, active); ps.setLong(5, id)
            ps.executeUpdate()
        }
    }

    fun listGroups(): List<AppGroup> {
        val counts = memberCounts(null)
        val rolesByGroup = groupRoles(null)
        return query("SELECT id, name, description, source, external_id FROM app_group ORDER BY name") {
            it.toGroup(counts[it.getLong("id")] ?: 0, rolesByGroup[it.getLong("id")].orEmpty())
        }
    }

    fun getGroup(id: Long): AppGroup? = dataSource.connection.use { getGroup(id, it) }

    fun getGroup(id: Long, c: Connection): AppGroup? {
        val count = c.prepareStatement("SELECT COUNT(*) FROM group_member WHERE group_id=?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
        val roles = listGroupRoles(id, c).map { GroupRef(it.roleId, it.roleName) }
        return c.prepareStatement("SELECT id, name, description, source, external_id FROM app_group WHERE id=?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toGroup(count, roles) else null }
        }
    }

    fun getGroupByName(name: String): AppGroup? = dataSource.connection.use { getGroupByName(name, it) }

    fun getGroupByName(name: String, c: Connection): AppGroup? {
        val id = c.prepareStatement("SELECT id FROM app_group WHERE name=?").use { ps ->
            ps.setString(1, name); ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        } ?: return null
        return getGroup(id, c)
    }

    fun createGroup(input: AppGroupInput): AppGroup = dataSource.connection.use { createGroup(input, it) }

    fun createGroup(input: AppGroupInput, c: Connection): AppGroup {
        val id = c.prepareStatement("INSERT INTO app_group (name, description) VALUES (?, ?) RETURNING id").use { ps ->
            ps.setString(1, input.name); ps.setString(2, input.description)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        return getGroup(id, c)!!
    }

    fun updateGroup(id: Long, input: AppGroupInput): AppGroup? = dataSource.connection.use { updateGroup(id, input, it) }

    fun updateGroup(id: Long, input: AppGroupInput, c: Connection): AppGroup? {
        if (getGroup(id, c) == null) return null
        c.prepareStatement("UPDATE app_group SET name=?, description=? WHERE id=?").use { ps ->
            ps.setString(1, input.name); ps.setString(2, input.description); ps.setLong(3, id); ps.executeUpdate()
        }
        return getGroup(id, c)
    }

    fun deleteGroup(id: Long): Boolean = dataSource.connection.use { deleteGroup(id, it) }
    fun deleteGroup(id: Long, c: Connection): Boolean = c.prepareStatement("DELETE FROM app_group WHERE id=?").use { ps ->
        ps.setLong(1, id); ps.executeUpdate() > 0
    }

    /**
     * True if the group is SYSTEM-owned (e.g. the seeded `system:admin`). Such groups are immutable
     * through the API/SCIM (docs/backlog.md) — the routes reject mutation. The internal
     * OIDC-sync ([provisionFromOidc]) still manages membership by calling the store methods directly.
     */
    fun isSystemGroup(id: Long): Boolean = dataSource.connection.use { isSystemGroup(id, it) }

    fun isSystemGroup(id: Long, c: Connection): Boolean = c.prepareStatement(
        "SELECT source = 'SYSTEM' FROM app_group WHERE id = ?",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }
    }

    /**
     * True if a SYSTEM group already owns [name]. Guards the SCIM POST upsert, which matches an existing
     * group by name — without this, `POST /Groups {displayName:"system:admin"}` would flip the seeded
     * SYSTEM group to source=SCIM and defeat every other immutability guard.
     */
    fun isSystemGroupByName(name: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement("SELECT source = 'SYSTEM' FROM app_group WHERE name = ?").use { ps ->
            ps.setString(1, name)
            ps.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }
        }
    }

    // ---- OIDC JIT provisioning + SCIM reconciliation (docs/auth-model.md) -------------------

    /**
     * JIT-provision an `app_user` from a validated OIDC login (id_token `sub`/`email` + the
     * `groups` claim) and additively mirror `groups` into local group membership. Never removes a
     * membership (SCIM push is the only path that revokes `group_member` rows) and never clobbers
     * a `source=SCIM` user — SCIM is authoritative once it manages a principal.
     */
    /**
     * Upsert an OIDC-authenticated user and **sync** their group membership to the IdP group claim
     * (docs/backlog.md): [idpGroups] is resolved through [mapping] to the authoritative
     * pm-group set, then the user's membership is reconciled to exactly it — added where missing, REMOVED
     * where no longer claimed (so dropping someone from the IdP admin group revokes their `system:admin`
     * on their next login). OIDC is authoritative for an OIDC user's membership; a manual/SCIM group
     * assignment for that user is reconciled away (accepted for now — no membership-origin column yet;
     * see the backlog). The internal add/remove intentionally bypasses the route-level SYSTEM-group
     * immutability guard: membership of `system:admin` is system-managed here, not hand-edited.
     */
    fun provisionFromOidc(
        principal: String,
        email: String?,
        idpGroups: List<String>,
        mapping: OidcGroupMapping = OidcGroupMapping(emptyMap(), null),
    ): AppUser {
        val userId = com.ridi.oss.proxymonster.auth.OidcDirectoryProvisioner(dataSource)
            .provision(principal, email, idpGroups, mapping)
        return getUser(userId)!!
    }

    private fun groupIdsForUser(userId: Long): Set<Long> = dataSource.connection.use { c ->
        c.prepareStatement("SELECT group_id FROM group_member WHERE user_id = ?").use { ps ->
            ps.setLong(1, userId)
            ps.executeQuery().use { rs -> val s = HashSet<Long>(); while (rs.next()) s += rs.getLong(1); s }
        }
    }

    /**
     * Upsert a SCIM-pushed user. Matches an existing row by `external_id` → `email` → `principal`
     * (in that order) so a prior JIT (`source=OIDC`) row is reconciled to `source=SCIM` instead of
     * duplicated once the IdP starts managing the principal via SCIM.
     *
     * Convenience overload for callers that don't hold the 3 credential stores ([ProvisionMergeDbTest]
     * JIT-merge assertions, `ScimUsersDbTest`/`ScimGroupsDbTest`): it delegates to the stores-threaded
     * overload below, self-constructing the credential stores from this store's own [dataSource]
     * (a revoke needs only that DataSource — no crypto), so a rename/deactivate through THIS overload is
     * ALSO fully atomic and tears down the retired principal's credentials. No "half-safe" upsert path
     * tombstones without revoking.
     */
    fun upsertScimUser(externalId: String, principal: String, email: String?, displayName: String?, active: Boolean): AppUser =
        upsertScimUser(
            externalId, principal, email, displayName, active,
            TokenStore(dataSource), AccessStore(dataSource), PrincipalSessionStore(dataSource, null),
        )

    /**
     * Same match/upsert as [upsertScimUser], but every credential-affecting effect commits as ONE
     * transaction under the per-principal advisory lock, so a concurrent liveness sweep or renew can
     * never observe a half-torn-down identity:
     *  - a RENAME (the matched row's principal string is changing) does the app_user UPDATE + the
     *    old-principal tombstone + the old-principal credential revoke atomically. The
     *    retired principal is RE-READ under the lock, so it's the string the row actually carries now,
     *    not a stale pre-lock snapshot (two concurrent renames of one externalId must
     *    not leave the intermediate principal live).
     *  - an `active=false` push (a deactivate, incl. a full-resource POST/PUT that reconciles a user
     *    down to inactive) revokes the CURRENT principal's credentials in that SAME commit — not a
     *    separate follow-up transaction, which a crash or a failed
     *    revoke could skip, leaving a principal inactive-but-still-credentialed (a later reactivation
     *    would then resurrect the live token/renewal secret).
     */
    fun upsertScimUser(
        externalId: String,
        principal: String,
        email: String?,
        displayName: String?,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
    ): AppUser = dataSource.inTx { c ->
        upsertScimUser(externalId, principal, email, displayName, active, tokenStore, accessStore, daemonSessionStore, c)
    }

    fun upsertScimUser(
        externalId: String,
        principal: String,
        email: String?,
        displayName: String?,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): AppUser {
        val existingId = findUserIdByExternalId(externalId, c)
            ?: email?.let { findUserIdByEmail(it, c) }
            ?: userIdForPrincipal(principal, c)

        // Lock + RE-READ the row's current principal before mutating it.
        val current = existingId?.let { lockCurrentPrincipal(c, it) }
        releaseTombstone(c, principal, existingId)
        val rowId = if (existingId != null) {
            updateScimAppUserRow(c, existingId, principal, displayName, email, externalId, active)
            existingId
        } else {
            insertScimAppUserRow(c, principal, displayName, email, externalId, active)
        }
        if (current != null && current != principal) {
            // Rename: retire the orphaned old string — tombstone + revoke its credentials.
            deactivatePrincipalTombstone(current, c)
            revokeActiveCredentialsTx(current, c, tokenStore, accessStore, daemonSessionStore)
        }
        // Deactivate: revoke the current principal atomically with the app_user write.
        if (!active) revokeActiveCredentialsTx(principal, c, tokenStore, accessStore, daemonSessionStore)
        return getUser(rowId, c)!!
    }

    /**
     * SCIM PUT — replace the resource AT THIS id (RFC 7644 full-resource-replace semantics). Resolves
     * and mutates the row addressed by [id] directly — unlike [upsertScimUser] (used by POST), it
     * never re-discovers a DIFFERENT row by externalId/email/principal (a PUT whose body
     * fields happen to match some other existing row must not silently mutate THAT row instead of the
     * one at this URI — that's not a "replace", it's an accidental cross-resource write). Same atomic
     * teardown as [upsertScimUser]/[updateUser]: tombstone-release + old-principal revoke on rename,
     * target-principal revoke on `active=false`, all under the per-principal advisory lock, with the
     * retired principal RE-READ under the lock. Null (404 at the route) if no such row.
     */
    fun replaceScimUserById(
        id: Long,
        principal: String,
        email: String?,
        displayName: String?,
        externalId: String,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
    ): AppUser? = dataSource.inTx { c ->
        replaceScimUserById(id, principal, email, displayName, externalId, active, tokenStore, accessStore, daemonSessionStore, c)
    }

    fun replaceScimUserById(
        id: Long,
        principal: String,
        email: String?,
        displayName: String?,
        externalId: String,
        active: Boolean,
        tokenStore: TokenStore,
        accessStore: AccessStore,
        daemonSessionStore: PrincipalSessionStore,
        c: Connection,
    ): AppUser? {
        if (getUser(id, c) == null) return null
        val current = lockCurrentPrincipal(c, id)
        releaseTombstone(c, principal, id)
        updateScimAppUserRow(c, id, principal, displayName, email, externalId, active)
        if (current != null && current != principal) {
            deactivatePrincipalTombstone(current, c)
            revokeActiveCredentialsTx(current, c, tokenStore, accessStore, daemonSessionStore)
        }
        if (!active) revokeActiveCredentialsTx(principal, c, tokenStore, accessStore, daemonSessionStore)
        return getUser(id, c)
    }

    private fun updateScimAppUserRow(
        c: Connection,
        id: Long,
        principal: String,
        displayName: String?,
        email: String?,
        externalId: String,
        active: Boolean,
    ) {
        c.prepareStatement(
            """UPDATE app_user
               SET principal=?, display_name=?, email=?, source='SCIM', external_id=?, active=?
               WHERE id=?""",
        ).use { ps ->
            ps.setString(1, principal); ps.setString(2, displayName); ps.setString(3, email)
            ps.setString(4, externalId); ps.setBoolean(5, active); ps.setLong(6, id)
            ps.executeUpdate()
        }
    }

    /** Insert a new SCIM-sourced app_user row on the caller-supplied connection [c] (atomic SCIM insert-and-revoke). */
    private fun insertScimAppUserRow(c: Connection, principal: String, displayName: String?, email: String?, externalId: String, active: Boolean): Long =
        c.prepareStatement(
            """INSERT INTO app_user (principal, display_name, email, source, external_id, active)
               VALUES (?, ?, ?, 'SCIM', ?, ?) RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal); ps.setString(2, displayName); ps.setString(3, email)
            ps.setString(4, externalId); ps.setBoolean(5, active)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }

    /**
     * Upsert a SCIM-pushed group, matching an existing row by `external_id → name`. The resolve → system
     * check → mutate runs as ONE transaction against ONE resolved id: the external_id/name lookup, a
     * `FOR UPDATE` re-read of the resolved row's `source`, and the write of that SAME id all share the
     * transaction — never a separate guard that re-resolves independently.
     *
     * That atomicity is load-bearing, not stylistic. A route-level guard that resolved external_id→name
     * on its own connection and then let this method re-resolve on another was defeatable by a TOCTOU: a
     * concurrent `PUT /Groups/{id}` moving an external_id off an ordinary group BETWEEN the two
     * resolutions made the guard inspect the ordinary group (pass) while this method then re-resolved to
     * the seeded `system:admin` by name and flipped it to source=SCIM — conferring admin and defeating
     * every source-based guard. Resolving once and mutating exactly the row that was checked,
     * under a row lock, closes it. Throws [SystemGroupImmutableException] (→ SCIM 409) if the resolved row
     * is SYSTEM; the seeded system:admin always matches by name, so it can never be created or hijacked here.
     */
    fun upsertScimGroup(externalId: String, displayName: String): AppGroup =
        dataSource.inTx { c -> upsertScimGroup(externalId, displayName, c) }

    fun upsertScimGroup(externalId: String, displayName: String, c: Connection): AppGroup {
        val existingId = groupIdByExternalId(c, externalId) ?: groupIdByName(c, displayName)
        val id = if (existingId != null) {
            // Re-read the resolved row's source UNDER a row lock, then mutate that SAME id — check and
            // write target the one resolved row atomically, with no window for a concurrent re-point.
            if (lockGroupSource(c, existingId) == "SYSTEM") throw SystemGroupImmutableException()
            c.prepareStatement("UPDATE app_group SET name=?, source='SCIM', external_id=? WHERE id=?").use { ps ->
                ps.setString(1, displayName); ps.setString(2, externalId); ps.setLong(3, existingId); ps.executeUpdate()
            }
            existingId
        } else {
            c.prepareStatement("INSERT INTO app_group (name, source, external_id) VALUES (?, 'SCIM', ?) RETURNING id").use { ps ->
                ps.setString(1, displayName); ps.setString(2, externalId)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        return getGroup(id, c)!!
    }

    // Connection-scoped group resolders + a FOR UPDATE source read — used by [upsertScimGroup] so its
    // resolve/check/mutate share one transaction (the standalone [findGroupIdByExternalId]/[findGroupIdByName]
    // each open their own connection and must NOT be mixed into the atomic path).
    private fun groupIdByExternalId(c: Connection, externalId: String): Long? =
        c.prepareStatement("SELECT id FROM app_group WHERE external_id=?").use { ps ->
            ps.setString(1, externalId); ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    private fun groupIdByName(c: Connection, name: String): Long? =
        c.prepareStatement("SELECT id FROM app_group WHERE name=?").use { ps ->
            ps.setString(1, name); ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    private fun lockGroupSource(c: Connection, id: Long): String? =
        c.prepareStatement("SELECT source FROM app_group WHERE id=? FOR UPDATE").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }

    /**
     * SCIM PUT — replace the Group resource AT THIS id, never re-discovering a different row by
     * externalId/displayName the way [upsertScimGroup] (POST) does (the same
     * cross-resource-write class of bug [replaceScimUserById] closes for Users: a PUT body that
     * happens to match a DIFFERENT group's externalId/displayName must not silently mutate that
     * group's membership-backing `group_role` instead of the one at this URI). Null (404 at the
     * route) if no such row.
     */
    fun replaceScimGroupById(id: Long, externalId: String, displayName: String): AppGroup? =
        dataSource.inTx { c -> replaceScimGroupById(id, externalId, displayName, c) }

    fun replaceScimGroupById(id: Long, externalId: String, displayName: String, c: Connection): AppGroup? {
        if (getGroup(id, c) == null) return null
        c.prepareStatement("UPDATE app_group SET name=?, source='SCIM', external_id=? WHERE id=?").use { ps ->
            ps.setString(1, displayName); ps.setString(2, externalId); ps.setLong(3, id); ps.executeUpdate()
        }
        return getGroup(id, c)
    }

    fun findUserByExternalId(id: String): AppUser? = findUserIdByExternalId(id)?.let { getUser(it) }
    fun findGroupByExternalId(id: String): AppGroup? = findGroupIdByExternalId(id)?.let { getGroup(it) }

    fun listMembers(groupId: Long): List<GroupMemberEntry> = dataSource.connection.use { listMembers(groupId, it) }
    fun listMembers(groupId: Long, c: Connection): List<GroupMemberEntry> = c.prepareStatement(
        """SELECT u.id AS user_id, u.principal, u.display_name
           FROM group_member gm JOIN app_user u ON u.id = gm.user_id
           WHERE gm.group_id = ? ORDER BY u.principal""",
    ).use { ps ->
        ps.setLong(1, groupId)
        ps.executeQuery().use { rs -> buildList {
            while (rs.next()) add(GroupMemberEntry(rs.getLong("user_id"), rs.getString("principal"), rs.getString("display_name")))
        } }
    }

    fun addMember(groupId: Long, userId: Long): Boolean = dataSource.connection.use { addMember(groupId, userId, it) }
    fun addMember(groupId: Long, userId: Long, c: Connection): Boolean = c.prepareStatement(
        "INSERT INTO group_member (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
    ).use { ps -> ps.setLong(1, groupId); ps.setLong(2, userId); ps.executeUpdate() > 0 }

    fun removeMember(groupId: Long, userId: Long): Boolean = dataSource.connection.use { removeMember(groupId, userId, it) }
    fun removeMember(groupId: Long, userId: Long, c: Connection): Boolean = c.prepareStatement(
        "DELETE FROM group_member WHERE group_id=? AND user_id=?",
    ).use { ps -> ps.setLong(1, groupId); ps.setLong(2, userId); ps.executeUpdate() > 0 }

    fun listGroupRoles(groupId: Long): List<GroupRoleEntry> = dataSource.connection.use { listGroupRoles(groupId, it) }
    fun listGroupRoles(groupId: Long, c: Connection): List<GroupRoleEntry> = c.prepareStatement(
        """SELECT r.id AS role_id, r.name AS role_name
           FROM group_role gr JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL
           WHERE gr.group_id = ? ORDER BY r.name""",
    ).use { ps ->
        ps.setLong(1, groupId)
        ps.executeQuery().use { rs -> buildList {
            while (rs.next()) add(GroupRoleEntry(rs.getLong("role_id"), rs.getString("role_name")))
        } }
    }

    fun addGroupRole(groupId: Long, roleId: Long): Boolean = dataSource.connection.use { addGroupRole(groupId, roleId, it) }
    fun addGroupRole(groupId: Long, roleId: Long, c: Connection): Boolean = c.prepareStatement(
        "INSERT INTO group_role (group_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
    ).use { ps -> ps.setLong(1, groupId); ps.setLong(2, roleId); ps.executeUpdate() > 0 }

    fun removeGroupRole(groupId: Long, roleId: Long): Boolean = dataSource.connection.use { removeGroupRole(groupId, roleId, it) }
    fun removeGroupRole(groupId: Long, roleId: Long, c: Connection): Boolean = c.prepareStatement(
        "DELETE FROM group_role WHERE group_id=? AND role_id=?",
    ).use { ps -> ps.setLong(1, groupId); ps.setLong(2, roleId); ps.executeUpdate() > 0 }

    /** Role names this principal gets via group membership. Empty if no (active) app_user row. */
    fun rolesForPrincipal(principal: String): List<String> =
        // INNER JOINs from app_user: an unknown or inactive principal yields zero rows (fail-closed).
        dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT DISTINCT r.name
                   FROM app_user u
                   JOIN group_member gm ON gm.user_id = u.id
                   JOIN group_role gr ON gr.group_id = gm.group_id
                   JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL
                   WHERE u.principal = ? AND u.active""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<String>()
                    while (rs.next()) out += rs.getString(1)
                    out
                }
            }
        }

    /**
     * Flip a user's active flag by principal (SCIM `active=true` reactivate, or a local admin action).
     * The credential-affecting DEACTIVATE paths (`active=false`) go through [setActiveById] instead, so
     * the teardown runs under the per-principal advisory lock addressed by the row's id.
     */
    fun setUserActive(principal: String, active: Boolean): Boolean = execUpdate(
        "UPDATE app_user SET active=? WHERE principal=?",
    ) { it.setBoolean(1, active); it.setString(2, principal) } > 0

    /**
     * True iff an `app_user` row exists for this principal AND it is inactive. A principal with NO
     * app_user row (pure `principal_role`/local-only identity) is NOT deactivated — this only
     * fires deprovisioning for principals the directory actually tracks (RoleResolver gate).
     */
    fun isDeactivated(principal: String): Boolean = dataSource.connection.use { c -> isDeactivated(principal, c) }

    /**
     * Same as [isDeactivated], read on the caller-supplied connection [c] so a locked renewal check
     * uses the transaction holding the per-principal advisory lock, rather than a separate connection
     * that could race a concurrent commit.
     */
    fun isDeactivated(principal: String, c: Connection): Boolean =
        c.prepareStatement("SELECT EXISTS(SELECT 1 FROM app_user WHERE principal=? AND NOT active)").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getBoolean(1) }
        }

    fun role(id: Long): GroupRoleEntry? = queryOne("SELECT id, name FROM app_role WHERE id=? AND deleted_at IS NULL", id) {
        GroupRoleEntry(it.getLong("id"), it.getString("name"))
    }
    fun roleExists(id: Long): Boolean = role(id) != null

    // ---- row mappers + tiny JDBC helpers ----
    private fun ResultSet.toUser(groups: List<GroupRef>) = AppUser(
        id = getLong("id"),
        principal = getString("principal"),
        displayName = getString("display_name"),
        email = getString("email"),
        source = getString("source"),
        externalId = getString("external_id"),
        active = getBoolean("active"),
        createdAt = getTimestamp("created_at").toInstant().toString(),
        groups = groups,
    )

    private fun ResultSet.toGroup(memberCount: Int, roles: List<GroupRef>) = AppGroup(
        id = getLong("id"),
        name = getString("name"),
        description = getString("description"),
        source = getString("source"),
        externalId = getString("external_id"),
        memberCount = memberCount,
        roles = roles,
    )

    private fun userGroups(userId: Long?): Map<Long, List<GroupRef>> = dataSource.connection.use { userGroups(userId, it) }

    private fun userGroups(userId: Long?, c: Connection): Map<Long, List<GroupRef>> {
        val sql = StringBuilder("SELECT gm.user_id, g.id, g.name FROM group_member gm JOIN app_group g ON g.id = gm.group_id")
        if (userId != null) sql.append(" WHERE gm.user_id = ?")
        sql.append(" ORDER BY g.name")
        return c.prepareStatement(sql.toString()).use { ps ->
            if (userId != null) ps.setLong(1, userId)
            ps.executeQuery().use { rs ->
                val out = linkedMapOf<Long, MutableList<GroupRef>>()
                while (rs.next()) out.getOrPut(rs.getLong("user_id")) { ArrayList() } += GroupRef(rs.getLong("id"), rs.getString("name"))
                out
            }
        }
    }

    private fun memberCounts(groupId: Long?): Map<Long, Int> = dataSource.connection.use { c ->
        val sql = StringBuilder("SELECT group_id, COUNT(*) AS member_count FROM group_member")
        if (groupId != null) sql.append(" WHERE group_id = ?")
        sql.append(" GROUP BY group_id")
        c.prepareStatement(sql.toString()).use { ps ->
            if (groupId != null) ps.setLong(1, groupId)
            ps.executeQuery().use { rs ->
                val out = linkedMapOf<Long, Int>()
                while (rs.next()) out[rs.getLong("group_id")] = rs.getInt("member_count")
                out
            }
        }
    }

    private fun groupRoles(groupId: Long?): Map<Long, List<GroupRef>> = dataSource.connection.use { c ->
        val sql = StringBuilder(
            """SELECT gr.group_id, r.id, r.name
               FROM group_role gr JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL""",
        )
        if (groupId != null) sql.append(" WHERE gr.group_id = ?")
        sql.append(" ORDER BY r.name")
        c.prepareStatement(sql.toString()).use { ps ->
            if (groupId != null) ps.setLong(1, groupId)
            ps.executeQuery().use { rs ->
                val out = linkedMapOf<Long, MutableList<GroupRef>>()
                while (rs.next()) out.getOrPut(rs.getLong("group_id")) { ArrayList() } += GroupRef(rs.getLong("id"), rs.getString("name"))
                out
            }
        }
    }

    private fun userIdForPrincipal(principal: String): Long? = dataSource.connection.use { userIdForPrincipal(principal, it) }
    private fun userIdForPrincipal(principal: String, c: Connection): Long? =
        c.prepareStatement("SELECT id FROM app_user WHERE principal=?").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }

    /** The principal string currently on this app_user row, read on the caller-supplied connection [c] (locked re-read). */
    private fun principalForUserId(id: Long, c: Connection): String? =
        c.prepareStatement("SELECT principal FROM app_user WHERE id=?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }

    /**
     * Take the per-principal advisory lock on the row's principal and return that principal RE-READ
     * under the lock — GUARANTEED to be the string [c] actually holds the lock for
     * (the single-shot version of this could lock a stale snapshot, then re-read a DIFFERENT,
     * unlocked value if a concurrent rename committed in between, and return THAT unlocked). Loops:
     * lock the last-seen value, re-read, and if the row moved on, lock the NEW value too (harmless —
     * re-entrant, and every lock taken here is released together at commit) and re-check. Converges
     * because each iteration either returns or observes a value it hasn't tried yet, and only a
     * bounded number of concurrent renames can interleave with this transaction. Null if the row
     * doesn't exist (defensive — every caller already confirmed it does moments earlier).
     */
    private fun lockCurrentPrincipal(c: Connection, id: Long): String? {
        var seen = principalForUserId(id, c) ?: return null
        while (true) {
            c.advisoryLockPrincipal(seen)
            val current = principalForUserId(id, c) ?: return null
            if (current == seen) return current
            seen = current
        }
    }

    /**
     * Leave [principal] deprovisioned in the directory — an inactive `source=SCIM` app_user row — so
     * isDeactivated([principal]) is true and every enforcement chokepoint fails it closed, composed onto
     * the caller-supplied connection [c] so it commits atomically with the rename teardown.
     * Used to retire a principal string a SCIM/local-admin rename orphaned. external_id is left
     * NULL so this tombstone never collides with the renamed row's external_id (and NULLs don't collide
     * with each other under the unique index); ON CONFLICT re-inactivates an existing row if the string
     * is later re-created.
     */
    private fun deactivatePrincipalTombstone(principal: String, c: Connection) {
        c.prepareStatement(
            """INSERT INTO app_user (principal, source, active) VALUES (?, 'SCIM', FALSE)
               ON CONFLICT (principal) DO UPDATE SET active = FALSE""",
        ).use { ps -> ps.setString(1, principal); ps.executeUpdate() }
    }

    /**
     * Free up [principal] for reuse by a genuinely new/renamed-back identity: a tombstone left by
     * [deactivatePrincipalTombstone] otherwise squats `principal` (globally UNIQUE) forever, so
     * renaming a different identity onto that same string — or the retired string legitimately coming
     * back into use — would 500 on a unique-constraint violation. Locks [principal] first, so this
     * can't race a concurrent writer reusing the same retired string. Deliberately narrow: matches
     * ONLY the exact shape [deactivatePrincipalTombstone] creates (`source='SCIM' AND external_id IS
     * NULL AND NOT active`), so a genuinely distinct inactive identity — a real SCIM user with its own
     * `external_id`, or a local admin's deliberately-deactivated user — is NEVER silently deleted, only
     * our own synthetic teardown artifact is. [excludeId], when given, additionally guards against ever
     * deleting the very row a caller is about to update.
     *
     * Also purges any `principal_role` direct grant left over for [principal]:
     * revoking wire tokens/JIT grants/daemon sessions on deprovision does NOT touch `principal_role` —
     * it's keyed purely on the principal STRING, independent of `app_user` entirely (V6's own comment:
     * "NOT an FK target for them"). While the string stays tombstoned that's harmless
     * (`RoleResolver.resolve` short-circuits to empty for a deactivated principal regardless), but the
     * MOMENT this string is handed to a genuinely different identity and goes active again, a stale
     * direct grant would silently reattach to whoever claims it — privilege escalation via principal
     * recycling. Checked and purged BEFORE the [excludeId] filter, deliberately: `upsertScimUser`'s
     * fallback principal-match can resolve `existingId` onto the tombstone row ITSELF (reusing that
     * exact id rather than inserting a fresh one), in which case the app_user DELETE below is
     * correctly excluded (there's no separate row to remove) but the STRING is still being handed to
     * a new identity (a different `externalId`) and the stale grant must still go.
     */
    private fun releaseTombstone(c: Connection, principal: String, excludeId: Long?) {
        c.advisoryLockPrincipal(principal)
        val isTombstone = c.prepareStatement(
            "SELECT 1 FROM app_user WHERE principal = ? AND source = 'SCIM' AND external_id IS NULL AND NOT active",
        ).use { ps -> ps.setString(1, principal); ps.executeQuery().use { it.next() } }
        if (!isTombstone) return

        c.prepareStatement("DELETE FROM principal_role WHERE principal = ?").use { ps ->
            ps.setString(1, principal); ps.executeUpdate()
        }
        val sql = buildString {
            append("DELETE FROM app_user WHERE principal = ? AND source = 'SCIM' AND external_id IS NULL AND NOT active")
            if (excludeId != null) append(" AND id <> ?")
        }
        c.prepareStatement(sql).use { ps ->
            ps.setString(1, principal)
            if (excludeId != null) ps.setLong(2, excludeId)
            ps.executeUpdate()
        }
    }

    private fun findUserIdByExternalId(externalId: String): Long? =
        dataSource.connection.use { findUserIdByExternalId(externalId, it) }
    private fun findUserIdByExternalId(externalId: String, c: Connection): Long? =
        c.prepareStatement("SELECT id FROM app_user WHERE external_id=?").use { ps ->
            ps.setString(1, externalId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }

    private fun findUserIdByEmail(email: String): Long? =
        dataSource.connection.use { findUserIdByEmail(email, it) }
    private fun findUserIdByEmail(email: String, c: Connection): Long? =
        c.prepareStatement("SELECT id FROM app_user WHERE email=?").use { ps ->
            ps.setString(1, email)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }

    private fun findGroupIdByExternalId(externalId: String): Long? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM app_group WHERE external_id=?").use { ps ->
            ps.setString(1, externalId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    }

    private fun findGroupIdByName(name: String): Long? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM app_group WHERE name=?").use { ps ->
            ps.setString(1, name)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    }

    /**
     * Ensure an `app_group` row exists for [name], reusing it (whatever its current source)
     * unmodified if present, else creating it with `source=OIDC`. Atomic upsert-returning-id via
     * `ON CONFLICT ... DO UPDATE SET name = EXCLUDED.name` (a no-op write) so RETURNING still fires
     * on a race with a concurrent JIT login, without ever touching an existing row's `source`.
     */
    private fun ensureGroupByName(name: String): Long = insertReturningId(
        """INSERT INTO app_group (name, source) VALUES (?, 'OIDC')
           ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
           RETURNING id""",
    ) { it.setString(1, name) }

    private fun <T> query(sql: String, map: (ResultSet) -> T): List<T> = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> val o = ArrayList<T>(); while (rs.next()) o += map(rs); o } }
    }
    private fun <T> queryOne(sql: String, id: Long, map: (ResultSet) -> T): T? = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.setLong(1, id); ps.executeQuery().use { rs -> if (rs.next()) map(rs) else null } }
    }
    private fun insertReturningId(sql: String, bind: (PreparedStatement) -> Unit): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> bind(ps); ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
    }
    private fun execUpdate(sql: String, bind: (PreparedStatement) -> Unit): Int =
        dataSource.connection.use { c -> c.prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() } }
}

// ---- Routes ------------------------------------------------------------------------------

internal fun SQLException.isUniqueViolation(): Boolean = sqlState == "23505"

fun Route.userGroupRoutes(
    config: Config,
    authz: Authz,
    store: UserGroupStore,
    tokenStore: TokenStore,
    accessStore: AccessStore,
    daemonSessionStore: PrincipalSessionStore,
    management: IdentityManagementService = IdentityManagementService(
        store.dataSource, store, PolicyStore(store.dataSource), tokenStore, accessStore, daemonSessionStore,
        ManagementAuditRecorder(AuditStore(store.dataSource)),
    ),
) {
    get("/api/users") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        call.respond(management.listUsers())
    }
    post("/api/users") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val input = call.receive<AppUserInput>()
        try {
            call.respond(HttpStatusCode.Created, management.createUser(input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    // A principal rename or an active-flip true->false here goes through the SAME atomic,
    // per-principal-locked teardown as a SCIM rename/deactivate — see
    // UserGroupStore.updateUser.
    put("/api/users/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<AppUserInput>()
        try {
            call.respond(management.updateUser(id, input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    // Deprovision, not hard-delete (mirrors SCIM DELETE) — tombstone + revoke active credentials
    // atomically.
    delete("/api/users/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deprovisionUser(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/groups") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        call.respond(management.listGroups())
    }
    post("/api/groups") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val input = call.receive<AppGroupInput>()
        try {
            call.respond(HttpStatusCode.Created, management.createGroup(input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/groups/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<AppGroupInput>()
        try {
            call.respond(management.updateGroup(id, input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/groups/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deleteGroup(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/groups/{id}/members") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        if (store.getGroup(id) == null) return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "group")))
        call.respond(store.listMembers(id))
    }
    post("/api/groups/{id}/members") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<GroupMemberInput>()
        try {
            call.respond(HttpStatusCode.Created, management.addGroupMember(id, input.userId, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/groups/{id}/members/{userId}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val userId = call.parameters["userId"]?.toLongOrNull() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            if (management.removeGroupMember(id, userId, call.auditActor(config)).deleted) call.respond(HttpStatusCode.NoContent)
            else call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "group member")))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/groups/{id}/roles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        if (store.getGroup(id) == null) return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "group")))
        call.respond(store.listGroupRoles(id))
    }
    post("/api/groups/{id}/roles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<GroupRoleInput>()
        try {
            call.respond(HttpStatusCode.Created, management.addGroupRole(id, input.roleId, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/groups/{id}/roles/{roleId}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val roleId = call.parameters["roleId"]?.toLongOrNull() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            if (management.removeGroupRole(id, roleId, call.auditActor(config)).deleted) call.respond(HttpStatusCode.NoContent)
            else call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "group role mapping")))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
}
