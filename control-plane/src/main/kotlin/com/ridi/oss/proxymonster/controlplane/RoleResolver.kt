package com.ridi.oss.proxymonster.controlplane

import javax.sql.DataSource

/**
 * Server-side role resolution (docs/authz-model.md, Layer 1 — identity, no Cedar). The ONLY
 * source of truth for "what roles does this principal have": direct `principal_role` assignments
 * ∪ group-derived roles ∪ active JIT grants — every source resolved here, server-side, from the
 * control-plane store. Callers (decideQuery et al.) MUST use [resolve] instead of trusting any
 * client- or session-asserted role list, so a caller cannot assert an arbitrary `baseRoles` and
 * have it honored verbatim.
 */
class RoleResolver(
    private val dataSource: DataSource,
    private val userGroupStore: UserGroupStore,
    private val accessStore: AccessStore,
) {
    /**
     * Every principal who could act at all: active directory users, plus anyone holding a role through a
     * direct assignment or an unexpired JIT grant. The union [hasActiveAssignee] tests as an EXISTS,
     * enumerated instead of counted.
     *
     * `app_user` alone is NOT the principal universe (V1__identity.sql): a principal string is free text and
     * a `principal_role`-only identity holds roles without ever having a directory row. A row that DOES exist
     * and is inactive is excluded, matching [UserGroupStore.isDeactivated] — deprovisioning wins over every
     * role source.
     *
     * Used by notification routing to enumerate candidates. It answers "who exists", never "who may do X" —
     * that stays a per-principal Cedar decision.
     */
    fun listActivePrincipals(): List<String> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT principal FROM app_user WHERE active
               UNION
               SELECT pr.principal
               FROM principal_role pr
               LEFT JOIN app_user u ON u.principal = pr.principal
               WHERE u.id IS NULL OR u.active
               UNION
               SELECT ag.principal
               FROM access_grant ag
               LEFT JOIN app_user u ON u.principal = ag.principal
               WHERE ag.revoked_at IS NULL
                 AND (ag.expires_at IS NULL OR ag.expires_at > now())
                 AND (u.id IS NULL OR u.active)
               ORDER BY 1""",
        ).use { ps ->
            ps.executeQuery().use { rs ->
                val out = ArrayList<String>()
                while (rs.next()) out += rs.getString(1)
                out
            }
        }
    }

    /** Role names this principal holds via a direct `principal_role` assignment. */
    fun directRoles(principal: String): List<String> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT r.name
               FROM principal_role pr
               JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL
               WHERE pr.principal = ?""",
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
     * The principal's full effective role set: direct `principal_role` ∪ group-derived roles ∪
     * active (non-expired, non-revoked) JIT grant roles. An unknown principal with none of the
     * three resolves to the empty set (fail-closed — no roles are invented).
     *
     * Deprovisioning short-circuits everything: if [UserGroupStore.isDeactivated] is true (an
     * `app_user` row exists AND is inactive — a SCIM `active=false` push, or a failed IdP liveness
     * recheck), this returns the empty set regardless of any direct `principal_role` assignment,
     * group membership, or JIT grant (docs/auth-model.md "Deprovisioning propagates two ways" —
     * fail-closed across ALL role sources). A principal with no `app_user` row at all (a purely
     * local `principal_role`-only identity, never synced into the directory) is unaffected — it
     * keeps its direct roles, since there's nothing to deactivate.
     */
    fun resolve(principal: String): Set<String> {
        if (userGroupStore.isDeactivated(principal)) return emptySet()
        return effectiveRoles(
            directRoles(principal),
            accessStore.listGrants(principal, activeOnly = true).map { it.roleName },
            userGroupStore.rolesForPrincipal(principal),
        )
    }

    /**
     * Whether at least one active principal can resolve [roleName] through the same complete union as
     * [resolve]: direct assignment, group membership, or an active JIT grant. A direct/JIT principal
     * without an app_user row counts (matching [UserGroupStore.isDeactivated]); an inactive directory
     * user does not. A group_role link with no active member deliberately does not count as an assignee.
     */
    fun hasActiveAssignee(roleName: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT
                   EXISTS (
                       SELECT 1
                       FROM principal_role pr
                       JOIN app_role r ON r.id = pr.role_id AND r.name = ? AND r.deleted_at IS NULL
                       LEFT JOIN app_user u ON u.principal = pr.principal
                       WHERE u.id IS NULL OR u.active
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM group_role gr
                       JOIN app_role r ON r.id = gr.role_id AND r.name = ? AND r.deleted_at IS NULL
                       JOIN app_group g ON g.id = gr.group_id AND g.deleted_at IS NULL
                       JOIN group_member gm ON gm.group_id = gr.group_id
                       JOIN app_user u ON u.id = gm.user_id AND u.active
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM access_grant ag
                       JOIN app_role r ON r.id = ag.role_id AND r.name = ? AND r.deleted_at IS NULL
                       LEFT JOIN app_user u ON u.principal = ag.principal
                       WHERE ag.revoked_at IS NULL
                         AND (ag.expires_at IS NULL OR ag.expires_at > now())
                         AND (u.id IS NULL OR u.active)
                   )""",
        ).use { ps ->
            ps.setString(1, roleName); ps.setString(2, roleName); ps.setString(3, roleName)
            ps.executeQuery().use { rs -> rs.next(); rs.getBoolean(1) }
        }
    }
}
