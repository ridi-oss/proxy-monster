package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
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
import java.sql.ResultSet
import javax.sql.DataSource

@Serializable data class Role(val id: Long, val name: String, val description: String? = null)
@Serializable data class RoleInput(val name: String, val description: String? = null)
@Serializable data class RoleAssignment(val id: Long, val principal: String, val roleId: Long, val roleName: String)
@Serializable data class RoleAssignmentInput(val principal: String, val roleId: Long)
@Serializable data class MaskFn(val id: Long, val name: String, val kind: String)
@Serializable data class MaskFnInput(val name: String, val kind: String)

class PolicyStore(internal val dataSource: DataSource) {

    fun listRoles(): List<Role> = dataSource.connection.use(::listRoles)
    fun listRoles(c: Connection): List<Role> = c.query("SELECT id, name, description FROM app_role WHERE deleted_at IS NULL ORDER BY name") { it.toRole() }
    fun getRole(id: Long): Role? = dataSource.connection.use { getRole(id, it) }
    fun getRole(id: Long, c: Connection): Role? = c.queryOne("SELECT id, name, description FROM app_role WHERE id=? AND deleted_at IS NULL", id) { it.toRole() }
    fun getRoleByName(name: String): Role? = dataSource.connection.use { getRoleByName(name, it) }
    fun getRoleByName(name: String, c: Connection): Role? = c.prepareStatement(
        "SELECT id, name, description FROM app_role WHERE name=? AND deleted_at IS NULL",
    ).use { ps -> ps.setString(1, name); ps.executeQuery().use { rs -> if (rs.next()) rs.toRole() else null } }

    /**
     * Of [names], the subset that names a LIVE role — for validating a task's frozen `execute_as` role
     * snapshot at execution/view time. A role soft-deleted after the snapshot was taken drops out here, so
     * the caller can fail closed rather than authorize a stored result under a role that no longer exists;
     * a name freed by a delete and reused resolves to its new live role, matching Cedar name semantics.
     */
    fun liveRoleNames(names: Collection<String>): Set<String> = dataSource.connection.use { liveRoleNames(names, it) }
    fun liveRoleNames(names: Collection<String>, c: Connection): Set<String> {
        if (names.isEmpty()) return emptySet()
        return c.prepareStatement("SELECT name FROM app_role WHERE name = ANY(?) AND deleted_at IS NULL").use { ps ->
            ps.setArray(1, c.createArrayOf("text", names.toTypedArray()))
            ps.executeQuery().use { rs -> buildSet { while (rs.next()) add(rs.getString(1)) } }
        }
    }
    fun createRole(input: RoleInput): Role = dataSource.connection.use { createRole(input, it) }
    fun createRole(input: RoleInput, c: Connection): Role {
        val id = c.insertReturningId("INSERT INTO app_role (name, description) VALUES (?, ?) RETURNING id") {
            it.setString(1, input.name); it.setString(2, input.description)
        }
        return getRole(id, c)!!
    }
    fun updateRole(id: Long, input: RoleInput): Role? = dataSource.connection.use { updateRole(id, input, it) }
    fun updateRole(id: Long, input: RoleInput, c: Connection): Role? {
        if (getRole(id, c) == null) return null
        c.exec("UPDATE app_role SET name=?, description=? WHERE id=? AND deleted_at IS NULL") {
            it.setString(1, input.name); it.setString(2, input.description); it.setLong(3, id)
        }
        return getRole(id, c)
    }
    fun deleteRole(id: Long): Boolean = dataSource.connection.use { deleteRole(id, it) }
    /** Soft delete: the row (and the access_request / access_grant history that references it) survives,
     *  while resolution and every live read exclude it and its name is freed for reuse. */
    fun deleteRole(id: Long, c: Connection): Boolean =
        c.execUpdate("UPDATE app_role SET deleted_at = now() WHERE id=? AND deleted_at IS NULL") { it.setLong(1, id) } > 0
    fun isSystemRole(id: Long): Boolean = dataSource.connection.use { isSystemRole(id, it) }
    fun isSystemRole(id: Long, c: Connection): Boolean = c.prepareStatement(
        """SELECT EXISTS(SELECT 1 FROM group_role gr JOIN app_group g ON g.id = gr.group_id
           WHERE gr.role_id = ? AND g.source = 'SYSTEM')""",
    ).use { ps -> ps.setLong(1, id); ps.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) } }

    fun listAssignments(principal: String?, roleId: Long?): List<RoleAssignment> =
        dataSource.connection.use { listAssignments(principal, roleId, it) }
    fun listAssignments(principal: String?, roleId: Long?, c: Connection): List<RoleAssignment> {
        val sql = StringBuilder(
            """SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
               FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE 1=1""",
        )
        if (principal != null) sql.append(" AND pr.principal = ?")
        if (roleId != null) sql.append(" AND pr.role_id = ?")
        sql.append(" ORDER BY pr.principal, r.name")
        return c.prepareStatement(sql.toString()).use { ps ->
            var index = 1
            if (principal != null) ps.setString(index++, principal)
            if (roleId != null) ps.setLong(index, roleId)
            ps.executeQuery().use { rs ->
                buildList {
                    while (rs.next()) add(RoleAssignment(rs.getLong("id"), rs.getString("principal"), rs.getLong("role_id"), rs.getString("role_name")))
                }
            }
        }
    }
    fun getAssignment(id: Long): RoleAssignment? = dataSource.connection.use { getAssignment(id, it) }
    fun getAssignment(id: Long, c: Connection): RoleAssignment? = c.prepareStatement(
        """SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
           FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE pr.id = ?""",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeQuery().use { rs ->
            if (rs.next()) RoleAssignment(rs.getLong("id"), rs.getString("principal"), rs.getLong("role_id"), rs.getString("role_name")) else null
        }
    }
    fun createAssignment(input: RoleAssignmentInput): RoleAssignment = dataSource.connection.use { createAssignment(input, it) }
    fun createAssignment(input: RoleAssignmentInput, c: Connection): RoleAssignment {
        val id = c.insertReturningId(
            "INSERT INTO principal_role (principal, role_id) VALUES (?, ?) ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal RETURNING id",
        ) { it.setString(1, input.principal); it.setLong(2, input.roleId) }
        return listAssignments(null, null, c).first { it.id == id }
    }
    fun deleteAssignment(id: Long): Boolean = dataSource.connection.use { deleteAssignment(id, it) }
    fun deleteAssignment(id: Long, c: Connection): Boolean = c.execUpdate("DELETE FROM principal_role WHERE id=?") { it.setLong(1, id) } > 0
    fun deleteAssignment(principal: String, roleId: Long, c: Connection): Boolean = c.execUpdate(
        "DELETE FROM principal_role WHERE principal=? AND role_id=?",
    ) { it.setString(1, principal); it.setLong(2, roleId) } > 0

    fun listMaskFns(): List<MaskFn> = dataSource.connection.use(::listMaskFns)
    fun listMaskFns(c: Connection): List<MaskFn> = c.query("SELECT id, name, kind FROM mask_fn WHERE deleted_at IS NULL ORDER BY name") { it.toMaskFn() }
    fun getMaskFn(id: Long): MaskFn? = dataSource.connection.use { getMaskFn(id, it) }
    fun getMaskFn(id: Long, c: Connection): MaskFn? = c.queryOne("SELECT id, name, kind FROM mask_fn WHERE id=? AND deleted_at IS NULL", id) { it.toMaskFn() }
    fun getMaskFnByName(name: String): MaskFn? = dataSource.connection.use { getMaskFnByName(name, it) }
    fun getMaskFnByName(name: String, c: Connection): MaskFn? = c.prepareStatement(
        "SELECT id, name, kind FROM mask_fn WHERE name=? AND deleted_at IS NULL",
    ).use { ps -> ps.setString(1, name); ps.executeQuery().use { rs -> if (rs.next()) rs.toMaskFn() else null } }
    fun createMaskFn(input: MaskFnInput): MaskFn = dataSource.connection.use { createMaskFn(input, it) }
    fun createMaskFn(input: MaskFnInput, c: Connection): MaskFn {
        val id = c.insertReturningId("INSERT INTO mask_fn (name, kind) VALUES (?, ?) RETURNING id") {
            it.setString(1, input.name); it.setString(2, input.kind)
        }
        return getMaskFn(id, c)!!
    }
    fun updateMaskFn(id: Long, input: MaskFnInput): MaskFn? = dataSource.connection.use { updateMaskFn(id, input, it) }
    fun updateMaskFn(id: Long, input: MaskFnInput, c: Connection): MaskFn? {
        if (getMaskFn(id, c) == null) return null
        c.exec("UPDATE mask_fn SET name=?, kind=? WHERE id=? AND deleted_at IS NULL") {
            it.setString(1, input.name); it.setString(2, input.kind); it.setLong(3, id)
        }
        return getMaskFn(id, c)
    }
    fun deleteMaskFn(id: Long): Boolean = dataSource.connection.use { deleteMaskFn(id, it) }
    /** Soft delete: a column classification still referencing this mask function falls back to FIXED
     *  masking (the column stays masked), and the name is freed for reuse. */
    fun deleteMaskFn(id: Long, c: Connection): Boolean =
        c.execUpdate("UPDATE mask_fn SET deleted_at = now() WHERE id=? AND deleted_at IS NULL") { it.setLong(1, id) } > 0

    private fun ResultSet.toRole() = Role(getLong("id"), getString("name"), getString("description"))
    private fun ResultSet.toMaskFn() = MaskFn(getLong("id"), getString("name"), getString("kind"))
    private fun <T> Connection.query(sql: String, map: (ResultSet) -> T): List<T> = prepareStatement(sql).use { ps ->
        ps.executeQuery().use { rs -> buildList { while (rs.next()) add(map(rs)) } }
    }
    private fun <T> Connection.queryOne(sql: String, id: Long, map: (ResultSet) -> T): T? = prepareStatement(sql).use { ps ->
        ps.setLong(1, id); ps.executeQuery().use { rs -> if (rs.next()) map(rs) else null }
    }
    private fun Connection.insertReturningId(sql: String, bind: (java.sql.PreparedStatement) -> Unit): Long =
        prepareStatement(sql).use { ps -> bind(ps); ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
    private fun Connection.exec(sql: String, bind: (java.sql.PreparedStatement) -> Unit) {
        prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() }
    }
    private fun Connection.execUpdate(sql: String, bind: (java.sql.PreparedStatement) -> Unit): Int =
        prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() }
}

fun Route.policyRoutes(
    config: Config,
    authz: Authz,
    store: PolicyStore,
    management: PolicyManagementService =
        PolicyManagementService(CedarPolicyStore(store.dataSource), store, ManagementAuditRecorder(AuditStore(store.dataSource))),
) {
    get("/api/roles") { call.requireApi() ?: return@get; call.respond(management.listRoles()) }
    post("/api/roles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val input = call.receive<RoleInput>()
        try {
            call.respond(HttpStatusCode.Created, management.createRole(input.name, input.description, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/roles/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<RoleInput>()
        try {
            call.respond(management.updateRole(id, input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/roles/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deleteRole(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/role-assignments") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@get
        val roleIdRaw = call.request.queryParameters["roleId"]
        val roleId = roleIdRaw?.toLongOrNull()
        if (roleIdRaw != null && roleId == null) return@get call.respond(emptyList<RoleAssignment>())
        call.respond(management.listAssignmentsByRoleId(call.request.queryParameters["principal"], roleId))
    }
    post("/api/role-assignments") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@post
        val input = call.receive<RoleAssignmentInput>()
        try {
            call.respond(HttpStatusCode.Created, management.assignRole(input.principal, input.roleId, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/role-assignments/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.unassignRole(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/mask-fns") { if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@get; call.respond(management.listMaskFns()) }
    post("/api/mask-fns") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val input = call.receive<MaskFnInput>()
        try {
            call.respond(HttpStatusCode.Created, management.createMaskFn(input, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/mask-fns/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.updateMaskFn(id, call.receive(), call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/mask-fns/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deleteMaskFn(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
}
