package com.ridi.oss.proxymonster.controlplane.authz

import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.auditActor
import com.ridi.oss.proxymonster.controlplane.idParam
import com.ridi.oss.proxymonster.controlplane.inTx
import com.ridi.oss.proxymonster.controlplane.management.CedarValidationManagementException
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.respondManagementError
import com.ridi.oss.proxymonster.controlplane.userSession
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.Serializable
import java.sql.ResultSet
import javax.sql.DataSource

// ---- DTOs — the wire contract for /api/policies (docs/authz-model.md) ---------------------

@Serializable
data class CedarPolicy(
    val id: Long,
    val origin: String,
    val systemKey: String? = null,
    val name: String,
    val cedarSrc: String,
    val enabled: Boolean,
    val updatedBy: String? = null,
    val updatedAt: String,
)

@Serializable
data class CedarPolicyInput(val name: String, val cedarSrc: String, val enabled: Boolean = true)

@Serializable
data class CedarValidateInput(val cedarSrc: String)

@Serializable
data class CedarValidateResult(val valid: Boolean, val errors: List<String> = emptyList())

/** The authz Cedar schema text, with the `context.tag::<name>` actions the stored policies derive —
 *  served to the policy editor so it can offer schema-aware linting/completion in the browser (the
 *  schema is the authz model, not secret). Changes as policies do. */
@Serializable
data class CedarSchemaResult(val schema: String)

/** Thrown by [CedarPolicyStore.create]/[CedarPolicyStore.update] when `cedarSrc` fails schema
 *  validation ([CedarSchema.validate]) — the route layer turns this into a 400 with [errors]. */
class InvalidCedarPolicyException(val errors: List<String>) : RuntimeException(errors.joinToString("; "))

class SystemPolicyImmutableException : RuntimeException("system policy is immutable")

class ReservedPolicyNameException : RuntimeException("policy names under 'system:' are reserved for migrations")

// ---- Store -------------------------------------------------------------------------------------

/**
 * CRUD over the `policy` table (V3__policy.sql) — the Cedar-source rows [CedarEngine] loads into
 * its PolicySet. Writes are gated on [CedarSchema.validate] so an invalid policy can never become
 * `enabled` (or exist at all): both create and update reject a schema-invalid `cedarSrc` before
 * touching the database.
 */
class CedarPolicyStore(internal val dataSource: DataSource) {
    // Bumped after every successful mutation (create/update/setEnabled/delete) — [CedarEngine] polls
    // this to know when its cached PolicySet is stale, instead of re-reading enabledSources() on
    // every isAuthorized() call. In-process only (not persisted): fine, since a fresh process always
    // starts with an empty cache anyway (cachedVersion = Long.MIN_VALUE) and rebuilds on first use.
    private val version = java.util.concurrent.atomic.AtomicLong(0)

    /** Monotonically increasing; changes exactly when a mutation below has committed. See [version]. */
    fun stateVersion(): Long = version.get()

    fun list(): List<CedarPolicy> = query(
        "SELECT id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at FROM policy WHERE deleted_at IS NULL ORDER BY id",
    ) { it.toPolicy() }

    fun get(id: Long): CedarPolicy? = dataSource.connection.use { get(id, it) }

    fun get(id: Long, c: java.sql.Connection): CedarPolicy? = c.prepareStatement(
        "SELECT id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at FROM policy WHERE id=? AND deleted_at IS NULL",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toPolicy() else null }
    }

    fun getByName(name: String): CedarPolicy? = dataSource.connection.use { getByName(name, it) }

    fun getByName(name: String, c: java.sql.Connection): CedarPolicy? = c.prepareStatement(
        "SELECT id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at FROM policy WHERE name=? AND deleted_at IS NULL",
    ).use { ps ->
        ps.setString(1, name)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toPolicy() else null }
    }

    /** Call only after the outer transaction containing a connection-aware mutation has committed. */
    fun markCommittedMutation() { version.incrementAndGet() }

    fun create(input: CedarPolicyInput, updatedBy: String?): CedarPolicy {
        val created = dataSource.inTx { c -> create(input, updatedBy, c) }
        markCommittedMutation()
        return created
    }

    fun create(input: CedarPolicyInput, updatedBy: String?, c: java.sql.Connection): CedarPolicy {
        if (input.name.startsWith("system:")) throw ReservedPolicyNameException()
        val errors = CedarSchema.validate(input.cedarSrc)
        if (errors.isNotEmpty()) throw InvalidCedarPolicyException(errors)
        val id = c.prepareStatement(
            "INSERT INTO policy (name, cedar_src, enabled, updated_by, origin) VALUES (?, ?, ?, ?, 'USER') RETURNING id",
        ).use { ps ->
            ps.setString(1, input.name); ps.setString(2, input.cedarSrc); ps.setBoolean(3, input.enabled); ps.setString(4, updatedBy)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        return get(id, c)!!
    }

    /**
     * Lock, classify, and mutate the same row in one transaction. The origin check lives here rather
     * than in the route so non-HTTP callers cannot rewrite migration-owned source, and a concurrent
     * transaction cannot swap the checked row between the guard and the update.
     */
    fun update(id: Long, input: CedarPolicyInput, updatedBy: String?): CedarPolicy? {
        val updated = dataSource.inTx { c -> update(id, input, updatedBy, c) } ?: return null
        markCommittedMutation()
        return updated
    }

    fun update(id: Long, input: CedarPolicyInput, updatedBy: String?, c: java.sql.Connection): CedarPolicy? {
        val origin = c.prepareStatement("SELECT origin FROM policy WHERE id=? AND deleted_at IS NULL FOR UPDATE").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString("origin") else null }
        } ?: return null
        if (origin == "SYSTEM") throw SystemPolicyImmutableException()
        if (input.name.startsWith("system:")) throw ReservedPolicyNameException()
        val errors = CedarSchema.validate(input.cedarSrc)
        if (errors.isNotEmpty()) throw InvalidCedarPolicyException(errors)
        c.prepareStatement(
            "UPDATE policy SET name=?, cedar_src=?, enabled=?, updated_by=?, updated_at=now() WHERE id=? AND deleted_at IS NULL",
        ).use { ps ->
            ps.setString(1, input.name); ps.setString(2, input.cedarSrc); ps.setBoolean(3, input.enabled)
            ps.setString(4, updatedBy); ps.setLong(5, id); ps.executeUpdate()
        }
        return get(id, c)
    }

    fun setEnabled(id: Long, enabled: Boolean, updatedBy: String?): CedarPolicy? {
        val updated = dataSource.inTx { c -> setEnabled(id, enabled, updatedBy, c) } ?: return null
        markCommittedMutation()
        return updated
    }

    fun setEnabled(id: Long, enabled: Boolean, updatedBy: String?, c: java.sql.Connection): CedarPolicy? {
        val existing = c.prepareStatement(
            "SELECT id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at FROM policy WHERE id=? AND deleted_at IS NULL FOR UPDATE",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toPolicy() else null }
        } ?: return null
        if (enabled) {
            val errors = CedarSchema.validate(existing.cedarSrc)
            if (errors.isNotEmpty()) throw InvalidCedarPolicyException(errors)
        }
        c.prepareStatement("UPDATE policy SET enabled=?, updated_by=?, updated_at=now() WHERE id=? AND deleted_at IS NULL").use { ps ->
            ps.setBoolean(1, enabled); ps.setString(2, updatedBy); ps.setLong(3, id); ps.executeUpdate()
        }
        return get(id, c)
    }

    /** See [update]: delete uses the same row-lock + origin guard on the mutation connection. */
    fun delete(id: Long): Boolean {
        val deleted = dataSource.inTx { c -> delete(id, c) }
        if (deleted) markCommittedMutation()
        return deleted
    }

    fun delete(id: Long, c: java.sql.Connection): Boolean {
        val origin = c.prepareStatement("SELECT origin FROM policy WHERE id=? AND deleted_at IS NULL FOR UPDATE").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString("origin") else null }
        } ?: return false
        if (origin == "SYSTEM") throw SystemPolicyImmutableException()
        // Soft delete: the row survives (name freed for reuse via the partial unique index), but it leaves
        // the evaluated policy set — enabledSources() filters it and the caller bumps the version.
        return c.prepareStatement("UPDATE policy SET deleted_at = now() WHERE id=? AND deleted_at IS NULL").use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }
    }

    /** `(id, cedar_src)` for every LIVE enabled row, in a stable order — the ONLY policy set [CedarEngine]
     *  evaluates. Filtering `deleted_at IS NULL` here is what makes a soft-deleted policy (permit OR forbid)
     *  stop applying: the delete bumps the version, the engine rebuilds its PolicySet, and the tombstone
     *  is gone from it. */
    fun enabledSources(): List<Pair<Long, String>> = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id, cedar_src FROM policy WHERE enabled = true AND deleted_at IS NULL ORDER BY id").use { ps ->
            ps.executeQuery().use { rs ->
                val out = ArrayList<Pair<Long, String>>()
                while (rs.next()) out += rs.getLong("id") to rs.getString("cedar_src")
                out
            }
        }
    }

    // ---- row mapper + tiny JDBC helpers (mirrors PolicyStore's idiom, Policies.kt) ----
    private fun ResultSet.toPolicy() = CedarPolicy(
        id = getLong("id"), origin = getString("origin"), systemKey = getString("system_key"), name = getString("name"),
        cedarSrc = getString("cedar_src"), enabled = getBoolean("enabled"), updatedBy = getString("updated_by"),
        updatedAt = getTimestamp("updated_at").toInstant().toString(),
    )
    private fun <T> query(sql: String, map: (ResultSet) -> T): List<T> = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> val o = ArrayList<T>(); while (rs.next()) o += map(rs); o } }
    }
    private fun insertReturningId(sql: String, bind: (java.sql.PreparedStatement) -> Unit): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> bind(ps); ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
    }
}

// ---- Routes — /api/policies ---------------------------------------------------------------------

/**
 * The Cedar policy admin API. Every route is gated via [requireAdmin]`(config, authz,
 * AuthzAction.ADMIN_POLICIES)` — this is itself part of what closes the "admin = any session" hole,
 * since editing policies is the most privileged surface in the whole authz boundary.
 */
fun Route.cedarPolicyRoutes(
    config: Config,
    authz: Authz,
    store: CedarPolicyStore,
    management: PolicyManagementService =
        PolicyManagementService(store, PolicyStore(store.dataSource), ManagementAuditRecorder(AuditStore(store.dataSource))),
) {
    get("/api/policies") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@get
        call.respond(management.listPolicies())
    }
    post("/api/policies") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val input = call.receive<CedarPolicyInput>()
        try {
            call.respond(
                HttpStatusCode.Created,
                management.createPolicy(input.name, input.cedarSrc, input.enabled, call.userSession()?.principal, call.auditActor(config)),
            )
        } catch (e: CedarValidationManagementException) {
            call.respond(HttpStatusCode.BadRequest, mapOf("errors" to e.errors))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/policies/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<CedarPolicyInput>()
        try {
            call.respond(management.updatePolicy(id, input, call.userSession()?.principal, call.auditActor(config)))
        } catch (e: CedarValidationManagementException) {
            call.respond(HttpStatusCode.BadRequest, mapOf("errors" to e.errors))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/policies/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deletePolicy(id, call.auditActor(config))
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    post("/api/policies/validate") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val input = call.receive<CedarValidateInput>()
        try {
            call.respond(management.validatePolicy(input.cedarSrc))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    get("/api/policies/schema") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@get
        call.respond(management.policySchema())
    }
    post("/api/policies/{id}/enable") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.setPolicyEnabled(id, true, call.userSession()?.principal, call.auditActor(config)))
        } catch (e: CedarValidationManagementException) {
            call.respond(HttpStatusCode.BadRequest, mapOf("errors" to e.errors))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    post("/api/policies/{id}/disable") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_POLICIES)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.setPolicyEnabled(id, false, call.userSession()?.principal, call.auditActor(config)))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
}
