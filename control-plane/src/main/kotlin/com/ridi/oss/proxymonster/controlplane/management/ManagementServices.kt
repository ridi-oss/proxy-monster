package com.ridi.oss.proxymonster.controlplane.management

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.AppGroup
import com.ridi.oss.proxymonster.controlplane.AppGroupInput
import com.ridi.oss.proxymonster.controlplane.AppUser
import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.ClassificationInput
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.GroupMemberEntry
import com.ridi.oss.proxymonster.controlplane.GroupRoleEntry
import com.ridi.oss.proxymonster.controlplane.MaskFn
import com.ridi.oss.proxymonster.controlplane.MaskFnInput
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.ProxyEventsHub
import com.ridi.oss.proxymonster.controlplane.Role
import com.ridi.oss.proxymonster.controlplane.RoleAssignment
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.TableDetailExecException
import com.ridi.oss.proxymonster.controlplane.TableDetailService
import com.ridi.oss.proxymonster.controlplane.TokenStore
import com.ridi.oss.proxymonster.controlplane.UserGroupStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicy
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchemaResult
import com.ridi.oss.proxymonster.controlplane.authz.CedarValidateResult
import com.ridi.oss.proxymonster.controlplane.authz.InvalidCedarPolicyException
import com.ridi.oss.proxymonster.controlplane.authz.ReservedPolicyNameException
import com.ridi.oss.proxymonster.controlplane.authz.SystemPolicyImmutableException
import com.ridi.oss.proxymonster.controlplane.advisoryLockPrincipal
import com.ridi.oss.proxymonster.controlplane.inTx
import com.ridi.oss.proxymonster.probe.Classification
import com.ridi.oss.proxymonster.probe.TableDetail
import kotlinx.serialization.Serializable
import java.sql.Connection
import java.sql.SQLException
import javax.sql.DataSource

/** A transport-neutral management failure represented only by a stable API code and parameters. */
class ManagementException(val error: ApiError) : RuntimeException(error.code)

/** Cedar source validation deliberately preserves the validator's raw error array. */
class CedarValidationManagementException(val errors: List<String>) : RuntimeException("invalid Cedar policy")

@Serializable
data class DeleteResult(val deleted: Boolean)

@Serializable
data class DatasourceLiveness(
    val datasource: String,
    val attached: Boolean,
    val catalogSyncedAt: String?,
    val lastSeenAt: String?,
)

@Serializable
data class ColumnTagEntry(
    val datasource: String,
    val schema: String,
    val table: String,
    val column: String,
    val tags: List<String>,
    val maskFnName: String? = null,
)

@Serializable
data class ColumnClassificationBatch(
    val datasource: String,
    val columns: List<Classification>,
)

class DatasourceManagementService(
    private val store: DatasourceStore,
    private val eventsHub: ProxyEventsHub,
    private val tableDetailService: TableDetailService,
) {
    fun listDatasources(): List<Datasource> = store.list()

    fun getDatasource(name: String): Datasource = datasource(name)

    fun getDatasourceLiveness(name: String): DatasourceLiveness {
        val datasource = datasource(name)
        val attached = name in eventsHub.attached()
        return DatasourceLiveness(name, attached, datasource.catalogSyncedAt, datasource.lastSeenAt)
    }

    fun browseCatalog(name: String): List<CatalogColumn> {
        val datasource = datasource(name)
        return store.catalog(datasource.id)
    }

    suspend fun getTableDetail(name: String, schema: String, table: String): TableDetail {
        required("schema", schema)
        required("table", table)
        datasource(name)
        return try {
            tableDetailService.fetch(name, schema, table)
                ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "table")))
        } catch (e: TableDetailExecException) {
            throw ManagementException(ApiError("datasource.table_introspection_failed", mapOf("detail" to (e.message ?: ""))))
        }
    }

    fun listColumnTags(name: String): List<ColumnTagEntry> = browseCatalog(name).mapNotNull { column ->
        column.classification?.let { classification ->
            ColumnTagEntry(name, column.schema, column.table, column.column, classification.tags, classification.maskFnName)
        }
    }

    fun setColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
        tags: List<String>,
        maskFnId: Long?,
    ): Classification = store.dataSource.inTx { connection ->
        setColumnClassification(datasourceName, schema, table, column, tags, maskFnId, connection)
    }

    fun setColumnClassification(
        datasourceId: Long,
        schema: String?,
        table: String,
        column: String,
        tags: List<String>,
        maskFnId: Long?,
    ): Classification = store.dataSource.inTx { connection ->
        required("table", table)
        required("column", column)
        val datasource = store.get(datasourceId, connection) ?: notFound("datasource")
        if (schema == null && store.defaultSchema(datasource.id, connection) == null) {
            throw ManagementException(ApiError("datasource.schema_required"))
        }
        tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }?.let {
            throw ManagementException(ApiError("datasource.reserved_tag", mapOf("tag" to it)))
        }
        store.upsertClassification(datasource.id, ClassificationInput(schema, table, column, tags, maskFnId), connection)
    }

    fun setColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
        tags: List<String>,
        maskFnId: Long?,
        connection: Connection,
    ): Classification {
        required("table", table)
        required("column", column)
        val datasource = datasource(datasourceName, connection)
        if (schema == null && store.defaultSchema(datasource.id, connection) == null) {
            throw ManagementException(ApiError("datasource.schema_required"))
        }
        tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }?.let {
            throw ManagementException(ApiError("datasource.reserved_tag", mapOf("tag" to it)))
        }
        return store.upsertClassification(datasource.id, ClassificationInput(schema, table, column, tags, maskFnId), connection)
    }

    /**
     * Tag many columns of one datasource in the caller's transaction — all of them or none.
     *
     * Every entry is validated before the first write, so a rejected entry leaves the whole batch
     * unapplied rather than a prefix of it. Two entries resolving to the same column are rejected
     * rather than silently letting the later one win: the caller cannot tell from the response which
     * of its conflicting tag sets survived, and for a masking decision that is the difference between
     * a column being masked and not.
     */
    fun setColumnClassifications(
        datasourceName: String,
        columns: List<ClassificationInput>,
        connection: Connection,
    ): List<Classification> {
        if (columns.isEmpty()) throw ManagementException(ApiError("common.field_required", mapOf("fields" to "columns")))
        if (columns.size > MAX_CLASSIFICATION_BATCH) {
            throw ManagementException(
                ApiError("datasource.batch_too_large", mapOf("max" to MAX_CLASSIFICATION_BATCH.toString())),
            )
        }
        val datasource = datasource(datasourceName, connection)
        val defaultSchema = store.defaultSchema(datasource.id, connection)
        val seen = HashSet<Triple<String, String, String>>(columns.size)
        // Resolve every entry to the identity it will actually be written under, so the duplicate check
        // and the write agree — dedup on the submitted schema would let an explicit "public" and an
        // omitted one both through and silently apply whichever ran last.
        val resolved = columns.map { input ->
            required("table", input.table)
            required("column", input.column)
            val schema = input.schema?.takeIf(String::isNotBlank) ?: defaultSchema
                ?: throw ManagementException(ApiError("datasource.schema_required"))
            input.tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }?.let {
                throw ManagementException(ApiError("datasource.reserved_tag", mapOf("tag" to it)))
            }
            if (!seen.add(Triple(schema, input.table, input.column))) {
                throw ManagementException(
                    ApiError(
                        "datasource.duplicate_column",
                        mapOf("column" to "$schema.${input.table}.${input.column}"),
                    ),
                )
            }
            ClassificationInput(schema, input.table, input.column, input.tags, input.maskFnId)
        }
        // Written in a canonical order, not the caller's: each upsert row-locks its classification, so
        // two overlapping batches submitted in opposite orders would deadlock and one would die with an
        // internal error. A total order over the key means concurrent batches queue instead.
        return resolved.sortedWith(compareBy({ it.schema }, { it.table }, { it.column }))
            .map { input -> store.upsertClassification(datasource.id, input, connection) }
    }

    fun clearColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
    ): DeleteResult = store.dataSource.inTx { connection ->
        clearColumnClassification(datasourceName, schema, table, column, connection)
    }

    fun clearColumnClassification(
        datasourceId: Long,
        schema: String?,
        table: String,
        column: String,
    ): DeleteResult = store.dataSource.inTx { connection ->
        required("table", table)
        required("column", column)
        val datasource = store.get(datasourceId, connection) ?: notFound("datasource")
        val resolvedSchema = schema ?: store.defaultSchema(datasource.id, connection)
            ?: throw ManagementException(ApiError("datasource.schema_required"))
        DeleteResult(store.deleteClassification(datasource.id, resolvedSchema, table, column, connection))
    }

    fun clearColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
        connection: Connection,
    ): DeleteResult {
        required("table", table)
        required("column", column)
        val datasource = datasource(datasourceName, connection)
        val resolvedSchema = schema ?: store.defaultSchema(datasource.id, connection)
            ?: throw ManagementException(ApiError("datasource.schema_required"))
        return DeleteResult(store.deleteClassification(datasource.id, resolvedSchema, table, column, connection))
    }

    private fun datasource(name: String): Datasource = store.getByName(name)
        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "datasource")))

    private fun datasource(name: String, connection: Connection): Datasource = store.getByName(name, connection)
        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "datasource")))

    companion object {
        /**
         * A batch runs as one transaction holding a row lock per column plus the audit chain-head lock,
         * so its size bounds how long every other writer waits. Large enough for a whole table's columns
         * in one call, small enough that a runaway agent cannot stall the chain.
         */
        const val MAX_CLASSIFICATION_BATCH = 500
    }
}

class PolicyManagementService(
    private val policyStore: CedarPolicyStore,
    private val store: PolicyStore,
) {
    fun listPolicies(): List<CedarPolicy> = policyStore.list()

    fun getPolicy(name: String): CedarPolicy = policyStore.getByName(name)
        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "policy")))
    fun getPolicy(name: String, c: Connection): CedarPolicy = policyStore.getByName(name, c)
        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "policy")))

    fun validatePolicy(cedarSrc: String): CedarValidateResult {
        required("cedarSrc", cedarSrc)
        val errors = CedarSchema.validate(cedarSrc)
        return CedarValidateResult(errors.isEmpty(), errors)
    }

    fun policySchema(): CedarSchemaResult = CedarSchemaResult(CedarSchema.text)
    fun listRoles(): List<Role> = store.listRoles()
    fun getRole(name: String): Role = store.getRoleByName(name) ?: notFound("role")
    fun getRole(name: String, c: Connection): Role = store.getRoleByName(name, c) ?: notFound("role")

    fun listAssignments(principal: String?, roleName: String?): List<RoleAssignment> {
        val roleId = roleName?.let { name -> store.getRoleByName(name)?.id ?: notFound("role") }
        return store.listAssignments(principal, roleId)
    }

    fun listMaskFns(): List<MaskFn> = store.listMaskFns()
    fun getMaskFn(name: String): MaskFn = store.getMaskFnByName(name) ?: notFound("mask function")
    fun getMaskFn(name: String, c: Connection): MaskFn = store.getMaskFnByName(name, c) ?: notFound("mask function")

    fun createPolicy(name: String, cedarSrc: String, enabled: Boolean, principal: String?): CedarPolicy {
        val created = store.dataSource.inTx { connection -> createPolicy(name, cedarSrc, enabled, principal, connection) }
        policyStore.markCommittedMutation()
        return created
    }

    fun createPolicy(name: String, cedarSrc: String, enabled: Boolean, principal: String?, c: Connection): CedarPolicy {
        required("name", name)
        required("cedarSrc", cedarSrc)
        return mapPolicyErrors { policyStore.create(CedarPolicyInput(name, cedarSrc, enabled), principal, c) }
    }

    fun updatePolicy(
        currentName: String,
        newName: String?,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
    ): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            updatePolicy(currentName, newName, cedarSrc, enabled, principal, connection)
        }
        policyStore.markCommittedMutation()
        return updated
    }

    /** ID-shaped REST adapter: resolve and mutate the addressed row in one transaction. */
    fun updatePolicy(id: Long, input: CedarPolicyInput, principal: String?): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            updatePolicy(id, input, principal, connection)
        }
        policyStore.markCommittedMutation()
        return updated
    }

    fun updatePolicy(id: Long, input: CedarPolicyInput, principal: String?, c: Connection): CedarPolicy {
        required("name", input.name)
        required("cedarSrc", input.cedarSrc)
        if (policyStore.get(id, c) == null) notFound("policy")
        return mapPolicyErrors { policyStore.update(id, input, principal, c) ?: notFound("policy") }
    }

    fun updatePolicy(
        currentName: String,
        newName: String?,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
        c: Connection,
    ): CedarPolicy {
        required("name", currentName)
        required("cedarSrc", cedarSrc)
        val current = policyStore.getByName(currentName, c) ?: notFound("policy")
        val targetName = newName ?: current.name
        required("newName", targetName)
        return mapPolicyErrors {
            policyStore.update(current.id, CedarPolicyInput(targetName, cedarSrc, enabled), principal, c)
                ?: notFound("policy")
        }
    }

    fun setPolicyEnabled(name: String, enabled: Boolean, principal: String?): CedarPolicy {
        val updated = store.dataSource.inTx { connection -> setPolicyEnabled(name, enabled, principal, connection) }
        policyStore.markCommittedMutation()
        return updated
    }

    fun setPolicyEnabled(id: Long, enabled: Boolean, principal: String?): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            if (policyStore.get(id, connection) == null) notFound("policy")
            mapPolicyErrors { policyStore.setEnabled(id, enabled, principal, connection) ?: notFound("policy") }
        }
        policyStore.markCommittedMutation()
        return updated
    }

    fun setPolicyEnabled(name: String, enabled: Boolean, principal: String?, c: Connection): CedarPolicy {
        required("name", name)
        val current = policyStore.getByName(name, c) ?: notFound("policy")
        return mapPolicyErrors { policyStore.setEnabled(current.id, enabled, principal, c) ?: notFound("policy") }
    }

    fun deletePolicy(name: String): DeleteResult {
        val deleted = store.dataSource.inTx { connection -> deletePolicy(name, connection) }
        if (deleted.deleted) policyStore.markCommittedMutation()
        return deleted
    }

    fun deletePolicy(id: Long): DeleteResult {
        val deleted = store.dataSource.inTx { connection ->
            if (policyStore.get(id, connection) == null) notFound("policy")
            try {
                DeleteResult(policyStore.delete(id, connection))
            } catch (_: SystemPolicyImmutableException) {
                throw ManagementException(ApiError("policy.system_immutable"))
            }
        }
        if (deleted.deleted) policyStore.markCommittedMutation()
        return deleted
    }

    fun deletePolicy(name: String, c: Connection): DeleteResult {
        required("name", name)
        val current = policyStore.getByName(name, c) ?: notFound("policy")
        return try {
            DeleteResult(policyStore.delete(current.id, c))
        } catch (_: SystemPolicyImmutableException) {
            throw ManagementException(ApiError("policy.system_immutable"))
        }
    }

    fun createRole(name: String, description: String?): Role = store.dataSource.inTx { createRole(name, description, it) }

    fun createRole(name: String, description: String?, c: Connection): Role {
        required("name", name)
        return unique("role", name) { store.createRole(RoleInput(name, description), c) }
    }

    fun updateRole(currentName: String, newName: String?, description: String?): Role =
        store.dataSource.inTx { updateRole(currentName, newName, description, it) }

    fun updateRole(id: Long, input: RoleInput): Role = store.dataSource.inTx { c ->
        val current = store.getRole(id, c) ?: notFound("role")
        if (store.isSystemRole(id, c)) throw ManagementException(ApiError("role.system_immutable"))
        required("name", input.name)
        unique("role", input.name) { store.updateRole(current.id, input, c) ?: notFound("role") }
    }

    fun updateRole(currentName: String, newName: String?, description: String?, c: Connection): Role {
        required("name", currentName)
        val current = store.getRoleByName(currentName, c) ?: notFound("role")
        if (store.isSystemRole(current.id, c)) throw ManagementException(ApiError("role.system_immutable"))
        val targetName = newName ?: currentName
        required("newName", targetName)
        return unique("role", targetName) {
            store.updateRole(current.id, RoleInput(targetName, description), c) ?: notFound("role")
        }
    }

    fun deleteRole(name: String): DeleteResult = store.dataSource.inTx { deleteRole(name, it) }

    fun deleteRole(id: Long): DeleteResult = store.dataSource.inTx { c ->
        if (store.getRole(id, c) == null) notFound("role")
        if (store.isSystemRole(id, c)) throw ManagementException(ApiError("role.system_immutable"))
        DeleteResult(store.deleteRole(id, c))
    }

    fun deleteRole(name: String, c: Connection): DeleteResult {
        required("name", name)
        val current = store.getRoleByName(name, c) ?: notFound("role")
        if (store.isSystemRole(current.id, c)) throw ManagementException(ApiError("role.system_immutable"))
        return DeleteResult(store.deleteRole(current.id, c))
    }

    fun assignRole(principal: String, roleName: String): RoleAssignment = store.dataSource.inTx { assignRole(principal, roleName, it) }

    fun assignRole(principal: String, roleId: Long): RoleAssignment = store.dataSource.inTx { c ->
        required("principal", principal)
        if (store.getRole(roleId, c) == null) notFound("role")
        store.createAssignment(RoleAssignmentInput(principal, roleId), c)
    }

    fun assignRole(principal: String, roleName: String, c: Connection): RoleAssignment {
        required("principal", principal)
        required("roleName", roleName)
        val role = store.getRoleByName(roleName, c) ?: notFound("role")
        return store.createAssignment(RoleAssignmentInput(principal, role.id), c)
    }

    /**
     * Make [roleNames] the principal's complete set of DIRECT assignments, in one transaction: every name is
     * resolved before anything is deleted, so an unknown name leaves the existing set untouched rather than
     * stripping a principal's roles and then failing. Unknown names are rejected (never created) — a typo that
     * silently became a real role would resolve fine and then deny every query, since no policy references it.
     *
     * Only direct `principal_role` rows are touched; group-derived roles and active JIT grants are separate
     * sources ([RoleResolver.resolve] unions all three) and are deliberately left alone.
     *
     * The rejection names the offending role, not just "role" — the caller asked for a set and needs to know
     * which member of it does not exist, since the whole request fails on any one of them.
     *
     * Serialized per principal by the same advisory lock deprovisioning and SCIM take. `inTx` alone is not
     * enough: it gives rollback, but at READ COMMITTED a list-delete-insert is a read-modify-write, so two
     * concurrent replacements each delete only the ids THEY listed and then insert their own — committing the
     * UNION rather than either caller's set. An assignment landing between the list and the delete survives the
     * same way. "The claim is the whole intended set" is only true if the sequence cannot interleave.
     *
     * Takes a [Connection] so a caller that must land another write atomically with the replacement — the debug
     * login, which mints a session for exactly these roles — composes both onto one transaction under one lock
     * rather than committing twice.
     */
    fun replaceDirectRoles(principal: String, roleNames: List<String>, c: Connection): List<RoleAssignment> {
        required("principal", principal)
        c.advisoryLockPrincipal(principal)
        val roles = roleNames.map { name -> store.getRoleByName(name, c) ?: notFound("role '$name'") }
        store.listAssignments(principal, null, c).forEach { store.deleteAssignment(it.id, c) }
        return roles.map { store.createAssignment(RoleAssignmentInput(principal, it.id), c) }
    }

    fun replaceDirectRoles(principal: String, roleNames: List<String>): List<RoleAssignment> =
        store.dataSource.inTx { replaceDirectRoles(principal, roleNames, it) }

    fun unassignRole(principal: String, roleName: String): DeleteResult = store.dataSource.inTx { unassignRole(principal, roleName, it) }

    fun unassignRole(id: Long): DeleteResult = store.dataSource.inTx { c ->
        if (store.getAssignment(id, c) == null) notFound("role assignment")
        DeleteResult(store.deleteAssignment(id, c))
    }

    fun listAssignmentsByRoleId(principal: String?, roleId: Long?): List<RoleAssignment> =
        store.listAssignments(principal, roleId)

    fun unassignRole(principal: String, roleName: String, c: Connection): DeleteResult {
        required("principal", principal)
        required("roleName", roleName)
        val role = store.getRoleByName(roleName, c) ?: notFound("role")
        return DeleteResult(store.deleteAssignment(principal, role.id, c))
    }

    fun createMaskFn(input: MaskFnInput): MaskFn = store.dataSource.inTx { createMaskFn(input, it) }

    fun createMaskFn(input: MaskFnInput, c: Connection): MaskFn {
        required("name", input.name)
        required("kind", input.kind)
        return unique("mask function", input.name) { store.createMaskFn(input, c) }
    }

    fun updateMaskFn(currentName: String, input: MaskFnInput): MaskFn = store.dataSource.inTx { updateMaskFn(currentName, input, it) }

    fun updateMaskFn(id: Long, input: MaskFnInput): MaskFn = store.dataSource.inTx { c ->
        if (store.getMaskFn(id, c) == null) notFound("mask function")
        required("name", input.name)
        required("kind", input.kind)
        unique("mask function", input.name) { store.updateMaskFn(id, input, c) ?: notFound("mask function") }
    }

    fun updateMaskFn(currentName: String, input: MaskFnInput, c: Connection): MaskFn {
        required("name", currentName)
        val current = store.getMaskFnByName(currentName, c) ?: notFound("mask function")
        required("newName", input.name)
        required("kind", input.kind)
        return unique("mask function", input.name) { store.updateMaskFn(current.id, input, c) ?: notFound("mask function") }
    }

    fun deleteMaskFn(name: String): DeleteResult = store.dataSource.inTx { deleteMaskFn(name, it) }

    fun deleteMaskFn(id: Long): DeleteResult = store.dataSource.inTx { c ->
        if (store.getMaskFn(id, c) == null) notFound("mask function")
        DeleteResult(store.deleteMaskFn(id, c))
    }

    fun deleteMaskFn(name: String, c: Connection): DeleteResult {
        required("name", name)
        val current = store.getMaskFnByName(name, c) ?: notFound("mask function")
        return DeleteResult(store.deleteMaskFn(current.id, c))
    }

    private fun <T> mapPolicyErrors(block: () -> T): T = try {
        block()
    } catch (e: InvalidCedarPolicyException) {
        throw CedarValidationManagementException(e.errors)
    } catch (_: ReservedPolicyNameException) {
        throw ManagementException(ApiError("policy.reserved_name"))
    } catch (_: SystemPolicyImmutableException) {
        throw ManagementException(ApiError("policy.system_immutable"))
    } catch (e: SQLException) {
        if (e.sqlState == "23505") throw ManagementException(ApiError("common.already_exists", mapOf("resource" to "policy")))
        throw e
    }
}

@Serializable
data class GroupRolesResult(val group: String, val roleNames: List<String>)

class IdentityManagementService(
    private val dataSource: DataSource,
    private val store: UserGroupStore,
    private val policyStore: PolicyStore,
    private val tokenStore: TokenStore,
    private val accessStore: AccessStore,
    private val daemonSessionStore: PrincipalSessionStore,
) {
    fun listUsers(): List<AppUser> = store.listUsers()
    fun listGroups(): List<AppGroup> = store.listGroups()
    fun getUser(principal: String): AppUser = store.getUserByPrincipal(principal) ?: notFound("user")
    fun getGroup(name: String): AppGroup = store.getGroupByName(name) ?: notFound("group")
    fun getUser(principal: String, c: Connection): AppUser = store.getUserByPrincipal(principal, c) ?: notFound("user")
    fun getGroup(name: String, c: Connection): AppGroup = store.getGroupByName(name, c) ?: notFound("group")

    fun createUser(input: AppUserInput): AppUser = dataSource.inTx { createUser(input, it) }

    fun createUser(input: AppUserInput, c: Connection): AppUser {
        required("principal", input.principal)
        return unique("principal", input.principal) {
            store.createUser(input, tokenStore, accessStore, daemonSessionStore, c)
        }
    }

    fun updateUser(
        currentPrincipal: String,
        newPrincipal: String?,
        displayName: String?,
        email: String?,
        active: Boolean,
    ): AppUser = dataSource.inTx { updateUser(currentPrincipal, newPrincipal, displayName, email, active, it) }

    fun updateUser(id: Long, input: AppUserInput): AppUser = dataSource.inTx { c ->
        if (store.getUser(id, c) == null) notFound("user")
        required("principal", input.principal)
        unique("principal", input.principal) {
            store.updateUser(id, input, tokenStore, accessStore, daemonSessionStore, c) ?: notFound("user")
        }
    }

    fun updateUser(
        currentPrincipal: String,
        newPrincipal: String?,
        displayName: String?,
        email: String?,
        active: Boolean,
        c: Connection,
    ): AppUser {
        required("principal", currentPrincipal)
        val current = store.getUserByPrincipal(currentPrincipal, c) ?: notFound("user")
        val targetPrincipal = newPrincipal ?: currentPrincipal
        required("newPrincipal", targetPrincipal)
        val input = AppUserInput(targetPrincipal, displayName, email, active)
        return unique("principal", input.principal) {
            store.updateUser(current.id, input, tokenStore, accessStore, daemonSessionStore, c) ?: notFound("user")
        }
    }

    fun deprovisionUser(principal: String): DeleteResult = dataSource.inTx { deprovisionUser(principal, it) }

    fun deprovisionUser(id: Long): DeleteResult = dataSource.inTx { c ->
        if (store.getUser(id, c) == null) notFound("user")
        DeleteResult(store.deleteUser(id, tokenStore, accessStore, daemonSessionStore, c))
    }

    fun deprovisionUser(principal: String, c: Connection): DeleteResult {
        required("principal", principal)
        val current = store.getUserByPrincipal(principal, c) ?: notFound("user")
        return DeleteResult(store.deleteUser(current.id, tokenStore, accessStore, daemonSessionStore, c))
    }

    fun createGroup(input: AppGroupInput): AppGroup = dataSource.inTx { createGroup(input, it) }

    fun createGroup(input: AppGroupInput, c: Connection): AppGroup {
        required("name", input.name)
        return unique("group", input.name) { store.createGroup(input, c) }
    }

    fun updateGroup(currentName: String, newName: String?, description: String?): AppGroup =
        dataSource.inTx { updateGroup(currentName, newName, description, it) }

    fun updateGroup(id: Long, input: AppGroupInput): AppGroup = dataSource.inTx { c ->
        val current = store.getGroup(id, c) ?: notFound("group")
        rejectSystem(current, c)
        required("name", input.name)
        unique("group", input.name) { store.updateGroup(id, input, c) ?: notFound("group") }
    }

    fun updateGroup(currentName: String, newName: String?, description: String?, c: Connection): AppGroup {
        required("name", currentName)
        val current = group(currentName, c)
        rejectSystem(current, c)
        val targetName = newName ?: currentName
        required("newName", targetName)
        return unique("group", targetName) {
            store.updateGroup(current.id, AppGroupInput(targetName, description), c) ?: notFound("group")
        }
    }

    fun deleteGroup(name: String): DeleteResult = dataSource.inTx { deleteGroup(name, it) }

    fun deleteGroup(id: Long): DeleteResult = dataSource.inTx { c ->
        val current = store.getGroup(id, c) ?: notFound("group")
        rejectSystem(current, c)
        DeleteResult(store.deleteGroup(id, c))
    }

    fun deleteGroup(name: String, c: Connection): DeleteResult {
        required("name", name)
        val current = group(name, c)
        rejectSystem(current, c)
        return DeleteResult(store.deleteGroup(current.id, c))
    }

    fun addGroupMember(groupName: String, principal: String): GroupMemberEntry =
        dataSource.inTx { addGroupMember(groupName, principal, it) }

    fun addGroupMember(groupId: Long, userId: Long): GroupMemberEntry = dataSource.inTx { c ->
        val group = store.getGroup(groupId, c) ?: notFound("group")
        rejectSystem(group, c)
        if (store.getUser(userId, c) == null) notFound("user")
        store.addMember(groupId, userId, c)
        store.listMembers(groupId, c).first { it.userId == userId }
    }

    fun addGroupMember(groupName: String, principal: String, c: Connection): GroupMemberEntry {
        required("groupName", groupName)
        required("principal", principal)
        val group = group(groupName, c)
        rejectSystem(group, c)
        val user = store.getUserByPrincipal(principal, c) ?: notFound("user")
        store.addMember(group.id, user.id, c)
        return store.listMembers(group.id, c).first { it.userId == user.id }
    }

    fun removeGroupMember(groupName: String, principal: String): DeleteResult =
        dataSource.inTx { removeGroupMember(groupName, principal, it) }

    fun removeGroupMember(groupId: Long, userId: Long): DeleteResult = dataSource.inTx { c ->
        val group = store.getGroup(groupId, c) ?: notFound("group")
        rejectSystem(group, c)
        if (store.getUser(userId, c) == null) notFound("user")
        DeleteResult(store.removeMember(groupId, userId, c))
    }

    fun removeGroupMember(groupName: String, principal: String, c: Connection): DeleteResult {
        required("groupName", groupName)
        required("principal", principal)
        val group = group(groupName, c)
        rejectSystem(group, c)
        val user = store.getUserByPrincipal(principal, c) ?: notFound("user")
        return DeleteResult(store.removeMember(group.id, user.id, c))
    }

    fun setGroupRoles(groupName: String, roleNames: Set<String>): GroupRolesResult =
        dataSource.inTx { setGroupRoles(groupName, roleNames, it) }

    fun addGroupRole(groupId: Long, roleId: Long): GroupRoleEntry = dataSource.inTx { c ->
        lockMutableGroup(groupId, c)
        val role = policyStore.getRole(roleId, c) ?: notFound("role")
        store.addGroupRole(groupId, roleId, c)
        GroupRoleEntry(role.id, role.name)
    }

    fun removeGroupRole(groupId: Long, roleId: Long): DeleteResult = dataSource.inTx { c ->
        lockMutableGroup(groupId, c)
        if (policyStore.getRole(roleId, c) == null) notFound("role")
        DeleteResult(store.removeGroupRole(groupId, roleId, c))
    }

    fun setGroupRoles(groupName: String, roleNames: Set<String>, c: Connection): GroupRolesResult {
        required("groupName", groupName)
        roleNames.forEach { required("roleNames", it) }
        val group = c.prepareStatement("SELECT id, source FROM app_group WHERE name = ? FOR UPDATE").use { statement ->
            statement.setString(1, groupName)
            statement.executeQuery().use { result ->
                if (!result.next()) notFound("group")
                result.getLong("id") to result.getString("source")
            }
        }
        if (group.second == "SYSTEM") throw ManagementException(ApiError("group.system_immutable"))
        val roles = roleNames.associateWith { name -> policyStore.getRoleByName(name, c) ?: notFound("role") }
        val current = store.listGroupRoles(group.first, c).associateBy(GroupRoleEntry::roleName)
        for (name in current.keys - roles.keys) store.removeGroupRole(group.first, current.getValue(name).roleId, c)
        for (name in roles.keys - current.keys) store.addGroupRole(group.first, roles.getValue(name).id, c)
        return GroupRolesResult(groupName, store.listGroupRoles(group.first, c).map(GroupRoleEntry::roleName))
    }

    private fun group(name: String, c: Connection): AppGroup = store.getGroupByName(name, c) ?: notFound("group")

    private fun lockMutableGroup(id: Long, c: Connection) {
        val source = c.prepareStatement("SELECT source FROM app_group WHERE id = ? FOR UPDATE").use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { result -> if (result.next()) result.getString("source") else notFound("group") }
        }
        if (source == "SYSTEM") throw ManagementException(ApiError("group.system_immutable"))
    }

    private fun rejectSystem(group: AppGroup, c: Connection) {
        if (store.isSystemGroup(group.id, c)) throw ManagementException(ApiError("group.system_immutable"))
    }
}

private fun required(field: String, value: String) {
    if (value.isBlank()) throw ManagementException(ApiError("common.field_required", mapOf("fields" to field)))
}

private fun notFound(resource: String): Nothing =
    throw ManagementException(ApiError("common.not_found", mapOf("resource" to resource)))

private fun <T> unique(resource: String, name: String?, block: () -> T): T = try {
    block()
} catch (e: SQLException) {
    if (e.sqlState == "23505") {
        throw ManagementException(
            ApiError("common.already_exists", buildMap { put("resource", resource); name?.let { put("name", it) } }),
        )
    }
    throw e
}
