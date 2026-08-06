package com.ridi.oss.proxymonster.controlplane.management

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.AppGroup
import com.ridi.oss.proxymonster.controlplane.AppGroupInput
import com.ridi.oss.proxymonster.controlplane.AppUser
import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.ClassificationInput
import com.ridi.oss.proxymonster.controlplane.ConnectionCatalogRegistry
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
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
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicy
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchemaResult
import com.ridi.oss.proxymonster.controlplane.authz.CedarValidateResult
import com.ridi.oss.proxymonster.controlplane.authz.InvalidCedarPolicyException
import com.ridi.oss.proxymonster.controlplane.authz.ReservedPolicyNameException
import com.ridi.oss.proxymonster.controlplane.authz.SystemPolicyImmutableException
import com.ridi.oss.proxymonster.controlplane.authz.extractContextTagNames
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
    private val recorder: ManagementAuditRecorder,
    private val connectionCatalog: ConnectionCatalogRegistry = ConnectionCatalogRegistry(),
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

    fun createDatasource(input: DatasourceInput, actor: AuditActor): Datasource =
        store.dataSource.inTx { createDatasource(input, actor, it) }

    fun createDatasource(input: DatasourceInput, actor: AuditActor, c: Connection): Datasource {
        val created = store.create(input, c)
        recordDatasource(c, actor, created.name, "create datasource '${created.name}'")
        return created
    }

    fun updateDatasource(id: Long, input: DatasourceInput, actor: AuditActor): Datasource? =
        store.dataSource.inTx { updateDatasource(id, input, actor, it) }

    fun updateDatasource(id: Long, input: DatasourceInput, actor: AuditActor, c: Connection): Datasource? {
        val before = store.get(id, c) ?: return null
        val updated = store.update(id, input, c) ?: return null
        recordDatasource(c, actor, updated.name, updateSummary("datasource", before.name, updated.name))
        return updated
    }

    fun deleteDatasource(id: Long, actor: AuditActor): DeleteResult =
        store.dataSource.inTx { deleteDatasource(id, actor, it) }

    fun deleteDatasource(id: Long, actor: AuditActor, c: Connection): DeleteResult {
        val current = store.get(id, c) ?: return DeleteResult(false)
        // Fail-closed guard: refuse while the datasource is still in use, so a delete never has to tear down
        // live runtime state under a name a new datasource may immediately reuse. A live proxy (open Events
        // stream) could keep serving the freed name; an outstanding request would be decided/executed with
        // an altered authorization context. Both are resolved by the operator first (detach the proxy, settle
        // the requests), not silently by the delete.
        if (current.name in eventsHub.attached()) {
            throw ManagementException(ApiError("datasource.in_use_proxy_attached"))
        }
        if (store.hasActiveRequests(id, c)) {
            throw ManagementException(ApiError("datasource.in_use_active_requests"))
        }
        val result = DeleteResult(store.delete(id, c))
        if (result.deleted) {
            recordDatasource(c, actor, current.name, "delete datasource '${current.name}'")
            // Drop the name-keyed in-memory enforcement catalog for this datasource. A soft-deleted name is
            // free for a new datasource to reuse, and the authoritative catalog is keyed by name, not id — so
            // without this a connection to the reused name could adopt structure measured from the deleted
            // predecessor's backend and mask the wrong result columns. Same hazard a retarget already
            // invalidates; idempotent and fail-safe (an over-drop only forces the next connection to
            // re-measure).
            connectionCatalog.invalidateDatasource(current.name)
        }
        return result
    }

    fun setColumnClassification(
        datasourceId: Long,
        schema: String?,
        table: String,
        column: String,
        tags: List<String>,
        maskFnId: Long?,
        actor: AuditActor,
    ): Classification = store.dataSource.inTx { connection ->
        required("table", table)
        required("column", column)
        val datasource = store.get(datasourceId, connection) ?: notFound("datasource")
        if (schema == null && store.defaultSchema(datasource.id, connection) == null) {
            throw ManagementException(ApiError("datasource.schema_required"))
        }
        DatasourceStore.requireWritableTags(tags)
        val written = store.upsertClassification(datasource.id, ClassificationInput(schema, table, column, tags, maskFnId), connection)
        recordClassification(connection, actor, datasource.name, written)
        written
    }

    fun setColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
        tags: List<String>,
        maskFnId: Long?,
        actor: AuditActor,
        connection: Connection,
    ): Classification {
        required("table", table)
        required("column", column)
        val datasource = datasource(datasourceName, connection)
        if (schema == null && store.defaultSchema(datasource.id, connection) == null) {
            throw ManagementException(ApiError("datasource.schema_required"))
        }
        DatasourceStore.requireWritableTags(tags)
        val written = store.upsertClassification(datasource.id, ClassificationInput(schema, table, column, tags, maskFnId), connection)
        recordClassification(connection, actor, datasource.name, written)
        return written
    }

    /**
     * Tag many columns of one datasource in the caller's transaction — all of them or none.
     *
     * Every entry is validated before the first write, so a rejected entry leaves the whole batch
     * unapplied rather than a prefix of it. Two entries resolving to the same column are rejected
     * rather than silently letting the later one win: the caller cannot tell from the response which
     * of its conflicting tag sets survived, and for a masking decision that is the difference between
     * a column being masked and not.
     *
     * One audit row covers the batch, naming every column it wrote: the batch is one atomic change, and
     * a row per column would let a partial trail imply a partial write that cannot happen.
     */
    fun setColumnClassifications(
        datasourceName: String,
        columns: List<ClassificationInput>,
        actor: AuditActor,
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
            DatasourceStore.requireWritableTags(input.tags)
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
        val written = resolved.sortedWith(compareBy({ it.schema }, { it.table }, { it.column }))
            .map { input -> store.upsertClassification(datasource.id, input, connection) }
        recordDatasource(
            connection, actor, datasource.name,
            "tag ${written.size} columns of '${datasource.name}' [${written.joinToString(", ") { it.path() }}]",
        )
        return written
    }

    fun clearColumnClassification(
        datasourceId: Long,
        schema: String?,
        table: String,
        column: String,
        actor: AuditActor,
    ): DeleteResult = store.dataSource.inTx { connection ->
        required("table", table)
        required("column", column)
        val datasource = store.get(datasourceId, connection) ?: notFound("datasource")
        val resolvedSchema = schema ?: store.defaultSchema(datasource.id, connection)
            ?: throw ManagementException(ApiError("datasource.schema_required"))
        clearResolved(datasource.name, datasource.id, resolvedSchema, table, column, actor, connection)
    }

    fun clearColumnClassification(
        datasourceName: String,
        schema: String?,
        table: String,
        column: String,
        actor: AuditActor,
        connection: Connection,
    ): DeleteResult {
        required("table", table)
        required("column", column)
        val datasource = datasource(datasourceName, connection)
        val resolvedSchema = schema ?: store.defaultSchema(datasource.id, connection)
            ?: throw ManagementException(ApiError("datasource.schema_required"))
        return clearResolved(datasource.name, datasource.id, resolvedSchema, table, column, actor, connection)
    }

    private fun clearResolved(
        datasourceName: String,
        datasourceId: Long,
        schema: String,
        table: String,
        column: String,
        actor: AuditActor,
        c: Connection,
    ): DeleteResult {
        val result = DeleteResult(store.deleteClassification(datasourceId, schema, table, column, c))
        if (result.deleted) {
            recordColumn(c, actor, datasourceName, schema, table, column, "clear tags on $datasourceName.$schema.$table.$column")
        }
        return result
    }

    private fun recordClassification(c: Connection, actor: AuditActor, datasourceName: String, written: Classification) =
        recordColumn(
            c, actor, datasourceName, written.schema, written.table, written.column,
            "tag $datasourceName.${written.path()} [${written.tags.joinToString(", ")}]",
        )

    private fun recordColumn(
        c: Connection,
        actor: AuditActor,
        datasourceName: String,
        schema: String,
        table: String,
        column: String,
        summary: String,
    ) = recorder.record(
        c, actor, AuthzAction.ADMIN_DATASOURCES,
        "${auditEntity("Datasource", datasourceName)} col $schema.$table.$column", summary,
    )

    private fun recordDatasource(c: Connection, actor: AuditActor, name: String, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_DATASOURCES, auditEntity("Datasource", name), summary)

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
    private val recorder: ManagementAuditRecorder,
) {
    fun listPolicies(): List<CedarPolicy> = policyStore.list()

    fun getPolicy(name: String): CedarPolicy = policyStore.getByName(name) ?: notFound("policy")
    fun getPolicy(name: String, c: Connection): CedarPolicy = policyStore.getByName(name, c) ?: notFound("policy")

    fun validatePolicy(cedarSrc: String): CedarValidateResult {
        required("cedarSrc", cedarSrc)
        val errors = CedarSchema.validate(cedarSrc)
        return CedarValidateResult(errors.isEmpty(), errors)
    }

    /** Carries the derived `context.tag::<name>` action declarations, not just the base schema: the
     *  console lints the editor against this, and without them a tag rule reads as an undeclared action
     *  in the editor while [validatePolicy] — which self-augments — accepts it. The vocabulary is the
     *  stored rule set, so it comes from the policies themselves (docs/authz-context.md), disabled rows
     *  included: a draft is edited before it goes live. Tag names a client is still typing are not in the
     *  store, so the editor augments this with its own draft's names. */
    fun policySchema(): CedarSchemaResult {
        val tagNames = policyStore.list().flatMapTo(mutableSetOf()) { extractContextTagNames(it.cedarSrc) }
        return CedarSchemaResult(CedarSchema.parseableSchemaTextFor(tagNames))
    }

    fun listRoles(): List<Role> = store.listRoles()
    fun getRole(name: String): Role = store.getRoleByName(name) ?: notFound("role")
    fun getRole(name: String, c: Connection): Role = store.getRoleByName(name, c) ?: notFound("role")

    fun listAssignments(principal: String?, roleName: String?): List<RoleAssignment> {
        val roleId = roleName?.let { name -> store.getRoleByName(name)?.id ?: notFound("role") }
        return store.listAssignments(principal, roleId)
    }

    fun listAssignmentsByRoleId(principal: String?, roleId: Long?): List<RoleAssignment> =
        store.listAssignments(principal, roleId)

    fun listMaskFns(): List<MaskFn> = store.listMaskFns()
    fun getMaskFn(name: String): MaskFn = store.getMaskFnByName(name) ?: notFound("mask function")
    fun getMaskFn(name: String, c: Connection): MaskFn = store.getMaskFnByName(name, c) ?: notFound("mask function")

    fun createPolicy(
        name: String,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
        actor: AuditActor,
    ): CedarPolicy {
        val created = store.dataSource.inTx { connection ->
            createPolicy(name, cedarSrc, enabled, principal, actor, connection)
        }
        policyStore.markCommittedMutation()
        return created
    }

    fun createPolicy(
        name: String,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
        actor: AuditActor,
        c: Connection,
    ): CedarPolicy {
        required("name", name)
        required("cedarSrc", cedarSrc)
        val created = mapPolicyErrors { policyStore.create(CedarPolicyInput(name, cedarSrc, enabled), principal, c) }
        recordPolicy(c, actor, created.id, "create policy '${created.name}'")
        return created
    }

    fun updatePolicy(
        currentName: String,
        newName: String?,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
        actor: AuditActor,
    ): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            updatePolicy(currentName, newName, cedarSrc, enabled, principal, actor, connection)
        }
        policyStore.markCommittedMutation()
        return updated
    }

    /** ID-shaped REST adapter: resolve and mutate the addressed row in one transaction. */
    fun updatePolicy(id: Long, input: CedarPolicyInput, principal: String?, actor: AuditActor): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            updatePolicy(id, input, principal, actor, connection)
        }
        policyStore.markCommittedMutation()
        return updated
    }

    fun updatePolicy(id: Long, input: CedarPolicyInput, principal: String?, actor: AuditActor, c: Connection): CedarPolicy {
        required("name", input.name)
        required("cedarSrc", input.cedarSrc)
        val current = policyStore.get(id, c) ?: notFound("policy")
        val updated = mapPolicyErrors { policyStore.update(id, input, principal, c) ?: notFound("policy") }
        recordPolicy(c, actor, updated.id, updateSummary("policy", current.name, updated.name))
        return updated
    }

    fun updatePolicy(
        currentName: String,
        newName: String?,
        cedarSrc: String,
        enabled: Boolean,
        principal: String?,
        actor: AuditActor,
        c: Connection,
    ): CedarPolicy {
        required("name", currentName)
        required("cedarSrc", cedarSrc)
        val current = policyStore.getByName(currentName, c) ?: notFound("policy")
        val targetName = newName ?: current.name
        required("newName", targetName)
        val updated = mapPolicyErrors {
            policyStore.update(current.id, CedarPolicyInput(targetName, cedarSrc, enabled), principal, c)
                ?: notFound("policy")
        }
        recordPolicy(c, actor, updated.id, updateSummary("policy", current.name, updated.name))
        return updated
    }

    fun setPolicyEnabled(name: String, enabled: Boolean, principal: String?, actor: AuditActor): CedarPolicy {
        val updated = store.dataSource.inTx { connection -> setPolicyEnabled(name, enabled, principal, actor, connection) }
        policyStore.markCommittedMutation()
        return updated
    }

    fun setPolicyEnabled(id: Long, enabled: Boolean, principal: String?, actor: AuditActor): CedarPolicy {
        val updated = store.dataSource.inTx { connection ->
            val current = policyStore.get(id, connection) ?: notFound("policy")
            mapPolicyErrors { policyStore.setEnabled(id, enabled, principal, connection) ?: notFound("policy") }
                .also { recordPolicyEnabled(connection, actor, current, enabled) }
        }
        policyStore.markCommittedMutation()
        return updated
    }

    fun setPolicyEnabled(name: String, enabled: Boolean, principal: String?, actor: AuditActor, c: Connection): CedarPolicy {
        required("name", name)
        val current = policyStore.getByName(name, c) ?: notFound("policy")
        val updated = mapPolicyErrors { policyStore.setEnabled(current.id, enabled, principal, c) ?: notFound("policy") }
        recordPolicyEnabled(c, actor, current, enabled)
        return updated
    }

    fun deletePolicy(name: String, actor: AuditActor): DeleteResult {
        val deleted = store.dataSource.inTx { connection -> deletePolicy(name, actor, connection) }
        if (deleted.deleted) policyStore.markCommittedMutation()
        return deleted
    }

    fun deletePolicy(id: Long, actor: AuditActor): DeleteResult {
        val deleted = store.dataSource.inTx { connection ->
            val current = policyStore.get(id, connection) ?: notFound("policy")
            deletePolicy(current, actor, connection)
        }
        if (deleted.deleted) policyStore.markCommittedMutation()
        return deleted
    }

    fun deletePolicy(name: String, actor: AuditActor, c: Connection): DeleteResult {
        required("name", name)
        return deletePolicy(policyStore.getByName(name, c) ?: notFound("policy"), actor, c)
    }

    private fun deletePolicy(current: CedarPolicy, actor: AuditActor, c: Connection): DeleteResult {
        val deleted = try {
            DeleteResult(policyStore.delete(current.id, c))
        } catch (_: SystemPolicyImmutableException) {
            throw ManagementException(ApiError("policy.system_immutable"))
        }
        if (deleted.deleted) recordPolicy(c, actor, current.id, "delete policy '${current.name}'")
        return deleted
    }

    private fun recordPolicy(c: Connection, actor: AuditActor, id: Long, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_POLICIES, auditEntity("Policy", id.toString()), summary)

    private fun recordPolicyEnabled(c: Connection, actor: AuditActor, policy: CedarPolicy, enabled: Boolean) =
        recordPolicy(c, actor, policy.id, "${if (enabled) "enable" else "disable"} policy '${policy.name}'")

    fun createRole(name: String, description: String?, actor: AuditActor): Role =
        store.dataSource.inTx { createRole(name, description, actor, it) }

    fun createRole(name: String, description: String?, actor: AuditActor, c: Connection): Role {
        required("name", name)
        val created = unique("role", name) { store.createRole(RoleInput(name, description), c) }
        recordRole(c, actor, created.name, "create role '${created.name}'")
        return created
    }

    fun updateRole(currentName: String, newName: String?, description: String?, actor: AuditActor): Role =
        store.dataSource.inTx { updateRole(currentName, newName, description, actor, it) }

    fun updateRole(id: Long, input: RoleInput, actor: AuditActor): Role = store.dataSource.inTx { c ->
        val current = store.getRole(id, c) ?: notFound("role")
        if (store.isSystemRole(id, c)) throw ManagementException(ApiError("role.system_immutable"))
        required("name", input.name)
        val updated = unique("role", input.name) { store.updateRole(current.id, input, c) ?: notFound("role") }
        recordRole(c, actor, updated.name, updateSummary("role", current.name, updated.name))
        updated
    }

    fun updateRole(currentName: String, newName: String?, description: String?, actor: AuditActor, c: Connection): Role {
        required("name", currentName)
        val current = store.getRoleByName(currentName, c) ?: notFound("role")
        if (store.isSystemRole(current.id, c)) throw ManagementException(ApiError("role.system_immutable"))
        val targetName = newName ?: currentName
        required("newName", targetName)
        val updated = unique("role", targetName) {
            store.updateRole(current.id, RoleInput(targetName, description), c) ?: notFound("role")
        }
        recordRole(c, actor, updated.name, updateSummary("role", current.name, updated.name))
        return updated
    }

    fun deleteRole(name: String, actor: AuditActor): DeleteResult = store.dataSource.inTx { deleteRole(name, actor, it) }

    fun deleteRole(id: Long, actor: AuditActor): DeleteResult = store.dataSource.inTx { c ->
        val current = store.getRole(id, c) ?: notFound("role")
        if (store.isSystemRole(id, c)) throw ManagementException(ApiError("role.system_immutable"))
        deleteRole(current, actor, c)
    }

    fun deleteRole(name: String, actor: AuditActor, c: Connection): DeleteResult {
        required("name", name)
        val current = store.getRoleByName(name, c) ?: notFound("role")
        if (store.isSystemRole(current.id, c)) throw ManagementException(ApiError("role.system_immutable"))
        return deleteRole(current, actor, c)
    }

    private fun deleteRole(current: Role, actor: AuditActor, c: Connection): DeleteResult {
        val deleted = DeleteResult(store.deleteRole(current.id, c))
        if (deleted.deleted) recordRole(c, actor, current.name, "delete role '${current.name}'")
        return deleted
    }

    private fun recordRole(c: Connection, actor: AuditActor, name: String, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_POLICIES, auditEntity("Role", name), summary)

    fun assignRole(principal: String, roleName: String, actor: AuditActor): RoleAssignment =
        store.dataSource.inTx { assignRole(principal, roleName, actor, it) }

    fun assignRole(principal: String, roleId: Long, actor: AuditActor): RoleAssignment = store.dataSource.inTx { c ->
        required("principal", principal)
        val role = store.getRole(roleId, c) ?: notFound("role")
        val newlyAssigned = store.listAssignments(principal, roleId, c).isEmpty()
        store.createAssignment(RoleAssignmentInput(principal, roleId), c)
            .also { if (newlyAssigned) recordAssignment(c, actor, role.name, principal, assigned = true) }
    }

    fun assignRole(principal: String, roleName: String, actor: AuditActor, c: Connection): RoleAssignment {
        required("principal", principal)
        required("roleName", roleName)
        val role = store.getRoleByName(roleName, c) ?: notFound("role")
        val newlyAssigned = store.listAssignments(principal, role.id, c).isEmpty()
        return store.createAssignment(RoleAssignmentInput(principal, role.id), c)
            .also { if (newlyAssigned) recordAssignment(c, actor, role.name, principal, assigned = true) }
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
    fun replaceDirectRoles(
        principal: String,
        roleNames: List<String>,
        actor: AuditActor,
        c: Connection,
    ): List<RoleAssignment> {
        required("principal", principal)
        c.advisoryLockPrincipal(principal)
        val roles = roleNames.map { name -> store.getRoleByName(name, c) ?: notFound("role '$name'") }
        store.listAssignments(principal, null, c).forEach { store.deleteAssignment(it.id, c) }
        val replaced = roles.map { store.createAssignment(RoleAssignmentInput(principal, it.id), c) }
        recorder.record(
            c, actor, AuthzAction.ADMIN_IDENTITY, auditEntity("User", principal),
            "replace direct roles of '$principal' [${replaced.joinToString(", ") { it.roleName }}]",
        )
        return replaced
    }

    fun replaceDirectRoles(principal: String, roleNames: List<String>, actor: AuditActor): List<RoleAssignment> =
        store.dataSource.inTx { replaceDirectRoles(principal, roleNames, actor, it) }

    fun unassignRole(principal: String, roleName: String, actor: AuditActor): DeleteResult =
        store.dataSource.inTx { unassignRole(principal, roleName, actor, it) }

    fun unassignRole(id: Long, actor: AuditActor): DeleteResult = store.dataSource.inTx { c ->
        val assignment = store.getAssignment(id, c) ?: notFound("role assignment")
        DeleteResult(store.deleteAssignment(id, c)).also { result ->
            if (result.deleted) recordAssignment(c, actor, assignment.roleName, assignment.principal, assigned = false)
        }
    }

    fun unassignRole(principal: String, roleName: String, actor: AuditActor, c: Connection): DeleteResult {
        required("principal", principal)
        required("roleName", roleName)
        val role = store.getRoleByName(roleName, c) ?: notFound("role")
        return DeleteResult(store.deleteAssignment(principal, role.id, c)).also { result ->
            if (result.deleted) recordAssignment(c, actor, role.name, principal, assigned = false)
        }
    }

    private fun recordAssignment(
        c: Connection,
        actor: AuditActor,
        roleName: String,
        principal: String,
        assigned: Boolean,
    ) = recorder.record(
        c, actor, AuthzAction.ADMIN_IDENTITY, auditEntity("Role", roleName),
        if (assigned) "assign role '$roleName' to '$principal'" else "unassign role '$roleName' from '$principal'",
    )

    fun createMaskFn(input: MaskFnInput, actor: AuditActor): MaskFn =
        store.dataSource.inTx { createMaskFn(input, actor, it) }

    fun createMaskFn(input: MaskFnInput, actor: AuditActor, c: Connection): MaskFn {
        required("name", input.name)
        required("kind", input.kind)
        val created = unique("mask function", input.name) { store.createMaskFn(input, c) }
        recordMaskFn(c, actor, created.name, "create mask function '${created.name}'")
        return created
    }

    fun updateMaskFn(currentName: String, input: MaskFnInput, actor: AuditActor): MaskFn =
        store.dataSource.inTx { updateMaskFn(currentName, input, actor, it) }

    fun updateMaskFn(id: Long, input: MaskFnInput, actor: AuditActor): MaskFn = store.dataSource.inTx { c ->
        val current = store.getMaskFn(id, c) ?: notFound("mask function")
        required("name", input.name)
        required("kind", input.kind)
        val updated = unique("mask function", input.name) { store.updateMaskFn(id, input, c) ?: notFound("mask function") }
        recordMaskFn(c, actor, updated.name, updateSummary("mask function", current.name, updated.name))
        updated
    }

    fun updateMaskFn(currentName: String, input: MaskFnInput, actor: AuditActor, c: Connection): MaskFn {
        required("name", currentName)
        val current = store.getMaskFnByName(currentName, c) ?: notFound("mask function")
        required("newName", input.name)
        required("kind", input.kind)
        val updated = unique("mask function", input.name) {
            store.updateMaskFn(current.id, input, c) ?: notFound("mask function")
        }
        recordMaskFn(c, actor, updated.name, updateSummary("mask function", current.name, updated.name))
        return updated
    }

    fun deleteMaskFn(name: String, actor: AuditActor): DeleteResult =
        store.dataSource.inTx { deleteMaskFn(name, actor, it) }

    fun deleteMaskFn(id: Long, actor: AuditActor): DeleteResult = store.dataSource.inTx { c ->
        deleteMaskFn(store.getMaskFn(id, c) ?: notFound("mask function"), actor, c)
    }

    fun deleteMaskFn(name: String, actor: AuditActor, c: Connection): DeleteResult {
        required("name", name)
        return deleteMaskFn(store.getMaskFnByName(name, c) ?: notFound("mask function"), actor, c)
    }

    private fun deleteMaskFn(current: MaskFn, actor: AuditActor, c: Connection): DeleteResult {
        val deleted = DeleteResult(store.deleteMaskFn(current.id, c))
        if (deleted.deleted) recordMaskFn(c, actor, current.name, "delete mask function '${current.name}'")
        return deleted
    }

    private fun recordMaskFn(c: Connection, actor: AuditActor, name: String, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_POLICIES, auditEntity("MaskFn", name), summary)

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
    private val recorder: ManagementAuditRecorder,
) {
    fun listUsers(): List<AppUser> = store.listUsers()
    fun listGroups(): List<AppGroup> = store.listGroups()
    fun getUser(principal: String): AppUser = store.getUserByPrincipal(principal) ?: notFound("user")
    fun getGroup(name: String): AppGroup = store.getGroupByName(name) ?: notFound("group")
    fun getUser(principal: String, c: Connection): AppUser = store.getUserByPrincipal(principal, c) ?: notFound("user")
    fun getGroup(name: String, c: Connection): AppGroup = store.getGroupByName(name, c) ?: notFound("group")

    fun createUser(input: AppUserInput, actor: AuditActor): AppUser = dataSource.inTx { createUser(input, actor, it) }

    fun createUser(input: AppUserInput, actor: AuditActor, c: Connection): AppUser {
        required("principal", input.principal)
        val created = unique("principal", input.principal) {
            store.createUser(input, tokenStore, accessStore, daemonSessionStore, c)
        }
        recordUser(c, actor, created.principal, "create user '${created.principal}'")
        return created
    }

    fun updateUser(
        currentPrincipal: String,
        newPrincipal: String?,
        displayName: String?,
        email: String?,
        active: Boolean,
        actor: AuditActor,
    ): AppUser = dataSource.inTx { updateUser(currentPrincipal, newPrincipal, displayName, email, active, actor, it) }

    fun updateUser(id: Long, input: AppUserInput, actor: AuditActor): AppUser = dataSource.inTx { c ->
        val current = store.getUser(id, c) ?: notFound("user")
        required("principal", input.principal)
        val updated = unique("principal", input.principal) {
            store.updateUser(id, input, tokenStore, accessStore, daemonSessionStore, c) ?: notFound("user")
        }
        recordUser(c, actor, updated.principal, updateSummary("user", current.principal, updated.principal))
        updated
    }

    fun updateUser(
        currentPrincipal: String,
        newPrincipal: String?,
        displayName: String?,
        email: String?,
        active: Boolean,
        actor: AuditActor,
        c: Connection,
    ): AppUser {
        required("principal", currentPrincipal)
        val current = store.getUserByPrincipal(currentPrincipal, c) ?: notFound("user")
        val targetPrincipal = newPrincipal ?: currentPrincipal
        required("newPrincipal", targetPrincipal)
        val input = AppUserInput(targetPrincipal, displayName, email, active)
        val updated = unique("principal", input.principal) {
            store.updateUser(current.id, input, tokenStore, accessStore, daemonSessionStore, c) ?: notFound("user")
        }
        recordUser(c, actor, updated.principal, updateSummary("user", current.principal, updated.principal))
        return updated
    }

    fun deprovisionUser(principal: String, actor: AuditActor): DeleteResult =
        dataSource.inTx { deprovisionUser(principal, actor, it) }

    fun deprovisionUser(id: Long, actor: AuditActor): DeleteResult = dataSource.inTx { c ->
        deprovisionUser(store.getUser(id, c) ?: notFound("user"), actor, c)
    }

    fun deprovisionUser(principal: String, actor: AuditActor, c: Connection): DeleteResult {
        required("principal", principal)
        return deprovisionUser(store.getUserByPrincipal(principal, c) ?: notFound("user"), actor, c)
    }

    private fun deprovisionUser(current: AppUser, actor: AuditActor, c: Connection): DeleteResult {
        val deleted = DeleteResult(store.deleteUser(current.id, tokenStore, accessStore, daemonSessionStore, c))
        if (deleted.deleted) recordUser(c, actor, current.principal, "deprovision user '${current.principal}'")
        return deleted
    }

    private fun recordUser(c: Connection, actor: AuditActor, principal: String, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_IDENTITY, auditEntity("User", principal), summary)

    fun createGroup(input: AppGroupInput, actor: AuditActor): AppGroup = dataSource.inTx { createGroup(input, actor, it) }

    fun createGroup(input: AppGroupInput, actor: AuditActor, c: Connection): AppGroup {
        required("name", input.name)
        val created = unique("group", input.name) { store.createGroup(input, c) }
        recordGroup(c, actor, created.name, "create group '${created.name}'")
        return created
    }

    fun updateGroup(currentName: String, newName: String?, description: String?, actor: AuditActor): AppGroup =
        dataSource.inTx { updateGroup(currentName, newName, description, actor, it) }

    fun updateGroup(id: Long, input: AppGroupInput, actor: AuditActor): AppGroup = dataSource.inTx { c ->
        val current = store.getGroup(id, c) ?: notFound("group")
        rejectSystem(current, c)
        required("name", input.name)
        val updated = unique("group", input.name) { store.updateGroup(id, input, c) ?: notFound("group") }
        recordGroup(c, actor, updated.name, updateSummary("group", current.name, updated.name))
        updated
    }

    fun updateGroup(
        currentName: String,
        newName: String?,
        description: String?,
        actor: AuditActor,
        c: Connection,
    ): AppGroup {
        required("name", currentName)
        val current = group(currentName, c)
        rejectSystem(current, c)
        val targetName = newName ?: currentName
        required("newName", targetName)
        val updated = unique("group", targetName) {
            store.updateGroup(current.id, AppGroupInput(targetName, description), c) ?: notFound("group")
        }
        recordGroup(c, actor, updated.name, updateSummary("group", current.name, updated.name))
        return updated
    }

    fun deleteGroup(name: String, actor: AuditActor): DeleteResult = dataSource.inTx { deleteGroup(name, actor, it) }

    fun deleteGroup(id: Long, actor: AuditActor): DeleteResult = dataSource.inTx { c ->
        val current = store.getGroup(id, c) ?: notFound("group")
        rejectSystem(current, c)
        deleteGroup(current, actor, c)
    }

    fun deleteGroup(name: String, actor: AuditActor, c: Connection): DeleteResult {
        required("name", name)
        val current = group(name, c)
        rejectSystem(current, c)
        return deleteGroup(current, actor, c)
    }

    private fun deleteGroup(current: AppGroup, actor: AuditActor, c: Connection): DeleteResult {
        val deleted = DeleteResult(store.deleteGroup(current.id, c))
        if (deleted.deleted) recordGroup(c, actor, current.name, "delete group '${current.name}'")
        return deleted
    }

    private fun recordGroup(c: Connection, actor: AuditActor, name: String, summary: String) =
        recorder.record(c, actor, AuthzAction.ADMIN_IDENTITY, auditEntity("Group", name), summary)

    fun addGroupMember(groupName: String, principal: String, actor: AuditActor): GroupMemberEntry =
        dataSource.inTx { addGroupMember(groupName, principal, actor, it) }

    fun addGroupMember(groupId: Long, userId: Long, actor: AuditActor): GroupMemberEntry = dataSource.inTx { c ->
        val group = store.getGroup(groupId, c) ?: notFound("group")
        rejectSystem(group, c)
        val user = store.getUser(userId, c) ?: notFound("user")
        if (store.addMember(group.id, user.id, c)) recordMember(c, actor, group.name, user.principal, added = true)
        store.listMembers(group.id, c).first { it.userId == user.id }
    }

    fun addGroupMember(groupName: String, principal: String, actor: AuditActor, c: Connection): GroupMemberEntry {
        required("groupName", groupName)
        required("principal", principal)
        val group = group(groupName, c)
        rejectSystem(group, c)
        val user = store.getUserByPrincipal(principal, c) ?: notFound("user")
        if (store.addMember(group.id, user.id, c)) recordMember(c, actor, group.name, user.principal, added = true)
        return store.listMembers(group.id, c).first { it.userId == user.id }
    }

    fun removeGroupMember(groupName: String, principal: String, actor: AuditActor): DeleteResult =
        dataSource.inTx { removeGroupMember(groupName, principal, actor, it) }

    fun removeGroupMember(groupId: Long, userId: Long, actor: AuditActor): DeleteResult = dataSource.inTx { c ->
        val group = store.getGroup(groupId, c) ?: notFound("group")
        rejectSystem(group, c)
        val user = store.getUser(userId, c) ?: notFound("user")
        removeMember(group, user.principal, user.id, actor, c)
    }

    fun removeGroupMember(groupName: String, principal: String, actor: AuditActor, c: Connection): DeleteResult {
        required("groupName", groupName)
        required("principal", principal)
        val group = group(groupName, c)
        rejectSystem(group, c)
        val user = store.getUserByPrincipal(principal, c) ?: notFound("user")
        return removeMember(group, user.principal, user.id, actor, c)
    }

    private fun removeMember(
        group: AppGroup,
        principal: String,
        userId: Long,
        actor: AuditActor,
        c: Connection,
    ): DeleteResult {
        val deleted = DeleteResult(store.removeMember(group.id, userId, c))
        if (deleted.deleted) recordMember(c, actor, group.name, principal, added = false)
        return deleted
    }

    private fun recordMember(
        c: Connection,
        actor: AuditActor,
        groupName: String,
        principal: String,
        added: Boolean,
    ) = recordGroup(
        c, actor, groupName,
        if (added) "add '$principal' to group '$groupName'" else "remove '$principal' from group '$groupName'",
    )

    fun setGroupRoles(groupName: String, roleNames: Set<String>, actor: AuditActor): GroupRolesResult =
        dataSource.inTx { setGroupRoles(groupName, roleNames, actor, it) }

    fun addGroupRole(groupId: Long, roleId: Long, actor: AuditActor): GroupRoleEntry = dataSource.inTx { c ->
        val groupName = lockMutableGroup(groupId, c)
        val role = policyStore.getRole(roleId, c) ?: notFound("role")
        if (store.addGroupRole(groupId, role.id, c)) recordGroup(c, actor, groupName, "add role '${role.name}' to group '$groupName'")
        GroupRoleEntry(role.id, role.name)
    }

    fun removeGroupRole(groupId: Long, roleId: Long, actor: AuditActor): DeleteResult = dataSource.inTx { c ->
        val groupName = lockMutableGroup(groupId, c)
        val role = policyStore.getRole(roleId, c) ?: notFound("role")
        DeleteResult(store.removeGroupRole(groupId, role.id, c)).also { deleted ->
            if (deleted.deleted) {
                recordGroup(c, actor, groupName, "remove role '${role.name}' from group '$groupName'")
            }
        }
    }

    fun setGroupRoles(
        groupName: String,
        roleNames: Set<String>,
        actor: AuditActor,
        c: Connection,
    ): GroupRolesResult {
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
        val result = GroupRolesResult(groupName, store.listGroupRoles(group.first, c).map(GroupRoleEntry::roleName))
        recordGroup(c, actor, groupName, "set group '$groupName' roles [${result.roleNames.joinToString(", ")}]")
        return result
    }

    private fun group(name: String, c: Connection): AppGroup = store.getGroupByName(name, c) ?: notFound("group")

    /**
     * Locks the `app_group` row, not just reading it: [setGroupRoles] holds the same lock while it lists
     * the current roles and writes the difference, so a single-role add or remove that skipped the lock
     * could land inside that window and be silently reverted by the diff.
     */
    /** Row-lock a mutable (non-SYSTEM) group, returning its name for the audit summary. */
    private fun lockMutableGroup(id: Long, c: Connection): String {
        val (source, name) = c.prepareStatement("SELECT source, name FROM app_group WHERE id = ? FOR UPDATE").use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { result ->
                if (result.next()) result.getString("source") to result.getString("name") else notFound("group")
            }
        }
        if (source == "SYSTEM") throw ManagementException(ApiError("group.system_immutable"))
        return name
    }

    private fun rejectSystem(group: AppGroup, c: Connection) {
        if (store.isSystemGroup(group.id, c)) throw ManagementException(ApiError("group.system_immutable"))
    }
}

private fun updateSummary(type: String, before: String, after: String): String =
    if (before == after) "update $type '$before'" else "update $type '$before' -> '$after'"

private fun Classification.path(): String = "$schema.$table.$column"

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
