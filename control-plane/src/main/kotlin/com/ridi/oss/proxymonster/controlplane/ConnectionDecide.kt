package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.Refetch

sealed interface EnforcementOutcome {
    data class Verdict(
        val ctx: DecisionContext,
        val decisionId: Long,
        val generation: Long,
        val afterStatement: List<Refetch>,
    ) : EnforcementOutcome

    data class BeforeDecide(val commands: List<Refetch>) : EnforcementOutcome
}

/**
 * Connection-scoped decide orchestration. The registry mutex is held from freshness pre-gate through audit and
 * verdict emission, so the generation stamped on a verdict is exactly the generation analyzed (the
 * connection's compare-and-set on the decision generation).
 */
suspend fun decideConnection(
    core: ControlPlaneCore,
    connectionId: ByteString,
    principal: String,
    ds: Datasource,
    sql: String,
    searchPath: List<String>,
    clientAddr: String?,
    ansiQuotes: Boolean = false,
    channel: Channel = Channel.WIRE,
    providedRoles: Set<String>? = null,
    tempColumns: List<CatalogColumn> = emptyList(),
    httpRequesterIp: String? = null,
    postgresFunctionShadowingObserved: Boolean = false,
    postgresShadowedFunctions: List<String> = emptyList(),
    postgresSystemXidVisible: Boolean? = null,
): EnforcementOutcome? = core.connectionCatalog.withConnection(connectionId) { connection ->
    // Snapshot the generation at entry; the registry mutex is held through analysis + audit, so only an
    // applyPush (which needs the same mutex) can bump it — impossible mid-flow. Stamping the entry value and
    // asserting it is unchanged at emit is the connection's compare-and-set on the decision generation,
    // and guards against a future edit bumping it under us.
    val generationAtEntry = connection.generation
    val required = searchPath.filterNot { it.startsWith("pg_temp", ignoreCase = true) }
    val preGate = core.connectionCatalog.freshnessGate(connection, required)
    if (preGate.isNotEmpty()) {
        return@withConnection EnforcementOutcome.BeforeDecide(
            core.connectionCatalog.markBeforeDecide(connection, preGate),
        )
    }

    val catalogName = ds.engine.catalogName(ds.dbName)
    val classifications = core.datasourceStore.classificationsFor(ds.id)
    val catalog = core.connectionCatalog.structuralRows(connection).map { row ->
        CatalogColumn(
            catalog = catalogName,
            schema = row.schema,
            table = row.table,
            column = row.column,
            dataType = row.dataType,
            sqlType = sqlTypeFor(row.dataType),
            ordinal = row.ordinal,
            nullable = row.nullable,
            classification = classifications[Triple(row.schema, row.table, row.column)],
        )
    }

    val t0 = System.nanoTime()
    // requester_ip's source is selected by CHANNEL, never nullable fallback: WIRE attests the client socket;
    // editor/workflow channels use only the HTTP carrier recorded when the CP minted their token.
    val requesterIp = when (channel) {
        Channel.WIRE -> parseRequesterIp(clientAddr)
        else -> httpRequesterIp
    }
    val ctx = decideQuery(
        principal = principal,
        ds = ds,
        sql = sql,
        channel = channel,
        catalog = catalog,
        policyStore = core.policyStore,
        accessStore = core.accessStore,
        userGroupStore = core.userGroupStore,
        roleResolver = core.roleResolver,
        authz = core.authz,
        providedRoles = providedRoles,
        context = AuthzContext(requesterIp = requesterIp),
        liveSearchPath = searchPath,
        liveAnsiQuotes = ansiQuotes,
        postgresFunctionShadowingObserved = postgresFunctionShadowingObserved,
        postgresShadowedFunctions = postgresShadowedFunctions,
        postgresSystemXidVisible = postgresSystemXidVisible,
        systemClassification = core.systemClassification,
        tempColumns = tempColumns,
    )

    val postGate = core.connectionCatalog.freshnessGate(connection, ctx.referencedSchemas)
    if (postGate.isNotEmpty()) {
        return@withConnection EnforcementOutcome.BeforeDecide(
            core.connectionCatalog.markBeforeDecide(connection, postGate),
        )
    }
    if (ctx.catalogMiss) {
        val fresh = core.connectionCatalog.heldAndFreshSchemas(connection)
        val candidates = ctx.schemaCandidates.filterNotTo(LinkedHashSet()) { it in fresh }
        if (candidates.isNotEmpty()) {
            return@withConnection EnforcementOutcome.BeforeDecide(
                core.connectionCatalog.markCatalogMiss(connection, candidates),
            )
        }
    }

    val wireGateDenied = channel == Channel.WIRE && !autoApproveTask(
        principal,
        ctx.effectiveRoles.toSet(),
        ds,
        AuthzContext(requesterIp = requesterIp),
        core.authz,
        Channel.WIRE,
    )
    val effectiveCtx = if (wireGateDenied) {
        wireTaskForbiddenDeny(ctx.effectiveRoles, ctx.contextTags)
    } else {
        ctx
    }
    val afterStatement = if (effectiveCtx.action != EnfAction.DENY && effectiveCtx.catalogChanging) {
        // schemaCandidates too: DDL reads no column, so its target schema appears in no source or read
        // grant, and a cross-schema `ALTER` would leave the schema it just changed held and stale.
        core.connectionCatalog.markAfterStatement(
            connection,
            required + effectiveCtx.referencedSchemas + effectiveCtx.schemaCandidates,
        )
    } else {
        emptyList()
    }
    val ms = (System.nanoTime() - t0) / 1_000_000
    val decisionRecord = decisionRecord(principal, ds, sql, clientAddr, effectiveCtx, ms, searchPath, channel)
    val decisionId = if (channel == Channel.WIRE) {
        core.dataSource.inTx { conn ->
            val id = core.auditStore.insert(conn, decisionRecord)
            if (!wireGateDenied) {
                // Each native-wire Decide creates one childless task. ALLOW/MASK authorize here, but the
                // proxy's post-relay completion confirms execution and terminalizes them later. A DENY relays
                // nothing and produces no completion, so fail its task inline. Keeping the decision and task
                // in one transaction prevents either record from existing without the other. The extra insert
                // under the audit chain-head lock is acceptable for this per-statement path's traffic volume.
                val taskId = core.accessStore.createWireTask(
                    conn,
                    principal,
                    ds.id,
                    ctx.effectiveRoles,
                    id,
                )
                if (effectiveCtx.action == EnfAction.DENY) {
                    check(core.accessStore.claimExecution(taskId, conn)) { "new wire task $taskId was not claimable" }
                    check(core.accessStore.markFailed(taskId, conn)) { "wire task $taskId left EXECUTING" }
                }
            }
            id
        }
    } else {
        core.auditStore.insert(decisionRecord)
    }
    check(connection.generation == generationAtEntry) { "connection generation changed during serialized decide" }
    EnforcementOutcome.Verdict(effectiveCtx, decisionId, generationAtEntry, afterStatement)
}
