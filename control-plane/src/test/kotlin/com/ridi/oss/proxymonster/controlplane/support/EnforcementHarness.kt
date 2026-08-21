package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.DecisionContext
import com.ridi.oss.proxymonster.controlplane.MASK_BIND_DENY
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.QueryResponse
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.SystemClassificationService
import com.ridi.oss.proxymonster.controlplane.UserGroupStore
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.decideQuery
import com.ridi.oss.proxymonster.controlplane.fingerprintOf
import com.ridi.oss.proxymonster.controlplane.decisionRecord
import com.ridi.oss.proxymonster.controlplane.parseRequesterIp
import com.ridi.oss.proxymonster.probe.Masking
import com.ridi.oss.proxymonster.probe.bindMasks
import java.sql.DriverManager

/**
 * Raw target result — the shape [runEnforcedForTest] returns from a connection the TEST owns. Test-only:
 * the control-plane does not dial the target; the proxy executes queries.
 */
data class QueryRows(val columns: List<String>, val rows: List<List<String?>>, val rowsAffected: Int? = null)

/** Thrown when the test-owned target query itself fails (distinct from a policy DENY). */
class TargetQueryException(message: String) : Exception(message)

/**
 * Config-catalog decision+audit path. The production gRPC wire path is now [com.ridi.oss.proxymonster.controlplane.decideConnection]
 * (per-connection held fragments) — this reads the GLOBAL catalog (`datasourceStore.catalog`) and so is kept
 * strictly in test scope, where SchemaThreadingDbTest uses it to prove live-search-path → audit
 * `effectiveNamespace` threading. It must never be wired back onto the enforcing path (the whole point of
 * the per-connection catalog is that the enforcing path can never read the global catalog). Resolves roles server-side,
 * selects `requester_ip` by channel (WIRE = the proxy-attested socket; editor/workflow = the HTTP carrier),
 * runs the decision under [principal] + the live [searchPath], audits, and returns the verdict + audit id.
 */
fun decideAndAudit(
    core: ControlPlaneCore,
    principal: String,
    ds: Datasource,
    sql: String,
    searchPath: List<String>?,
    clientAddr: String?,
    channel: Channel = Channel.WIRE,
    providedRoles: Set<String>? = null,
    tempColumns: List<CatalogColumn> = emptyList(),
    httpRequesterIp: String? = null,
): Pair<DecisionContext, Long> {
    val t0 = System.nanoTime()
    val requesterIp = when (channel) {
        Channel.WIRE -> parseRequesterIp(clientAddr)
        else -> httpRequesterIp
    }
    val ctx = decideQuery(
        principal, ds, sql, channel,
        core.datasourceStore.catalog(ds.id), core.policyStore, core.accessStore, core.userGroupStore, core.roleResolver, core.authz,
        providedRoles = providedRoles,
        tempColumns = tempColumns,
        context = AuthzContext(requesterIp = requesterIp),
        liveSearchPath = searchPath,
        systemClassification = core.systemClassification,
    )
    val ms = (System.nanoTime() - t0) / 1_000_000
    val decisionId = core.auditStore.insert(
        decisionRecord(principal, ds, sql, clientAddr, ctx, ms, searchPath ?: ds.defaultSchemas, channel),
    )
    return ctx to decisionId
}

/**
 * Execute [sql] against a target over a throwaway JDBC connection the TEST owns (Testcontainers creds),
 * capped at [maxRows]. Mirrors the deleted `DatasourceStore.runQuery` body so the enforcement suite can
 * still drive decide → execute → mask end-to-end against a real database without standing up a proxy.
 */
fun execOnTarget(jdbcUrl: String, user: String, password: String, sql: String, maxRows: Int): QueryRows =
    DriverManager.getConnection(jdbcUrl, user, password).use { c ->
        c.createStatement().use { st ->
            st.maxRows = maxRows
            val hasRs = st.execute(sql)
            if (!hasRs) return QueryRows(emptyList(), emptyList(), st.updateCount)
            st.resultSet.use { rs ->
                val md = rs.metaData
                val n = md.columnCount
                val cols = (1..n).map { md.getColumnLabel(it) }
                val out = ArrayList<List<String?>>()
                while (rs.next()) out += (1..n).map { rs.getString(it) }
                QueryRows(cols, out)
            }
        }
    }

/**
 * The in-process decide → execute → mask composition, kept as a TEST
 * harness so the enforcement suite exercises the full decide + mask/deny pipeline against a real
 * target. [execute] runs on a connection the test owns; the control-plane itself does not dial the
 * target (the proxy executes queries), and holds no service credentials.
 */
fun runEnforcedForTest(
    principal: String,
    ds: Datasource,
    sql: String,
    maxRows: Int,
    clientAddr: String?,
    datasourceStore: DatasourceStore,
    policyStore: PolicyStore,
    auditStore: AuditStore,
    accessStore: AccessStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    systemClassification: SystemClassificationService? = null,
    execute: (sql: String, maxRows: Int) -> QueryRows,
): QueryResponse {
    val started = System.nanoTime()
    val ctx = decideQuery(
        principal, ds, sql, Channel.EDITOR, datasourceStore.catalog(ds.id), policyStore, accessStore, userGroupStore, roleResolver, authz,
        systemClassification = systemClassification,
    )

    if (ctx.action == EnfAction.DENY) {
        val ms = (System.nanoTime() - started) / 1_000_000
        val decisionId = auditStore.insert(decisionRecord(principal, ds, sql, clientAddr, ctx, ms, ds.defaultSchemas, Channel.EDITOR))
        return QueryResponse(
            EnfAction.DENY, decisionId = decisionId, denyReason = ctx.denyReason,
            piiTouched = ctx.piiTouched, effectiveRoles = ctx.effectiveRoles, latencyMs = ms,
        )
    }

    val rows = try {
        // Run the `*`-expanded query when one was produced, so JDBC result columns arrive in the exact
        // order ctx.masks index — robust even if the catalog's column order has drifted. Null -> verbatim.
        execute(ctx.rewrittenSql ?: sql, maxRows.coerceIn(1, 5000))
    } catch (e: Exception) {
        throw TargetQueryException(e.message ?: e.javaClass.simpleName)
    }
    val binding = bindMasks(ctx.masks, rows.columns.size)
    val ms = (System.nanoTime() - started) / 1_000_000
    if (!binding.allBound) {
        val denyCtx = ctx.copy(action = EnfAction.DENY, denyReason = MASK_BIND_DENY, detail = MASK_BIND_DENY, failedStage = "mask-binding")
        val decisionId = auditStore.insert(decisionRecord(principal, ds, sql, clientAddr, denyCtx, ms, ds.defaultSchemas, Channel.EDITOR))
        return QueryResponse(
            EnfAction.DENY, decisionId = decisionId, denyReason = MASK_BIND_DENY,
            piiTouched = ctx.piiTouched, effectiveRoles = ctx.effectiveRoles, latencyMs = ms,
        )
    }
    val decisionId = auditStore.insert(decisionRecord(principal, ds, sql, clientAddr, ctx, ms, ds.defaultSchemas, Channel.EDITOR))
    val maskedRows = if (binding.byIndex.isEmpty()) rows.rows else rows.rows.map { row ->
        // An index with no bound mask keeps its value; a masked index takes Masking.apply's result, which
        // is null for a full redaction (kind NULL). Not `?: v` — that would fall a redacted-to-null cell
        // back to the cleartext value (the bug a derived-masking NULL redaction would otherwise hit).
        row.mapIndexed { i, v ->
            val kind = binding.byIndex[i]
            if (kind == null) v else Masking.apply(v, kind)
        }
    }
    return QueryResponse(
        decision = ctx.action, decisionId = decisionId, maskedColumns = ctx.masks.map { it.column }, piiTouched = ctx.piiTouched,
        effectiveRoles = ctx.effectiveRoles, columns = rows.columns, rows = maskedRows,
        rowsAffected = rows.rowsAffected, resultFingerprint = fingerprintOf(ctx.resultFingerprint), latencyMs = ms,
    )
}
