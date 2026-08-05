package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import javax.sql.DataSource

/**
 * The single shared enforcement dependency graph, built ONCE and used by BOTH surfaces — the HTTP API
 * ([Application.module]) and the gRPC service the proxy talks to (docs/datasource-registration.md).
 *
 * Sharing is mandatory, not an optimization. [CedarEngine] caches its compiled `PolicySet` and rebuilds
 * only when [CedarPolicyStore.stateVersion] moves — and that version is an in-memory `AtomicLong` bumped
 * on the *same instance* that commits a policy mutation. Two separate graphs would each keep their own
 * counter, so a policy edited through the HTTP admin API would never invalidate a second (gRPC-side)
 * engine's cache: its authorization decisions would go silently, permanently stale. One graph → one
 * cache → one version counter → HTTP edits and gRPC decisions always agree.
 *
 * Only the enforcement-decision dependencies live here (the ones both surfaces share). HTTP-only stores
 * (query history, approval policy, OIDC, at-rest crypto, …) stay local to [Application.module].
 */
class ControlPlaneCore(val dataSource: DataSource) {
    val auditStore = AuditStore(dataSource)
    val authAudit = AuthAuditRecorder(auditStore)
    val datasourceStore = DatasourceStore(dataSource)
    val policyStore = PolicyStore(dataSource)
    val accessStore = AccessStore(dataSource)
    val userGroupStore = UserGroupStore(dataSource)
    val tokenStore = TokenStore(dataSource)
    val mcpTokenStore = com.ridi.oss.proxymonster.auth.McpTokenStore(dataSource)
    val roleResolver = RoleResolver(dataSource, userGroupStore, accessStore)
    val cedarPolicyStore = CedarPolicyStore(dataSource)
    val cedarEngine = CedarEngine(cedarPolicyStore)
    val authz = Authz(cedarEngine, cedarPolicyStore, RoleSource { p -> roleResolver.resolve(p) })

    // System classification (docs/system-classification.md). Loads + validates the bundled
    // manifests at boot (a malformed manifest aborts startup); classifies system Tables into system: tags
    // keyed off datasource.engine_version. Fallback off by default (an uncertified major → deny-by-default).
    val systemClassification = SystemClassificationService()

    // Open proxy Events streams (docs/datasource-registration.md) — liveness + refresh/run push.
    // Shared so the gRPC handlers and the HTTP routes agree on attached proxies and pending run dials.
    val proxyEventsHub = ProxyEventsHub()
    val connectionCatalog = ConnectionCatalogRegistry()
    val runChannels = RunChannelRegistry()
    val tableDetailChannels = TableDetailChannelRegistry()

    // The HTTP requester IP observed when an ephemeral EDITOR/
    // APPROVER_EXEC token was minted (docs/authz-context.md), keyed by token hash — the async decide-time carrier the gRPC decide
    // handler reads (RunExec.kt's [RequesterIpRegistry] doc has the full rationale). Lives here for the
    // SAME reason [runChannels] does: [com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService]
    // is constructed independently in Main.kt, before Application.module's RunExecService exists.
    val runRequesterIps = RequesterIpRegistry()
}
