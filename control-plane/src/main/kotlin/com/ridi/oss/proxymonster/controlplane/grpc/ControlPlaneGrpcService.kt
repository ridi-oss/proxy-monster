package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.Attached
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_WIRE_VALIDATE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_WIRE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.PRINCIPAL_UNATTRIBUTED
import com.ridi.oss.proxymonster.controlplane.auditedValue
import com.ridi.oss.proxymonster.controlplane.AttachedTableDetail
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.FragmentColumn
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.CatalogMutationResult
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.DatasourceEngineConflictException
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.catalogIsConnectionIndependent
import com.ridi.oss.proxymonster.controlplane.catalogName
import com.ridi.oss.proxymonster.controlplane.EnforcementOutcome
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.TokenKind
import com.ridi.oss.proxymonster.controlplane.decideConnection
import com.ridi.oss.proxymonster.controlplane.inTx
import com.ridi.oss.proxymonster.controlplane.systemSchemas
import com.ridi.oss.proxymonster.controlplane.tokenHash
import com.google.protobuf.Empty
import com.ridi.oss.proxymonster.grpc.CatalogRequest
import com.ridi.oss.proxymonster.grpc.CatalogResponse
import com.ridi.oss.proxymonster.grpc.CloseConnectionRequest
import com.ridi.oss.proxymonster.grpc.CloseConnectionResponse
import com.ridi.oss.proxymonster.grpc.CompletionReport
import com.ridi.oss.proxymonster.grpc.ControlRunMsg
import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg
import com.ridi.oss.proxymonster.grpc.DecisionRequest
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.EventsRequest
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.ProxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.RegisterRequest
import com.ridi.oss.proxymonster.grpc.RegisterResponse
import com.ridi.oss.proxymonster.grpc.SchemaFragmentAck
import com.ridi.oss.proxymonster.grpc.SchemaFragmentPush
import com.ridi.oss.proxymonster.grpc.TempColumn
import com.ridi.oss.proxymonster.grpc.ValidateTokenRequest
import com.ridi.oss.proxymonster.grpc.WireDecision
import com.ridi.oss.proxymonster.grpc.WireIdentity
import com.ridi.oss.proxymonster.grpc.catalogResponse
import com.ridi.oss.proxymonster.grpc.closeConnectionResponse
import com.ridi.oss.proxymonster.grpc.proxyCommand
import com.ridi.oss.proxymonster.grpc.registerResponse
import com.ridi.oss.proxymonster.grpc.schemaFragmentAck
import com.ridi.oss.proxymonster.grpc.wireIdentity
import io.grpc.Status
import io.grpc.StatusException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

// The run handler bounds only the wait for the FIRST frame (the run's id): a proxy that opens a stream but
// never identifies its run, or never closes, must not park the handler forever. Once a stream is attached to
// its run there is no fixed overall cap — its lifetime is the run's or session's own (see runExec). This
// backstop sits above RUN_DIALBACK_TIMEOUT_MS so the caller's own dial-back timeout reports first on a live
// run; it only reaps a handler the caller has already given up on.
internal const val RUN_FIRST_FRAME_TIMEOUT_MS = 30_000L
private const val TABLE_DETAIL_STREAM_TIMEOUT_MS = 60_000L
// The proxy<->control-plane wire-protocol version this control-plane speaks, exchanged at Register so a
// half-finished rollout (proxy and control-plane on different server-v* releases) fails fast with a clear
// error instead of a stalled run channel. Bump it on any incompatible wire change. It MUST match the proxy's
// goproxy cp.ProtocolVersion; the two are separate constants in separate languages kept in lockstep by hand —
// a server-v* release always ships both at the same value.
internal const val CONTROL_PROTOCOL_VERSION = 2

// The completion-event terminal statuses the proxy reports: a clean finish, a target DB/relay error carrying
// partial counts, or a canceled statement. Any other value is rejected fail-closed so a malformed report
// can't write an uninterpretable outcome into the audit trail.
private val COMPLETION_STATUSES = setOf("ok", "error", "canceled")

/**
 * Build the session-temp overlay from a decide request's proxy-supplied [temps], applying BOTH
 * trust gates before any column can be read UNMASKED (an overlay column is read without a Cedar grant and
 * skips the uncovered-scan gate, so it is load-bearing that only genuine session temps reach it):
 *  - **channel gate** — temps are only legitimate on the [Channel.EDITOR] path (a persistent editor session
 *    holds the target-DB connection whose temps these are). A wire / approver-exec decision carrying
 *    temp_columns is a buggy or compromised proxy: drop them all rather than grant the unmask on a channel
 *    that was never analyzed for it (the native-wire/one-shot proxies never send temps).
 *  - **pg_temp\* filter** — a temp overlay entry names a schema read unmasked, so it must be an actual
 *    session-temp namespace. Drop anything whose schema isn't `pg_temp*`, so a proxy cannot unmask a real
 *    table (e.g. `public.users`) by mislabeling it a temp. Postgres reserves the `pg_` prefix, so no real
 *    schema is ever named `pg_temp*`.
 * The catalog segment must match the analyzer namespace's (PG: the database name; MySQL: "def") so a temp
 * key aligns with the base-catalog keys.
 */
internal fun editorTempOverlay(
    channel: Channel,
    temps: List<TempColumn>,
    engine: Engine,
    dbName: String,
): List<CatalogColumn> {
    if (channel != Channel.EDITOR || temps.isEmpty()) return emptyList()
    val catalogName = engine.catalogName(dbName)
    return temps
        .filter { it.schema.startsWith("pg_temp") }
        .map { t ->
            CatalogColumn(
                catalog = catalogName, schema = t.schema, table = t.table, column = t.column,
                dataType = t.sqlType, sqlType = t.sqlType, ordinal = t.ordinal, nullable = true,
                isTemp = true,
            )
        }
}

/**
 * The control-plane's gRPC `ControlPlane` service (docs/datasource-registration.md), backed by the
 * shared [ControlPlaneCore] — the SAME store/authz graph the HTTP surface uses, so policy edits made
 * through the web API are seen by these decisions (see ControlPlaneCore for why sharing is mandatory).
 *
 * The hot path is [validateToken] (session handshake) and [decide] (per-query
 * enforcement, re-validating the raw token EVERY call so a revoked token or deprovisioned principal
 * loses access on the next query, not at session end). [register]/[pushCatalog] keep the datasource
 * catalog current and [events] carries the liveness + refresh/run push stream.
 */
class ControlPlaneGrpcService(
    private val core: ControlPlaneCore,
    private val firstFrameTimeoutMs: Long = RUN_FIRST_FRAME_TIMEOUT_MS,
) :
    ControlPlaneGrpcKt.ControlPlaneCoroutineImplBase() {

    private val log = org.slf4j.LoggerFactory.getLogger(ControlPlaneGrpcService::class.java)

    /**
     * Record a rejected wire credential. The proxy carries the end-client address on [ValidateTokenRequest],
     * stored raw (blank→null), exactly as the decide audit row stores it. The requested datasource is
     * caller-supplied and unvalidated at this point, so it is bounded and confined to `detail` rather than
     * naming the resource.
     */
    private fun auditWireRejection(request: ValidateTokenRequest, principal: String?, reason: String) {
        // Best-effort: this rejection changes no state, and validateToken is the hot wire path — an audit
        // insert that throws (the chain-head lock, a broken chain) must not replace UNAUTHENTICATED with
        // INTERNAL, which every bad token got before this trail existed.
        core.authAudit.failureBestEffort(
            AuditActor(principal ?: PRINCIPAL_UNATTRIBUTED, clientAddr = request.clientAddr.ifBlank { null }, channel = CHANNEL_WIRE),
            ACTION_WIRE_VALIDATE,
            if (principal == null) auditEntity("Token", "unresolved") else auditEntity("User", principal),
            "Wire token validation failed",
            detail = "datasource=${auditedValue(request.datasourceName)};reason=$reason",
        )
    }

    override suspend fun validateToken(request: ValidateTokenRequest): WireIdentity {
        val id = core.tokenStore.validate(request.token)
        if (id == null) {
            // validate() collapses invalid/expired/revoked into one null, and none of them names a
            // principal — hence one reason covering the set, and no attribution.
            auditWireRejection(request, principal = null, reason = "invalid_expired_or_revoked")
            throw StatusException(Status.UNAUTHENTICATED.withDescription("invalid, expired, or revoked wire token"))
        }
        if (core.userGroupStore.isDeactivated(id.principal)) {
            auditWireRejection(request, id.principal, reason = "principal_deprovisioned")
            throw StatusException(Status.UNAUTHENTICATED.withDescription("principal is deprovisioned"))
        }
        if (request.datasourceName.isBlank()) {
            throw StatusException(Status.INVALID_ARGUMENT.withDescription("datasource_name must not be blank"))
        }
        val ds = core.datasourceStore.getByName(request.datasourceName)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown datasource '${request.datasourceName}'"))
        val opened = core.connectionCatalog.open(
            Binding(ds.name, id.principal, id.kind),
            ds.defaultSchemas + ds.engine.systemSchemas,
            adoptHeldContent = ds.engine.catalogIsConnectionIndependent,
        )
        return wireIdentity {
            principal = id.principal
            roles.addAll(id.roles)
            connectionId = opened.connectionId
            onOpen.addAll(opened.onOpen.map { proxyCommand { refetch = it } })
        }
    }

    override suspend fun decide(request: DecisionRequest): WireDecision {
        // Re-validate the RAW token on every query so a mid-session revocation takes effect on the next
        // query, not at session end — the proxy-asserted principal is never trusted for the life of the
        // connection. Read-only (resolve, not validate) so the per-query check doesn't
        // serialize concurrent queries on the token row's last_used_at write. An authN failure
        // (bad/revoked/expired token, deprovisioned principal) is UNAUTHENTICATED so the proxy can tear
        // the session down, distinct from an authZ policy DENY.
        val id = core.tokenStore.resolve(request.token)
            ?: throw StatusException(Status.UNAUTHENTICATED.withDescription("invalid, expired, or revoked wire token"))
        if (core.userGroupStore.isDeactivated(id.principal)) {
            throw StatusException(Status.UNAUTHENTICATED.withDescription("principal is deprovisioned"))
        }
        val ds = core.datasourceStore.getByName(request.datasourceName)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown datasource '${request.datasourceName}'"))
        // The proxy always sends its live namespace. Pass search_path through verbatim — do NOT
        // collapse an empty list to the datasource default: treating "absent = default" would be
        // fail-OPEN here, since a failed/empty namespace probe would authorize against the stored
        // default (possibly the wrong schema). An empty namespace reaches decideQuery as-is and resolves
        // fail-closed (unqualified references can't resolve -> DENY).
        val clientAddr = request.clientAddr.ifBlank { null }
        // Derive the channel and assume-role set from the resolved token's KIND (the
        // control-plane minted it; the proxy can't assert it). A native-wire token (SESSION/USER) is
        // channel=wire, and its roles are ALWAYS resolved server-side (never taken from the token). The
        // ephemeral editor/approver-exec kinds map to editor/workflow-executor; only they may carry a
        // CP-computed assume-role set (execute-under-R).
        val kind = TokenKind.fromWire(id.kind)
            ?: throw StatusException(Status.UNAUTHENTICATED.withDescription("token kind is not valid for query decisions"))
        val assumeRoles = if (kind == TokenKind.EDITOR || kind == TokenKind.APPROVER_EXEC) {
            id.roles.toSet().takeIf { it.isNotEmpty() }
        } else {
            null
        }
        val channel = when (kind) {
            TokenKind.SESSION, TokenKind.USER -> Channel.WIRE
            TokenKind.EDITOR -> Channel.EDITOR
            // workflow-executor (where a policy may unmask R at execute) is reachable ONLY by an approver-exec
            // token that actually carries an assume-role set (execute-under-R). A no-R approver-exec (approver
            // runs as themselves, no elevation) decides at the editor channel with NORMAL enforcement.
            TokenKind.APPROVER_EXEC -> if (assumeRoles != null) Channel.WORKFLOW_EXECUTOR else Channel.EDITOR
        }
        // The connection's session/temp columns, overlaid onto the base catalog. Both trust
        // gates (EDITOR-channel-only + pg_temp* filter) live in [editorTempOverlay] so they're unit-testable.
        val tempColumns = editorTempOverlay(channel, request.tempColumnsList, ds.engine, ds.dbName)
        // The HTTP requester IP recorded on [ControlPlaneCore.runRequesterIps] at ephemeral
        // token mint time, keyed by this token's hash. Gated strictly on KIND (never just "an entry exists")
        // so a native-wire (SESSION/USER) token can never pick up a registry entry — the registry is only ever
        // populated for EDITOR/APPROVER_EXEC tokens, but this keeps the read itself honest about that intent.
        val httpIp = if (kind == TokenKind.EDITOR || kind == TokenKind.APPROVER_EXEC) {
            core.runRequesterIps.get(tokenHash(request.token))
        } else {
            null
        }
        if (request.connectionId.size() != 16) {
            throw StatusException(Status.INVALID_ARGUMENT.withDescription("connection_id must be exactly 16 bytes"))
        }
        val binding = Binding(ds.name, id.principal, id.kind)
        val connection = core.connectionCatalog.find(request.connectionId)
        if (connection == null) {
            val recovered = core.connectionCatalog.recover(
                request.connectionId,
                binding,
                request.searchPathList + ds.defaultSchemas + ds.engine.systemSchemas,
                adoptHeldContent = ds.engine.catalogIsConnectionIndependent,
            ) ?: throw StatusException(Status.ABORTED.withDescription("connection recovery raced with another request"))
            return beforeDecideDecision(recovered.onOpen)
        }
        if (connection.binding != binding) {
            throw StatusException(Status.FAILED_PRECONDITION.withDescription("connection binding mismatch"))
        }
        return when (
            val outcome = decideConnection(
                core, request.connectionId, id.principal, ds, request.sql, request.searchPathList,
                clientAddr, request.mysqlAnsiQuotes, channel, assumeRoles, tempColumns, httpRequesterIp = httpIp,
            ) ?: throw StatusException(Status.NOT_FOUND.withDescription("connection disappeared during Decide"))
        ) {
            is EnforcementOutcome.BeforeDecide -> beforeDecideDecision(outcome.commands)
            is EnforcementOutcome.Verdict -> outcome.ctx.toWireDecision(
                outcome.decisionId,
                outcome.generation,
                outcome.afterStatement,
            )
        }
    }

    /**
     * Record the post-relay completion as a chained audit event and the execution boundary for a native-wire
     * task. The correlated task moves APPROVED → EXECUTED on `ok`, or APPROVED → FAILED on `error`/`canceled`,
     * in the same transaction as the completion event. Decisions without a WIRE task remain audit-only, so
     * editor and workflow execution lifecycles are untouched. This handler records the proxy's outcome; it
     * never re-decides enforcement.
     *
     * The completion mirrors the referenced decision's identity fields so the row is self-describing for the
     * audit monitor and satisfies the audit schema. `decision_id` 0 is rejected, and an unknown id is
     * `NOT_FOUND`. Duplicate reports still append completion events as before; the task transition is an
     * idempotent compare-and-set and silently no-ops after the first terminal report.
     */
    override suspend fun reportCompletion(request: CompletionReport): Empty {
        if (request.decisionId == 0L) {
            throw StatusException(Status.INVALID_ARGUMENT.withDescription("decision_id must reference a recorded decision"))
        }
        val status = request.status
        if (status !in COMPLETION_STATUSES) {
            throw StatusException(
                Status.INVALID_ARGUMENT.withDescription("status must be one of ${COMPLETION_STATUSES.joinToString("|")}"),
            )
        }
        val decision = core.auditStore.get(request.decisionId)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown decision_id ${request.decisionId}"))
        val completionEvent = AuditEvent(
            principal = decision.principal,
            datasource = decision.datasource,
            statement = decision.statement,
            decision = decision.decision,
            channel = decision.channel,
            kind = "completion",
            decisionId = request.decisionId,
            rowsReturned = request.rowsReturned,
            bytesReturned = request.bytesReturned,
            outcome = status,
            latencyMs = request.durationMs,
        )
        core.dataSource.inTx { conn ->
            core.auditStore.insert(conn, completionEvent)
            core.accessStore.wireTaskIdForDecision(request.decisionId, conn)?.let { taskId ->
                if (core.accessStore.claimExecution(taskId, conn)) {
                    if (status == "ok") {
                        check(core.accessStore.markExecuted(taskId, conn)) { "wire task $taskId left EXECUTING" }
                    } else {
                        check(core.accessStore.markFailed(taskId, conn)) { "wire task $taskId left EXECUTING" }
                    }
                }
            }
        }
        return Empty.getDefaultInstance()
    }

    override suspend fun pushSchemaFragment(request: SchemaFragmentPush): SchemaFragmentAck {
        val connection = core.connectionCatalog.find(request.connectionId)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown connection_id"))
        if (request.datasourceName != connection.binding.datasourceName) {
            throw StatusException(Status.FAILED_PRECONDITION.withDescription("datasource binding mismatch"))
        }
        val ds = core.datasourceStore.getByName(request.datasourceName)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown datasource '${request.datasourceName}'"))
        return when (val result = core.connectionCatalog.applyPush(request, ds)) {
            is CatalogMutationResult.Applied -> schemaFragmentAck { generation = result.generation }
            is CatalogMutationResult.Rejected -> throw StatusException(
                Status.fromCode(result.code).withDescription(result.description),
            )
        }
    }

    override suspend fun closeConnection(request: CloseConnectionRequest): CloseConnectionResponse {
        return when (val result = core.connectionCatalog.close(request.connectionId, request.datasourceName)) {
            is CatalogMutationResult.Applied -> closeConnectionResponse { }
            is CatalogMutationResult.Rejected -> throw StatusException(
                Status.fromCode(result.code).withDescription(result.description),
            )
        }
    }

    // A server-v* release ships the proxy and control-plane at the same wire-protocol version; a mismatch
    // means a half-finished rollout is talking across versions. Register is the primary guard, but the Events
    // stream applies this too (the datasource row outlives a rejected Register). A proxy that predates the
    // field sends 0, which fails this. The proxy classifies the rejection as fatal by matching the phrase
    // "wire-protocol version" in the message (goproxy cp.protocolVersionRejectionMarker); keep that phrase.
    private fun requireCompatibleProtocolVersion(protocolVersion: Int) {
        if (protocolVersion != CONTROL_PROTOCOL_VERSION) {
            throw StatusException(
                Status.FAILED_PRECONDITION.withDescription(
                    "proxy wire-protocol version $protocolVersion is incompatible with this " +
                        "control-plane's version $CONTROL_PROTOCOL_VERSION — deploy the proxy and " +
                        "control-plane from the same server-v* release",
                ),
            )
        }
    }

    override suspend fun register(request: RegisterRequest): RegisterResponse {
        if (request.name.isBlank()) {
            throw StatusException(Status.INVALID_ARGUMENT.withDescription("datasource name must not be blank"))
        }
        // Reject a half-finished rollout talking across versions here — the proxy's first call — rather than
        // let it surface later as a stalled run channel. The proxy makes the mirror check against
        // RegisterResponse.protocol_version, so an OLDER control-plane is refused on that side.
        requireCompatibleProtocolVersion(request.protocolVersion)
        // Pass the proto Engine through as the domain type, rejecting only the invalid sentinels (the proto3
        // zero value and the generated unrecognized value) — an unset/garbage engine must not silently
        // default to postgres and mis-drive introspection/dialect resolution. Inverting the check this way
        // lets a future proto engine pass through untouched instead of being rejected by an enumeration of
        // the currently-known ones.
        val engine = when (request.engine) {
            Engine.ENGINE_UNSPECIFIED, Engine.UNRECOGNIZED -> throw StatusException(
                Status.INVALID_ARGUMENT.withDescription("engine must be POSTGRES or MYSQL"),
            )
            else -> request.engine
        }
        // The advertised chain is inspected, never refused. Whether a chain is usable is the CLIENT's
        // verification to make, and it will fail loudly on its own if it cannot build a path. Rejecting at
        // registration costs far more than it buys: the datasource never gets created at all, so no catalog is
        // pushed and every decision fails closed — a total outage in place of one client's TLS error.
        //
        // A note is logged instead, so an operator sees the problem where it can be fixed. This is also the
        // honest boundary: the registering proxy is authenticated by the same shared secret either way, and it
        // chooses advertise_addr and the chain together, so a compromised registrar is not stopped by the
        // control plane second-guessing the material.
        //
        // Explicit presence is load-bearing: ABSENT means "no opinion, keep what is stored" (a transient cert
        // read on the proxy), while PRESENT-but-empty means "publish nothing" and clears it. Collapsing the two
        // would either drop a chain on every hiccup or strand clients on roots the proxy no longer serves.
        val certChain = if (request.hasAdvertiseCertChain()) request.advertiseCertChain else null
        if (!certChain.isNullOrBlank()) {
            inspectTrustChain(certChain)?.let { reason ->
                log.warn(
                    "datasource '{}' advertised a wire cert chain that may not verify: {} — serving it anyway; " +
                        "clients will report their own verification errors",
                    request.name, reason,
                )
            }
        }
        val priorDbName = core.datasourceStore.getByName(request.name)?.dbName
        val ds = try {
            core.datasourceStore.register(
                name = request.name,
                engine = engine,
                host = request.host,
                port = request.port,
                dbName = request.dbName,
                tags = request.tagsList,
                advertiseAddr = request.advertiseAddr,
                advertiseCertChain = certChain,
                advertiseWireTls = request.advertiseWireTls,
            )
        } catch (e: DatasourceEngineConflictException) {
            // Engine is immutable at register — a mismatched re-register is a client precondition
            // failure (fix the caller's engine or delete-and-recreate), not a server error.
            throw StatusException(Status.FAILED_PRECONDITION.withDescription(e.message))
        } catch (e: ManagementException) {
            // A refused tag name (PM_DATASOURCE_TAGS naming a `system:` tag the product does not define) is
            // the proxy's own misconfiguration, so it must read as one rather than an opaque server error.
            throw StatusException(Status.INVALID_ARGUMENT.withDescription(e.error.code))
        }
        // The catalog push that follows registration cannot repair this: it only confirms content it agrees
        // with, and a retarget is precisely the case where it disagrees. So the held structure would survive,
        // describing a database that is no longer there, and the next connection would adopt it.
        if (priorDbName != null && priorDbName != ds.dbName) {
            val dropped = core.connectionCatalog.invalidateDatasource(ds.name)
            log.info(
                "datasource '{}' retargeted {} -> {}: dropped {} enforcement schema(s)",
                ds.name, priorDbName, ds.dbName, dropped.size,
            )
        }
        return registerResponse {
            name = ds.name
            protocolVersion = CONTROL_PROTOCOL_VERSION
        }
    }

    override suspend fun pushCatalog(request: CatalogRequest): CatalogResponse {
        // The proxy must Register (which creates/upserts the row) before it can push a catalog for it;
        // an unknown name is a fail-closed NOT_FOUND, never an implicit create here.
        val ds = core.datasourceStore.getByName(request.datasourceName)
            ?: throw StatusException(
                Status.NOT_FOUND.withDescription("unknown datasource '${request.datasourceName}' — Register first"),
            )
        val pushedColumns = request.columnsList.map {
            DatasourceStore.PushedColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable)
        }
        val mysqlLowerCaseTableNames =
            if (request.hasMysqlLowerCaseTableNames()) request.mysqlLowerCaseTableNames else null
        val stored = core.datasourceStore.storePushedCatalog(
            id = ds.id,
            defaultSchemas = request.defaultSchemasList,
            mysqlLowerCaseTableNames = mysqlLowerCaseTableNames,
            engineVersion = request.engineVersion,
            columns = pushedColumns,
        )
        // This push is a fresh whole-catalog read of the target DB, so where it agrees with content the
        // enforcement pool already holds it re-measures that content — the ambient refresh keeps held
        // fragments verified instead of only feeding the config catalog, and a connection is not made to
        // re-probe a schema the proxy just confirmed.
        val confirmed = core.connectionCatalog.recordAmbientMeasurement(
            ds.name,
            pushedColumns.groupBy({ it.schema }) {
                FragmentColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable)
            },
        )
        if (confirmed.isNotEmpty()) {
            log.debug("datasource '{}': ambient refresh re-verified {} pooled schema(s)", ds.name, confirmed.size)
        }
        // Which shipped system-classification manifest governs THIS datasource, resolved from the version the
        // proxy just pushed — so an operator sees at connect time whether its system schemas are classified,
        // on a fallback major, or uncertified (deny-by-default). Boot logs the available set; this logs the hit.
        log.info(
            "datasource '{}': {}",
            ds.name,
            core.systemClassification.describeManifestFor(ds.engine, request.engineVersion),
        )
        return catalogResponse { columns = stored }
    }

    /**
     * A proxy-dialed, single-request run stream. The first request must claim a pending run session;
     * every later proxy message is relayed to that request's private inbound channel. The request Flow is
     * collected exactly once because grpc-kotlin's bidi request stream is single-collect.
     */
    override fun runExec(requests: Flow<ProxyRunMsg>): Flow<ControlRunMsg> = channelFlow {
        var sessionId: String? = null
        var attached: Attached? = null
        // Bound ONLY the wait for the first frame. There is deliberately no overall stream cap: once the
        // stream is attached to its run, its lifetime is the run's or session's own — the caller's RunClose
        // for a one-shot run, and the idle sweep / closeSession / token expiry for a persistent editor session.
        // A fixed overall cap here would silently cut a live, actively-used session short.
        val firstFrameTimer = launch {
            delay(firstFrameTimeoutMs)
            // The attach cancels this timer, but delay is the only cancellation point — if attach lands after
            // delay returns, cancel() alone would not stop the throw below from failing the just-attached
            // stream. Re-check liveness so an attach that raced the deadline wins.
            ensureActive()
            throw StatusException(
                Status.DEADLINE_EXCEEDED.withDescription("RunExec sent no first frame in time"),
            )
        }
        try {
            requests.collect { message ->
                val current = attached
                if (current == null) {
                    if (!message.hasSessionReady()) {
                        throw StatusException(
                            Status.FAILED_PRECONDITION.withDescription(
                                "the first RunExec message must be RunReady",
                            ),
                        )
                    }
                    val id = message.sessionReady.sessionId
                    sessionId = id
                    attached = core.runChannels.attach(id, channel)
                        ?: throw StatusException(
                            Status.NOT_FOUND.withDescription("unknown or already-claimed run session '$id'"),
                        )
                    // Attached — the run/session lifecycle governs the stream from here; drop the first-frame bound.
                    firstFrameTimer.cancel()
                } else {
                    current.inbound.send(message)
                }
            }
            if (attached == null) {
                throw StatusException(
                    Status.FAILED_PRECONDITION.withDescription(
                        "RunExec closed before RunReady",
                    ),
                )
            }
        } catch (e: ClosedSendChannelException) {
            // The run consumer closed its inbound while the proxy was still streaming: the run ended
            // (served-and-done or abandoned at the open ceiling) but this proxy has not closed its side.
            // That is a normal end of the stream, not a fault — complete it so the proxy sees a clean
            // close rather than an UNKNOWN status.
        } finally {
            firstFrameTimer.cancel()
            attached?.inbound?.close()
            sessionId?.let { core.runChannels.remove(it) }
        }
    }

    /**
     * A proxy-dialed, single-request table-detail stream. The first request claims the pending HTTP fetch;
     * the remaining proxy result/error is relayed to that request's private inbound channel.
     */
    override fun tableDetailExec(requests: Flow<ProxyTableDetailMsg>): Flow<ControlTableDetailMsg> = channelFlow {
        var sessionId: String? = null
        var attached: AttachedTableDetail? = null
        try {
            try {
                withTimeout(TABLE_DETAIL_STREAM_TIMEOUT_MS) {
                    requests.collect { message ->
                        val current = attached
                        if (current == null) {
                            if (!message.hasSessionReady()) {
                                throw StatusException(
                                    Status.FAILED_PRECONDITION.withDescription(
                                        "the first TableDetailExec message must be TableDetailReady",
                                    ),
                                )
                            }
                            val id = message.sessionReady.sessionId
                            sessionId = id
                            attached = core.tableDetailChannels.attach(id, channel)
                                ?: throw StatusException(
                                    Status.NOT_FOUND.withDescription(
                                        "unknown or already-claimed table-detail session '$id'",
                                    ),
                                )
                        } else {
                            current.inbound.send(message)
                        }
                    }
                    if (attached == null) {
                        throw StatusException(
                            Status.FAILED_PRECONDITION.withDescription(
                                "TableDetailExec closed before TableDetailReady",
                            ),
                        )
                    }
                }
            } catch (e: TimeoutCancellationException) {
                throw StatusException(Status.DEADLINE_EXCEEDED.withDescription("table-detail stream lifetime exceeded"))
            }
        } finally {
            attached?.inbound?.close()
            sessionId?.let { core.tableDetailChannels.remove(it) }
        }
    }

    /**
     * The proxy-initiated liveness + refresh stream. The proxy opens this once at startup and holds it
     * open for its lifetime; the open stream IS the liveness signal (close == the proxy detached). The
     * control-plane only ever writes back down this proxy-opened pipe — it never dials into a proxy. An
     * unknown datasource is NOT_FOUND (Register first). While open, the stream relays any `RefreshCatalog`
     * an admin pushes (see [ProxyEventsHub]); it emits nothing on its own.
     */
    override fun events(request: EventsRequest): Flow<ControlEvent> = channelFlow {
        val name = request.datasourceName
        // Version-gate the liveness stream too, not just Register. The datasource row outlives a rejected
        // Register, so an old proxy could otherwise attach here and be treated as live — the exact mixed-version
        // state Register rejects. Check before markSeen / hub.register so a mismatch never counts as attached.
        requireCompatibleProtocolVersion(request.protocolVersion)
        val ds = core.datasourceStore.getByName(name)
            ?: throw StatusException(Status.NOT_FOUND.withDescription("unknown datasource '$name' — Register first"))
        core.datasourceStore.markSeen(ds.id)
        core.proxyEventsHub.register(name, channel)
        awaitClose {
            core.proxyEventsHub.deregister(name, channel)
            // Stamp last-alive on detach too — otherwise last_seen_at would report when the proxy ATTACHED,
            // under-reporting liveness by a whole (possibly days-long) session. `attached()` covers "live now".
            core.datasourceStore.markSeen(ds.id)
        }
    }
}


/**
 * Inspects a PEM certificate chain the way a client will, returning null when it looks usable or a short
 * reason when it does not. This REPORTS; it never decides. Callers log the reason and serve the chain
 * regardless — the client performs the real verification and is the only party that can act on the outcome.
 *
 * The chain must actually CHAIN: the first certificate is the leaf a client will be presented, the last is
 * the trust anchor, and each must be issued by the next. A single certificate is only valid when it is
 * self-signed — then it is its own anchor, which is the ordinary self-signed-proxy case.
 *
 * A client pointed at this as `sslrootcert` / `--ssl-ca` trusts EVERY certificate in it, so an extra CA
 * appended to a real leaf is worth flagging — it is not a link in the chain. It is only a warning, though:
 * whoever registered the chain is authenticated, and could equally advertise a different address to go with
 * it, so the control plane is not the security boundary here.
 *
 * Issuance is checked by SIGNATURE, never by name: a certificate naming itself or its predecessor as issuer
 * proves nothing on its own.
 */
private const val KEY_USAGE_CERT_SIGN = 5

internal fun inspectTrustChain(pem: String): String? {
    val certs = runCatching {
        java.io.ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)).use { input ->
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(input)
        }.filterIsInstance<java.security.cert.X509Certificate>()
    }.getOrNull() ?: return "is not a parseable PEM certificate chain"
    if (certs.isEmpty()) return "contains no certificate"
    if (certs.size == 1) {
        val leaf = certs.first()
        return runCatching { leaf.verify(leaf.publicKey) }.fold(
            onSuccess = { null },
            onFailure = {
                "carries one certificate and it is not self-signed, so it cannot be a trust anchor — " +
                    "append the issuing CA"
            },
        )
    }
    // Each certificate must be signed by the next, and each issuer must be ALLOWED to issue. A signature
    // alone is not enough: a client enforces basicConstraints, so a chain whose issuer is CA:FALSE is
    // rejected by OpenSSL as "invalid CA certificate" — accepting it here would store a chain no client can
    // use, and would let a leaf that happens to hold a key be presented as an issuer.
    for (i in 0 until certs.size - 1) {
        val issuer = certs[i + 1]
        if (issuer.basicConstraints < 0) {
            return "is not a valid chain: certificate ${i + 1} is not a CA, so it cannot issue certificate $i"
        }
        if (issuer.keyUsage?.getOrNull(KEY_USAGE_CERT_SIGN) == false) {
            return "is not a valid chain: certificate ${i + 1} is not permitted to sign certificates"
        }
        if (runCatching { certs[i].verify(issuer.publicKey) }.isFailure) {
            return "is not a valid chain: certificate ${i + 1} does not issue certificate $i"
        }
    }
    val anchor = certs.last()
    if (runCatching { anchor.verify(anchor.publicKey) }.isFailure) {
        return "does not end in a self-signed trust anchor, so a client could not verify the leaf"
    }
    return null
}
