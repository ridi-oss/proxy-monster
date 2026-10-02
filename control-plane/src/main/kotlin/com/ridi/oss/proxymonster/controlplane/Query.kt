package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CapResource
import com.ridi.oss.proxymonster.controlplane.authz.ResolvedCaps
import com.ridi.oss.proxymonster.controlplane.authz.resolveResultCaps
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ColumnVerdict
import com.ridi.oss.proxymonster.controlplane.authz.FunctionRef
import com.ridi.oss.proxymonster.controlplane.authz.FunctionVerdict
import com.ridi.oss.proxymonster.controlplane.authz.TableRef
import com.ridi.oss.proxymonster.controlplane.authz.TableVerdict
import com.ridi.oss.proxymonster.controlplane.authz.UtilityRef
import com.ridi.oss.proxymonster.controlplane.authz.UtilityVerdict
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumns
import com.ridi.oss.proxymonster.controlplane.authz.authorizeFunctions
import com.ridi.oss.proxymonster.controlplane.authz.authorizeTables
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.authz.authorizeUtilities
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceActionId
import com.ridi.oss.proxymonster.classification.BaselineDangerousFunctions
import com.ridi.oss.proxymonster.grpc.ColumnMask
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.ProxyCommand
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.ObjectRef
import com.ridi.oss.proxymonster.grpc.columnMask
import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.Column
import com.ridi.oss.proxymonster.analyzer.pb.Submission
import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.analyzer.pb.ResultFingerprint
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.analyzer.pb.resultFingerprint
import com.ridi.oss.proxymonster.analyzer.pb.namespace as pbNamespace
import com.ridi.oss.proxymonster.probe.Analyzer
import com.ridi.oss.proxymonster.probe.Dialect
import com.ridi.oss.proxymonster.probe.Masking
import com.ridi.oss.proxymonster.probe.analyzerFor
import com.ridi.oss.proxymonster.probe.bindMasks
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.CoroutineScope
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.slf4j.LoggerFactory
import java.time.Instant

private val queryLog = LoggerFactory.getLogger("com.ridi.oss.proxymonster.controlplane.Query")

/**
 * kotlinx serializer for the proto [EnfAction] enum (which is not itself kotlinx-@Serializable). It
 * (de)serializes BY NAME so REST JSON keeps the exact string values "ALLOW"/"MASK"/"DENY". Deserializing
 * an unknown / ENF_ACTION_UNSPECIFIED / UNRECOGNIZED name fails CLOSED to DENY — a verdict never falls
 * open to ALLOW.
 */
object EnfActionSerializer : KSerializer<EnfAction> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("EnfAction", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: EnfAction) = encoder.encodeString(value.name)
    override fun deserialize(decoder: Decoder): EnfAction = when (decoder.decodeString()) {
        "ALLOW" -> EnfAction.ALLOW
        "MASK" -> EnfAction.MASK
        else -> EnfAction.DENY
    }
}

/**
 * Fail-closed normalization of a proto [EnfAction]: anything that is not an explicit ALLOW/MASK/DENY —
 * the proto3 ENF_ACTION_UNSPECIFIED zero value or the generated UNRECOGNIZED sentinel — collapses to
 * DENY, so an unknown verdict arriving from the wire never falls open. Call this at every point a proto
 * EnfAction enters from an untrusted source.
 */
fun EnfAction.knownOrDeny(): EnfAction = when (this) {
    EnfAction.ALLOW, EnfAction.MASK, EnfAction.DENY -> this
    else -> EnfAction.DENY
}

@Serializable
data class QueryRequest(val sql: String, val maxRows: Int = 500)

@Serializable
data class QueryResponse(
    @Serializable(with = EnfActionSerializer::class)
    val decision: EnfAction,
    val decisionId: Long? = null,
    val denyReason: String? = null,
    val maskedColumns: List<String> = emptyList(),
    // The tagged columns touched, not only `pii`-tagged ones; see decideQuery (Query.kt).
    val piiTouched: List<String> = emptyList(),
    val effectiveRoles: List<String> = emptyList(),
    val columns: List<String> = emptyList(),
    val rows: List<List<String?>> = emptyList(),
    val rowsAffected: Int? = null,
    // The executed decision's requirements ([ResultFingerprint]), frozen with the stored result so a later
    // view can deny drift ([decideResultView]). Carried back from the Decide handler on the RunDecision.
    @Serializable(with = ResultFingerprintSerializer::class)
    val resultFingerprint: ResultFingerprint = ResultFingerprint.getDefaultInstance(),
    // The verdict's row cap, and whether it — not the requested page size — ended this result.
    val truncatedByCap: Boolean = false,
    val capRows: Long? = null,
    val latencyMs: Long = 0,
)

/**
 * Which surface/phase a decision is in (docs/authz-context.md). Drives the session-statement
 * gate (only a persistent WIRE session may passthrough BEGIN/SET) and is overlaid onto the Cedar
 * `context.channel` a policy conditions on — authoritative, from the entry point / ephemeral-token kind,
 * never client-asserted. [contextValue] is the exact Cedar string.
 */
enum class Channel(val contextValue: String) {
    WIRE("wire"),
    EDITOR("editor"),
    WORKFLOW_EXECUTOR("workflow-executor"),
    /**
     * The whole console-facing side of a workflow task — viewing a stored result AND deciding it (approve /
     * reject / read-status). One actor, one session, so one channel a policy can scope. NOT
     * `workflow-executor`: a saved result re-masks here precisely because this value is not that permit.
     */
    WORKFLOW_VIEWER("workflow-viewer"),
    /**
     * A task decided from a Slack click rather than a console session (docs/notifications.md) — no OIDC
     * session, no attested address, so its own channel a policy can scope or forbid. It carries no
     * `requester_ip` (an IP-conditioned policy denies), and [system:no-self-approval] does not exempt it —
     * only the server-attested `editor`/`wire` channels are.
     */
    SLACK("slack"),
    MCP("mcp"),
}

/** The analyzer's result-read grants bundled as the [ResultFingerprint] message [decideResultView] freezes
 *  with a stored result and compares (by the message's own structural equality). */
internal fun fingerprintOf(requirements: List<RequireResultReadGrant>): ResultFingerprint =
    resultFingerprint { grants.addAll(requirements) }

/**
 * kotlinx serializer for [ResultFingerprint]: a `@Serializable` payload ([QueryResponse], [DecryptedResult])
 * holds the proto MESSAGE itself, persisted as base64 of its proto bytes. kotlinx can't serialize a protobuf
 * message directly, so this delegates to proto's own serialization rather than exposing a raw ByteArray field.
 */
object ResultFingerprintSerializer : KSerializer<ResultFingerprint> {
    override val descriptor = PrimitiveSerialDescriptor("ResultFingerprint", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ResultFingerprint) =
        encoder.encodeString(java.util.Base64.getEncoder().encodeToString(value.toByteArray()))
    override fun deserialize(decoder: Decoder): ResultFingerprint =
        ResultFingerprint.parseFrom(java.util.Base64.getDecoder().decode(decoder.decodeString()))
}

/** The verdict for a statement, without executing it: action + masks (output col → kind) + context. */
data class DecisionContext(
    val action: EnfAction,
    val denyReason: String?,
    val masks: List<ColumnMask>,
    // The tagged columns touched, not only `pii`-tagged ones; see decideQuery (Query.kt).
    val piiTouched: List<String>,
    val effectiveRoles: List<String>,
    val failedStage: String?,
    val detail: String?,
    val passthrough: Boolean,
    val structural: Boolean = false,
    /** ALLOW/MASK only: the `*`-expanded query the wire proxy must send instead of the client's original
     * so target-DB column order matches the mask ordinals. Null = send verbatim. */
    val rewrittenSql: String? = null,
    /** The engine-specific companion to [rewrittenSql] (analyzer.proto Submission); the proxy's engine reads it. */
    val submission: Submission? = null,
    /** Non-empty: no verdict yet; the proxy runs these, then re-sends the same statement. */
    val beforeDecide: List<ProxyCommand> = emptyList(),
    /** The analyzer's ordered output column names for this decision (an empty list for a passthrough /
     * unanalyzed statement). */
    val outputColumns: List<String> = emptyList(),
    /** The analyzer's classified statement kind (STMT_UNKNOWN for a passthrough / pre-parse failure). */
    val statementKind: StatementKind = StatementKind.STATEMENT_KIND_STMT_UNKNOWN,
    /** The decision's authorization requirements — the analyzer's result-read grants (empty for a
     * passthrough / unanalyzed statement). Carried structured to the proxy and back; an execute-under-R
     * result freezes them ([fingerprintOf]) and the view denies if the live re-decision's differ.
     * E.g. a column reorder moves `ssn` from ordinal 1 to 0, so the frozen grant (ssn MASK_OUTPUT @1) no
     * longer matches the live one (@0) and the re-decided mask can't bind to the wrong stored column and
     * leak it. See [decideResultView]. */
    val resultFingerprint: List<RequireResultReadGrant> = emptyList(),
    /** The derived `context.tags` this decision was evaluated under, surfaced so [decisionRecord]
     * logs which tags the request earned. Stamped on EVERY decision that runs after context derivation —
     * ALLOW, MASK, DENY (structural + policy), and passthrough alike — so an audit row carries the attested
     * tags no matter the outcome. The only rows that legitimately leave this empty are the pre-derivation
     * early denies (admission-reject / deactivated principal), which return before any `context.tags` is
     * derived and so were evaluated under none. */
    val contextTags: List<String> = emptyList(),
    /** How much of this statement's result may be relayed, folded from the `result.cap` policies that
     * answer for its datasource and its returned columns (docs/result-caps.md). Null = unbounded, which only
     * a `result.cap` forbid produces; a DENY relays nothing and leaves both null. */
    val maxRows: Long? = null,
    val maxBytes: Long? = null,
    /** MASK-only capability grant. A proxy may relay an unmaskable binary result unmasked iff this is true
     * AND the proxy's local feature capability says that relay path is supported. */
    val unmaskablePermitted: Boolean = false,
    /** Whether the proxy must strip this statement's target-DB diagnostics to code + severity: a MASK
     * verdict, or an ALLOW whose viewer can't read every leak column unmasked (docs/diagnostic-redaction.md). */
    val sanitizeDiagnostics: Boolean = false,
    /** True when a successful statement may change persistent catalog structure. */
    val catalogChanging: Boolean = false,
    /** True when the deny may be caused by absent structural catalog rows. */
    val catalogMiss: Boolean = false,
    /** Non-temp schemas the analyzer resolved or touched. */
    val referencedSchemas: Set<com.ridi.oss.proxymonster.grpc.ObjectRef> = emptySet(),
    /** Parsed dotted-identifier candidates used by the catalog-miss retry path. */
    val schemaCandidates: Set<com.ridi.oss.proxymonster.grpc.ObjectRef> = emptySet(),
)

/**
 * Whether [principal] reads unmasked every column in the analyzer's diagnostic leak set ([leakColumns]);
 * empty ⇒ true. A leak column missing from the catalog denies, and stmt_kind is stripped so a
 * kind-conditional grant cannot qualify. See docs/diagnostic-redaction.md.
 */
internal fun readsAllUnmasked(
    principal: String,
    roles: Set<String>,
    ds: Datasource,
    catalog: List<CatalogColumn>,
    leakColumns: List<ObjectRef>,
    context: AuthzContext,
    authz: Authz,
    systemClassification: SystemClassificationService?,
): Boolean {
    if (leakColumns.isEmpty()) return true
    val byKey = catalog.associateBy { listOf(it.catalog, it.schema, it.table, it.column) }
    val refs = leakColumns.map { col ->
        val row = byKey[listOf(col.catalog, col.schema, col.table, col.column)] ?: return false
        ColumnRef(
            "${row.catalog}.${row.schema}.${row.table}.${row.column}",
            row.catalog, row.schema, row.table, row.column, row.classification?.tags ?: emptyList(),
        )
    }
    // Same system-tag attachment as the main column authz — a leak column of pg_authid must keep
    // system:critical, or a datasource-wide unmasked grant would release its failing-row dump raw.
    val systemTags = systemClassification?.let { sc ->
        refs.mapNotNull { ref ->
            sc.tagForColumn(ds.engine, ds.engineVersion, ref.catalog, ref.schema, ref.table, ref.column)
                ?.let { ref.key to it }
        }.toMap()
    } ?: emptyMap()
    return authz.authorizeColumns(principal, roles, ds.name, refs, context.copy(stmtKind = null), systemTags, ds.tags)
        .values.all { it == ColumnVerdict.UNMASKED }
}

/**
 * Pure union of a principal's role sources: the base set (direct `principal_role`) ∪ active JIT grant
 * roles ∪ group-derived roles. [RoleResolver.resolve] is the sole production caller and passes the
 * server-resolved sets (never a client/session-asserted list); kept as a pure fn so the union
 * logic stays unit-testable (EffectiveRolesTest).
 */
fun effectiveRoles(baseRoles: List<String>, grantRoles: List<String>, groupRoles: List<String>): Set<String> =
    (baseRoles + grantRoles + groupRoles).toSet()

/** The one catalog representation shared by analyzer construction and exact lineage-key matching. */
internal data class CatalogColumnIndex(
    val snapshot: CatalogSnapshot,
    val rowsByKey: Map<String, CatalogColumn>,
)

/**
 * Build the catalog's exact normalized-key index from an [analyzer] already built over [snapshot] (the
 * same columns, in the same order, as [catalog] maps to) — reusing [Analyzer.columnKeys] rather than
 * re-deriving every row's key via a second full-catalog walk. Key uniqueness is already guaranteed by
 * [analyzerFor]'s own validation (it would have thrown), so [decideQuery] never observes a duplicate
 * here; the check below is defense-in-depth against a wiring bug, not a fold-drift concern.
 */
internal fun buildCatalogColumnIndex(
    catalog: List<CatalogColumn>,
    snapshot: CatalogSnapshot,
    analyzer: Analyzer,
): CatalogColumnIndex {
    require(catalog.size == analyzer.columnKeys.size) {
        "catalog/analyzer column count mismatch: ${catalog.size} vs ${analyzer.columnKeys.size}"
    }
    val rowsByKey = LinkedHashMap<String, CatalogColumn>()
    for ((row, key) in catalog.zip(analyzer.columnKeys)) {
        require(rowsByKey.putIfAbsent(key, row) == null) {
            "catalog contains ambiguous normalized column key '$key'"
        }
    }
    return CatalogColumnIndex(snapshot, rowsByKey)
}

/**
 * Build the analyzer and the exact catalog key-index for [ds]'s [catalog] (+ any [tempColumns]). The shared
 * analysis SETUP behind the two INDEPENDENT consumers of a statement — authorization ([decideQuery]) and the
 * reader-neutral disclosure hint ([protectedPredicateLiterals]) — so neither re-derives it and, more to the
 * point, neither is entangled with the other's control flow. Throws on a catalog/engine configuration error;
 * each caller maps that to its own outcome.
 */
internal fun analyzerAndCatalogIndex(
    ds: Datasource,
    catalog: Catalog,
    tempColumns: List<CatalogColumn>,
    resolvedSearchPath: List<String>,
    session: SessionObservation = SessionObservation.getDefaultInstance(),
): Pair<CatalogColumnIndex, Analyzer> {
    val namespace = pbNamespace {
        this.catalog = ds.effectiveCatalog
        this.searchPath.addAll(resolvedSearchPath)
    }
    val engineConfig = ds.engine.definition.analyzerEngineConfig(ds, session)
    val effectiveCatalog = (catalog.columns + tempColumns).let { it + ds.engine.implicitColumns(it) }
    val snapshot = catalogSnapshot {
        functions = catalog.functions
        columns += effectiveCatalog.map { col ->
            column {
                this.catalog = col.catalog
                schema = col.schema
                table = col.table
                column = col.column
                dataType = col.sqlType
                ordinal = col.ordinal
                nullable = col.nullable
                implicit = col.implicit
            }
        }
    }
    val analyzer = analyzerFor(namespace, snapshot, engineConfig)
    return buildCatalogColumnIndex(effectiveCatalog, snapshot, analyzer) to analyzer
}

/**
 * The reader-neutral disclosure HINT (docs/notifications.md, "The statement in the message"): the classified
 * columns this statement compares a LITERAL against — values that sit in the query TEXT, where masking cannot
 * reach them (`WHERE ssn = '987-65-4320'`). Advisory and best-effort, NOT a security boundary: a non-empty
 * result means a notification should withhold the text; null means the statement wasn't analyzed and is
 * withheld the same way (unknown, not proven clean).
 *
 * Its own path, sharing nothing with authorization but the analyzer above — no principal, no roles, no
 * verdict, because "does this text carry a value some approver cannot see" has the same answer whoever
 * composed it and whether or not THEY could run it; it keys on classification, never on a reader. A protected
 * column merely SELECTED or FILTERED is not here (masking handles the result stream); only a literal VALUE on
 * a classified column is. Best-effort by construction — absence is NEVER proof of safety. Known blind spots
 * it does not report, by design: a value reaching a column through a function/CASE/subquery/bound parameter,
 * a subquery inside a `SET`, and a system-catalog column tagged only by the classification manifest. A hint,
 * not a guarantee; a missed case shows a statement the console would have shown anyway.
 */
fun protectedPredicateLiterals(
    ds: Datasource,
    sql: String,
    catalog: Catalog,
    tempColumns: List<CatalogColumn> = emptyList(),
    liveSearchPath: List<String>? = null,
    session: SessionObservation = SessionObservation.getDefaultInstance(),
): List<String>? {
    val resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { listOf(ds.dbName.ifBlank { "public" }) }
    val (catalogIndex, facts) = try {
        val (index, analyzer) = analyzerAndCatalogIndex(ds, catalog, tempColumns, resolvedSearchPath, session)
        index to analyzer.analyze(sql)
    } catch (e: Exception) {
        return null
    }
    if (!facts.resolved) return null
    return facts.predicateLiteralsList.mapNotNull { lit ->
        val key = lit.column.key
        // Unknown to the catalog ⇒ cannot be vouched for ⇒ protected. Known ⇒ protected iff it carries a tag
        // or a mask function; a bare known column is genuinely unclassified.
        val row = catalogIndex.rowsByKey[key]
        val classified = row == null || row.classification?.let { it.tags.isNotEmpty() || it.maskFnName != null } == true
        key.takeIf { classified }
    }.distinct().sorted()
}

internal sealed interface CatalogCoverage {
    data object Covered : CatalogCoverage
    data class Denied(val reason: String) : CatalogCoverage
}

/** Analyzer keys remain opaque and must each match exactly one row in the already-unique index. */
internal fun catalogCoverage(index: CatalogColumnIndex, touched: Set<String>): CatalogCoverage {
    val missing = touched.firstOrNull { it !in index.rowsByKey } ?: return CatalogCoverage.Covered
    return CatalogCoverage.Denied("fail-closed: analyzer emitted column absent from catalog: $missing")
}

/**
 * Build the effective request context for a decision (docs/authz-context.md). The [channel] is
 * AUTHORITATIVE — it comes from the entry point / ephemeral-token kind and OVERRIDES any [caller]-supplied
 * `channel`. `context.tags` is DERIVED by pass-1 ([resolveContextTags]) and OVERWRITES any [caller]-supplied
 * `tags`. So neither `channel` nor `tags` is ever client-asserted, even if a caller (or a client upstream)
 * puts them in the context. Raw inputs the CP attests (`requester_ip`, `network_zones`) are preserved from
 * [caller]. Pass-1 runs over the channel-overlaid raw context (tags omitted there — no recursion).
 */
internal fun effectiveAuthzContext(
    caller: AuthzContext,
    channel: Channel,
    authz: Authz,
    principal: String,
    roles: Set<String>,
    datasource: String,
    datasourceTags: List<String>,
    stmtKind: String? = null,
): AuthzContext {
    val raw = caller.copy(channel = channel.contextValue, stmtKind = stmtKind)
    return raw.copy(tags = authz.resolveContextTags(principal, roles, datasource, raw, datasourceTags))
}

/**
 * The enforcement decision, callable with an explicit identity — analysis only, no execution.
 * An INADMISSIBLE statement (from the analyzer's StatementFacts) hard-denies before role resolution or
 * any grant walk; otherwise effective roles (base ∪ active JIT grants ∪ group-derived roles) authorize
 * the analyzer-emitted required grants in category order. Wire-safe metadata/session chatter is
 * passthrough-classified; the wire and editor channels may passthrough connection-scoped
 * (TX_CONTROL/SESSION_MUTATING) statements on their held connection — re-decided per statement — while
 * the workflow channels refuse them, since each workflow run uses a fresh connection.
 */
fun decideQuery(
    principal: String,
    ds: Datasource,
    sql: String,
    channel: Channel,
    catalog: Catalog,
    policyStore: PolicyStore,
    accessStore: AccessStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    auditStore: AuditStore? = null,
    // Almost always null (resolve server-side below). Tests that already resolved roles once and
    // want decideQuery + authz.authorizeColumns to see the EXACT same set (no risk of a second,
    // out-of-band resolve() disagreeing with the first) may pass them explicitly.
    providedRoles: Set<String>? = null,
    context: AuthzContext = AuthzContext(),
    // Wire connections' live effective namespace, probed as PostgreSQL search_path or MySQL current
    // database by the proxy; null resolves under ds.defaultSchemas (editor / callers that do not supply a
    // live namespace).
    liveSearchPath: List<String>? = null,
    // What the proxy observed on the target session before this statement, forwarded to the analyzer as-is.
    session: SessionObservation = SessionObservation.getDefaultInstance(),
    // The shipped system classifier. Null → no system tags marshaled (system schemas stay deny-by-default).
    // Keyed off ds.engineVersion, path-agnostic (CP-introspect + proxy PushCatalog).
    systemClassification: SystemClassificationService? = null,
    // The connection's session/temp columns (proxy-introspected off its held connection), overlaid
    // onto the base catalog so a bare name resolves to the temp the target DB binds. Empty for one-shot/wire.
    tempColumns: List<CatalogColumn> = emptyList(),
    // TEST-ONLY seam. When non-null, the grant walk runs over these StatementFacts instead of analyzing
    // [sql] — the ONLY way to exercise the fail-closed contract branches (an UNSPECIFIED disposition, a
    // resourceless result-read, a missing execute grant, an invalid ordinal) that a resolved Go analyzer can
    // never emit. Production callers leave it null; the catalog/analyzer are still built so column-grant
    // resolution is real.
    factsOverride: StatementFacts? = null,
): DecisionContext {
    val id = ds.id
    val dialect = ds.engine.dialect
    if (liveSearchPath != null && liveSearchPath.isEmpty() && catalog.columns.isNotEmpty()) {
        return structuralDeny(CATALOG_CONFIGURATION_DENY, emptyList(), failedStage = "catalog").copy(catalogMiss = true)
    }
    val resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { listOf(ds.dbName.ifBlank { "public" }) }

    val catalogAndFacts = try {
        val (index, analyzer) = analyzerAndCatalogIndex(ds, catalog, tempColumns, resolvedSearchPath, session)
        index to (factsOverride ?: analyzer.analyze(sql))
    } catch (e: Exception) {
        return structuralDeny(
            "$CATALOG_CONFIGURATION_DENY: ${e.message ?: e.javaClass.simpleName}",
            emptyList(),
            failedStage = "catalog",
        ).copy(catalogMiss = true)
    }
    val catalogIndex = catalogAndFacts.first
    val facts = catalogAndFacts.second

    if (facts.failureClass == FailureClass.FAILURE_CLASS_INADMISSIBLE ||
        facts.failureClass == FailureClass.FAILURE_CLASS_UNSPECIFIED && !facts.resolved
    ) {
        return structuralDeny(facts.detail.ifBlank { "statement is inadmissible" }, emptyList())
    }
    // The analyzer asked for input only the proxy can fetch: no verdict, run the commands and retry.
    val beforeDecide = ds.engine.definition.beforeDecideCommands(facts)
    if (beforeDecide.isNotEmpty()) {
        return structuralDeny(facts.detail.ifBlank { "more input is required" }, emptyList()).copy(beforeDecide = beforeDecide)
    }

    if (userGroupStore.isDeactivated(principal)) {
        return structuralDeny(DEACTIVATED_PRINCIPAL_DENY, emptyList(), failedStage = "deprovisioned")
    }

    // providedRoles is a task's frozen execute_as snapshot (approval execute + stored-result view). Re-filter
    // it to LIVE roles at this final authorization point so a role soft-deleted AFTER the route-level liveness
    // check — including between the route and the async proxy Decide — cannot still authorize the run. An
    // all-deleted snapshot collapses to the empty set and denies here (never falls back to the principal's
    // own roles). Ordinary resolution is already deleted-role-filtered in RoleResolver.
    val roles = providedRoles?.let { policyStore.liveRoleNames(it) } ?: roleResolver.resolve(principal)
    val roleList = roles.toList()
    // The statement's classified kind, resolved before the context so a read policy can condition on it
    // (`context.stmt_kind`) — e.g. permit unmasked reads only under a plan-only EXPLAIN, which returns no
    // rows. STMT_UNKNOWN (a pre-parse failure), like an unspecified/unrecognized kind, leaves stmt_kind
    // ABSENT rather than exposing a value to condition on; it routes through exception.unanalyzable at the
    // kind gate below.
    val statementKind = if (facts.hasStatementExec()) facts.statementExec.statementKind
    else StatementKind.STATEMENT_KIND_STMT_UNKNOWN
    @Suppress("NAME_SHADOWING")
    val context = effectiveAuthzContext(
        context, channel, authz, principal, roles, ds.name, ds.tags,
        stmtKind = statementKind
            .takeIf {
                it != StatementKind.STATEMENT_KIND_UNSPECIFIED &&
                    it != StatementKind.STATEMENT_KIND_STMT_UNKNOWN &&
                    it != StatementKind.UNRECOGNIZED
            }
            ?.name?.removePrefix("STATEMENT_KIND_")?.lowercase(),
    )
    val derivedTags = context.tags.toList()
    // The datasource-level `result.cap` answer, asked up front: it alone decides a passthrough or relay's cap.
    val datasourceCaps = authz.resolveResultCaps(principal, roles, ds.name, emptyList(), context, ds.tags)

    // Fail-closed contract validation (analyzer.proto): the single statement-execution grant is the sole
    // per-statement authorization signal. A RESOLVED statement without it would default to the grantable
    // STMT_UNKNOWN gate, so its absence fails closed. (An unresolved fact may carry the grant — a classified-
    // but-unanalyzable statement like KILL does — or omit it on a pre-parse failure; either way it routes
    // through exception.unanalyzable, and the kind gate below denies an unspecified/unrecognized kind. The
    // analyzer emits the grant exactly once, so no runtime count check is needed.)
    if (facts.resolved && !facts.hasStatementExec()) {
        return structuralDeny("fail-closed: a resolved statement must carry its execute grant", roleList, failedStage = "policy", contextTags = derivedTags)
    }
    // Every result-read grant must name a resource. The proto oneof guarantees AT MOST one; a grant naming
    // NONE is invisible to the has*-filtered walk below and would silently ride a resolved statement to
    // ALLOW, so a resourceless grant is a fail-closed DENY. A resolved analyzer never emits one.
    facts.resultReadsList.firstOrNull { grant ->
        !grant.hasColumn() && !grant.hasTable() && !grant.hasFunction() && !grant.hasUtility()
    }?.let {
        return structuralDeny("fail-closed: analyzer emitted a resourceless result-read grant", roleList, failedStage = "policy", contextTags = derivedTags)
    }

    // Fail-closed contract validation continued, up front and INDEPENDENT of any later Cedar verdict: every
    // column grant a recognized non-UNSPECIFIED masking disposition; every output ordinal an in-range index
    // into output_columns. Validated here — not only inside the eventual MASKED branch — so an allowed/
    // UNMASKED column can never ride a malformed disposition or a bogus ordinal to ALLOW.
    facts.resultReadsList.firstOrNull { grant ->
        grant.outputOrdinalsList.any { it !in facts.outputColumnsList.indices }
    }?.let {
        return structuralDeny("invalid mask output ordinal", roleList, failedStage = "mask-binding", contextTags = derivedTags)
    }
    facts.resultReadsList.firstOrNull { grant ->
        grant.hasColumn() && grant.maskedDisposition in MALFORMED_DISPOSITIONS
    }?.let {
        return structuralDeny("fail-closed: column grant has no masking disposition", roleList, failedStage = "policy", contextTags = derivedTags)
    }

    // A policy-DENY on the DATA — an uncovered table scan or the column/table verdict — fails closed: a
    // denied query stays denied. A catalog-miss deny carries the statement's schema qualifiers so the
    // connection layer can issue a bounded refetch of the (possibly newly-created) schema and retry —
    // without them the query stays denied until an unrelated refresh (ConnectionDecide.markCatalogMiss).
    fun deny(reason: String, catalogMiss: Boolean = false): DecisionContext =
        policyDeny(reason, roleList, derivedTags)
            .copy(catalogMiss = catalogMiss, schemaCandidates = facts.namespaceQualifierCandidatesList.toSet())

    when (authz.authorizeDatasourceAction(principal, roles, AuthzAction.DATASOURCE_CONNECT, ds.name, context, ds.tags)) {
        is AuthzDecision.Deny -> return policyDeny("no access to datasource '${ds.name}'", roleList, derivedTags)
        AuthzDecision.Allow -> Unit
    }

    var usedUtilityTags: Map<String, String> = emptyMap()
    var allowedFunctionTags: Map<String, String> = emptyMap()
    val utilityGrants = facts.resultReadsList.filter { it.hasUtility() }
    if (utilityGrants.isNotEmpty()) {
        if (systemClassification == null || ds.engineVersion.isNullOrBlank()) {
            return structuralDeny(
                "$SYSTEM_UTILITY_DENY '${utilityGrants.first().utility.command}'",
                roleList,
                failedStage = "policy",
                contextTags = derivedTags,
            )
        }
        val utilityTags = utilityGrants.mapNotNull { grant ->
            val command = grant.utility.command
            systemClassification.tagForCommand(ds.engine, ds.engineVersion, command)?.let { command to it }
        }.toMap()
        utilityGrants.firstOrNull { it.utility.command !in utilityTags }?.let {
            return structuralDeny(
                "$SYSTEM_UTILITY_DENY '${it.utility.command}'",
                roleList,
                failedStage = "policy",
                contextTags = derivedTags,
            )
        }
        val utilRefs = utilityTags.keys.map(::UtilityRef)
        val verdicts = authz.authorizeUtilities(principal, roles, ds.name, utilRefs, context, utilityTags, ds.tags)
        usedUtilityTags = utilityTags
        utilRefs.firstOrNull { verdicts[it.command] != UtilityVerdict.USE }?.let {
            return structuralDeny(
                "$SYSTEM_UTILITY_DENY '${it.command}'",
                roleList,
                failedStage = "policy",
                contextTags = derivedTags,
            )
        }
    }

    // Statement-kind gate — the sole per-statement authorization. The analyzer's statement_exec grant names
    // the granular kind; Cedar's schema alone maps it to a category (stmt.kind.<k> in stmt.cat.<c>), so a
    // category preset covers the kind while an exact-kind forbid still overrides a broad category permit.
    // EVERY statement is gated here — including a no-column metadata/session/admin/unknown one — closing the
    // connect-only gaps (ANALYZE TABLE, SHOW MASTER STATUS, …). A missing grant (a pre-parse failure) reads
    // as STMT_UNKNOWN → exception.unanalyzable. Runs after connect/utility, before the passthrough allow; the
    // unanalyzable/utility gates still apply on top (e.g. ALTER TABLE stays prod-denied).
    val kindAction = statementKindActionId(statementKind)
        ?: return structuralDeny("statement kind is unspecified", roleList, contextTags = derivedTags)
    if (authz.authorizeDatasourceActionId(principal, roles, kindAction, ds.name, context, ds.tags) !is AuthzDecision.Allow) {
        val kindName = statementKind.name.removePrefix("STATEMENT_KIND_").lowercase()
        return policyDeny("statement kind '$kindName' is not permitted", roleList, derivedTags)
    }

    // A resolved statement that touches no column/table/function, changes no catalog, and calls no function
    // has nothing to mask, re-measure, or authorize beyond the kind gate it already passed: relay it verbatim
    // (SHOW/SET/const-SELECT). A catalog-changing (DDL) or function-bearing no-column statement falls through
    // so its re-measure and function authorization still run. A session statement on a non-persistent channel
    // (MCP/workflow) is denied earlier at the kind gate by the seeded `stmt.cat.session` Cedar forbid.
    if (facts.resolved &&
        !facts.catalogChanging &&
        facts.functionsList.isEmpty() &&
        facts.resultReadsList.none { it.hasColumn() || it.hasTable() || it.hasFunction() }
    ) {
        // A literal write reaches this relay too, and its diagnostic can leak (a PostgreSQL constraint ERR
        // dumps the whole target row) — gate on the analyzer's leak set. `SELECT 1` has an empty set: raw.
        if (relaysRows(statementKind)) {
            spentRate(auditStore, principal, ds.name, datasourceCaps)?.let { return policyDeny(it, roleList, derivedTags) }
        }
        return passthroughAllow(roleList, "passthrough (no data touched)", derivedTags)
            .copy(
                sanitizeDiagnostics = !readsAllUnmasked(principal, roles, ds, catalogIndex.rowsByKey.values.toList(), facts.diagnosticLeakColumnsList, context, authz, systemClassification),
                schemaCandidates = facts.namespaceQualifierCandidatesList.toSet(),
                statementKind = statementKind,
            )
            .withCaps(datasourceCaps)
            .withAnalyzerRewrite(facts)
    }

    if (!facts.resolved) {
        if (facts.failureClass != FailureClass.FAILURE_CLASS_UNANALYZABLE) {
            return structuralDeny(facts.detail.ifBlank { "statement analysis failed" }, roleList, contextTags = derivedTags)
        }
        if (facts.functionsList.isNotEmpty()) {
            val functionTags = facts.functionsList.mapNotNull { name ->
                (systemClassification?.tagForFunction(ds.engine, ds.engineVersion, name)
                    ?: BaselineDangerousFunctions.classify(name.substringAfterLast('.'))?.id)?.let { name to it }
            }.toMap()
            if (functionTags.isNotEmpty()) {
                val refs = functionTags.keys.map(::FunctionRef)
                val verdicts = authz.authorizeFunctions(principal, roles, ds.name, refs, context, functionTags, ds.tags)
                refs.firstOrNull { verdicts[it.name] != FunctionVerdict.ALLOWED }?.let {
                    return structuralDeny("$SYSTEM_FUNCTION_DENY '${it.name}'", roleList, failedStage = "policy", contextTags = derivedTags)
                }
            }
        }
        val stage = facts.failedStage.takeIf { facts.hasFailedStage() }?.lowercase()
        val reason = "fail-closed: could not analyze ($stage)"
        return when (authz.authorizeDatasourceAction(principal, roles, AuthzAction.EXCEPTION_UNANALYZABLE, ds.name, context, ds.tags)) {
            is AuthzDecision.Allow -> DecisionContext(
                action = EnfAction.ALLOW,
                denyReason = null,
                masks = emptyList(),
                piiTouched = emptyList(),
                effectiveRoles = roleList,
                failedStage = null,
                detail = "unanalyzable relay (exception.unanalyzable): $reason",
                passthrough = true,
                contextTags = derivedTags,
                catalogChanging = facts.catalogChanging || facts.functionsList.isNotEmpty(),
                schemaCandidates = facts.namespaceQualifierCandidatesList.toSet(),
                // A statement may be unresolvable only because this connection never fetched the schema it
                // names, so refetch the qualifiers before relaying it unmasked.
                catalogMiss = true,
                // Unanalyzable: no leak set to authorize, so fail closed and redact the diagnostic.
                sanitizeDiagnostics = true,
            ).withCaps(datasourceCaps).let { relay ->
                if (relaysRows(statementKind)) spentRate(auditStore, principal, ds.name, datasourceCaps)?.let { deny(it) } ?: relay else relay
            }
            is AuthzDecision.Deny -> deny(reason, catalogMiss = true)
        }
    }

    val columnGrants = facts.resultReadsList.filter { it.hasColumn() }
    val columnKeys = LinkedHashMap<String, ObjectRef>()
    for (grant in columnGrants) columnKeys.putIfAbsent(grant.column.key, grant.column)
    when (val coverage = catalogCoverage(catalogIndex, columnKeys.keys)) {
        CatalogCoverage.Covered -> Unit
        // A resolved statement traced a column key with no row in the catalog index. This is NOT a stale
        // fragment: a column truly absent from the catalog fails to RESOLVE (the analyzer is built from the
        // same catalog), taking the !resolved exception.unanalyzable path above — not this branch. So this is a
        // fail-closed guard for an analyzer<->CP key-rendering divergence (a contract bug; it also guards the
        // rowsByKey.getValue below). catalogMiss=true + the qualifier candidates are kept (matching the prior
        // hard deny) so decideConnection still runs its bounded refetch-first retry — harmless here, since a
        // re-fetch cannot change a key-rendering mismatch. Rather than a hard code deny, the miss routes
        // through the same exception.unanalyzable escape hatch as an unanalyzable statement ("authorization
        // belongs to Cedar"): a principal without exception.unanalyzable stays fail-closed (no
        // non-admin holds it — the only shipped grant is preset-scoped to system:development, where dev has
        // no PII), while a holder may relay. The relay is a whole-statement unmasked passthrough — masks for
        // any COVERED columns selected alongside the uncovered one are dropped too — which is no new
        // capability over the unanalyzable relay above, which likewise relays everything unmasked under
        // the same grant.
        is CatalogCoverage.Denied -> return when (
            authz.authorizeDatasourceAction(principal, roles, AuthzAction.EXCEPTION_UNANALYZABLE, ds.name, context, ds.tags)
        ) {
            is AuthzDecision.Allow -> DecisionContext(
                action = EnfAction.ALLOW,
                denyReason = null,
                masks = emptyList(),
                piiTouched = emptyList(),
                effectiveRoles = roleList,
                failedStage = null,
                detail = "uncovered-column relay (exception.unanalyzable): ${coverage.reason}",
                passthrough = true,
                contextTags = derivedTags,
                catalogChanging = facts.catalogChanging || facts.functionsList.isNotEmpty(),
                catalogMiss = true,
                schemaCandidates = facts.namespaceQualifierCandidatesList.toSet(),
                // An uncovered column means the leak set can't be authorized — fail closed and redact.
                sanitizeDiagnostics = true,
            ).withCaps(datasourceCaps).let { relay ->
                if (relaysRows(statementKind)) spentRate(auditStore, principal, ds.name, datasourceCaps)?.let { deny(it) } ?: relay else relay
            }
            is AuthzDecision.Deny -> structuralDeny(
                coverage.reason, roleList, failedStage = "catalog", contextTags = derivedTags,
            ).copy(catalogMiss = true, schemaCandidates = facts.namespaceQualifierCandidatesList.toSet())
        }
    }

    val maskKinds = try {
        policyStore.listMaskFns().associate { it.name to it.kind }
    } catch (_: Exception) {
        return structuralDeny(CATALOG_CONFIGURATION_DENY, roleList, failedStage = "catalog", contextTags = derivedTags)
            .copy(catalogMiss = true, schemaCandidates = facts.namespaceQualifierCandidatesList.toSet())
    }
    val columnRefs = columnKeys.keys.map { key ->
        val row = catalogIndex.rowsByKey.getValue(key)
        ColumnRef(key, row.catalog, row.schema, row.table, row.column, row.classification?.tags ?: emptyList())
    }
    val touchedTableIds = buildSet {
        columnRefs.mapTo(this) { Triple(it.catalog, it.schema, it.table) }
        facts.sourcesList.mapTo(this) { Triple(it.catalog, it.schema, it.table) }
        facts.resultReadsList.filter { it.hasTable() }.mapTo(this) { Triple(it.table.catalog, it.table.schema, it.table.table) }
    }
    val tableSystemTags = systemClassification?.let { sc ->
        touchedTableIds.mapNotNull { (cat, schema, table) ->
            sc.tagForTable(ds.engine, ds.engineVersion, cat, schema, table)?.let { Triple(cat, schema, table) to it }
        }.toMap()
    } ?: emptyMap()
    val columnSystemTags = systemClassification?.let { sc ->
        columnRefs.mapNotNull { ref ->
            sc.tagForColumn(
                ds.engine,
                ds.engineVersion,
                ref.catalog,
                ref.schema,
                ref.table,
                ref.column,
            )?.let { ref.key to it }
        }.toMap()
    } ?: emptyMap()
    val systemRedactedColumns = systemClassification?.let { sc ->
        columnRefs.filterTo(LinkedHashSet()) { ref ->
            sc.redactsColumn(ds.engine, ds.engineVersion, ref.catalog, ref.schema, ref.table, ref.column)
        }.mapTo(HashSet()) { it.key }
    } ?: emptySet()

    val functionGrants = facts.resultReadsList.filter { it.hasFunction() }
    if (functionGrants.isNotEmpty() || facts.functionsList.isNotEmpty()) {
        val names = (functionGrants.map { it.function.name } + facts.functionsList).distinct()
        val functionTags = names.mapNotNull { name ->
            (systemClassification?.tagForFunction(ds.engine, ds.engineVersion, name)
                ?: BaselineDangerousFunctions.classify(name.substringAfterLast('.'))?.id)?.let { name to it }
        }.toMap()
        // now() relays; pg_read_file and every user function need a grant. functionsList (calls seen in an
        // unanalyzable statement) has no builtin flag, so only its dangerous names are gated.
        val functionsToAuthorize = LinkedHashSet<String>()
        for (grant in functionGrants) {
            val name = grant.function.name
            if (grant.function.builtin && name !in functionTags) continue
            functionsToAuthorize += name
        }
        facts.functionsList.filterTo(functionsToAuthorize) { it in functionTags }
        if (functionsToAuthorize.isNotEmpty()) {
            val refs = functionsToAuthorize.map(::FunctionRef)
            val verdicts = authz.authorizeFunctions(principal, roles, ds.name, refs, context, functionTags, ds.tags)
            refs.firstOrNull { verdicts[it.name] != FunctionVerdict.ALLOWED }?.let {
                return structuralDeny("$SYSTEM_FUNCTION_DENY '${it.name}'", roleList, failedStage = "policy", contextTags = derivedTags)
            }
            allowedFunctionTags = functionTags
        }
    }

    val columnVerdicts = if (columnRefs.isEmpty()) emptyMap() else
        authz.authorizeColumns(principal, roles, ds.name, columnRefs, context, columnSystemTags, ds.tags)
    val masks = ArrayList<ColumnMask>()
    var hasMandatoryRedaction = false
    for (grant in columnGrants) {
        val key = grant.column.key
        val row = catalogIndex.rowsByKey.getValue(key)
        val systemRedacted = key in systemRedactedColumns
        val authorizedVerdict = if (row.isTemp) {
            ColumnVerdict.UNMASKED
        } else {
            columnVerdicts[key] ?: ColumnVerdict.DENIED
        }
        val verdict = if (systemRedacted && authorizedVerdict != ColumnVerdict.DENIED) {
            ColumnVerdict.MASKED
        } else {
            authorizedVerdict
        }
        when (verdict) {
            ColumnVerdict.UNMASKED -> Unit
            ColumnVerdict.DENIED -> return deny("policy denies column $key")
            ColumnVerdict.MASKED -> when (grant.maskedDisposition) {
                MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT,
                MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED,
                MaskedDisposition.UNRECOGNIZED -> return deny(
                    "protected column $key appears in a position that cannot be masked (a write payload or a subquery/reference)",
                )
                MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT,
                MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL -> {
                    // Ordinals were bounds-checked up front (fail-closed contract validation), so each is a
                    // valid index here. NULL redaction dominates any ordinary mask on that ordinal.
                    for (ordinal in grant.outputOrdinalsList) {
                        val redactOutput = systemRedacted ||
                            grant.maskedDisposition == MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL
                        hasMandatoryRedaction = hasMandatoryRedaction || systemRedacted
                        val candidate = if (redactOutput) {
                            columnMask {
                                this.column = facts.outputColumnsList[ordinal]
                                maskFn = "redact"
                                kind = "NULL"
                                this.ordinal = ordinal
                            }
                        } else {
                            val fn = row.classification?.maskFnName
                            columnMask {
                                this.column = facts.outputColumnsList[ordinal]
                                maskFn = fn ?: "mask"
                                kind = fn?.let { maskKinds[it] } ?: "FIXED"
                                this.ordinal = ordinal
                            }
                        }
                        val existing = masks.indexOfFirst { it.ordinal == ordinal }
                        if (existing == -1) {
                            masks += candidate
                        } else if (redactOutput && masks[existing].kind != "NULL") {
                            masks[existing] = candidate
                        }
                    }
                }
            }
        }
    }

    val tempTableIds = tempColumns.mapTo(HashSet()) { Triple(it.catalog, it.schema, it.table) }
    val tableGrants = facts.resultReadsList.filter { it.hasTable() && Triple(it.table.catalog, it.table.schema, it.table.table) !in tempTableIds }
    if (tableGrants.isNotEmpty()) {
        val refs = tableGrants.map { grant ->
            val table = grant.table
            TableRef(table.key, table.catalog, table.schema, table.table)
        }.distinctBy { it.key }
        val verdicts = authz.authorizeTables(principal, roles, ds.name, refs, context, tableSystemTags, ds.tags)
        refs.firstOrNull { verdicts[it.key] != TableVerdict.READ }?.let {
            return deny("no read grant for scanned table '${it.schema}.${it.table}'")
        }
    }

    val action = if (masks.isEmpty()) EnfAction.ALLOW else EnfAction.MASK
    // Ask result.cap on every returned column, with context.masked telling a cap policy whether this
    // principal's read reaches the client in the clear: an UNMASKED read feeding an output no mask covers
    // (RETURNING has no ordinals and counts as bare). A column read only in a predicate returns nothing and is
    // not asked.
    val maskedOrdinals = masks.mapTo(HashSet()) { it.ordinal }
    // A permitted exception.unmaskable lets the proxy relay a masked result raw, so for the cap ask a masked
    // column counts as reaching the client in the clear.
    val unmaskablePermitted = masks.isNotEmpty() && !hasMandatoryRedaction && authz.authorizeDatasourceAction(
        principal, roles, AuthzAction.EXCEPTION_UNMASKABLE, ds.name, context, ds.tags,
    ) is AuthzDecision.Allow
    val returnedMasked = LinkedHashMap<String, Boolean>()
    for (rc in facts.returnedColumnsList) {
        val key = rc.column.key
        val clear = unmaskablePermitted || columnVerdicts[key] == ColumnVerdict.UNMASKED &&
            (rc.outputOrdinalsList.isEmpty() || rc.outputOrdinalsList.any { o -> o !in maskedOrdinals })
        returnedMasked[key] = (returnedMasked[key] ?: true) && !clear
    }
    val capResources = buildList<CapResource> {
        for (ref in columnRefs) {
            val masked = returnedMasked[ref.key] ?: continue
            add(CapResource.Column(ref, columnSystemTags[ref.key], masked))
        }
        for (grant in tableGrants) {
            val t = grant.table
            add(CapResource.Table(TableRef(t.key, t.catalog, t.schema, t.table), tableSystemTags[Triple(t.catalog, t.schema, t.table)]))
        }
        for ((name, tagId) in allowedFunctionTags) add(CapResource.Function(FunctionRef(name), tagId))
        for ((command, tagId) in usedUtilityTags) add(CapResource.Utility(UtilityRef(command), tagId))
    }
    val statementCaps = authz.resolveResultCaps(principal, roles, ds.name, capResources, context, ds.tags)
    spentRate(auditStore, principal, ds.name, datasourceCaps, statementCaps)?.let { return deny(it) }
    // Every classified column the statement touched, whatever its tags are named: `pii` is a deployment's
    // own tag, so keying this on that one string leaves auditmon's mass-export detector blind on a
    // deployment that classifies with `pci`.
    // TODO: rename to tagged_columns_touched. Needs a migration plus the Go verifier, the SIEM export name,
    // and the console; the canonical form is positional, so CHAIN_VERSION is unaffected.
    val tagged = columnKeys.keys.filter {
        catalogIndex.rowsByKey.getValue(it).classification?.tags?.isNotEmpty() == true
    }
    val referencedSchemas = buildSet {
        facts.sourcesList.mapTo(this) { namespace(it.catalog, it.schema) }
        columnGrants.mapTo(this) { namespace(it.column.catalog, it.column.schema) }
    }.filterNotTo(LinkedHashSet()) { it.schema.startsWith("pg_temp", ignoreCase = true) }
    // MASK/DENY always redacts; an ALLOW redacts iff the analyzer's leak set holds a column the viewer
    // can't read unmasked. `select id from users` (all readable) relays raw.
    val sanitizeDiagnostics = action != EnfAction.ALLOW ||
        !readsAllUnmasked(principal, roles, ds, catalogIndex.rowsByKey.values.toList(), facts.diagnosticLeakColumnsList, context, authz, systemClassification)
    return DecisionContext(
        action = action,
        denyReason = null,
        masks = masks,
        piiTouched = tagged,
        effectiveRoles = roleList,
        failedStage = facts.failedStage.takeIf { facts.hasFailedStage() }?.lowercase(),
        detail = facts.detail,
        passthrough = false,
        outputColumns = facts.outputColumnsList,
        statementKind = statementKind,
        resultFingerprint = facts.resultReadsList,
        contextTags = derivedTags,
        unmaskablePermitted = unmaskablePermitted,
        sanitizeDiagnostics = sanitizeDiagnostics,
        // A call may run DDL inside its body, builtin or UDF alike.
        catalogChanging = facts.catalogChanging || facts.functionsList.isNotEmpty() || functionGrants.isNotEmpty(),
        referencedSchemas = referencedSchemas,
        schemaCandidates = facts.namespaceQualifierCandidatesList.toSet(),
    ).withCaps(datasourceCaps, statementCaps).withAnalyzerRewrite(facts)
}

// A column grant must carry a real masking disposition; an absent/unrecognized one is a malformed effect
// the walk would otherwise treat as a plain unmasked read, so it fails closed.
private val MALFORMED_DISPOSITIONS = setOf(
    MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED,
    MaskedDisposition.UNRECOGNIZED,
)

/** The cap when no `result.cap` policy answers on that dimension: fail closed, never uncapped. */
internal const val DEFAULT_CAP_ROWS = 5_000L
internal const val DEFAULT_CAP_BYTES = 50_000_000L

/** The resolved per-statement cap; null on a dimension = unbounded (only a `result.cap` forbid produces it). */
internal data class ResultCaps(val rows: Long?, val bytes: Long?)

/**
 * Fold the `result.cap` answers a statement collected (docs/result-caps.md): a forbid that matched any ask
 * lifts both; else the tightest cap rows and the tightest cap bytes, falling back to the shipped default on a
 * dimension nothing answered.
 */
internal fun resultCaps(vararg resolved: ResolvedCaps): ResultCaps {
    if (resolved.any { it.unbounded }) return ResultCaps(null, null)
    return ResultCaps(
        resolved.mapNotNull { it.rows }.minOrNull() ?: DEFAULT_CAP_ROWS,
        resolved.mapNotNull { it.bytes }.minOrNull() ?: DEFAULT_CAP_BYTES,
    )
}

/**
 * The deny reason when a rate entry the statement's `result.cap` permits carry is already spent, else null.
 * A forbid on any ask lifts every rate; with no rate collected no audit scan runs. The scan is one query
 * over the widest window, lower-bounded by the principal's last rate reset (AuditStore.relayedVolume).
 */
/** A rate bounds relayed volume, so a statement that relays no rows (COMMIT, SET, USE) is never rate-denied. */
private fun relaysRows(kind: StatementKind): Boolean = kind !in SESSION_KINDS

private val SESSION_KINDS = setOf(
    StatementKind.STATEMENT_KIND_START_TRANSACTION, StatementKind.STATEMENT_KIND_COMMIT,
    StatementKind.STATEMENT_KIND_ROLLBACK, StatementKind.STATEMENT_KIND_SAVEPOINT,
    StatementKind.STATEMENT_KIND_SET_TRANSACTION, StatementKind.STATEMENT_KIND_SET_SESSION_VAR,
    StatementKind.STATEMENT_KIND_USE,
)

internal fun spentRate(auditStore: AuditStore?, principal: String, datasource: String, vararg resolved: ResolvedCaps): String? {
    if (auditStore == null || resolved.any { it.unbounded }) return null
    val rates = resolved.flatMap { it.rates }
    if (rates.isEmpty()) return null
    val relayed = auditStore.relayedVolume(principal, datasource, rates.map { it.window }, Instant.now())
    val spent = rates.firstOrNull { rate ->
        val volume = relayed.getValue(rate.window)
        (rate.rows != null && volume.rows >= rate.rows) || (rate.bytes != null && volume.bytes >= rate.bytes)
    } ?: return null
    return "$RATE_SPENT_DENY ${spent.spec} spent"
}

private fun DecisionContext.withCaps(vararg resolved: ResolvedCaps): DecisionContext {
    val caps = resultCaps(*resolved)
    return copy(maxRows = caps.rows, maxBytes = caps.bytes)
}

internal const val MASK_BIND_DENY = "required mask could not be bound to a result column"
private const val SYSTEM_FUNCTION_DENY = "dangerous system function is not allowed:"
private const val SYSTEM_UTILITY_DENY = "utility command is not allowed on this datasource:"
private const val DEACTIVATED_PRINCIPAL_DENY = "principal is deprovisioned (deactivated) — access denied"
private const val CATALOG_CONFIGURATION_DENY = "fail-closed: invalid catalog or analyzer namespace configuration"
internal const val RATE_SPENT_DENY = "rate"
private const val WIRE_TASK_FORBIDDEN_DENY = "automatic task approval is not permitted for this datasource"

private fun structuralDeny(
    reason: String,
    roles: List<String>,
    failedStage: String = "admission",
    // Audit fidelity: the derived context.tags the decision was evaluated under. Defaults empty for
    // the pre-derivation early denies (admission-reject / deactivated) that return before any tag is derived.
    contextTags: List<String> = emptyList(),
): DecisionContext = DecisionContext(
    action = EnfAction.DENY,
    denyReason = reason,
    masks = emptyList(),
    piiTouched = emptyList(),
    effectiveRoles = roles,
    failedStage = failedStage,
    detail = reason,
    passthrough = false,
    structural = true,
    contextTags = contextTags,
)

/**
 * A missing `datasource.connect` / `sql.<kind>` Cedar grant (the once-per-query gates ahead of the
 * catalog/analyzer/column loop). Unlike [structuralDeny] this is grant-overridable — a JIT grant could
 * add a role that holds the missing action — and "policy" is a more honest audit `failedStage` than
 * "admission" for a Cedar deny (docs/authz-model.md wants sql_kind + matched policy in the audit trail).
 */
private fun policyDeny(
    reason: String,
    roles: List<String>,
    // Audit fidelity: the derived context.tags the decision was evaluated under (every policyDeny
    // site runs after context derivation, so callers always pass the request's derived tags).
    contextTags: List<String> = emptyList(),
): DecisionContext = DecisionContext(
    action = EnfAction.DENY,
    denyReason = reason,
    masks = emptyList(),
    piiTouched = emptyList(),
    effectiveRoles = roles,
    failedStage = "policy",
    detail = reason,
    passthrough = false,
    structural = false,
    contextTags = contextTags,
)

/**
 * Fail-closed override when a native-wire statement's self-approve is forbidden — the Cedar `task.request` or
 * `task.approve` gate on the wire channel denied it, so no task is created and nothing relays. Surfaces as an
 * ordinary policy DENY (SQLSTATE 42501/1142), never a gRPC status, so the client sees the same shape as any
 * other denied statement.
 */
internal fun wireTaskForbiddenDeny(
    roles: List<String>,
    contextTags: List<String>,
): DecisionContext = policyDeny(WIRE_TASK_FORBIDDEN_DENY, roles, contextTags)

// Relay the analyzer's optional rewritten SQL on a decision we allow. rewrittenSql is Go-analyzer output
// (the `SELECT *` expansion, the MySQL charset pin) independent of statement class, so every
// understood-and-allowed decision — analyzed, metadata, session — routes it through this one point rather
// than each building its own. An EXPLAIN/DESCRIBE keeps its original text — the analyzer emits no
// rewritten_sql for it (the rewrite is for the inner query it plans). The exception.unanalyzable escape
// hatches deliberately relay the original whole statement, so they do not call this.
private fun DecisionContext.withAnalyzerRewrite(facts: StatementFacts): DecisionContext = when {
    facts.hasRewrittenSql() -> copy(
        rewrittenSql = facts.rewrittenSql,
        submission = if (facts.hasSubmission()) facts.submission else null,
    )
    else -> this
}

// The Cedar action a statement's kind is gated by. "stmt.kind.<k>" is a member of its category action in
// the schema, so a category or kind preset matches it; an admin-category kind with no preset denies —
// closing the connect-only gaps (ANALYZE TABLE, SHOW MASTER STATUS, …). UNSPECIFIED/UNRECOGNIZED is the
// invalid zero value the analyzer never emits on a real classification; it returns null → hard deny.
private fun statementKindActionId(kind: StatementKind): String? = when (kind) {
    StatementKind.STATEMENT_KIND_UNSPECIFIED, StatementKind.UNRECOGNIZED -> null
    // An unclassified statement (a parse fallback, or a discriminator the classifier does not map yet) is
    // gated by the same deny-by-default exception as an unanalyzable one, not a distinct kind action:
    // existing exception.unanalyzable exceptions carry it, a dev datasource may relay, prod denies.
    StatementKind.STATEMENT_KIND_STMT_UNKNOWN -> AuthzAction.EXCEPTION_UNANALYZABLE.cedarId
    else -> "stmt.kind." + kind.name.removePrefix("STATEMENT_KIND_").lowercase()
}

private fun passthroughAllow(
    roles: List<String>,
    detail: String,
    // Audit fidelity: the derived context.tags the passthrough was evaluated under.
    contextTags: List<String> = emptyList(),
): DecisionContext = DecisionContext(
    action = EnfAction.ALLOW,
    denyReason = null,
    masks = emptyList(),
    piiTouched = emptyList(),
    effectiveRoles = roles,
    failedStage = null,
    detail = detail,
    passthrough = true,
    contextTags = contextTags,
)

// Structural DENY rows intentionally use the normal audit path and still receive a decisionId. The
// current UI may offer approval for those rows; the minting path must refuse rows with failed_stage='admission'.
// `internal` (not private): shared with the per-connection enforcing decide flow ([decideConnection] in
// ConnectionDecide.kt) AND the test-only enforcement harness (support/EnforcementHarness.kt), which reuse
// this exact audit shape.
internal fun decisionRecord(
    principal: String,
    ds: Datasource,
    sql: String,
    clientAddr: String?,
    ctx: DecisionContext,
    latencyMs: Long,
    effectiveNamespace: List<String>,
    channel: Channel,
) = AuditEvent(
        principal = principal, roles = ctx.effectiveRoles, datasource = ds.name, clientAddr = clientAddr, statement = sql,
        decision = when (ctx.action) {
            EnfAction.ALLOW -> Decision.ALLOW
            EnfAction.MASK -> Decision.MASK
            // DENY plus the proto-only ENF_ACTION_UNSPECIFIED / UNRECOGNIZED sentinels fail closed to DENY.
            else -> Decision.DENY
        },
        failedStage = ctx.failedStage, maskedColumns = ctx.masks.map { it.column },
        piiTouched = ctx.piiTouched, latencyMs = latencyMs, detail = ctx.detail,
        effectiveNamespace = effectiveNamespace,
        channel = channel.contextValue, contextTags = ctx.contextTags,
    )

fun Route.queryRoutes(
    config: Config,
    datasourceStore: DatasourceStore,
    historyStore: QueryHistoryStore,
    runExecService: RunExecService,
) {
    post("/api/datasources/{id}/query") {
        val principal = call.requireApi() ?: return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val ds = datasourceStore.get(id) ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        val req = call.receive<QueryRequest>()
        // Auto-save the run to the principal's editor history (best-effort; never blocks the query).
        runCatching { historyStore.add(principal, id, req.sql) }
        try {
            call.respond(
                runExecService.run(
                    principal, ds, req.sql, req.maxRows,
                    requesterIp = call.httpRequesterIp(config),
                    exchangeTimeoutMs = config.queryExchangeTimeoutMs,
                ),
            )
        } catch (_: NoProxyAttachedException) {
            call.respond(HttpStatusCode.ServiceUnavailable, ApiError("query.no_proxy_attached"))
        } catch (_: ProxyStreamWedgedException) {
            call.respond(HttpStatusCode.ServiceUnavailable, ApiError("query.proxy_stream_wedged"))
        } catch (_: ProxyRunTimeoutException) {
            call.respond(HttpStatusCode.GatewayTimeout, ApiError("query.proxy_timeout"))
        } catch (e: TargetDbRunException) {
            // The run's decision already chose the form (raw for a full reader, redacted for a masked one).
            call.respond(HttpStatusCode.BadGateway, ApiError("query.failed", mapOf("detail" to e.decidedMessage)))
        } catch (e: ProxyRunException) {
            // A generic failure's text can echo the target host (`dial tcp 10.0.3.7:5432: …`) — log only.
            call.application.environment.log.warn("query run failed", e)
            call.respond(HttpStatusCode.BadGateway, ApiError("query.failed"))
        }
    }
}

@Serializable
data class OpenEditorSessionInput(val datasourceId: Long)

@Serializable
data class EditorSessionOpened(val sessionId: String)

/** [searchPath] is the held connection's effective namespace; null until the proxy reports one, or when it could not read it. */
@Serializable
data class EditorSessionState(val searchPath: List<String>?)

@Serializable
data class DefaultSchemaInput(val schema: String)

/** The statement run to set the default schema, its outcome, and the session's namespace afterwards. */
@Serializable
data class DefaultSchemaResult(val statement: String, val result: QueryResultMeta?, val searchPath: List<String>?)

/** Async editor SUBMIT ack: the born-APPROVED EDITOR task and its single result child (task:child 1:1). No
 *  rows inline — completion is observed by polling the task/result endpoints. */
@Serializable
data class EditorSubmitResponse(
    val taskId: Long,
    val childId: Long,
    /** The statements the submit was split into, in run order — one result child each. */
    val statements: List<String> = emptyList(),
)

/** Editor task poll: the parent task status plus its child result metadata (rows stay behind /result). */
@Serializable
data class EditorTaskStatus(
    val taskId: Long,
    val status: String,
    /** The batch's active statement. */
    val result: QueryResultMeta? = null,
    /** Every statement of the batch, in run order, each with its own status. */
    val statements: List<QueryResultMeta> = emptyList(),
)

/**
 * Persistent editor SESSION + async task routes (connection-model.md; editor-as-task). Open
 * ONE proxy-dialed stream — one target-DB connection — per editor session, then submit queries that run
 * ASYNC as auto-approved EDITOR tasks: each submit creates a born-APPROVED task with one query_result child,
 * launches the run on [appScope] over the held session, and saves the enforced result. The client polls the
 * task/result endpoints — the editor never blocks and each tab polls independently. Enforcement stays
 * PER-STATEMENT (each query re-decides against the connection's live namespace on the EDITOR channel under
 * the caller's own roles). Rows are gated by task.assume + a live re-decision, exactly like an approval view.
 */
fun Route.editorSessionRoutes(
    config: Config,
    datasourceStore: DatasourceStore,
    accessStore: AccessStore,
    // null when PM_RESULT_KEY is unset → async editor submit is refused fail-closed (no plaintext PII persisted).
    queryResultStore: QueryResultStore?,
    policyStore: PolicyStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    runExecService: RunExecService,
    appScope: CoroutineScope,
    systemClassification: SystemClassificationService? = null,
    // Pushes a task's terminal transition to the owner's SSE stream so the tab updates without waiting for
    // its next poll (null in the many Config-free test constructions — publish is then a no-op).
    taskCompletionHub: TaskCompletionHub? = null,
    // Feeds the stored-result re-decision the viewer's relayed volume for its rate entries, as the wire path does.
    auditStore: AuditStore? = null,
    service: EditorTaskService = EditorTaskService(
        config, datasourceStore, accessStore, queryResultStore, policyStore, userGroupStore, roleResolver, authz,
        runExecService, appScope, systemClassification, taskCompletionHub, auditStore,
    ),
) {
    post("/api/editor/sessions") {
        val principal = call.requireApi() ?: return@post
        val input = call.receive<OpenEditorSessionInput>()
        val ds = datasourceStore.get(input.datasourceId)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        try {
            call.respond(EditorSessionOpened(runExecService.openSession(principal, ds, call.httpRequesterIp(config))))
        } catch (_: NoProxyAttachedException) {
            call.respond(HttpStatusCode.ServiceUnavailable, ApiError("query.no_proxy_attached"))
        } catch (_: ProxyStreamWedgedException) {
            call.respond(HttpStatusCode.ServiceUnavailable, ApiError("query.proxy_stream_wedged"))
        } catch (_: ProxyRunTimeoutException) {
            call.respond(HttpStatusCode.GatewayTimeout, ApiError("query.proxy_timeout"))
        } catch (e: ProxyRunException) {
            // An open failure's text can echo the target host (`dial tcp 10.0.3.7:5432: …`) — log only.
            call.application.environment.log.warn("editor session open failed", e)
            call.respond(HttpStatusCode.BadGateway, ApiError("query.failed"))
        }
    }

    // Async submit: launch the run as an auto-approved EDITOR task on the held session and ACK 202 — no rows
    // inline (mirrors /api/approvals/{id}/execute). The web swaps its tab's taskId and polls to completion.
    post("/api/editor/sessions/{sessionId}/query") {
        val principal = call.requireApi() ?: return@post
        val sessionId = call.parameters["sessionId"]
            ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val req = call.receive<QueryRequest>()
        try {
            val sub = service.submitOnSession(principal, call.httpRequesterIp(config), sessionId, req.sql, req.maxRows)
            call.respond(HttpStatusCode.Accepted, sub.response)
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    get("/api/editor/tasks/{taskId}") {
        val principal = call.requireApi() ?: return@get
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(service.status(principal, call.httpRequesterIp(config), taskId))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    post("/api/editor/tasks/{taskId}/cancel") {
        val principal = call.requireApi() ?: return@post
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(service.cancel(principal, call.httpRequesterIp(config), taskId))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    // ?statement=<ordinal> selects one statement of a batch; absent takes the active one.
    get("/api/editor/tasks/{taskId}/result") {
        val principal = call.requireApi() ?: return@get
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val ordinalParam = call.request.queryParameters["statement"]
        val ordinal = if (ordinalParam == null) null else {
            ordinalParam.toIntOrNull()?.takeIf { it >= 0 }
                ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        }
        try {
            call.respond(service.result(principal, call.httpRequesterIp(config), taskId, ordinal))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    // Delete-on-close: idempotent 204, so a leaked id is not an existence oracle.
    delete("/api/editor/tasks/{taskId}") {
        val principal = call.requireApi() ?: return@delete
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        service.delete(principal, taskId)
        call.respond(HttpStatusCode.NoContent)
    }

    // The session's datasource when [principal] owns the session and may connect to it; the response is sent
    // otherwise. A missing session and someone else's get the same 404, so a guessed id reveals nothing. The
    // session's path names the target's schemas, so reading it needs datasource.connect, as the catalog does.
    suspend fun ApplicationCall.ownedConnectableSession(principal: String): Pair<OpenEditorSession, Datasource>? {
        val sessionId = parameters["sessionId"]
            ?: return null.also { respond(HttpStatusCode.BadRequest, ApiError("common.bad_id")) }
        val session = runExecService.sessionOwnedBy(sessionId, principal)
            ?: return null.also { respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor_session"))) }
        val ds = datasourceStore.getByName(session.datasourceName)
        if (ds == null || userGroupStore.isDeactivated(principal) ||
            !authorizeMetadata(authz, principal, roleResolver.resolve(principal), ds, httpAuthzContext(config))
        ) {
            return null.also { respond(HttpStatusCode.Forbidden, ApiError("datasource.not_connectable")) }
        }
        return session to ds
    }

    get("/api/editor/sessions/{sessionId}") {
        val principal = call.requireApi() ?: return@get
        val (session, _) = call.ownedConnectableSession(principal) ?: return@get
        call.respond(EditorSessionState(session.namespace))
    }

    // The engine builds the statement; it then runs as an ordinary editor submit on the session (the same
    // auto-approval and per-statement decision as typed SQL) and its task is dropped once read.
    post("/api/editor/sessions/{sessionId}/default-schema") {
        val principal = call.requireApi() ?: return@post
        val (session, ds) = call.ownedConnectableSession(principal) ?: return@post
        val schema = call.receive<DefaultSchemaInput>().schema
        if (schema.isBlank()) {
            return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "schema")))
        }
        val statement = ds.engine.definition.defaultSchemaStatement?.invoke(schema)
            ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("query.default_schema_unsupported"))
        val requesterIp = call.httpRequesterIp(config)
        try {
            val sub = service.submitOnSession(principal, requesterIp, session.sessionId, statement, 1)
            sub.job.join()
            val result = service.status(principal, requesterIp, sub.response.taskId).result
            service.delete(principal, sub.response.taskId)
            call.respond(DefaultSchemaResult(statement, result, session.namespace))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }

    delete("/api/editor/sessions/{sessionId}") {
        val principal = call.requireApi() ?: return@delete
        val sessionId = call.parameters["sessionId"]
            ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        // Close only if the caller owns the session (mirrors runOnSession) — a leaked sessionId must not let
        // another principal tear down this connection. Idempotent NoContent regardless, so it's not an
        // existence oracle for someone else's session id.
        runExecService.closeSessionOwnedBy(sessionId, principal)
        call.respond(HttpStatusCode.NoContent)
    }
}

/**
 * Extract the bare IP from a proxy-supplied `client_addr` for the Cedar `requester_ip`. The proxy
 * captures it from Netty's `SocketAddress.toString()`, so it arrives as `/1.2.3.4:5432` or `/[::1]:5432` (or
 * occasionally a bare IP). Strips the leading slash + the port. Returns null when there's nothing parseable —
 * fail-closed: the attribute is then absent, never a malformed value. A residual non-IP survivor is dropped
 * defensively at [AuthzContext.toCedarMap].
 */
internal fun parseRequesterIp(clientAddr: String?): String? {
    val a = clientAddr?.trim()?.removePrefix("/")?.takeIf { it.isNotEmpty() } ?: return null
    return when {
        a.startsWith("[") -> a.substringAfter('[').substringBefore(']')  // [v6]:port
        a.count { it == ':' } == 1 -> a.substringBefore(':')            // v4:port
        else -> a                                                       // bare v4/v6 (no port)
    }.takeIf { it.isNotEmpty() }
}
