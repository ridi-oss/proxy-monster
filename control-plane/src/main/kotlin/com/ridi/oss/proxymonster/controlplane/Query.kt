package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
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
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.classification.BaselineDangerousFunctions
import com.ridi.oss.proxymonster.grpc.ColumnMask
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.RunError
import com.ridi.oss.proxymonster.grpc.columnMask
import com.ridi.oss.proxymonster.analyzer.pb.ColumnSpec
import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.ResultFingerprint
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.analyzer.pb.columnSpec
import com.ridi.oss.proxymonster.analyzer.pb.resultFingerprint
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig as pbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace as pbNamespace
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.probe.Analyzer
import com.ridi.oss.proxymonster.probe.Dialect
import com.ridi.oss.proxymonster.probe.Masking
import com.ridi.oss.proxymonster.probe.analyzerFor
import com.ridi.oss.proxymonster.probe.bindMasks
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.slf4j.LoggerFactory

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
    /** The analyzer's ordered output column names for this decision (an empty list for a passthrough /
     * unanalyzed statement). */
    val outputColumns: List<String> = emptyList(),
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
    val referencedSchemas: Set<String> = emptySet(),
    /** Parsed dotted-identifier candidates used by the catalog-miss retry path. */
    val schemaCandidates: Set<String> = emptySet(),
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
    leakColumns: List<com.ridi.oss.proxymonster.analyzer.pb.ColumnResource>,
    context: AuthzContext,
    authz: Authz,
    systemClassification: SystemClassificationService?,
): Boolean {
    if (leakColumns.isEmpty()) return true
    val byKey = catalog.associateBy { listOf(it.catalog, it.schema, it.table, it.column) }
    val refs = leakColumns.map { col ->
        val row = byKey[listOf(col.catalog, col.identity.schema, col.identity.table, col.identity.column)] ?: return false
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
    val specs: List<ColumnSpec>,
    val rowsByKey: Map<String, CatalogColumn>,
)

/**
 * Build the catalog's exact normalized-key index from an [analyzer] already built over [specs] (the
 * same list, in the same order, as [catalog] maps to) — reusing [Analyzer.columnKeys] rather than
 * re-deriving every row's key via a second full-catalog walk. Key uniqueness is already guaranteed by
 * [analyzerFor]'s own validation (it would have thrown), so [decideQuery] never observes a duplicate
 * here; the check below is defense-in-depth against a wiring bug, not a fold-drift concern.
 */
internal fun buildCatalogColumnIndex(
    catalog: List<CatalogColumn>,
    specs: List<ColumnSpec>,
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
    return CatalogColumnIndex(specs, rowsByKey)
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
    catalog: List<CatalogColumn>,
    tempColumns: List<CatalogColumn>,
    resolvedSearchPath: List<String>,
    liveAnsiQuotes: Boolean,
    postgresFunctionShadowingObserved: Boolean = false,
    postgresShadowedFunctions: List<String> = emptyList(),
    postgresSystemXidVisible: Boolean? = null,
): Pair<CatalogColumnIndex, Analyzer> {
    val mysqlCaseMode = ds.engine.requireCaseMode(ds.mysqlLowerCaseTableNames)
    val namespace = pbNamespace {
        this.catalog = ds.engine.catalogName(ds.dbName)
        this.searchPath.addAll(resolvedSearchPath)
    }
    val engineConfig = pbEngineConfig {
        this.engine = ds.engine
        this.engineVersion = ds.engineVersion ?: ""
        mysqlCaseMode?.let { this.mysqlLowerCaseTableNames = it }
        // Only meaningful for MySQL (the proxy observes ANSI_QUOTES off a MySQL session and leaves this
        // false otherwise); the PostgreSQL engine ignores it regardless.
        if (liveAnsiQuotes) this.mysqlAnsiQuotes = true
        if (postgresFunctionShadowingObserved) this.postgresFunctionShadowingObserved = true
        this.postgresShadowedFunctions.addAll(postgresShadowedFunctions)
        postgresSystemXidVisible?.let { this.postgresSystemXidVisible = it }
    }
    val effectiveCatalog = catalog + tempColumns
    val specs = effectiveCatalog.map { col ->
        columnSpec {
            this.catalog = col.catalog
            this.identity = relationIdentity {
                this.schema = col.schema
                this.table = col.table
                this.column = col.column
            }
            this.dataType = col.sqlType
            this.pii = col.classification != null
        }
    }
    val analyzer = analyzerFor(namespace, specs, engineConfig)
    return buildCatalogColumnIndex(effectiveCatalog, specs, analyzer) to analyzer
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
    catalog: List<CatalogColumn>,
    tempColumns: List<CatalogColumn> = emptyList(),
    liveSearchPath: List<String>? = null,
    liveAnsiQuotes: Boolean = false,
): List<String>? {
    val resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { listOf(ds.dbName.ifBlank { "public" }) }
    val (catalogIndex, facts) = try {
        val (index, analyzer) = analyzerAndCatalogIndex(ds, catalog, tempColumns, resolvedSearchPath, liveAnsiQuotes)
        index to analyzer.analyze(sql)
    } catch (e: Exception) {
        return null
    }
    if (!facts.resolved) return null
    return facts.predicateLiteralsList.mapNotNull { lit ->
        val identity = lit.column.identity
        val key = "${lit.column.catalog}.${identity.schema}.${identity.table}.${identity.column}"
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
    catalog: List<CatalogColumn>,
    policyStore: PolicyStore,
    accessStore: AccessStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    authz: Authz,
    // Almost always null (resolve server-side below). Tests that already resolved roles once and
    // want decideQuery + authz.authorizeColumns to see the EXACT same set (no risk of a second,
    // out-of-band resolve() disagreeing with the first) may pass them explicitly.
    providedRoles: Set<String>? = null,
    context: AuthzContext = AuthzContext(),
    // Wire connections' live effective namespace, probed as PostgreSQL search_path or MySQL current
    // database by the proxy; null resolves under ds.defaultSchemas (editor / callers that do not supply a
    // live namespace).
    liveSearchPath: List<String>? = null,
    // Whether the wire connection's live MySQL sql_mode has ANSI_QUOTES active (observed per statement).
    // Forwarded to the analyzer's EngineConfig so a masked column quoted with `"` is parsed as the column
    // and still masked; false for PostgreSQL and default MySQL mode.
    liveAnsiQuotes: Boolean = false,
    // PostgreSQL function visibility observed on the held target session. An unobserved empty list is not
    // equivalent to an observed empty list for polymorphic builtins such as unnest.
    postgresFunctionShadowingObserved: Boolean = false,
    postgresShadowedFunctions: List<String> = emptyList(),
    postgresSystemXidVisible: Boolean? = null,
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
    if (liveSearchPath != null && liveSearchPath.isEmpty() && catalog.isNotEmpty()) {
        return structuralDeny(CATALOG_CONFIGURATION_DENY, emptyList(), failedStage = "catalog").copy(catalogMiss = true)
    }
    val resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { listOf(ds.dbName.ifBlank { "public" }) }

    val catalogAndFacts = try {
        val (index, analyzer) = analyzerAndCatalogIndex(
            ds,
            catalog,
            tempColumns,
            resolvedSearchPath,
            liveAnsiQuotes,
            postgresFunctionShadowingObserved,
            postgresShadowedFunctions,
            postgresSystemXidVisible,
        )
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
            .copy(catalogMiss = catalogMiss, schemaCandidates = facts.schemaQualifierCandidatesList.toSet())

    when (authz.authorizeDatasourceAction(principal, roles, AuthzAction.DATASOURCE_CONNECT, ds.name, context, ds.tags)) {
        is AuthzDecision.Deny -> return policyDeny("no access to datasource '${ds.name}'", roleList, derivedTags)
        AuthzDecision.Allow -> Unit
    }

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
        return passthroughAllow(roleList, "passthrough (no data touched)", derivedTags)
            .copy(
                sanitizeDiagnostics = !readsAllUnmasked(principal, roles, ds, catalog, facts.diagnosticLeakColumnsList, context, authz, systemClassification),
                schemaCandidates = facts.schemaQualifierCandidatesList.toSet(),
            )
            .withAnalyzerRewrite(facts)
    }

    if (!facts.resolved) {
        if (facts.failureClass != FailureClass.FAILURE_CLASS_UNANALYZABLE) {
            return structuralDeny(facts.detail.ifBlank { "statement analysis failed" }, roleList, contextTags = derivedTags)
        }
        if (facts.functionsList.isNotEmpty()) {
            val functionTags = facts.functionsList.mapNotNull { name ->
                (systemClassification?.tagForFunction(ds.engine, ds.engineVersion, name)
                    ?: BaselineDangerousFunctions.classify(name)?.id)?.let { name to it }
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
                schemaCandidates = facts.schemaQualifierCandidatesList.toSet(),
                // A statement may be unresolvable only because this connection never fetched the schema it
                // names, so refetch the qualifiers before relaying it unmasked.
                catalogMiss = true,
                // Unanalyzable: no leak set to authorize, so fail closed and redact the diagnostic.
                sanitizeDiagnostics = true,
            )
            is AuthzDecision.Deny -> deny(reason, catalogMiss = true)
        }
    }

    val columnGrants = facts.resultReadsList.filter { it.hasColumn() }
    val columnKeys = LinkedHashMap<String, com.ridi.oss.proxymonster.analyzer.pb.ColumnResource>()
    for (grant in columnGrants) {
        val column = grant.column
        val key = listOf(column.catalog, column.identity.schema, column.identity.table, column.identity.column).joinToString(".")
        columnKeys.putIfAbsent(key, column)
    }
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
                schemaCandidates = facts.schemaQualifierCandidatesList.toSet(),
                // An uncovered column means the leak set can't be authorized — fail closed and redact.
                sanitizeDiagnostics = true,
            )
            is AuthzDecision.Deny -> structuralDeny(
                coverage.reason, roleList, failedStage = "catalog", contextTags = derivedTags,
            ).copy(catalogMiss = true, schemaCandidates = facts.schemaQualifierCandidatesList.toSet())
        }
    }

    val maskKinds = try {
        policyStore.listMaskFns().associate { it.name to it.kind }
    } catch (_: Exception) {
        return structuralDeny(CATALOG_CONFIGURATION_DENY, roleList, failedStage = "catalog", contextTags = derivedTags)
            .copy(catalogMiss = true, schemaCandidates = facts.schemaQualifierCandidatesList.toSet())
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

    val functionGrants = facts.resultReadsList.filter { it.hasFunction() }
    if (functionGrants.isNotEmpty() || facts.functionsList.isNotEmpty()) {
        val names = (functionGrants.map { it.function.name } + facts.functionsList).distinct()
        val functionTags = names.mapNotNull { name ->
            (systemClassification?.tagForFunction(ds.engine, ds.engineVersion, name)
                ?: BaselineDangerousFunctions.classify(name)?.id)?.let { name to it }
        }.toMap()
        functionGrants.firstOrNull { it.function.name !in functionTags }?.let {
            return structuralDeny("$SYSTEM_FUNCTION_DENY '${it.function.name}'", roleList, failedStage = "policy", contextTags = derivedTags)
        }
        if (functionTags.isNotEmpty()) {
            val refs = functionTags.keys.map(::FunctionRef)
            val verdicts = authz.authorizeFunctions(principal, roles, ds.name, refs, context, functionTags, ds.tags)
            refs.firstOrNull { verdicts[it.name] != FunctionVerdict.ALLOWED }?.let {
                return structuralDeny("$SYSTEM_FUNCTION_DENY '${it.name}'", roleList, failedStage = "policy", contextTags = derivedTags)
            }
        }
    }

    val columnVerdicts = if (columnRefs.isEmpty()) emptyMap() else
        authz.authorizeColumns(principal, roles, ds.name, columnRefs, context, columnSystemTags, ds.tags)
    val masks = ArrayList<ColumnMask>()
    for (grant in columnGrants) {
        val column = grant.column
        val key = listOf(column.catalog, column.identity.schema, column.identity.table, column.identity.column).joinToString(".")
        val row = catalogIndex.rowsByKey.getValue(key)
        val verdict = if (row.isTemp) ColumnVerdict.UNMASKED else columnVerdicts[key] ?: ColumnVerdict.DENIED
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
                    // valid index here; apply the first grant per ordinal (first-wins).
                    for (ordinal in grant.outputOrdinalsList) {
                        if (masks.none { it.ordinal == ordinal }) {
                            masks += if (grant.maskedDisposition == MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL) {
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
            TableRef("${table.catalog}.${table.schema}.${table.table}", table.catalog, table.schema, table.table)
        }.distinctBy { it.key }
        val verdicts = authz.authorizeTables(principal, roles, ds.name, refs, context, tableSystemTags, ds.tags)
        refs.firstOrNull { verdicts[it.key] != TableVerdict.READ }?.let {
            return deny("no read grant for scanned table '${it.schema}.${it.table}'")
        }
    }

    val action = if (masks.isEmpty()) EnfAction.ALLOW else EnfAction.MASK
    // Every classified column the statement touched, whatever its tags are named: `pii` is a deployment's
    // own tag, so keying this on that one string leaves auditmon's mass-export detector blind on a
    // deployment that classifies with `pci`.
    // TODO: rename to tagged_columns_touched. Needs a migration plus the Go verifier, the SIEM export name,
    // and the console; the canonical form is positional, so CHAIN_VERSION is unaffected.
    val tagged = columnKeys.keys.filter {
        catalogIndex.rowsByKey.getValue(it).classification?.tags?.isNotEmpty() == true
    }
    val referencedSchemas = buildSet {
        facts.sourcesList.mapTo(this) { it.schema }
        columnGrants.mapTo(this) { it.column.identity.schema }
    }.filterNotTo(LinkedHashSet()) { it.startsWith("pg_temp", ignoreCase = true) }
    val unmaskablePermitted = action == EnfAction.MASK && authz.authorizeDatasourceAction(
        principal, roles, AuthzAction.EXCEPTION_UNMASKABLE, ds.name, context, ds.tags,
    ) is AuthzDecision.Allow
    // MASK/DENY always redacts; an ALLOW redacts iff the analyzer's leak set holds a column the viewer
    // can't read unmasked. `select id from users` (all readable) relays raw.
    val sanitizeDiagnostics = action != EnfAction.ALLOW ||
        !readsAllUnmasked(principal, roles, ds, catalog, facts.diagnosticLeakColumnsList, context, authz, systemClassification)
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
        resultFingerprint = facts.resultReadsList,
        contextTags = derivedTags,
        unmaskablePermitted = unmaskablePermitted,
        sanitizeDiagnostics = sanitizeDiagnostics,
        catalogChanging = facts.catalogChanging || facts.functionsList.isNotEmpty(),
        referencedSchemas = referencedSchemas,
        schemaCandidates = facts.schemaQualifierCandidatesList.toSet(),
    ).withAnalyzerRewrite(facts)
}

// A column grant must carry a real masking disposition; an absent/unrecognized one is a malformed effect
// the walk would otherwise treat as a plain unmasked read, so it fails closed.
private val MALFORMED_DISPOSITIONS = setOf(
    MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED,
    MaskedDisposition.UNRECOGNIZED,
)

internal const val MASK_BIND_DENY = "required mask could not be bound to a result column"
private const val SYSTEM_FUNCTION_DENY = "dangerous system function is not allowed:"
private const val SYSTEM_UTILITY_DENY = "utility command is not allowed on this datasource:"
private const val DEACTIVATED_PRINCIPAL_DENY = "principal is deprovisioned (deactivated) — access denied"
private const val CATALOG_CONFIGURATION_DENY = "fail-closed: invalid catalog or analyzer namespace configuration"
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
private fun DecisionContext.withAnalyzerRewrite(facts: StatementFacts): DecisionContext =
    if (facts.hasRewrittenSql()) copy(rewrittenSql = facts.rewrittenSql) else this

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

/** Async editor SUBMIT ack: the born-APPROVED EDITOR task and its single result child (task:child 1:1). No
 *  rows inline — completion is observed by polling the task/result endpoints. */
@Serializable
data class EditorSubmitResponse(val taskId: Long, val childId: Long)

/** Editor task poll: the parent task status plus its child result metadata (rows stay behind /result). */
@Serializable
data class EditorTaskStatus(val taskId: Long, val status: String, val result: QueryResultMeta? = null)

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
        val sql = req.sql
        if (sql.isBlank()) {
            return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "sql")))
        }
        // Own roles, freshly resolved at THIS submit — the task executes as exactly these (never elevation,
        // never frozen across submits: a re-run resolves again, so a revoked role fails closed next time).
        val ownRoles = roleResolver.resolve(principal)
        if (ownRoles.isEmpty()) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("common.forbidden"))
        }
        // Resolve the datasource from the held session (owner-scoped) — a leaked session id can't target
        // another principal's connection.
        val dsName = runExecService.sessionDatasourceName(sessionId, principal)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor session")))
        val ds = datasourceStore.getByName(dsName)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        val store = queryResultStore
            ?: return@post call.respond(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))
        // Self-approve on the editor channel: must clear task.request AND task.approve.
        if (!autoApproveTask(principal, ownRoles, ds, call.httpAuthzContext(config), authz, Channel.EDITOR)) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("common.forbidden"))
        }

        val task = accessStore.createEditorTask(principal, ds.id, sql, ownRoles.toList(), approver = principal)
        val childId = accessStore.editorChildId(task.id) ?: -1L
        // Same single-execution claim as /execute, atomic so a cancel can't slip into an EXECUTING-but-no-
        // RUNNING-child gap: APPROVED → EXECUTING and the child NULL → RUNNING commit in one transaction.
        if (store.claimAndStartRun(task.id, principal) { c -> accessStore.claimExecution(task.id, c) } == null) {
            return@post call.respond(HttpStatusCode.Conflict, ApiError("approval.already_executed"))
        }

        val requesterIp = call.httpRequesterIp(config)
        val maxRows = req.maxRows
        appScope.launch {
            // A policy DENY carries its reason and audit decision id onto the failed child, so the polling
            // tab can offer an approval request built from that decision instead of showing a bare error.
            var denyReason: String? = null
            var denyDecisionId: Long? = null
            // The target-DB error behind a failure (both forms), stored so the FAILED view releases one per viewer.
            var diagnostic: RunError? = null
            val failureCode = try {
                // runOnSession decides on the EDITOR channel under empty assumeRoles (the caller's own roles)
                // and saves the enforced result instead of returning it inline.
                val response = runExecService.runOnSession(
                    sessionId, principal, sql, maxRows,
                    requesterIp = requesterIp,
                    taskId = task.id,
                    preflight = { store.meta(task.id)?.status == "RUNNING" },
                    exchangeTimeoutMs = config.queryExchangeTimeoutMs,
                )
                if (response.decision == EnfAction.DENY) {
                    denyReason = response.denyReason
                    denyDecisionId = response.decisionId
                    // Reuse the already-translated approval.* result codes (en/ko errors.json) — the messages
                    // ("denied at execution time" / "execution failed") are channel-agnostic, so the web
                    // localizes the polled code with no editor-specific catalog entries.
                    "approval.execute_denied"
                } else {
                    val result = DecryptedResult(response.columns, response.rows, response.rowsAffected, response.resultFingerprint)
                    // Child DONE + parent EXECUTED commit in ONE transaction (see /execute): a crash can never
                    // leave a readable DONE child under a non-EXECUTED task. The run's per-statement Decide
                    // round-trip already wrote the real audit decision (ALLOW/MASK/DENY + decisionId), so no
                    // task-level audit row is added here — it would only duplicate that as a false ALLOW.
                    val completed = store.completeRun(task.id, result, QueryResultStore.RESULT_RETENTION_SEC) { conn, _ ->
                        if (!accessStore.markExecuted(task.id, conn)) {
                            throw IllegalStateException("editor task ${task.id} left EXECUTING before completion")
                        }
                    }
                    if (completed != null) null else "approval.query_failed"
                }
            } catch (_: RunCanceledBeforeStartException) {
                null
            } catch (_: NoProxyAttachedException) {
                "query.no_proxy_attached"
            } catch (_: ProxyStreamWedgedException) {
                "query.proxy_stream_wedged"
            } catch (_: ProxyRunTimeoutException) {
                "query.proxy_timeout"
            } catch (e: TargetDbRunException) {
                diagnostic = e.toDiagnostic()
                "approval.query_failed"
            } catch (_: ProxyRunException) {
                "approval.query_failed"
            } catch (t: Throwable) {
                call.application.environment.log.error("editor task execution failed task=${task.id}", t)
                "approval.query_failed"
            }
            if (failureCode != null) {
                // Child FAILED + parent FAILED in ONE transaction (mirrors the success path's single commit).
                runCatching {
                    store.failRun(task.id, failureCode, denyReason, denyDecisionId, diagnostic = diagnostic) { conn, _ ->
                        accessStore.markFailed(task.id, conn)
                    }
                }
                    .onFailure { call.application.environment.log.error("editor task failure transition failed task=${task.id}", it) }
            }
            // Push the ACTUAL terminal state (EXECUTED / FAILED / or CANCELLED if a cancel raced) to the owner's
            // SSE stream so the tab updates at once; best-effort, the tab also polls (see TaskCompletionHub).
            accessStore.getRequest(task.id)?.status?.let { taskCompletionHub?.publish(principal, TaskEvent(task.id, it)) }
        }
        call.respond(HttpStatusCode.Accepted, EditorSubmitResponse(taskId = task.id, childId = childId))
    }

    // Poll: task status + child metadata. Owner-scoped to the caller's own EDITOR tasks (task.read/own);
    // 404 for a non-owner / non-EDITOR id, so it's not an existence oracle. Rows stay behind /result.
    get("/api/editor/tasks/{taskId}") {
        val principal = call.requireApi() ?: return@get
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val task = accessStore.getRequest(taskId)
        if (task == null || task.kind != "QUERY" || task.creatorKind != "EDITOR" || task.principal != principal) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        // task.read gates the metadata (status, row count, column names, error code, timestamps) — the owner
        // guard above is not a substitute: a Cedar forbid (e.g. task.read denied from an untrusted zone) must
        // still override the self-read permit.
        val mayRead = authz.authorizeWithContext(
            principal, AuthzAction.TASK_READ,
            task.toApprovalResource(),
            call.httpAuthzContext(config), task.datasourceName,
            task.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        if (mayRead is AuthzDecision.Deny) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        call.respond(EditorTaskStatus(task.id, task.status, queryResultStore?.meta(taskId)))
    }

    post("/api/editor/tasks/{taskId}/cancel") {
        val principal = call.requireApi() ?: return@post
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val task = accessStore.getRequest(taskId)
        if (task == null || task.kind != "QUERY" || task.creatorKind != "EDITOR" || task.principal != principal) {
            return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        val mayCancel = authz.authorizeWithContext(
            principal, AuthzAction.TASK_CANCEL,
            task.toApprovalResource(),
            call.httpAuthzContext(config), task.datasourceName,
            task.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        if (mayCancel is AuthzDecision.Deny) {
            return@post call.respond(HttpStatusCode.Forbidden, ApiError("approval.cancel_forbidden"))
        }
        if (task.status != "EXECUTING") {
            return@post call.respond(EditorTaskStatus(task.id, task.status, queryResultStore?.meta(taskId)))
        }
        val store = queryResultStore
            ?: return@post call.respond(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))
        val cancelled = store.cancelRun(taskId) { conn, _ ->
            if (!accessStore.markCancelled(taskId, conn)) {
                throw IllegalStateException("editor task $taskId left EXECUTING before cancellation")
            }
        }
        if (cancelled != null) {
            runExecService.cancelActiveRun(taskId)
            // The run coroutine also pushes its terminal state, but a cancel of a stuck/slow run may win the
            // CAS well before the coroutine unwinds — push CANCELLED now so the owner's tab reflects it at once.
            taskCompletionHub?.publish(principal, TaskEvent(taskId, "CANCELLED"))
        }
        val updated = accessStore.getRequest(taskId)
            ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        call.respond(EditorTaskStatus(updated.id, updated.status, store.meta(taskId)))
    }

    // Rows: task.assume gates the viewer (no authDebug bypass — data confidentiality), then the stored result
    // is re-decided live under the task's execute-as roles on the EDITOR channel — mirrors the approval view.
    get("/api/editor/tasks/{taskId}/result") {
        val principal = call.requireApi() ?: return@get
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val task = accessStore.getRequest(taskId)
        // Owner-scoped (frozen contract): an editor result is readable ONLY by its own submitter. The
        // task.assume check below is defense-in-depth (the owner passes it via the task.assume-parties policy);
        // without this principal guard a task.assume grantee (e.g. system:auditor via V40) could read another
        // user's editor rows, which the contract forbids. A non-owner / non-EDITOR id is an opaque 404.
        if (task == null || task.kind != "QUERY" || task.creatorKind != "EDITOR" || task.principal != principal) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        // Deprovisioning gate before result lookup (defense in depth; the live decide repeats it). Fail-closed.
        if (userGroupStore.isDeactivated(principal)) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        // One read captures ciphertext + meta; decrypt is lazy (only after authz passes → an unauthorized
        // viewer never triggers a decrypt, and a concurrent re-run can't swap the row between check + decrypt).
        val access = queryResultStore?.accessFor(taskId)
            ?: return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        val mayAssume = authz.authorizeWithContext(
            principal, AuthzAction.TASK_ASSUME,
            task.toApprovalResource(),
            call.httpAuthzContext(config, Channel.EDITOR), task.datasourceName,
            task.datasourceId?.let(datasourceStore::getIncludingDeleted)?.tags.orEmpty(),
        )
        if (mayAssume is AuthzDecision.Deny) {
            return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "editor task")))
        }
        val meta = access.meta
        // One re-decision gates both the FAILED diagnostic and the DONE rows. Not audited here — the
        // per-statement Decide already recorded it.
        val ctx = viewerDecision(
            principal, task, access.sql, call.httpAuthzContext(config),
            datasourceStore, policyStore, accessStore, userGroupStore, roleResolver, authz,
            systemClassification, Channel.EDITOR,
        )
        if (meta.status == "FAILED" && access.errorDetail != null) {
            return@get call.respond(
                QueryResultView(meta, emptyList(), emptyList(), errorDetail = failedDiagnosticForViewer(ctx, access.errorDetail)),
            )
        }
        if (meta.status != "DONE") {
            return@get call.respond(HttpStatusCode.Conflict, ApiError("approval.result_not_ready"))
        }
        val decrypted = access.decrypted
            ?: return@get call.respond(HttpStatusCode.Gone, ApiError("approval.result_expired"))
        val viewDecision =
            if (ctx == null) ResultViewDecision.Denied("stored result has no live decision to re-mask under")
            else decideResultView(ctx, decrypted)
        when (viewDecision) {
            is ResultViewDecision.Denied -> {
                call.application.environment.log.warn(
                    "editor result view denied task={} viewer={} reason={}", taskId, principal, viewDecision.reason,
                )
                call.respond(HttpStatusCode.Forbidden, ApiError("approval.result_view_denied"))
            }
            is ResultViewDecision.Allowed ->
                call.respond(
                    QueryResultView(
                        meta, viewDecision.columns, viewDecision.rows,
                        // MASK iff this view actually masked something. The editor labels its result from
                        // this; deriving it client-side from "are there rows" is what let a masked result
                        // display as a clean ALLOW.
                        decision = if (viewDecision.maskedColumns.isEmpty()) Decision.ALLOW else Decision.MASK,
                        maskedColumns = viewDecision.maskedColumns,
                    ),
                )
        }
    }

    // Delete-on-close: drop the tab's saved rows + its task row (CASCADE). Owner-scoped + EDITOR-only, so a
    // leaked id can't delete another principal's task; a non-owner / unknown id is a silent, idempotent 204.
    delete("/api/editor/tasks/{taskId}") {
        val principal = call.requireApi() ?: return@delete
        val taskId = call.parameters["taskId"]?.toLongOrNull()
            ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val task = accessStore.getRequest(taskId)
        if (task != null && task.kind == "QUERY" && task.creatorKind == "EDITOR" && task.principal == principal) {
            if (task.status == "EXECUTING") runExecService.cancelActiveRun(taskId)
            queryResultStore?.deleteResultsForTask(taskId)
            accessStore.deleteEditorTask(taskId, principal)
        }
        call.respond(HttpStatusCode.NoContent)
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
