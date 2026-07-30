package com.ridi.oss.proxymonster.controlplane.authz

import com.cedarpolicy.model.AuthorizationResponse
import com.cedarpolicy.model.entity.Entities
import com.cedarpolicy.model.entity.Entity
import com.cedarpolicy.value.CedarList
import com.cedarpolicy.value.EntityTypeName
import com.cedarpolicy.value.EntityUID
import com.cedarpolicy.value.IpAddress
import com.cedarpolicy.value.PrimString
import com.cedarpolicy.value.Value
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.TokenKind
import com.ridi.oss.proxymonster.controlplane.httpAuthzContext
import com.ridi.oss.proxymonster.controlplane.userSession
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond

/**
 * The Cedar action set (docs/authz-model.md). `cedarId` is the literal Cedar `Action::"..."` id — see
 * resources/authz/schema.cedarschema.
 */
enum class AuthzAction(val cedarId: String) {
    ADMIN_DATASOURCES("admin.datasources"),
    ADMIN_POLICIES("admin.policies"),
    ADMIN_IDENTITY("admin.identity"),
    TASK_APPROVE("task.approve"),
    // Task lifecycle actions replace code-side group-membership / ownership gates. TASK_REQUEST is
    // Datasource-scoped; TASK_READ gates metadata; TASK_ASSUME gates result data; GRANT_REVOKE acts on an
    // AccessGrant. Executing under R remains the same R-scoped TASK_APPROVE authority.
    TASK_REQUEST("task.request"),
    TASK_READ("task.read"),
    TASK_ASSUME("task.assume"),
    TASK_CANCEL("task.cancel"),
    TASK_DELETE("task.delete"),
    GRANT_REVOKE("grant.revoke"),
    TOKEN_MINT("token.mint"),
    TOKEN_LIST("token.list"),
    TOKEN_REVOKE("token.revoke"),
    AUDIT_READ("audit.read"),
    RESULT_READ_UNMASKED("result.read.unmasked"),
    RESULT_READ_MASKED("result.read.masked"),
    DATASOURCE_CONNECT("datasource.connect"),
    SQL_SELECT("sql.select"),
    SQL_INSERT("sql.insert"),
    SQL_UPDATE("sql.update"),
    SQL_DELETE("sql.delete"),
    SQL_DDL("sql.ddl"),
    // Datasource-level exception gates (facts-emission.md). A statement the analyzer cannot
    // fully reason about (`analyzable=false`) or whose result cannot be masked on the chosen path
    // (`maskable=false`, e.g. EXPLAIN-of-masked) asks its datasource for this exception instead of a blanket
    // hardcoded DENY. Deny-by-default: no exception policy → DENY (the production floor is unchanged); a
    // permissive dev datasource can permit the relay.
    SQL_UNANALYZABLE("sql.unanalyzable"),
    SQL_UNMASKABLE("sql.unmaskable"),
}

/** The Cedar-side resource an [AuthzAction] applies to. Marshalled to a Cedar entity by [Authz] —
 *  callers never touch cedar-java types directly. */
sealed interface AuthzResource {
    /** The instance-wide admin scope: admin.* actions are not scoped to one entity. */
    data object System : AuthzResource
    /** One audit decision, carrying the principal that owns the record. */
    data class AuditRecord(val principal: String) : AuthzResource
    /** The whole audit collection, for policies granting a global read capability. */
    data object AuditLog : AuthzResource
    /** A task request. Datasource and role parents support scoped lifecycle policies. */
    data class ApprovalRequest(
        val requester: String,
        val approver: String? = null,
        val executedBy: String? = null,
        val datasourceName: String? = null,
        val roleName: String? = null,
    ) : AuthzResource

    /** An issued JIT access grant (`access_grant` row). [owner] is the elevated principal, so an
     *  ownership policy scopes read/revoke (`resource.owner == principal`). [datasourceName]/[roleName],
     *  when set, attach the grant's Datasource/Role as Cedar parents so a per-datasource / per-role revoke
     *  policy matches — the grant analog of [ApprovalRequest]. [id] only disambiguates the EUID. */
    data class AccessGrant(
        val owner: String,
        val id: Long,
        val datasourceName: String? = null,
        val roleName: String? = null,
    ) : AuthzResource

    /** A wire/personal-access token being minted or managed (`proxy_token` row). [owner] is the
     *  principal it authenticates as; [kind] lets a policy permit short sessions but forbid long-lived
     *  PATs — null when the operation isn't tied to one token (e.g. listing a principal's tokens), which
     *  leaves the Cedar `kind` attribute absent. Prospective at mint time (no id), so it is Token{owner, kind}. */
    data class Token(val owner: String, val kind: TokenKind?) : AuthzResource
}

/** A column touched by a query, marshalled to Cedar entities by [authorizeColumns]. [key] is the
 *  caller's fully-qualified analyzer identifier — it stays opaque here and is only the map key the
 *  verdict comes back under. [catalog], [schema], [table], and [column] come from the exact matching
 *  catalog row; they are never recovered by parsing [key]. [tags] drive tag-scoped grants/exclusions
 *  (e.g. "read table X except pii"); the caller resolves them from the catalog ([Authz] never queries it). */
data class ColumnRef(
    val key: String,
    val catalog: String,
    val schema: String,
    val table: String,
    val column: String,
    val tags: List<String> = emptyList(),
)

/** Per-column authz verdict — deny-by-default: [DENIED] unless a Cedar grant says otherwise. Which
 *  mask fn to apply on [MASKED] is column config, not part of this decision — see [authorizeColumns]. */
enum class ColumnVerdict { UNMASKED, MASKED, DENIED }

/** A physical table SCANNED by a query with zero traced columns (docs/facts-emission.md),
 *  marshalled to a Cedar `Table` entity by [authorizeTables]. [key] is the caller's `catalog.schema.table`
 *  identity — opaque here, only the map key the verdict returns under. [catalog]/[schema]/[table] come
 *  from the analyzer's resolved identity, never by parsing [key]. [authorizeTables] marshals the datasource
 *  parent plus — when the caller supplies a `systemTags` entry — the `system:` Tag parent
 *  (`entity Table in [Datasource, Tag]`), so an uncovered scan of a system table is decided against its tag. */
data class TableRef(
    val key: String,
    val catalog: String,
    val schema: String,
    val table: String,
)

/** Per-table scan verdict — deny-by-default. [READ] means a `result.read.{unmasked|masked}` grant
 *  covers the Table (directly, or via a Datasource grant): a masked reader is already allowed to observe
 *  the table's rows through masked projections, so it may observe existence + row count. */
enum class TableVerdict { READ, DENIED }

/** A function CALLED by a query (facts-emission.md), marshalled to a Cedar `Function` entity by
 *  [authorizeFunctions]. [name] is the bare (unqualified) function name — the analyzer drops the schema
 *  qualifier at parse time, and the caller classifies it via the datasource's system manifests. Only
 *  DANGEROUS-classified functions ([systemTag] non-null) are passed; safe functions are never marshalled. */
data class FunctionRef(val name: String)

/** Per-function verdict — [DENIED] when a `system:` forbid covers the function (a `system:data-leak`/
 *  `system:critical` builtin), else [ALLOWED]. Since only dangerous functions are marshalled, a marshalled
 *  Function is denied by the shipped forbid even against a broad datasource read grant (forbid overrides). */
enum class FunctionVerdict { ALLOWED, DENIED }

/** A resource-bearing utility command a query performs (facts-emission.md), marshalled to a
 *  Cedar `Utility` entity by [authorizeUtilities]. [command] is the canonical per-engine command id
 *  (`SHOW_PROCESSLIST`, …); the caller resolves its shipped `system:` tag via the manifest. */
data class UtilityRef(val command: String)

/** Per-utility verdict — deny-by-default. [USE] iff a `result.read.unmasked`/`masked` permit covers the
 *  Utility (a shipped `system:catalog` permit, or a dev/broad grant) AND no `system:` forbid overrides. A
 *  RECOGNIZED utility with no classification carries no permit → DENIED (fail-closed on unsupported versions). */
enum class UtilityVerdict { USE, DENIED }

/**
 * Request-scoped context Cedar policies condition on (docs/authz-context.md). **Server-attested,
 * never client-asserted** — the control-plane sets these from the entry point + observed connection.
 *  - [channel]      which surface/phase: `wire` | `editor` | `workflow-executor` | `workflow-viewer`.
 *  - [requesterIp]  the end client's source address, a Cedar `ipaddr`; null when unknown.
 *  - [tags]         DERIVED (two-pass tag rules) — the tag names the request earns; never client-supplied.
 *  - [networkZones] a coarse network-zone list (authz-model.md); requester_ip and derived [tags] are the primary mechanism.
 */
data class AuthzContext(
    val networkZones: List<String> = emptyList(),
    val channel: String? = null,
    val requesterIp: String? = null,
    val tags: Set<String> = emptySet(),
) {
    /**
     * The Cedar `context` map. `network_zones` is always present (empty set if none); `tags` too UNLESS
     * [includeTags] is false — pass-1 tag derivation ([resolveContextTags]) omits it so a tag rule can't read
     * `context.tags` at all (no tag-on-tag / no recursion; the generated tag-action schema also omits it, so
     * an unguarded read is rejected outright). Optional `channel` / `requester_ip` are included only when set
     * — a policy conditioning on an absent attr fails closed (Cedar skips it). No client value ever reaches here.
     */
    fun toCedarMap(includeTags: Boolean = true): Map<String, Value> = buildMap {
        put("network_zones", CedarList(networkZones.map { PrimString(it) as Value }))
        if (includeTags) put("tags", CedarList(tags.map { PrimString(it) as Value }))
        channel?.let { put("channel", PrimString(it)) }
        requesterIp?.let { ip ->
            // Defensive: a malformed IP must NEVER break the whole decision. Fail-closed means the attribute
            // is simply absent (a policy conditioning on it then denies), not a thrown IpAddress constructor
            // that would error every query. So an unparseable value is dropped, not propagated.
            runCatching { IpAddress(ip) }.getOrNull()?.let { put("requester_ip", it) }
        }
    }
}

sealed interface AuthzDecision {
    data object Allow : AuthzDecision
    data class Deny(val reason: String, val code: String = "forbidden") : AuthzDecision
}

/**
 * Authz's identity port (Layer 1 — RoleResolver, no Cedar). [Authz] never resolves roles itself; the
 * caller wires in a [RoleSource] backed by `RoleResolver.resolve` (or a stub, in tests) — this is
 * what keeps role resolution swappable/testable independent of Cedar.
 */
fun interface RoleSource {
    fun rolesOf(principal: String): Set<String>
}

private val USER_TYPE: EntityTypeName = EntityTypeName.parse("User").get()
private val ROLE_TYPE: EntityTypeName = EntityTypeName.parse("Role").get()
private val ACTION_TYPE: EntityTypeName = EntityTypeName.parse("Action").get()
private val SYSTEM_TYPE: EntityTypeName = EntityTypeName.parse("System").get()
private val DATASOURCE_TYPE: EntityTypeName = EntityTypeName.parse("Datasource").get()
private val REQUEST_TYPE: EntityTypeName = EntityTypeName.parse("Request").get()
private val ACCESS_GRANT_TYPE: EntityTypeName = EntityTypeName.parse("AccessGrant").get()
private val TOKEN_TYPE: EntityTypeName = EntityTypeName.parse("Token").get()
private val AUDIT_RECORD_TYPE: EntityTypeName = EntityTypeName.parse("AuditRecord").get()
private val AUDIT_LOG_TYPE: EntityTypeName = EntityTypeName.parse("AuditLog").get()
private val TABLE_TYPE: EntityTypeName = EntityTypeName.parse("Table").get()
private val COLUMN_TYPE: EntityTypeName = EntityTypeName.parse("Column").get()
private val TAG_TYPE: EntityTypeName = EntityTypeName.parse("Tag").get()
private val FUNCTION_TYPE: EntityTypeName = EntityTypeName.parse("Function").get()
private val UTILITY_TYPE: EntityTypeName = EntityTypeName.parse("Utility").get()

/**
 * The `system:` (and `udf:`) tag namespaces are TYPE-SCOPED (facts-emission.md, system-classification.md)
 * — a security invariant enforced HERE, at Cedar marshalling, not just at the admin write API:
 *   - `system:development` / `system:production` (datasource posture) → marshalled ONLY onto a **Datasource**;
 *   - every other `system:*` tag (the shipped classification: system:critical/activity/data-leak/catalog) is
 *     attached to a Table/Column/Function ONLY from the shipped manifest, never honored from user column tags;
 *   - `udf:output-vouched` → valid only on a UDF **Function**.
 * Without this, a Column whose catalog row carried a hand-written `system:development` (or a forged
 * `system:critical`) tag would satisfy a preset permit / bypass a shipped forbid and leak cleartext. So each
 * resource attaches ONLY the reserved tags valid for its own type, plus its ordinary user tags; every other
 * reserved tag is dropped before the Cedar graph is built. Datasource tags are otherwise free-form: any
 * non-reserved tag is carried but inert. [DATASOURCE_POSTURE_TAGS] is the allowlist for a Datasource;
 * [isReservedTag] identifies a `system:`/`udf:` tag a Column/Table/Function must NOT carry directly (its
 * shipped `system:` classification is attached separately, from the manifest, not here).
 */
private val DATASOURCE_POSTURE_TAGS = setOf("system:development", "system:production")
private fun isReservedTag(t: String): Boolean =
    t.startsWith("system:") || t == "udf:output-vouched"

/** The Datasource entity carrying ONLY its recognized posture Tag parents (others dropped), so a policy's
 *  `resource in Tag::"system:development"` matches this datasource AND — transitively via the Datasource
 *  parent — every Table/Column/Function under it. [tagEuids] is the caller's shared dedup map. */
private fun datasourceEntity(
    dsEuid: EntityUID,
    name: String,
    datasourceTags: List<String>,
    tagEuids: HashMap<String, EntityUID>,
): Entity {
    val parents = datasourceTags.filter { it in DATASOURCE_POSTURE_TAGS }
        .map { tagEuids.getOrPut(it) { TAG_TYPE.of(it) } }
        .toSet()
    return Entity(dsEuid, mapOf("name" to PrimString(name)), parents)
}

/** Collapse entities sharing an EUID to one (first wins) — cedar-java rejects a set containing two
 *  distinct [Entity] objects for the same [EntityUID] outright ("duplicate entity entry"), even when
 *  they're structurally identical placeholders (`Entity(euid)`). */
private fun dedupeByEuid(entities: List<Entity>): Set<Entity> {
    val seen = LinkedHashMap<EntityUID, Entity>()
    for (e in entities) seen.putIfAbsent(e.getEUID(), e)
    return seen.values.toSet()
}

/**
 * Translate a cedar-java [AuthorizationResponse] into our [AuthzDecision]: fail closed on an engine
 * error (no success payload), ALLOW iff a policy permits, else deny-by-default carrying the diagnosing
 * reasons. Shared by [Authz.authorize] and [authorizeDatasourceAction] so the two single-resource entry
 * points can never drift in how they read a Cedar verdict. (Per-column [authorizeColumns] reads only the
 * boolean `isAllowed` inline — it needs a verdict, not a reason, for each of its many columns.)
 */
private fun AuthorizationResponse.toAuthzDecision(): AuthzDecision {
    val success = success.orElse(null)
        ?: return AuthzDecision.Deny(
            reason = "authorization engine error: " +
                errors.map { list -> list.joinToString("; ") { it.message } }.orElse("unknown error"),
        )
    if (success.isAllowed) return AuthzDecision.Allow
    val reasons = success.getReason()
    return AuthzDecision.Deny(
        reason = if (reasons.isEmpty()) "no policy permits this action" else "denied by policy: ${reasons.joinToString(", ")}",
    )
}

/**
 * The authz decision service (docs/authz-model.md — "authz boundary": Cedar, schema, entity
 * marshalling, and the policy store stay internal; consumers only see [authorize]). Every call
 * evaluates Cedar for real — there is no bypass here; that's `requireAdmin`'s job (the authDebug
 * dev bypass short-circuits *before* ever reaching [authorize], see [requireAdmin] below).
 */
class Authz(
    // internal, not private: [authorizeColumns] is a top-level extension in this file (mirrors
    // requireAdmin's style below) that needs the raw engine for its own two-actions-per-column
    // marshalling — [authorize]'s single-resource shape doesn't fit a whole-query column batch. Still
    // module-private: never exposed outside control-plane (the authz boundary — see class doc).
    internal val engine: CedarEngine,
    @Suppress("unused") private val policyStore: CedarPolicyStore,
    private val roleSource: RoleSource,
) {
    /** Accessor over the private [roleSource]: [authorizeWithContext] resolves a principal's
     *  roles ONCE to feed BOTH pass-1 tag derivation and pass-2 authorization — this accessor is how it reaches
     *  the role port to take that single snapshot before threading it through [authorizeAs]. */
    internal fun rolesOf(principal: String): Set<String> = roleSource.rolesOf(principal)

    /**
     * Whether the ENGINE can evaluate [ip] as a `requester_ip` — which cedar-java's `IpAddress` regex
     * does not answer (see [com.ridi.oss.proxymonster.controlplane.isStorableIpLiteral]).
     *
     * Runs one throwaway decision and asks only whether the engine produced a verdict at all: the
     * verdict itself is irrelevant, only the absence of an engine ERROR is being tested.
     */
    fun evaluatesInCedar(ip: String): Boolean {
        val principal = USER_TYPE.of("ip-probe")
        val entities = Entities(setOf(Entity(principal, emptyMap(), emptySet())))
        val context = AuthzContext(requesterIp = ip).toCedarMap()
        val response = runCatching {
            engine.isAuthorized(principal, ACTION_TYPE.of(AuthzAction.SQL_SELECT.cedarId), SYSTEM_TYPE.of("system"), entities, context)
        }.getOrNull() ?: return false
        return response.success.isPresent
    }

    /**
     * Single-resolution entry: resolve [principal]'s roles once, then authorize via [authorizeAs]. This is the
     * common case (System / AuditLog resources with no datasource-scoped tags — `requireAdmin`, computeMePermissions,
     * the audit routes). When a datasource-scoped `context.tags` derivation must AGREE with the final decision on
     * the same role snapshot (the approval-authority routes), go through [authorizeWithContext] instead.
     */
    fun authorize(
        principal: String,
        action: AuthzAction,
        resource: AuthzResource,
        context: AuthzContext = AuthzContext(),
    ): AuthzDecision = authorizeAs(principal, roleSource.rolesOf(principal), action, resource, context)

    /**
     * Authorize with an EXPLICIT, already-resolved [roles] set — no second, out-of-band [RoleSource]
     * resolution. The single-resource analog of [authorizeColumns]/[authorizeDatasourceAction] taking `roles`
     * explicitly: [authorizeWithContext] resolves a principal's roles ONCE and threads that same snapshot
     * through BOTH pass-1 tag derivation and this pass-2 authorization, so a role revoked / a JIT grant
     * expiring between the two passes can never earn a `context.tag` the final decision no longer sees
     * (decideQuery's single-resolution invariant, Query.kt, carried onto the non-query surface).
     */
    fun authorizeAs(
        principal: String,
        roles: Set<String>,
        action: AuthzAction,
        resource: AuthzResource,
        context: AuthzContext = AuthzContext(),
    ): AuthzDecision {
        val roleEuids = roles.map { ROLE_TYPE.of(it) }
        val principalEuid = USER_TYPE.of(principal)
        val principalEntity = Entity(principalEuid, emptyMap(), roleEuids.toSet())
        val roleEntities = roleEuids.map { Entity(it) }

        val (resourceEuid, resourceEntities) = marshalResource(resource)
        val actionEuid = ACTION_TYPE.of(action.cedarId)
        val contextMap: Map<String, Value> = context.toCedarMap()

        // dedupeByEuid, not a plain .toSet(): a resource can legitimately reference the SAME Role
        // EUID the principal already carries as a parent (e.g. ApprovalRequest.roleName equal to one
        // of the principal's own roles) — two structurally-identical-but-distinct Entity objects for
        // one EUID, which cedar-java rejects outright ("duplicate entity entry").
        val entities = Entities(dedupeByEuid(listOf(principalEntity) + roleEntities + resourceEntities))
        return engine.isAuthorized(principalEuid, actionEuid, resourceEuid, entities, contextMap).toAuthzDecision()
    }

    private fun marshalResource(resource: AuthzResource): Pair<EntityUID, List<Entity>> = when (resource) {
        AuthzResource.System -> SYSTEM_TYPE.of("system") to emptyList()

        is AuthzResource.AuditRecord -> {
            val recordEuid = AUDIT_RECORD_TYPE.of(resource.principal)
            val recordEntity = Entity(
                recordEuid,
                mapOf("principal" to USER_TYPE.of(resource.principal)),
                emptySet(),
            )
            recordEuid to listOf(recordEntity)
        }

        AuthzResource.AuditLog -> AUDIT_LOG_TYPE.of("all") to emptyList()

        is AuthzResource.ApprovalRequest -> {
            val requesterEuid = USER_TYPE.of(resource.requester)
            val extraEntities = ArrayList<Entity>()
            val parents = mutableSetOf<EntityUID>()
            if (resource.datasourceName != null) {
                val dsEuid = DATASOURCE_TYPE.of(resource.datasourceName)
                parents += dsEuid
                extraEntities += Entity(dsEuid)
            }
            if (resource.roleName != null) {
                val roleEuid = ROLE_TYPE.of(resource.roleName)
                parents += roleEuid
                extraEntities += Entity(roleEuid)
            }
            val reqEuid = REQUEST_TYPE.of("${resource.requester}#${resource.datasourceName ?: "-"}")
            val attrs = buildMap<String, Value> {
                put("requester", requesterEuid)
                resource.approver?.let { put("approver", USER_TYPE.of(it)) }
                resource.executedBy?.let { put("executedBy", USER_TYPE.of(it)) }
            }
            reqEuid to (listOf(Entity(reqEuid, attrs, parents)) + extraEntities)
        }

        is AuthzResource.AccessGrant -> {
            val ownerEuid = USER_TYPE.of(resource.owner)
            val extraEntities = ArrayList<Entity>()
            val parents = mutableSetOf<EntityUID>()
            if (resource.datasourceName != null) {
                val dsEuid = DATASOURCE_TYPE.of(resource.datasourceName)
                parents += dsEuid
                extraEntities += Entity(dsEuid)
            }
            if (resource.roleName != null) {
                val roleEuid = ROLE_TYPE.of(resource.roleName)
                parents += roleEuid
                extraEntities += Entity(roleEuid)
            }
            val grantEuid = ACCESS_GRANT_TYPE.of("${resource.owner}#${resource.id}")
            val grantEntity = Entity(grantEuid, mapOf("owner" to ownerEuid), parents)
            grantEuid to (listOf(grantEntity) + extraEntities)
        }

        is AuthzResource.Token -> {
            val ownerEuid = USER_TYPE.of(resource.owner)
            val tokenEuid = TOKEN_TYPE.of("${resource.owner}#${resource.kind?.name ?: "-"}")
            val attrs = buildMap<String, Value> {
                put("owner", ownerEuid)
                resource.kind?.let { put("kind", PrimString(it.name)) }
            }
            tokenEuid to listOf(Entity(tokenEuid, attrs, emptySet()))
        }
    }
}

/**
 * Per-column authz (docs/authz-model.md: masking is column config, not authorization). Builds ONE
 * [Entities] set for the whole batch — principal + [roles] + the datasource + every touched column
 * (each carrying its table/tag membership, table/tag entities deduped across columns) — then asks
 * Cedar twice per column (result.read.unmasked, then result.read.masked); neither permitting is
 * DENIED. There is no bypass and no "absent = allow": every entry in [columns] gets an explicit
 * verdict.
 *
 * [roles] is the caller's EXPLICIT, already-resolved role set — unlike [Authz.authorize], this does
 * NOT call [RoleSource] itself. Query.kt's `decideQuery` resolves roles once (deliberately AFTER
 * admission, per the SECURITY INVARIANT documented there) and threads that same set through to both
 * the engine and this call, so there's no risk of a second, out-of-band resolution disagreeing with
 * the first.
 *
 * EUID convention: entities are keyed off the datasource's NAME and the full catalog identity, not
 * its numeric id — `Table::"<dsName>/<catalog>/<schema>/<table>"` and
 * `Column::"<dsName>/<catalog>/<schema>/<table>/<column>"`. The datasource's name is always in hand
 * at the call site (Query.kt holds the live [com.ridi.oss.proxymonster.controlplane.Datasource] row).
 */
fun Authz.authorizeColumns(
    principal: String,
    roles: Set<String>,
    datasource: String,
    columns: List<ColumnRef>,
    context: AuthzContext = AuthzContext(),
    // System tag per touched table identity `(catalog, schema, table)` (system-classification.md):
    // attached to the Table entity so its Columns inherit it transitively — a column of `pg_authid`
    // is `in Tag::"system:critical"` through its Table parent. Empty = no system object touched.
    systemTags: Map<Triple<String, String, String>, String> = emptyMap(),
    // The datasource's own `system:*` posture tags. Attached to the Datasource entity
    // so the shipped conditional forbids / preset permits match transitively (a Column is `in system:development`
    // through its Datasource parent). Reserved tags on a Column itself are stripped (isReservedTag).
    datasourceTags: List<String> = emptyList(),
): Map<String, ColumnVerdict> {
    val roleEuids = roles.map { ROLE_TYPE.of(it) }
    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roleEuids.toSet())
    val roleEntities = roleEuids.map { Entity(it) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)

    // EUIDs slash-join their segments — and BOTH '/' and '.' are legal INSIDE a quoted SQL identifier
    // (the analyzer key delimits components with '.', the Cedar EUID with '/'). A delimiter inside a
    // component would let two DISTINCT identities render to one EUID → a wrong-grant collision (e.g.
    // schema "public/a"+table "users" vs schema "public"+table "a/users" both → ".../public/a/users").
    // Such identifiers are pathological and a real ambiguity/injection risk, so any column whose
    // resolved identity contains a delimiter is DENIED fail-closed (mirroring the analyzer's own
    // rejection of dot-rendering collisions). Because delimiter-bearing identities never reach the
    // join, the EUID slash-joins raw and stays injective.
    fun hasDelim(s: String) = '/' in s || '.' in s
    val tableEuids = HashMap<Triple<String, String, String>, EntityUID>()
    val columnEuids = HashMap<String, EntityUID>()
    val columnEntities = ArrayList<Entity>()
    for (col in columns) {
        if (hasDelim(datasource) || hasDelim(col.catalog) || hasDelim(col.schema) ||
            hasDelim(col.table) || hasDelim(col.column)
        ) {
            continue // no EUID built → denied in the final mapping below
        }
        val tableIdentity = Triple(col.catalog, col.schema, col.table)
        val tableEuid = tableEuids.getOrPut(tableIdentity) {
            TABLE_TYPE.of("$datasource/${col.catalog}/${col.schema}/${col.table}")
        }
        val colEuid = COLUMN_TYPE.of("$datasource/${col.catalog}/${col.schema}/${col.table}/${col.column}")
        columnEuids[col.key] = colEuid
        // Strip reserved tags off the Column (the type-scoping invariant): a catalog/legacy `system:development`
        // or `system:*` on a column must NOT be honored — it would satisfy the dev unmasked permit / forge a
        // shipped classification. The column's real system tag is inherited from its Table parent, not here.
        val tagParents = col.tags.filterNot { isReservedTag(it) }.map { tag -> tagEuids.getOrPut(tag) { TAG_TYPE.of(tag) } }
        columnEntities += Entity(colEuid, emptyMap(), (setOf(tableEuid, dsEuid) + tagParents).toSet())
    }
    // Each Table entity carries its datasource parent + its system tag, so a Column inherits
    // the system classification through its Table parent (no second direct system tag on the column).
    val tableEntities = tableEuids.map { (identity, euid) ->
        val parents = mutableSetOf(dsEuid)
        systemTags[identity]?.let { parents += tagEuids.getOrPut(it) { TAG_TYPE.of(it) } }
        Entity(euid, emptyMap(), parents)
    }
    val tagEntities = tagEuids.values.map { Entity(it) }

    val contextMap: Map<String, Value> = context.toCedarMap()
    // dedupeByEuid, not a plain .toSet(): see the comment on the identical call in [authorize] — the
    // per-column build already dedupes tables/tags among themselves, but a role name theoretically
    // colliding with a datasource/table/tag id can't (different Cedar TYPES => different EUIDs), so
    // this is defensive, not load-bearing, for this call specifically.
    val entities = Entities(
        dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + tableEntities + tagEntities + columnEntities),
    )
    val unmaskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_UNMASKED.cedarId)
    val maskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_MASKED.cedarId)

    fun allowed(action: EntityUID, resource: EntityUID): Boolean =
        engine.isAuthorized(principalEuid, action, resource, entities, contextMap).success.orElse(null)?.isAllowed == true

    return columns.associate { col ->
        // a column with no EUID was rejected above (a delimiter in its resolved identity) → deny-closed
        val colEuid = columnEuids[col.key] ?: return@associate col.key to ColumnVerdict.DENIED
        val verdict = when {
            allowed(unmaskedAction, colEuid) -> ColumnVerdict.UNMASKED
            allowed(maskedAction, colEuid) -> ColumnVerdict.MASKED
            else -> ColumnVerdict.DENIED
        }
        col.key to verdict
    }
}

/**
 * Table-scan authz (docs/facts-emission.md). An UNCOVERED scanned table — read with zero traced
 * columns (`count(*)`, `SELECT 1`, `EXISTS`, a cross-join side) — leaks the relation's existence + row
 * count unless a `result.read` grant covers its Table resource. Deny-by-default: every [tables] entry
 * gets an explicit verdict; there is no "absent = allow".
 *
 * Mirrors [authorizeColumns]: ONE [Entities] batch (principal + [roles] + datasource + Table entities),
 * name-keyed EUIDs (`Table::"<ds>/<catalog>/<schema>/<table>"`), and a delimiter-bearing identity (`/`
 * or `.` inside a component) builds no EUID → DENIED fail-closed. Either `result.read.unmasked` OR
 * `result.read.masked` on the Table permits the scan — a masked reader already observes the table's rows
 * (masked), so existence/cardinality is not additionally protected. [roles] is the caller's explicit
 * resolved set (no out-of-band [RoleSource] re-resolution), matching [authorizeColumns].
 */
fun Authz.authorizeTables(
    principal: String,
    roles: Set<String>,
    datasource: String,
    tables: List<TableRef>,
    context: AuthzContext = AuthzContext(),
    // System tag per table identity `(catalog, schema, table)` — so an uncovered scan of a
    // system Table (e.g. `count(*) FROM pg_authid`) is decided against its `system:` tag by the shipped
    // policy (forbid critical/data-leak/activity; permit catalog), not just a per-datasource read grant.
    systemTags: Map<Triple<String, String, String>, String> = emptyMap(),
    // The datasource's `system:*` posture tags — attached to the Datasource entity so a
    // conditional forbid (`… unless resource in Tag::"system:development"`) sees an uncovered system-table scan
    // on a dev datasource through the Table's Datasource parent.
    datasourceTags: List<String> = emptyList(),
): Map<String, TableVerdict> {
    val roleEuids = roles.map { ROLE_TYPE.of(it) }
    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roleEuids.toSet())
    val roleEntities = roleEuids.map { Entity(it) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)

    // Same delimiter guard as authorizeColumns: '/' (EUID join) and '.' (analyzer key join) inside a
    // component would let two distinct identities render to one EUID → a wrong-grant collision. Such a
    // table builds no EUID and is DENIED below (never silently authorized).
    fun hasDelim(s: String) = '/' in s || '.' in s
    val tableEuids = HashMap<String, EntityUID>()
    val tableEntities = ArrayList<Entity>()
    for (t in tables) {
        if (hasDelim(datasource) || hasDelim(t.catalog) || hasDelim(t.schema) || hasDelim(t.table)) {
            continue // no EUID built → denied in the final mapping below
        }
        val euid = tableEuids.getOrPut(t.key) {
            TABLE_TYPE.of("$datasource/${t.catalog}/${t.schema}/${t.table}")
        }
        val parents = mutableSetOf(dsEuid)
        systemTags[Triple(t.catalog, t.schema, t.table)]?.let { parents += tagEuids.getOrPut(it) { TAG_TYPE.of(it) } }
        tableEntities += Entity(euid, emptyMap(), parents)
    }
    val tagEntities = tagEuids.values.map { Entity(it) }

    val contextMap: Map<String, Value> = context.toCedarMap()
    val entities = Entities(
        dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + tableEntities + tagEntities),
    )
    val unmaskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_UNMASKED.cedarId)
    val maskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_MASKED.cedarId)

    fun allowed(action: EntityUID, resource: EntityUID): Boolean =
        engine.isAuthorized(principalEuid, action, resource, entities, contextMap).success.orElse(null)?.isAllowed == true

    return tables.associate { t ->
        val euid = tableEuids[t.key] ?: return@associate t.key to TableVerdict.DENIED
        val verdict = if (allowed(unmaskedAction, euid) || allowed(maskedAction, euid)) {
            TableVerdict.READ
        } else {
            TableVerdict.DENIED
        }
        t.key to verdict
    }
}

/**
 * Authorize the DANGEROUS functions a query calls (facts-emission.md). Mirrors
 * [authorizeTables]: ONE [Entities] batch, name-keyed EUIDs (`Function::"<ds>/<name>"`), a delimiter-bearing
 * name builds no EUID → DENIED fail-closed. Each function carries its shipped `system:` tag ([systemTags],
 * keyed by bare name) as a Cedar parent, so the V24 `system:data-leak`/`system:critical` forbids override
 * any read grant → DENIED. The caller passes ONLY classified (dangerous) functions — a safe function has no
 * tag and no permit, so marshalling it would deny-by-default and break every `now()`/user-UDF query; it is
 * therefore left out entirely and unaffected on this phase. A function permitted (never, while every
 * marshalled function is forbidden) OR — future — carrying a safe/vouched permit is [ALLOWED]; else DENIED.
 */
fun Authz.authorizeFunctions(
    principal: String,
    roles: Set<String>,
    datasource: String,
    functions: List<FunctionRef>,
    context: AuthzContext = AuthzContext(),
    // System tag per bare function name — the ONLY reason a Function is marshalled. A name
    // absent from this map is a safe function and must not be passed by the caller (see [authorizeFunctions] doc).
    systemTags: Map<String, String> = emptyMap(),
    // The datasource's `system:*` posture tags — attached to the Datasource entity so a
    // conditional forbid can relax a dangerous function on a dev datasource through its Datasource parent.
    datasourceTags: List<String> = emptyList(),
): Map<String, FunctionVerdict> {
    val roleEuids = roles.map { ROLE_TYPE.of(it) }
    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roleEuids.toSet())
    val roleEntities = roleEuids.map { Entity(it) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)

    // Same delimiter guard as authorizeTables: '/' (EUID join) inside a component would collide two
    // identities to one EUID. A function name with a delimiter builds no EUID and is DENIED below.
    fun hasDelim(s: String) = '/' in s
    val fnEuids = HashMap<String, EntityUID>()
    val fnEntities = ArrayList<Entity>()
    for (f in functions) {
        if (hasDelim(datasource) || hasDelim(f.name)) {
            continue // no EUID built → denied in the final mapping below
        }
        val euid = fnEuids.getOrPut(f.name) { FUNCTION_TYPE.of("$datasource/${f.name}") }
        val parents = mutableSetOf(dsEuid)
        systemTags[f.name]?.let { parents += tagEuids.getOrPut(it) { TAG_TYPE.of(it) } }
        fnEntities += Entity(euid, emptyMap(), parents)
    }
    val tagEntities = tagEuids.values.map { Entity(it) }

    val contextMap: Map<String, Value> = context.toCedarMap()
    val entities = Entities(
        dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + fnEntities + tagEntities),
    )
    val unmaskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_UNMASKED.cedarId)
    val maskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_MASKED.cedarId)

    fun allowed(action: EntityUID, resource: EntityUID): Boolean =
        engine.isAuthorized(principalEuid, action, resource, entities, contextMap).success.orElse(null)?.isAllowed == true

    return functions.associate { f ->
        val euid = fnEuids[f.name] ?: return@associate f.name to FunctionVerdict.DENIED
        val verdict = if (allowed(unmaskedAction, euid) || allowed(maskedAction, euid)) {
            FunctionVerdict.ALLOWED
        } else {
            FunctionVerdict.DENIED
        }
        f.name to verdict
    }
}

/**
 * Authorize the resource-bearing UTILITY commands a query performs (facts-emission.md). Mirrors
 * [authorizeFunctions] — ONE [Entities] batch, name-keyed EUIDs (`Utility::"<ds>/<command>"`), each carrying
 * its shipped `system:` tag ([systemTags], keyed by command id). The caller (`Query.kt`) passes ONLY CLASSIFIED
 * utilities — an unclassifiable one (no governing manifest) is HARD-denied UPSTREAM, never marshalled here,
 * because an untagged Utility (Datasource parent only, no forbid) would be PERMITTED by a Datasource-scoped
 * read grant. So every utility here carries a `system:` tag: a `system:data-leak`/
 * `activity`/`critical` one is forbidden on the floor (relaxed only under system:development via its
 * Datasource parent → USE), and a `system:catalog` one (or a dev/broad-granted datasource) has a read permit →
 * USE. [datasourceTags] attaches the datasource posture so the dev relaxation applies. (The
 * deny-by-default on an EUID with no tag remains a defensive backstop, but is not the load-bearing path.)
 */
fun Authz.authorizeUtilities(
    principal: String,
    roles: Set<String>,
    datasource: String,
    utilities: List<UtilityRef>,
    context: AuthzContext = AuthzContext(),
    systemTags: Map<String, String> = emptyMap(),
    datasourceTags: List<String> = emptyList(),
): Map<String, UtilityVerdict> {
    val roleEuids = roles.map { ROLE_TYPE.of(it) }
    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roleEuids.toSet())
    val roleEntities = roleEuids.map { Entity(it) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)

    fun hasDelim(s: String) = '/' in s
    val utilEuids = HashMap<String, EntityUID>()
    val utilEntities = ArrayList<Entity>()
    for (u in utilities) {
        if (hasDelim(datasource) || hasDelim(u.command)) {
            continue // no EUID built → denied in the final mapping below
        }
        val euid = utilEuids.getOrPut(u.command) { UTILITY_TYPE.of("$datasource/${u.command}") }
        val parents = mutableSetOf(dsEuid)
        systemTags[u.command]?.let { parents += tagEuids.getOrPut(it) { TAG_TYPE.of(it) } }
        utilEntities += Entity(euid, emptyMap(), parents)
    }
    val tagEntities = tagEuids.values.map { Entity(it) }

    val contextMap: Map<String, Value> = context.toCedarMap()
    val entities = Entities(
        dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + utilEntities + tagEntities),
    )
    val unmaskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_UNMASKED.cedarId)
    val maskedAction = ACTION_TYPE.of(AuthzAction.RESULT_READ_MASKED.cedarId)

    fun allowed(action: EntityUID, resource: EntityUID): Boolean =
        engine.isAuthorized(principalEuid, action, resource, entities, contextMap).success.orElse(null)?.isAllowed == true

    return utilities.associate { u ->
        val euid = utilEuids[u.command] ?: return@associate u.command to UtilityVerdict.DENIED
        val verdict = if (allowed(unmaskedAction, euid) || allowed(maskedAction, euid)) {
            UtilityVerdict.USE
        } else {
            UtilityVerdict.DENIED
        }
        u.command to verdict
    }
}

/**
 * The two once-per-query gates ahead of the catalog/analyzer/column loop (docs/authz-model.md:
 * `datasource.connect` then `sql.<kind>`, wired in decideQuery's Query.kt). A single-resource
 * decision, like [Authz.authorize], but — like [authorizeColumns] — takes [roles] EXPLICITLY (no
 * second, out-of-band [RoleSource] resolution) and keys the [datasource] resource EUID off its NAME,
 * not its numeric id: `Datasource::"acme-mysql"`, matching [authorizeColumns] and every seed policy /
 * doc example. [Authz.authorize]'s own `AuthzResource.Datasource` marshalling keys off the numeric id
 * instead (`Datasource::"2"`) — reusing it here would silently deny every query; this function
 * intentionally does NOT go through [Authz.authorize] or [Authz]'s private `marshalResource`.
 */
fun Authz.authorizeDatasourceAction(
    principal: String,
    roles: Set<String>,
    action: AuthzAction,
    datasource: String,
    context: AuthzContext = AuthzContext(),
    // The datasource's `system:*` posture tags — attached to the Datasource entity so a
    // preset permit (`sql.unanalyzable`/`sql.unmaskable` on `system:development`, policy ids -201/-202) matches
    // this datasource. A datasource-level action's resource IS the Datasource, so its own tag parent suffices.
    datasourceTags: List<String> = emptyList(),
): AuthzDecision {
    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roles.map { ROLE_TYPE.of(it) }.toSet())
    val roleEntities = roles.map { Entity(ROLE_TYPE.of(it)) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)
    val tagEntities = tagEuids.values.map { Entity(it) }

    val contextMap: Map<String, Value> = context.toCedarMap()
    val entities = Entities(dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + tagEntities))
    return engine.isAuthorized(principalEuid, ACTION_TYPE.of(action.cedarId), dsEuid, entities, contextMap).toAuthzDecision()
}

/**
 * Pass-1 of the two-pass (docs/authz-context.md): derive the request's `context.tags` by evaluating
 * each admin-authored tag rule over the RAW attested inputs. For every tag name `T` in the vocabulary (the
 * `context.tag::<name>` actions the enabled rules target — DERIVED, not predefined), evaluate
 * `isAuthorized(principal, Action::"context.tag::T", <the request's datasource>, [rawContext])`; each ALLOW
 * earns `T`. Fail-closed: a tag exists only if a rule PERMITTED it; a pass-1 engine error is a non-allow, so
 * the tag is absent (never "present on error"). The resource is the request's Datasource (name-keyed, plus
 * its `system:*` posture), so a rule can scope by datasource/principal, not just the raw context.
 *
 * [rawContext] MUST carry only raw inputs (`channel`, `requester_ip`, …) and NO derived tags — the generated
 * tag-action schema omits `tags`, so a tag-on-tag rule can't validate; the pre-pass is a pure one-level
 * function of attested inputs. Returns an empty set when no tag rule is enabled (the common case → no eval).
 * Mirrors [authorizeDatasourceAction]'s NAME-keyed datasource marshalling (never the id-keyed path).
 */
fun Authz.resolveContextTags(
    principal: String,
    roles: Set<String>,
    datasource: String,
    rawContext: AuthzContext,
    datasourceTags: List<String> = emptyList(),
): Set<String> {
    val vocab = engine.contextTagVocabulary()
    if (vocab.isEmpty()) return emptySet()

    val principalEuid = USER_TYPE.of(principal)
    val principalEntity = Entity(principalEuid, emptyMap(), roles.map { ROLE_TYPE.of(it) }.toSet())
    val roleEntities = roles.map { Entity(ROLE_TYPE.of(it)) }

    val dsEuid = DATASOURCE_TYPE.of(datasource)
    val tagEuids = HashMap<String, EntityUID>()
    val dsEntity = datasourceEntity(dsEuid, datasource, datasourceTags, tagEuids)
    val tagEntities = tagEuids.values.map { Entity(it) }

    val entities = Entities(dedupeByEuid(listOf(principalEntity, dsEntity) + roleEntities + tagEntities))
    // includeTags = false: pass-1 must not expose `tags` at all (no tag-on-tag). The generated tag-action
    // schema also omits it, so a rule reading context.tags won't validate; omitting it here closes the eval side.
    val contextMap: Map<String, Value> = rawContext.toCedarMap(includeTags = false)

    return vocab.filterTo(sortedSetOf()) { tag ->
        engine.isAuthorized(principalEuid, ACTION_TYPE.of("context.tag::$tag"), dsEuid, entities, contextMap)
            .success.orElse(null)?.isAllowed == true
    }
}

/**
 * The coherent non-query decision (docs/authz-context.md) — the non-query analog of decideQuery's
 * single-resolution path ([com.ridi.oss.proxymonster.controlplane.effectiveAuthzContext] + the engine calls that
 * follow, Query.kt). Resolves [principal]'s roles ONCE, derives the datasource-scoped `context.tags` with that
 * exact set (pass-1 [resolveContextTags], the SAME two-pass the query path runs — never a fork), then authorizes
 * [action] on [resource] with the SAME role snapshot + derived context (pass-2 [Authz.authorizeAs]). Threading one
 * snapshot through both passes is what keeps the two coherent: a role revoked / a JIT grant expiring between them
 * can never earn a `context.tag` the final authorization no longer sees (the disagreement a separate
 * "build a context, then call authorize()" would have re-resolved into existence).
 *
 * `channel` is deliberately never set — these admin/audit/approval routes have no query-decision
 * [com.ridi.oss.proxymonster.controlplane.Channel] to overlay, and inventing one for a route that isn't deciding
 * a query would be dishonest. `context.tags` is derived ONLY when [datasourceName] is non-null: the tag mechanism
 * is Datasource-scoped BY CONSTRUCTION — [resolveContextTags]'s pass-1 Cedar action `appliesTo { resource:
 * [Datasource] }` (CedarEngine.kt) requires a Datasource resource to evaluate against, and "tags resolve at the
 * datasource level" (authz-context.md) is the documented invariant. A null [datasourceName]
 * (e.g. [com.ridi.oss.proxymonster.controlplane.AuthzResource.System] /
 * [com.ridi.oss.proxymonster.controlplane.AuthzResource.AuditLog] — no datasource in scope) authorizes over
 * [raw] UNCHANGED: `requesterIp` (and any other raw signal) still reaches Cedar, but `tags` stays empty —
 * fail-closed, since a tag-conditioned policy then simply doesn't fire, never "invents" a tag from a fabricated
 * resource. No sentinel/pseudo-datasource is ever synthesized to route around this.
 */
internal fun Authz.authorizeWithContext(
    principal: String,
    action: AuthzAction,
    resource: AuthzResource,
    raw: AuthzContext,
    datasourceName: String?,
    datasourceTags: List<String> = emptyList(),
): AuthzDecision {
    val roles = rolesOf(principal)
    val context = if (datasourceName == null) {
        raw
    } else {
        raw.copy(tags = resolveContextTags(principal, roles, datasourceName, raw, datasourceTags))
    }
    return authorizeAs(principal, roles, action, resource, context)
}

/**
 * Gate an admin/privileged route: `true` if [Config.authDebug] (the dev-only bypass — mirrors
 * `requireApi`'s posture, the trusted-network dev story; this is NOT a Cedar bypass, Cedar
 * itself is never skipped, only never *reached* here), else 401 with no session, else the real
 * [Authz.authorize] decision (403 + the deny reason on Deny). This is what closes the "admin routes
 * require admin.*, not any session" hole once `config.authDebug=false` in production.
 *
 * The ONE choke point every admin route funnels through — threading
 * [com.ridi.oss.proxymonster.controlplane.httpAuthzContext] here fixes `requester_ip` for every admin
 * action (~35 call sites: CedarPolicyStore.kt, Users.kt, Policies.kt, Datasources.kt) with zero call-site
 * churn. No `channel` (admin routes aren't a query-decision phase) and no datasource tags (the resource
 * here is always [AuthzResource.System] — nothing to derive tags against, see [authorizeWithContext]).
 */
suspend fun ApplicationCall.requireAdmin(
    config: Config,
    authz: Authz,
    action: AuthzAction,
    resource: AuthzResource = AuthzResource.System,
): Boolean = requireAuthz(config, authz, action, resource)

/**
 * The general per-(action, resource) route gate — [requireAdmin]'s body, named for the routes that
 * aren't admin surfaces (token.* / workflow.* self-service and grant routes). Same posture:
 * [Config.authDebug] dev bypass → true; no session → 401; else the real
 * [Authz.authorize] decision (403 + reason on Deny). [requireAdmin] is the `System`-resource alias.
 * Build the [resource] (e.g. `Token(owner)`) from [userSession]'s principal at the call site, since it
 * usually references the caller — under `authDebug` this short-circuits before the session is read.
 */
suspend fun ApplicationCall.requireAuthz(
    config: Config,
    authz: Authz,
    action: AuthzAction,
    resource: AuthzResource,
): Boolean {
    if (config.authDebug) return true
    val session = userSession()
    if (session == null) {
        respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
        return false
    }
    return when (val decision = authz.authorize(session.principal, action, resource, httpAuthzContext(config))) {
        AuthzDecision.Allow -> true
        is AuthzDecision.Deny -> {
            respond(HttpStatusCode.Forbidden, ApiError("common.forbidden", mapOf("detail" to decision.reason)))
            false
        }
    }
}
