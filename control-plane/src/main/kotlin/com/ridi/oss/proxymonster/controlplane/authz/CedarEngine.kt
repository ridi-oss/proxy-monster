package com.ridi.oss.proxymonster.controlplane.authz

import com.cedarpolicy.BasicAuthorizationEngine
import com.cedarpolicy.model.AuthorizationRequest
import com.cedarpolicy.model.AuthorizationResponse
import com.cedarpolicy.model.ValidationRequest
import com.cedarpolicy.model.entity.Entities
import com.cedarpolicy.model.entity.Entity
import com.cedarpolicy.model.exception.AuthException
import com.cedarpolicy.model.policy.Policy
import com.cedarpolicy.model.policy.PolicySet
import com.cedarpolicy.model.schema.Schema
import com.cedarpolicy.value.EntityUID
import com.cedarpolicy.value.Value

/**
 * The bundled Cedar schema (resources/authz/schema.cedarschema) plus the stateless half of Cedar
 * evaluation: parsing the schema once and validating a single candidate policy against it. This is
 * independent of the live *enabled* policy set on purpose — [CedarPolicyStore] uses it to reject
 * invalid Cedar at write time (before a bad row could ever become "enabled"), and [CedarEngine] uses
 * the same logic both to fail fast on startup and to back [CedarEngine.validate]. cedar-java's
 * [BasicAuthorizationEngine] and parsed [Schema] are safe to share across calls/threads — they hold
 * no per-call mutable state, every JNI call is given the full policy/entity/request payload.
 */
private val CONTEXT_TAG_ACTION = Regex("""Action::"context\.tag::([^"]+)"""")

/**
 * The tag names a Cedar policy targets via a `context.tag::<name>` action — the tag vocabulary is
 * DERIVED from these (no predefinition, docs/authz-context.md). An action EID is always a literal
 * `Action::"context.tag::<name>"`, so scanning the source is exact + cheap. Used both to augment the
 * validation schema (a tag rule must have its action declared) and to build the pass-1 vocabulary.
 */
internal fun extractContextTagNames(cedarSrc: String): Set<String> =
    CONTEXT_TAG_ACTION.findAll(cedarSrc).mapTo(mutableSetOf()) { it.groupValues[1] }

private val CEDAR_ESCAPE = Regex("""\\(u\{([0-9A-Fa-f]{1,6})\}|.)""")

/**
 * A Cedar string literal's value, as the parser resolves it — `\u{61}` and `a` are the same action id
 * spelled two ways. Used to compare tag names by identity rather than by source text; an unrecognized
 * escape is left as written, since the goal is collapsing aliases, not validating the literal.
 */
internal fun unescapeCedarString(literal: String): String =
    CEDAR_ESCAPE.replace(literal) { m ->
        val hex = m.groupValues[2]
        if (hex.isNotEmpty()) {
            hex.toInt(16).takeIf { it <= 0x10FFFF }?.let { String(Character.toChars(it)) } ?: m.value
        } else when (val c = m.groupValues[1]) {
            "n" -> "\n"; "r" -> "\r"; "t" -> "\t"; "0" -> "\u0000"
            "\\" -> "\\"; "'" -> "'"; "\"" -> "\""
            else -> c
        }
    }

private val CONTEXT_TAGS_CONSUMED = Regex("""context\.tags\.contains\(\s*"([^"]+)"\s*\)""")

/**
 * The dangling-tag lint (docs/authz-context.md). Compares PRODUCED tags (the `context.tag::<name>`
 * actions the enabled tag rules target) against CONSUMED tags (the `context.tags.contains("<name>")` literals
 * in the real policies) and reports each mismatch: a consumer with no producer (a grant that can NEVER apply
 * — fail-closed-safe, but almost always a typo) and a producer no consumer uses (a dead tag rule). Purely a
 * diagnostic — dangling tags are fail-closed-safe — so this WARNS; it never blocks a policy write or boot.
 */
fun contextTagLint(enabledSources: List<Pair<Long, String>>): List<String> {
    val produced = enabledSources.flatMapTo(mutableSetOf()) { extractContextTagNames(it.second) }
    val consumed = enabledSources.flatMapTo(mutableSetOf()) { (_, src) ->
        CONTEXT_TAGS_CONSUMED.findAll(src).map { m -> m.groupValues[1] }.toList()
    }
    return buildList {
        (consumed - produced).sorted().forEach {
            add("context tag \"$it\" is consumed by a policy but no tag rule produces it (grant can never apply)")
        }
        (produced - consumed).sorted().forEach {
            add("context tag \"$it\" is produced by a tag rule but no policy consumes it (dead tag rule)")
        }
    }
}

/** The reusable half of a decision: the [principal] and the shared [entities] graph (its roles plus any
 *  auxiliary parents). The focal resource is spliced in per call by [CedarEngine.isAuthorized], which reads
 *  its EUID off the entity — so one graph answers for many resources (the per-column/table/function batches
 *  build it once). */
internal data class CedarRequest(
    val principal: EntityUID,
    val entities: Set<Entity>,
)

object CedarSchema {
    private const val RESOURCE_PATH = "/authz/schema.cedarschema"

    val text: String = CedarSchema::class.java.getResourceAsStream(RESOURCE_PATH)
        ?.bufferedReader()
        ?.use { it.readText() }
        ?: error("authz: $RESOURCE_PATH is missing from the classpath (control-plane/src/main/resources/authz/)")

    val schema: Schema = Schema.parse(Schema.JsonOrCedar.Cedar, text)

    // Validation-only cache of schemas augmented with derived `context.tag::<name>` action declarations,
    // keyed by the tag-name set. Cedar EVALUATION is schema-free (isAuthorized takes no schema), so this
    // never touches the authorization path — only [validate] below.
    private val augmentedSchemas = java.util.concurrent.ConcurrentHashMap<Set<String>, Schema>()

    /**
     * The bundled schema augmented with one `action "context.tag::<name>"` declaration per derived tag name
     * (two-pass, docs/authz-context.md). Cedar strict validation rejects an UNDECLARED action, so a
     * tag rule is only loadable if its action is declared — but tags aren't predefined, so the declarations
     * are DERIVED from the rules themselves (the vocabulary IS the rule set). The generated action's context
     * deliberately OMITS `tags` (no tag-on-tag: a rule reading context.tags fails to validate). Returns the
     * base schema when there are no tag actions (the common case).
     */
    fun schemaFor(tagNames: Set<String>): Schema {
        if (tagNames.isEmpty()) return schema
        return augmentedSchemas.getOrPut(tagNames) {
            Schema.parse(Schema.JsonOrCedar.Cedar, schemaTextFor(tagNames))
        }
    }

    /** [schemaFor]'s source text, for callers that need the schema as Cedar source rather than a parsed
     *  [Schema] — the console's in-editor linter validates against this same text. */
    fun schemaTextFor(tagNames: Set<String>): String {
        if (tagNames.isEmpty()) return text
        // Deduplicate by the id Cedar resolves the name to, not by its spelling: `a` and `\u{61}` are
        // the same action, so emitting both declares it twice and the whole schema fails to parse.
        val decls = tagNames.distinctBy(::unescapeCedarString).sorted().joinToString("\n") { name ->
            "action \"context.tag::$name\" appliesTo { principal: [User, Role], resource: [Datasource], " +
                "context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };"
        }
        return "$text\n$decls"
    }

    /**
     * The schema text for [tagNames], guaranteed to parse — the base schema alone if the derived
     * declarations do not. A tag name reaches this from stored policy source, which the store validates
     * per policy but cannot validate as a set, and a row written out of band never validated at all. A
     * single bad name must not cost every reader its schema, so the fallback degrades to base rather
     * than serving text nothing can parse.
     */
    fun parseableSchemaTextFor(tagNames: Set<String>): String {
        val candidate = schemaTextFor(tagNames)
        if (candidate === text) return candidate
        return runCatching { Schema.parse(Schema.JsonOrCedar.Cedar, candidate) }
            .fold(onSuccess = { candidate }, onFailure = { text })
    }

    private val engine = BasicAuthorizationEngine()

    fun isAuthorized(request: AuthorizationRequest, policies: PolicySet, entities: Entities): AuthorizationResponse =
        engine.isAuthorized(request, policies, entities)

    /**
     * Parse+validate a single candidate Cedar policy against the schema, independent of any other
     * policy. Empty list = valid. Never throws for policy-shaped input — syntax and semantic errors
     * alike come back as messages (cedar-java itself never throws for either; both surface as a
     * [com.cedarpolicy.model.ValidationResponse] with `errors`/`success.validationErrors`
     * populated, verified empirically against cedar-java 4.3.1).
     */
    fun validate(cedarSrc: String): List<String> {
        if (cedarSrc.isBlank()) return listOf("cedar policy source must not be blank")
        val policy = try {
            Policy(cedarSrc, "candidate")
        } catch (e: NullPointerException) {
            return listOf(e.message ?: "cedar policy source must not be null")
        }
        // Self-augment: if the candidate IS a tag rule (targets a context.tag::<name> action), validate it
        // against a schema that DECLARES that action — so a not-yet-predefined tag rule is loadable
        // (docs/authz-context.md). A consuming policy reads context.tags (a string), targets no such action,
        // and validates against the base schema unchanged. schemaFor(...) is INSIDE the try: a pathological
        // tag name (e.g. a trailing backslash from a `\"` escape) yields a malformed generated action decl
        // whose Schema.parse throws — that must come back as a validation error (fail-closed reject), not an
        // unhandled throw that breaks validate()'s "never throws for policy-shaped input" contract.
        val response = try {
            engine.validate(ValidationRequest(schemaFor(extractContextTagNames(cedarSrc)), PolicySet(setOf(policy))))
        } catch (e: AuthException) {
            return listOf(e.message.orElse(e.toString()))
        } catch (e: Exception) {
            return listOf("invalid context.tag action name: ${e.message ?: e.toString()}")
        }
        // Failure = the policy set didn't even parse (response.errors, top-level). Success-with-
        // validationErrors = it parsed but is semantically ill-typed against the schema (unknown
        // action, wrong attribute type, ...). Concatenating both covers either shape.
        val parseErrors = response.errors.map { list -> list.map { it.message } }.orElseGet { emptyList() }
        val typeErrors = response.success
            .map { success -> success.validationErrors.map { it.error.message } }
            .orElseGet { emptyList() }
        return parseErrors + typeErrors
    }
}

/**
 * The live authorization engine: the current *enabled* policy set, cached and rebuilt only when
 * [CedarPolicyStore.stateVersion] changes (the column path calls [isAuthorized] O(N=touched
 * columns) per query, so re-parsing every enabled policy on every call would not be cheap).
 * Fails fast at construction if any enabled policy doesn't validate against the schema, so a bad
 * row never silently no-ops (Cedar would otherwise just refuse to load a malformed policy and
 * effectively deny everything for it).
 *
 * The primary (production) constructor takes a live [CedarPolicyStore] and polls
 * [CedarPolicyStore.stateVersion] on every [isAuthorized] call, rebuilding the [PolicySet] from
 * [CedarPolicyStore.enabledSources] only when that version has moved since the last build. The
 * `List<Pair<Long,String>>` constructor is a fixed, in-memory policy set with no store/DataSource/DB
 * involved at all — for unit tests (AuthzTest.kt) that want a real
 * [CedarEngine]/[com.ridi.oss.proxymonster.controlplane.authz.Authz] without touching JDBC; its version
 * supplier is a constant `0L`, so the PolicySet is built once and never invalidated (correct: the
 * list is immutable for the lifetime of the engine).
 */
class CedarEngine private constructor(private val sources: () -> List<Pair<Long, String>>, private val version: () -> Long) {
    constructor(policyStore: CedarPolicyStore) : this({ policyStore.enabledSources() }, { policyStore.stateVersion() })
    constructor(policySources: List<Pair<Long, String>>) : this({ policySources }, { 0L })

    @Volatile private var cachedVersion = Long.MIN_VALUE
    @Volatile private var cachedPolicies: PolicySet? = null
    @Volatile private var cachedVocab: Set<String> = emptySet()

    /** How many times [policySet] has actually rebuilt the [PolicySet] — exposed for
     *  CedarEngineCacheTest's O(1)-per-query assertion; not meant for production use. */
    @JvmField internal var buildCount = 0

    init {
        val invalid = sources().mapNotNull { (id, src) ->
            CedarSchema.validate(src).takeIf { it.isNotEmpty() }?.let { errors -> id to errors }
        }
        check(invalid.isEmpty()) {
            "authz: enabled cedar polic${if (invalid.size == 1) "y" else "ies"} failed schema validation at startup: " +
                invalid.joinToString("; ") { (id, errors) -> "policy #$id: ${errors.joinToString(", ")}" }
        }
    }

    /** Rebuild the cached [PolicySet] AND the derived tag vocabulary together — only when [version] has
     *  moved since the last build, so both stay consistent and O(1) per query. Synchronized so concurrent
     *  callers never race to rebuild or observe a torn cache. */
    @Synchronized
    private fun rebuildIfStale() {
        val v = version()
        if (cachedPolicies != null && v == cachedVersion) return
        val srcs = sources()
        cachedPolicies = PolicySet(srcs.map { (id, src) -> Policy(src, "policy-$id") }.toSet())
        cachedVocab = srcs.flatMapTo(mutableSetOf()) { extractContextTagNames(it.second) }
        cachedVersion = v
        buildCount++
    }

    private fun policySet(): PolicySet {
        rebuildIfStale()
        return cachedPolicies!!
    }

    /**
     * The tag vocabulary (docs/authz-context.md): every tag name the enabled rules target via a
     * `context.tag::<name>` action — DERIVED, not predefined. Empty when no tag rule is enabled, so pass-1
     * (`Authz.resolveContextTags`) is a no-op for the common deployment. Cached with the policy set (rebuilt
     * only on a version change).
     */
    fun contextTagVocabulary(): Set<String> {
        rebuildIfStale()
        return cachedVocab
    }

    internal fun isAuthorized(
        request: CedarRequest,
        action: EntityUID,
        resource: Entity,
        context: Map<String, Value> = emptyMap(),
    ): AuthorizationResponse =
        CedarSchema.isAuthorized(
            AuthorizationRequest(request.principal, action, resource.getEUID(), context),
            policySet(),
            Entities(request.entities + resource),
        )

    /** Parse+validate a single candidate policy against the schema; see [CedarSchema.validate]. */
    fun validate(cedarSrc: String): List<String> = CedarSchema.validate(cedarSrc)
}
