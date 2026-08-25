package com.ridi.oss.proxymonster.classification

/** A manifest that fails boot validation (docs/system-classification.md) — fail-closed, aborts startup. */
class SystemManifestException(message: String) : Exception(message)

/**
 * A compiled, validated [SystemManifest] that classifies a resource into exactly one [SystemTag] (or none,
 * when the object is not in an exposed system surface). Compilation builds hash maps + schema-scoped prefix
 * lists so a decision classifies each distinct key once, not by scanning every rule.
 *
 * Matching is case-insensitive ASCII fold: system schemas and their objects are conventionally lower-case,
 * and matching is scoped to the exposed system schemas, so a user object can't be caught. The caller passes
 * the already schema-resolved `(catalog, schema, name)` identity (mapping-schema-construction.md); the
 * classifier owns only the manifest lookup, never namespace resolution.
 *
 * The constructor VALIDATES and throws [SystemManifestException] on any manifest violation (bad tag, duplicate
 * exact identity with a different tag, overlapping families with different tags, an invalid column scope, or
 * an exact relation rule that would downgrade a stronger family by match ordering). A malformed manifest must
 * abort startup like a bad
 * migration.
 */
class SystemClassifier(val manifest: SystemManifest) {
    private fun fold(s: String) = s.lowercase()

    private val systemSchemas: Set<String> = manifest.systemSchemas.map { fold(it.schema) }.toSet()
    private val logicalSchemas: Set<String> = manifest.logicalFunctionSchemas.map { fold(it.schema) }.toSet()

    // (schema, name) -> tag, deduped strongest-first so the exact-map value is already the winning tag.
    private val relationExact: Map<Pair<String, String>, SystemTag> = exactMap(manifest.relations, "relation")
    private val functionExact: Map<Pair<String, String>, SystemTag> = exactMap(manifest.functions, "function")
    private val columnOverrides: Map<Triple<String, String, String>, SystemTag> = columnMap(manifest.columnOverrides)
    // schema -> [(prefix, tag)]; a "*" schema (cross-schema function) is keyed under "*".
    private val relationFamilies: Map<String, List<Pair<String, SystemTag>>> = familyMap(manifest.relationFamilies)
    private val functionFamilies: Map<String, List<Pair<String, SystemTag>>> = familyMap(manifest.functionFamilies)
    private val redactedColumns: Set<Triple<String, String, String>> = manifest.redactedColumns
        .map { Triple(fold(it.schema), fold(it.table), fold(it.column)) }
        .toSet()
    private val commandTags: Map<String, SystemTag> = manifest.commands.associate { it.id to requireTag(it.tag, "command ${it.id}") }
    // Cross-schema (schema "*") function rules apply in ANY schema.
    private val functionAnySchema: Map<String, SystemTag> =
        manifest.functions.filter { it.schema == "*" }.associate { fold(it.name) to requireTag(it.tag, "function *.${it.name}") }

    init {
        validate()
    }

    /**
     * The system tag for a relation, or null when `(catalog, schema)` is not an exposed system schema (the
     * caller then applies ordinary user classification). A relation in a system schema is at least
     * [SystemTag.CATALOG]; exact and family overrides raise it to the strongest matching tag.
     */
    fun classifyRelation(catalog: String, schema: String, name: String): SystemTag? {
        if (!isSystemSchema(catalog, schema)) return null
        return classifySystemRelation(schema, name)
    }

    /** The exact column override, or the owning relation's tag when no override exists. */
    fun classifyColumn(catalog: String, schema: String, table: String, column: String): SystemTag? {
        if (!isSystemSchema(catalog, schema)) return null
        return columnOverrides[Triple(fold(schema), fold(table), fold(column))]
            ?: classifySystemRelation(schema, table)
    }

    /** True when the shipped manifest requires the catalog column to be output only as NULL. */
    fun redactsColumn(catalog: String, schema: String, table: String, column: String): Boolean =
        isSystemSchema(catalog, schema) && Triple(fold(schema), fold(table), fold(column)) in redactedColumns

    private fun classifySystemRelation(schema: String, name: String): SystemTag {
        val s = fold(schema)
        val n = fold(name)
        var tag = SystemTag.CATALOG
        relationExact[s to n]?.let { tag = SystemTag.stronger(tag, it) }
        relationFamilies[s]?.forEach { (prefix, t) -> if (n.startsWith(prefix)) tag = SystemTag.stronger(tag, t) }
        return tag
    }

    /**
     * The system tag for a function, or null when it is neither in an exposed/logical system schema nor a
     * shipped cross-schema dangerous function. A recognized cross-schema function (rule `schema: "*"`, e.g.
     * an extension `dblink`) is classified in ANY schema — over-classifying a same-named user function is
     * safe (fail-closed).
     */
    fun classifyFunction(catalog: String, schema: String, name: String): SystemTag? {
        val n = fold(name)
        val s = fold(schema)
        var tag: SystemTag? = null
        // Cross-schema (`schema:"*"`) rules classify a dangerous extension function wherever it is
        // installed: exacts (e.g. `dblink`) AND families (e.g. pageinspect `heap_page_`, `bt_page_`).
        functionAnySchema[n]?.let { tag = combine(tag, it) }
        functionFamilies["*"]?.forEach { (prefix, t) -> if (n.startsWith(prefix)) tag = combine(tag, t) }
        // In an exposed system schema (or the logical builtin schema): the catalog default + in-schema rules.
        if (isSystemSchema(catalog, schema) || s in logicalSchemas) {
            tag = combine(tag, SystemTag.CATALOG)
            functionExact[s to n]?.let { tag = combine(tag, it) }
            functionFamilies[s]?.forEach { (prefix, t) -> if (n.startsWith(prefix)) tag = combine(tag, t) }
        }
        return tag
    }

    /**
     * Classify an UNQUALIFIED function call (facts-emission.md). sqlglot drops a function's
     * schema qualifier at parse time — `pg_catalog.pg_read_file`, `mysql.rds_kill`, and a bare
     * `pg_read_file` are indistinguishable post-parse — so the analyzer can only emit the bare name. We
     * resolve it against the cross-schema (`*`) rules AND every system/logical schema the manifest governs,
     * taking the strongest tag. Unlike [classifyFunction] this never adds the CATALOG default: a bare name
     * that matches no dangerous rule is an ordinary safe builtin (now/count/lower) and stays UNCLASSIFIED
     * (null), so the control-plane marshals a Cedar Function only for the dangerous ones (never a forbid on
     * every projection). Over-classifying a same-named user function is safe (fail-closed).
     */
    fun classifyBareFunction(name: String): SystemTag? {
        val n = fold(name)
        var tag: SystemTag? = null
        functionAnySchema[n]?.let { tag = combine(tag, it) }
        functionFamilies["*"]?.forEach { (prefix, t) -> if (n.startsWith(prefix)) tag = combine(tag, t) }
        for (s in systemSchemas + logicalSchemas) {
            functionExact[s to n]?.let { tag = combine(tag, it) }
            functionFamilies[s]?.forEach { (prefix, t) -> if (n.startsWith(prefix)) tag = combine(tag, t) }
        }
        return tag
    }

    private fun combine(cur: SystemTag?, new: SystemTag): SystemTag = if (cur == null) new else SystemTag.stronger(cur, new)

    /** The system tag of the resource a utility command exposes, or null if the command is unmapped. */
    fun classifyCommand(id: String): SystemTag? = commandTags[id]

    private fun isSystemSchema(catalog: String, schema: String): Boolean {
        if (fold(schema) !in systemSchemas) return false
        // The manifest may pin a catalog ("def" for MySQL) or wildcard it ("*" for PostgreSQL, since system
        // schemas repeat in every database). A pinned catalog must match; "*" matches any.
        return manifest.systemSchemas.any { fold(it.schema) == fold(schema) && (it.catalog == "*" || fold(it.catalog) == fold(catalog)) }
    }

    private fun requireTag(id: String, where: String): SystemTag =
        SystemTag.fromId(id) ?: throw SystemManifestException("${manifestId()}: $where has non-system tag '$id'")

    private fun exactMap(rules: List<ObjectRule>, kind: String): Map<Pair<String, String>, SystemTag> {
        val out = HashMap<Pair<String, String>, SystemTag>()
        for (r in rules) {
            if (r.schema == "*") continue // cross-schema function handled separately; not a keyed exact
            val tag = requireTag(r.tag, "$kind ${r.schema}.${r.name}")
            val key = fold(r.schema) to fold(r.name)
            val prev = out[key]
            if (prev != null && prev != tag) {
                throw SystemManifestException("${manifestId()}: duplicate exact $kind ${r.schema}.${r.name} with conflicting tags $prev/$tag")
            }
            out[key] = tag
        }
        return out
    }

    private fun columnMap(rules: List<ColumnRule>): Map<Triple<String, String, String>, SystemTag> {
        val out = HashMap<Triple<String, String, String>, SystemTag>()
        for (r in rules) {
            val key = Triple(fold(r.schema), fold(r.table), fold(r.column))
            val tag = requireTag(r.tag, "column ${r.schema}.${r.table}.${r.column}")
            val previous = out.putIfAbsent(key, tag)
            if (previous != null && previous != tag) {
                throw SystemManifestException(
                    "${manifestId()}: duplicate column ${r.schema}.${r.table}.${r.column} with conflicting tags $previous/$tag",
                )
            }
        }
        return out
    }

    private fun familyMap(rules: List<FamilyRule>): Map<String, List<Pair<String, SystemTag>>> {
        val out = HashMap<String, MutableList<Pair<String, SystemTag>>>()
        for (r in rules) {
            val tag = requireTag(r.tag, "family ${r.schema}.${r.prefix}*")
            out.getOrPut(fold(r.schema)) { mutableListOf() }.add(fold(r.prefix) to tag)
        }
        return out
    }

    private fun validate() {
        // The wildcard schema "*" is valid ONLY on a function rule (a cross-schema extension function),
        // never on a relation — a "*" relation would be silently un-keyed and classify nothing (open).
        (manifest.relations.map { it.schema } + manifest.relationFamilies.map { it.schema })
            .firstOrNull { it == "*" }
            ?.let { throw SystemManifestException("${manifestId()}: wildcard schema \"*\" is only valid on a function rule, not a relation") }
        for (rule in manifest.columnOverrides) {
            if (fold(rule.schema) !in systemSchemas) {
                throw SystemManifestException(
                    "${manifestId()}: column override ${rule.schema}.${rule.table}.${rule.column} is outside a system schema",
                )
            }
        }
        val redactionKeys = manifest.redactedColumns.map { Triple(fold(it.schema), fold(it.table), fold(it.column)) }
        if (redactionKeys.size != redactionKeys.toSet().size) {
            throw SystemManifestException("${manifestId()}: duplicate redacted column")
        }
        for (rule in manifest.redactedColumns) {
            if (fold(rule.schema) !in systemSchemas) {
                throw SystemManifestException("${manifestId()}: redacted column ${rule.schema}.${rule.table}.${rule.column} is outside a system schema")
            }
            if (classifySystemRelation(rule.schema, rule.table) != SystemTag.CATALOG) {
                throw SystemManifestException("${manifestId()}: redacted column ${rule.schema}.${rule.table}.${rule.column} belongs to a non-catalog relation")
            }
        }
        for ((schema, families) in relationFamilies + functionFamilies) {
            // Overlapping families with different tags are ambiguous (which wins?). Reject.
            for (i in families.indices) for (j in families.indices) if (i != j) {
                val (pa, ta) = families[i]
                val (pb, tb) = families[j]
                if (pa.startsWith(pb) && ta != tb) {
                    throw SystemManifestException("${manifestId()}: overlapping families in $schema ('$pa' ⊂ '$pb') with conflicting tags $ta/$tb")
                }
            }
        }
        // Category downgrade by ordering: a WEAKER exact rule whose name matches a STRONGER family prefix in
        // the same schema would appear to downgrade the family. The strongest-first combinator already
        // prevents the downgrade, but the doc requires rejecting a manifest that even LOOKS like it relies on
        // ordering — so surface it at boot rather than trust the runtime combinator.
        checkNoDowngrade(relationExact, relationFamilies, "relation")
        checkNoDowngrade(functionExact, functionFamilies, "function")
    }

    private fun checkNoDowngrade(
        exact: Map<Pair<String, String>, SystemTag>,
        families: Map<String, List<Pair<String, SystemTag>>>,
        kind: String,
    ) {
        for ((key, exactTag) in exact) {
            val (schema, name) = key
            families[schema]?.forEach { (prefix, familyTag) ->
                if (name.startsWith(prefix) && exactTag.ordinal > familyTag.ordinal) {
                    throw SystemManifestException(
                        "${manifestId()}: exact $kind $schema.$name (tag $exactTag) is weaker than the family '$prefix*' (tag $familyTag) it matches — would rely on match ordering",
                    )
                }
            }
        }
    }

    private fun manifestId() = "${manifest.engine}/${manifest.series}"
}
