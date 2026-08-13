package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.classification.BaselineDangerousFunctions
import com.ridi.oss.proxymonster.classification.SystemClassificationStore
import com.ridi.oss.proxymonster.classification.SystemTag
import com.ridi.oss.proxymonster.grpc.Engine
import org.slf4j.LoggerFactory

/**
 * Control-plane wrapper over the bundled system-classification manifests (docs/system-classification.md).
 * Loads + validates every manifest once at construction — a malformed manifest aborts boot, like a failed
 * migration. At decision time it maps a system Table to its shipped `system:` tag by resolving the
 * datasource's engine version to the right manifest.
 *
 * Keyed off the STORED `datasource.engine_version` (raw `SELECT version()` + `(aurora <v>)`), so it is
 * path-agnostic — it works identically for a proxy-`PushCatalog` datasource and a legacy CP-introspected one,
 * without touching either catalog path. A datasource whose version is absent or an uncertified major resolves
 * to no manifest; its FIXED system schemas then stay closed (a table is treated as [SystemTag.CRITICAL]
 * unless a shipped manifest explicitly classifies it as dangerous — see [tagForTable]), and its dangerous
 * functions fall back to the version-independent union floor ([tagForFunction]). A user schema stays
 * unclassified.
 */
class SystemClassificationService(
    private val store: SystemClassificationStore = SystemClassificationStore.load(),
    private val allowFallback: Boolean = false,
) {
    init {
        // Boot-log the governing manifest set so an operator can see, at startup, which system-classification
        // manifests are active, the combined checksum (to spot a drifted bundle), and whether uncertified
        // engine versions fall back or stay deny-by-default. (Per-datasource resolution / fallback-hit
        // observability is a deferred follow-up — docs/system-classification.md "Known limitations".)
        val manifests = store.supported().map { (engine, series) -> "$engine/$series" }.sorted()
        log.info(
            "system-classification: {} manifest(s) loaded [{}] checksum={} uncertified-version-fallback={}",
            manifests.size,
            manifests.joinToString(", "),
            store.checksum.take(12),
            if (allowFallback) "on" else "off — uncertified versions keep system schemas deny-by-default",
        )
    }

    /**
     * The shipped `system:` tag id for a Table, or null when the table is not in a system schema (ordinary
     * user classification then applies).
     *
     * A datasource with NO governing manifest (absent or uncertified `engine_version`, fallback off) cannot
     * classify its system schemas, yet the classifier's [SystemTag.CATALOG] default plus the role-agnostic
     * `system:catalog` read permit would make every unrecognized fixed-system-schema table world-readable.
     * That is fail-open: the manifests do not enumerate every value-bearing system table (e.g. MySQL
     * `performance_schema.user_variables_by_thread`, the `sys.x$…` twins), so an unrecognized one cannot be
     * assumed benign catalog metadata. So a fixed system schema without a governing manifest is closed:
     * an explicitly-dangerous tag any shipped manifest of the engine assigns is kept (it routes through its
     * own Cedar forbid), and everything else — the catalog default and any unrecognized or catalog-mismatched
     * relation — is treated as [SystemTag.CRITICAL] so the unconditional critical forbid denies it even under
     * a broad Datasource grant. Ephemeral `pg_temp_`/`pg_toast` schemas are excluded
     * ([Engine.isFixedSystemSchema]): their connection-local handling owns that separate path.
     */
    fun tagForTable(engine: Engine, engineVersion: String?, catalog: String, schema: String, table: String): String? {
        classifierFor(engine, engineVersion)?.let { return it.classifyRelation(catalog, schema, table)?.id }
        if (!engine.isFixedSystemSchema(schema)) return null
        return (noManifestDangerousFloor(engine, catalog, schema, table) ?: SystemTag.CRITICAL).id
    }

    /**
     * The strongest EXPLICIT dangerous tag (stronger than [SystemTag.CATALOG]) any shipped manifest of [engine]
     * assigns the relation, or null when no manifest classifies it beyond the catalog default. Used only for a
     * datasource with no governing manifest: an explicit critical/data-leak/activity classification is
     * version-stable enough to trust (and over-classifying is fail-safe), while the bare catalog default cannot
     * be distinguished from an unrecognized relation, so [tagForTable] closes that case instead.
     */
    private fun noManifestDangerousFloor(engine: Engine, catalog: String, schema: String, table: String): SystemTag? {
        var tag: SystemTag? = null
        for (classifier in store.classifiersForEngine(engine.wireName)) {
            val t = classifier.classifyRelation(catalog, schema, table) ?: continue
            if (t == SystemTag.CATALOG) continue
            tag = if (tag == null) t else SystemTag.stronger(tag, t)
        }
        return tag
    }

    /**
     * The shipped `system:` tag id for a called function, or null when it is an ordinary safe function
     * (a standard builtin or an unclassified user/UDF). The analyzer emits only the BARE function name
     * (sqlglot drops the schema qualifier at parse time), so this resolves it against every system/logical
     * schema + the cross-schema rules — see [SystemClassifier.classifyBareFunction]. Only a non-null
     * (dangerous) result is marshalled as a Cedar Function and hits the shipped `system:data-leak`/
     * `system:critical` forbid.
     *
     * The version-independent [BaselineDangerousFunctions] floor is unioned in strongest-first: it classifies
     * the cross-engine-stable IO/exec builtins EVEN when no manifest
     * governs the datasource (absent/uncertified `engine_version`) OR the governing manifest doesn't classify
     * the name. It is a FLOOR only — it can raise (or match) but never LOWER a manifest classification, and it
     * classifies no safe function — so those builtins stay gated even on a no-manifest datasource.
     */
    fun tagForFunction(engine: Engine, engineVersion: String?, name: String): String? {
        val governing = classifierFor(engine, engineVersion)
        // A GOVERNED datasource trusts its own certified manifest; a NO-manifest datasource (uncertified/
        // absent major, fallback off) falls back to the version-INDEPENDENT union floor of every shipped
        // manifest of this engine — strongest tag per name. That brings no-manifest function-gating to
        // PARITY with certified: the manifest's `table_to_xml*`/pageinspect/`lo_*`/replication/backup
        // dangerous families (which a thin hand-curated baseline missed → a cleartext-PII relay on any
        // pg≠16/17, mysql≠8.0/8.4 datasource) are now classified there too, derived from the manifests
        // themselves so nothing drifts. Over-classifying a function absent in the datasource's real version
        // is a harmless over-deny (fail-safe). The whole function model is enumerate-dangerous / allow-safe
        // (the certified path too), so this is parity, not a new posture.
        val manifestTag = if (governing != null) {
            governing.classifyBareFunction(name)
        } else {
            noManifestFunctionFloor(engine, name)
        }
        val baselineTag = BaselineDangerousFunctions.classify(name)
        return floor(manifestTag, baselineTag)?.id
    }

    /** The strongest dangerous-function tag any shipped manifest of [engine] assigns [name] — the
     *  version-independent floor for a datasource with no governing manifest. Null when no manifest of the
     *  engine classifies it (an ordinary safe builtin / a UDF stays unclassified → not forbidden). */
    private fun noManifestFunctionFloor(engine: Engine, name: String): SystemTag? {
        var tag: SystemTag? = null
        for (classifier in store.classifiersForEngine(engine.wireName)) {
            classifier.classifyBareFunction(name)?.let { tag = if (tag == null) it else SystemTag.stronger(tag!!, it) }
        }
        return tag
    }

    /** The strongest of the manifest and the baseline tag (either may be null) — the FLOOR combinator: the
     *  baseline never weakens a manifest classification, and a name neither classifies stays null (safe). */
    private fun floor(manifestTag: SystemTag?, baselineTag: SystemTag?): SystemTag? = when {
        manifestTag == null -> baselineTag
        baselineTag == null -> manifestTag
        else -> SystemTag.stronger(manifestTag, baselineTag)
    }

    /**
     * The `system:` tag id for a utility command id — `SHOW_PROCESSLIST` → `system:activity`,
     * `SHOW_BINLOG_EVENTS` → `system:data-leak`, … — or null when no manifest governs the datasource. Unlike a
     * function, a null result does NOT mean "safe": the caller marshals the utility anyway, so an unclassified
     * recognized utility denies-by-default (Authz.authorizeUtilities).
     */
    fun tagForCommand(engine: Engine, engineVersion: String?, command: String): String? =
        classifierFor(engine, engineVersion)?.classifyCommand(command)?.id

    private fun classifierFor(engine: Engine, engineVersion: String?): com.ridi.oss.proxymonster.classification.SystemClassifier? {
        val (version, _) = engine.parseServerVersion(engineVersion)
        if (version == null) return null
        return store.resolve(engine.wireName, version, allowFallback)?.classifier
    }

    /**
     * A one-line description of which shipped manifest governs a datasource's `(engine, engineVersion)` — for
     * the proxy-registration log, so an operator can see at connect time whether that datasource's system
     * schemas are classified by an exact manifest, a fallback major, or left uncertified (deny-by-default).
     */
    fun describeManifestFor(engine: Engine, engineVersion: String?): String {
        val engineName = engine.wireName
        val parsed = engine.parseServerVersion(engineVersion).first
            ?: return "$engineName (version unreported) → no manifest (system schemas deny-by-default)"
        val resolved = store.resolve(engineName, parsed, allowFallback)
            ?: return "$engineName $parsed → no manifest (uncertified series → system schemas deny-by-default)"
        return if (resolved.isFallback) {
            "$engineName $parsed → manifest $engineName/${resolved.resolvedSeries} (FALLBACK — series ${resolved.requestedSeries} uncertified)"
        } else {
            "$engineName $parsed → manifest $engineName/${resolved.resolvedSeries}"
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(SystemClassificationService::class.java)
    }
}

/**
 * Extract the comparable server version + the Aurora marker from a `datasource.engine_version` string
 * (the raw `SELECT version()` output, with `(aurora <v>)` appended when `aurora_version()` resolves).
 * PostgreSQL `version()` is `PostgreSQL 17.4 on …`; MySQL `version()` is `8.0.44` / `8.0.44-log`.
 * Returns (versionForResolution, isAurora); null version when nothing parseable.
 */
fun Engine.parseServerVersion(raw: String?): Pair<String?, Boolean> {
    if (raw.isNullOrBlank()) return null to false
    val isAurora = raw.contains("aurora", ignoreCase = true)
    val version = when (this) {
        // MySQL: the base MySQL release. Aurora MySQL `version()` embeds the MySQL major.minor BEFORE a
        // `mysql_aurora` infix — `8.0.mysql_aurora.3.04.0` → 8.0, `5.7.mysql_aurora.2.11.4` → 5.7 —
        // and the datasource-registration `engine_version` also appends a `(aurora <v>)` marker.
        // Take the base BEFORE either, so the Aurora engine version (3.04.0) is never grabbed as the
        // server version. Vanilla is `8.0.44` / `8.0.44-log`.
        Engine.MYSQL -> {
            val base = raw.substringBefore("mysql_aurora").substringBefore("(aurora")
            Regex("""\d+\.\d+\.\d+""").find(base)?.value ?: Regex("""\d+\.\d+""").find(base)?.value
        }
        // PostgreSQL (and any other value): the number right after "PostgreSQL " (17.4); fall back to the
        // first version-like token.
        else -> Regex("""PostgreSQL\s+(\d+(?:\.\d+)?)""").find(raw)?.groupValues?.get(1)
            ?: Regex("""\d+(?:\.\d+)?""").find(raw)?.value
    }
    return version to isAurora
}
