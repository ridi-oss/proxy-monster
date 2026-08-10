package com.ridi.oss.proxymonster.classification

import kotlinx.serialization.json.Json
import java.security.MessageDigest

/**
 * A resolved manifest for a datasource's detected engine version (docs/system-classification.md).
 * [isFallback] is true when no manifest matched the version's major and the nearest supported major is being
 * used instead — the caller raises the high-severity `classification_stale`/fallback health signal + audits
 * `resolvedSeries != requestedSeries`.
 */
data class ResolvedClassification(
    val classifier: SystemClassifier,
    val requestedSeries: String,
    val resolvedSeries: String,
    val isFallback: Boolean,
)

/**
 * Loads and holds all bundled system-classification manifests (docs/system-classification.md).
 * Every manifest is validated at construction — a malformed or conflicting manifest throws
 * [SystemManifestException] and must abort startup, like a failed Flyway migration. Manifests are keyed by
 * engine + MAJOR series; [resolve] selects a datasource's manifest by its parsed engine version, with an
 * opt-in fallback for a version no bundled manifest covers.
 *
 * The bundled set covers PostgreSQL 16 & 17 and MySQL 8.0 & 8.4, vanilla or Aurora: a manifest is keyed by
 * engine major series, and each also classifies the Aurora-proprietary system surface vanilla lacks.
 */
class SystemClassificationStore private constructor(
    private val byEngineSeries: Map<Pair<String, String>, SystemClassifier>,
    val checksum: String,
) {
    /**
     * Resolve the manifest for a datasource. [serverVersion] is the parsed target DB release (e.g. `17.9`,
     * `8.0.44`, `8.4.7`). [allowFallback] is the operator opt-in: when false (the safe default), an
     * uncertified major returns null (system schemas stay unavailable); when true, it falls back to the
     * nearest supported major of the same engine.
     *
     * Returns null when there is no manifest for the major and fallback is off — the caller then does NOT
     * expose the datasource's system schemas (fail-closed; user schemas keep ordinary deny-by-default).
     */
    fun resolve(engine: String, serverVersion: String, allowFallback: Boolean): ResolvedClassification? {
        val eng = engine.lowercase()
        val requested = seriesOf(eng, serverVersion)
        byEngineSeries[eng to requested]?.let {
            return ResolvedClassification(it, requested, requested, isFallback = false)
        }
        if (!allowFallback) return null
        val nearest = nearestSeries(eng, requested) ?: return null
        return ResolvedClassification(byEngineSeries.getValue(eng to nearest), requested, nearest, isFallback = true)
    }

    /** All (engine, series) pairs with a bundled manifest — for health/diagnostics. */
    fun supported(): Set<Pair<String, String>> = byEngineSeries.keys

    /** The classifier for an exact (engine, series), or null — for tests/diagnostics. */
    fun classifierFor(engine: String, series: String): SystemClassifier? = byEngineSeries[engine.lowercase() to series]

    /**
     * Every shipped classifier for [engine] (all its certified series). Used to build the version-INDEPENDENT
     * dangerous-function floor for a datasource whose version resolves to NO manifest (uncertified/absent
     * major) — the union of these classifiers, strongest tag per name, closes the no-manifest function leak
     * (the manifest's `table_to_xml*`/pageinspect/`lo_*`/replication families a thin hand-curated baseline
     * missed) without a hand-maintained duplicate that would drift from the manifests. Empty for an engine
     * with no bundled manifest.
     */
    fun classifiersForEngine(engine: String): List<SystemClassifier> {
        val eng = engine.lowercase()
        return byEngineSeries.entries.filter { it.key.first == eng }.map { it.value }
    }

    /**
     * Nearest supported series of the same engine: the highest supported major ≤ requested; if the datasource
     * is older than every supported major, the lowest supported. Series compare component-wise as ints
     * (PostgreSQL `17` → [17]; MySQL `8.0`/`8.4` → [8,0]/[8,4]).
     */
    private fun nearestSeries(engine: String, requested: String): String? {
        val candidates = byEngineSeries.keys.filter { it.first == engine }.map { it.second }
        if (candidates.isEmpty()) return null
        val req = seriesKey(requested)
        val notNewer = candidates.filter { seriesKey(it) <= req }
        return if (notNewer.isNotEmpty()) {
            notNewer.maxByOrNull { seriesKey(it) }
        } else {
            candidates.minByOrNull { seriesKey(it) }
        }
    }

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        /**
         * The bundled manifest resource stems (`system-classification/<stem>.json`). Adding an engine
         * version is a deliberate, release-reviewed change here + the resource file (the safety-property
         * curation loop).
         */
        private val BUNDLED = listOf(
            "postgres/16",
            "postgres/17",
            "mysql/8.0",
            "mysql/8.4",
        )

        private const val RESOURCE_DIR = "/system-classification"

        /** Load, validate, and index every bundled manifest. Throws [SystemManifestException] on any problem. */
        fun load(): SystemClassificationStore {
            val map = HashMap<Pair<String, String>, SystemClassifier>()
            val digest = MessageDigest.getInstance("SHA-256")
            for (stem in BUNDLED.sorted()) {
                val path = "$RESOURCE_DIR/$stem.json"
                val text = SystemClassificationStore::class.java.getResourceAsStream(path)
                    ?.bufferedReader()?.use { it.readText() }
                    ?: throw SystemManifestException("bundled manifest missing from the classpath: $path")
                digest.update(text.toByteArray(Charsets.UTF_8))
                val manifest = try {
                    JSON.decodeFromString(SystemManifest.serializer(), text)
                } catch (e: Exception) {
                    throw SystemManifestException("malformed manifest $path: ${e.message}")
                }
                // Path ↔ (engine, series) consistency.
                val (dirEngine, fileSeries) = stem.split("/", limit = 2)
                if (manifest.engine != dirEngine || manifest.series != fileSeries) {
                    throw SystemManifestException(
                        "manifest $path declares engine/series ${manifest.engine}/${manifest.series} but its path says $dirEngine/$fileSeries",
                    )
                }
                val classifier = SystemClassifier(manifest) // validates; throws on any manifest violation
                if (map.put(manifest.engine.lowercase() to manifest.series, classifier) != null) {
                    throw SystemManifestException("duplicate manifest for ${manifest.engine}/${manifest.series}")
                }
            }
            val checksum = digest.digest().joinToString("") { "%02x".format(it) }
            return SystemClassificationStore(map, checksum)
        }

        /** Test/diagnostic factory from in-memory manifests (bypasses the classpath). */
        fun of(manifests: List<SystemManifest>): SystemClassificationStore {
            val map = HashMap<Pair<String, String>, SystemClassifier>()
            for (m in manifests) map[m.engine.lowercase() to m.series] = SystemClassifier(m)
            return SystemClassificationStore(map, "test")
        }

        /** Engine version → major series. PostgreSQL: the leading integer (`17.9`→`17`). MySQL: the LTS family (`8.0.44`→`8.0`, `8.4.7`→`8.4`). */
        fun seriesOf(engine: String, version: String): String = when (engine.lowercase()) {
            "mysql" -> version.split(".").take(2).joinToString(".")
            else -> version.substringBefore(".")
        }

        // A single comparable key for ordering series WITHIN one engine (never compared cross-engine):
        // `major*1000 + minor` — PostgreSQL `17`→17000, MySQL `8.0`→8000, `8.4`→8004.
        private fun seriesKey(series: String): Int {
            val parts = series.split(".")
            return (parts.getOrNull(0)?.toIntOrNull() ?: 0) * 1000 + (parts.getOrNull(1)?.toIntOrNull() ?: 0)
        }
    }
}
