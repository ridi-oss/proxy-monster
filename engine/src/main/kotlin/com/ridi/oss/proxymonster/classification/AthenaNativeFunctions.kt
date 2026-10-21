package com.ridi.oss.proxymonster.classification

/**
 * The pinned Athena built-in function names per engine version — the control plane seeds
 * FunctionCatalog.builtin_functions from this list because Athena exposes no routine catalog. Names are
 * folded lowercase, one per line in `native-functions/athena/<version>.txt`; loaded once from the classpath.
 */
object AthenaNativeFunctions {
    private val byVersion: Map<String, List<String>> = listOf("3").associateWith(::load)

    private fun load(version: String): List<String> {
        val path = "/native-functions/athena/$version.txt"
        val stream = javaClass.getResourceAsStream(path)
            ?: error("missing pinned Athena native-function list: $path")
        return stream.bufferedReader().useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .map { it.lowercase() }
                .toList()
        }
    }

    /** The builtin names for an Athena engine [version] ("3"); an unknown or blank version resolves to 3. */
    fun forVersion(version: String?): List<String> = byVersion[version?.trim()] ?: byVersion.getValue("3")
}
