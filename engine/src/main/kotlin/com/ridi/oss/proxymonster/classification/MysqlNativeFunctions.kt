package com.ridi.oss.proxymonster.classification

/**
 * The pinned MySQL native (built-in) function names per server series — the control plane seeds
 * FunctionCatalog.builtin_functions from this list because the proxy cannot enumerate builtins live (they
 * are compiled in). Names are folded lowercase, one per line in `native-functions/mysql/<series>.txt`
 * (`#` and blank lines ignored), verified against a live server; loaded once from the classpath.
 */
object MysqlNativeFunctions {
    private val bySeries: Map<String, List<String>> = listOf("8.0", "8.4").associateWith(::load)

    private fun load(series: String): List<String> {
        val path = "/native-functions/mysql/$series.txt"
        val stream = javaClass.getResourceAsStream(path)
            ?: error("missing pinned MySQL native-function list: $path")
        return stream.bufferedReader().useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .map { it.lowercase() }
                .toList()
        }
    }

    /**
     * The builtin names for a MySQL server [version] (raw `major.minor[.patch]`, e.g. "8.0.44"). Resolves to
     * the nearest pinned series: 8.4+ → 8.4, anything else → 8.0 (the widely-deployed baseline). A null/blank
     * or unparseable version falls back to 8.0.
     */
    fun forVersion(version: String?): List<String> = bySeries.getValue(seriesFor(version))

    private fun seriesFor(version: String?): String {
        val m = version?.let { Regex("""(\d+)\.(\d+)""").find(it) } ?: return "8.0"
        val (major, minor) = m.destructured
        return if (major.toInt() == 8 && minor.toInt() >= 4) "8.4" else "8.0"
    }
}
