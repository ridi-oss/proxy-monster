package com.ridi.oss.proxymonster.controlplane

import java.io.File
import java.util.Locale
import java.util.ResourceBundle
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Every `ApiError` code the control plane can emit must resolve in both MCP error bundles.
 *
 * The MCP surface localizes an error by looking its code up in `mcp_errors_<locale>.properties`. A code
 * with no entry used to throw `MissingResourceException` from inside the failure handler, so a missing
 * key turned a structured refusal into a raw failure on exactly the path that reports refusals. The
 * lookup now degrades to the code, and this test is what keeps the bundles actually complete — a
 * grep-the-source guard rather than a per-route test, since the gap appears when a code is ADDED.
 */
class McpErrorBundleTest {
    /**
     * The layer MCP tool calls actually run through: the management services every tool dispatches into,
     * plus the MCP transport itself. Routes outside this set (approvals, device login, the query path)
     * are HTTP-only — their codes localize from `web/messages/` and never reach a bundle lookup.
     */
    private val mcpReachableSources = listOf(
        File("src/main/kotlin/com/ridi/oss/proxymonster/controlplane/management"),
        File("src/main/kotlin/com/ridi/oss/proxymonster/controlplane/mcp"),
    )

    private fun emittedCodes(): Set<String> {
        // DOT_MATCHES_ALL: an ApiError whose params wrap onto later lines still has its code on the
        // first, and a single-line-only regex silently skips exactly those multi-line constructions.
        val pattern = Regex("""ApiError\(\s*"([a-z0-9_]+(?:\.[a-z0-9_]+)+)"""", RegexOption.DOT_MATCHES_ALL)
        return mcpReachableSources.asSequence()
            .flatMap { it.walkTopDown() }
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file -> pattern.findAll(file.readText()).map { it.groupValues[1] } }
            .toSet()
    }

    @Test
    fun `every emitted ApiError code resolves in both MCP error bundles`() {
        val codes = emittedCodes()
        assertTrue(codes.size >= 15, "the source scan found only ${codes.size} codes — the regex likely broke")
        assertTrue(
            "classification_profile.attached" in codes,
            "the scan must see multi-line ApiError constructions; found: ${codes.sorted()}",
        )

        val missing = buildMap<String, MutableList<String>> {
            for (locale in listOf(Locale.ENGLISH, Locale.KOREAN)) {
                val bundle = ResourceBundle.getBundle("mcp_errors", locale)
                for (code in codes.sorted()) {
                    if (!bundle.containsKey(code)) {
                        getOrPut(locale.language) { mutableListOf() } += code
                    }
                }
            }
        }
        assertEquals(emptyMap(), missing, "ApiError codes missing from mcp_errors_<locale>.properties")
    }

    @Test
    fun `both MCP bundles carry exactly the same keys`() {
        val en = ResourceBundle.getBundle("mcp_errors", Locale.ENGLISH).keySet()
        val ko = ResourceBundle.getBundle("mcp_errors", Locale.KOREAN).keySet()
        assertEquals(emptySet(), en - ko, "keys present only in English")
        assertEquals(emptySet(), ko - en, "keys present only in Korean")
    }
}
