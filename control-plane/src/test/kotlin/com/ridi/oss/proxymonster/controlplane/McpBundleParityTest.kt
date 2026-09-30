package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.oauth.MCPA_SCOPES
import org.junit.jupiter.api.Test
import java.util.Locale
import java.util.ResourceBundle
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Every MCP-facing message exists in every locale, and the tool bundle names exactly the registered tools. */
class McpBundleParityTest {
    private fun keys(bundle: String, locale: Locale): Set<String> {
        val loaded = ResourceBundle.getBundle(bundle, locale, ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES))
        assertEquals(locale.language, loaded.locale.language, "$bundle has no ${locale.language} file")
        return loaded.keySet()
    }

    @Test
    fun `tool descriptions cover exactly the registered tools in every locale`() {
        val en = keys("mcp_tools", Locale.ENGLISH)
        assertEquals(en, keys("mcp_tools", Locale.KOREAN))
        assertEquals(McpCapabilityRegistry.approvedToolNames, en)
    }

    @Test
    fun `error messages match across locales`() {
        assertEquals(keys("mcp_errors", Locale.ENGLISH), keys("mcp_errors", Locale.KOREAN))
    }

    @Test
    fun `every consent scope has a label in every locale`() {
        for (locale in listOf(Locale.ENGLISH, Locale.KOREAN)) {
            val labels = keys("authorization_messages", locale)
            for (scope in MCPA_SCOPES) assertTrue("consent.scope.$scope" in labels, "${locale.language}: $scope")
        }
        assertEquals(MCPA_SCOPES, McpCapabilityRegistry.supportedScopes)
    }
}
