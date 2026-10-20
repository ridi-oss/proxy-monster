package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.oauth.MCPA_SCOPES
import org.junit.jupiter.api.Test
import java.util.Locale
import java.util.ResourceBundle
import kotlin.test.assertEquals

/** Every user-facing MCP message exists in every locale, and the tool bundle names exactly the registered tools. */
class McpBundleParityTest {
    private fun keys(bundle: String, locale: Locale): Set<String> {
        val loaded = ResourceBundle.getBundle(bundle, locale, ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES))
        assertEquals(locale.language, loaded.locale.language, "$bundle has no ${locale.language} file")
        return loaded.keySet()
    }

    @Test
    fun `tool descriptions cover exactly the registered tools`() {
        assertEquals(McpCapabilityRegistry.approvedToolNames, ResourceBundle.getBundle("mcp_tools", Locale.ROOT).keySet())
    }

    @Test
    fun `error messages match across locales`() {
        assertEquals(keys("mcp_errors", Locale.ENGLISH), keys("mcp_errors", Locale.KOREAN))
    }

    @Test
    fun `the authorization server offers exactly the scopes the MCP tools use`() {
        assertEquals(MCPA_SCOPES, McpCapabilityRegistry.supportedScopes)
    }
}
