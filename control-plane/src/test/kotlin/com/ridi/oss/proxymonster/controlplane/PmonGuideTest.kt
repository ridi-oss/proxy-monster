package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.mcp.pmonGuide
import com.ridi.oss.proxymonster.controlplane.mcp.shellArg
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import org.junit.jupiter.api.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

class PmonGuideTest {
    @Test
    fun `shell lines quote names a shell would split`() {
        assertEquals("hr", shellArg("hr"))
        assertEquals("https://pm.example.com", shellArg("https://pm.example.com"))
        assertEquals("'sales data'", shellArg("sales data"))
        assertEquals("'a; rm -rf ~'", shellArg("a; rm -rf ~"))
        assertEquals("'it'\\''s'", shellArg("it's"))
        assertEquals("''", shellArg(""))

        val guide = pmonGuide(mcpTestConfig(), listOf("sales data", "orders"))
        assertContains(guide, "pmon show local 'sales data' --cli")
        assertContains(guide, "pmon show local orders --cli")
    }
}
