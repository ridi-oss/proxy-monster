package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeAuthorizationTest {
    @Test
    fun `native invocation is not an MCP management tool`() {
        McpCapabilityRegistry.verify()
        assertTrue(AuthzAction.NATIVE_INVOKE in McpCapabilityRegistry.excludedActions)
    }
}
