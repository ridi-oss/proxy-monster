package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeNativeResource
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import java.lang.reflect.Proxy
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeAuthorizationTest {
    private val resource = AuthzResource.NativeResource("reports", "query-execution", "query/123", "alice", listOf("production"))
    private val context = AuthzContext(channel = "wire", requesterIp = "10.2.3.4")

    @Test
    fun `native invocation is not an MCP management tool`() {
        McpCapabilityRegistry.verify()
        assertTrue(AuthzAction.NATIVE_INVOKE in McpCapabilityRegistry.excludedActions)
    }

    @Test
    fun `native invocation requires its own permit`() {
        assertFalse(allowed(authz()))
        assertFalse(allowed(authz("""permit(principal, action == Action::"datasource.connect", resource);""")))
        assertFalse(allowed(authz("""permit(principal, action == Action::"result.read.unmasked", resource);""")))
        assertTrue(allowed(authz("""permit(principal, action == Action::"native.invoke", resource in Datasource::"reports");""")))
    }

    @Test
    fun `native resources preserve datasource tags owner kind id role and request context`() {
        val gate = authz(
            """permit(principal in Role::"reader", action == Action::"native.invoke", resource in Tag::"production")
                when { resource.kind == "query-execution" && resource.id == "query/123" && resource has owner && resource.owner == principal &&
                    context has native_operation && context.native_operation == "athena:GetQueryResults" &&
                    context has channel && context.channel == "wire" && context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
        )
        assertTrue(allowed(gate))
        assertFalse(allowed(gate, roles = emptySet()))
        assertFalse(allowed(gate, resource = resource.copy(owner = "bob")))
        assertFalse(allowed(gate, resource = resource.copy(owner = null)))
        assertFalse(allowed(gate, resource = resource.copy(kind = "workgroup")))
        assertFalse(allowed(gate, resource = resource.copy(id = "query/456")))
        assertFalse(allowed(gate, resource = resource.copy(datasourceTags = emptyList())))
        assertFalse(allowed(gate, operation = "athena:GetQueryExecution"))
        assertFalse(allowed(gate, context = context.copy(requesterIp = "198.51.100.1")))
        assertFalse(allowed(gate, context = context.copy(channel = "editor")))
    }

    @Test
    fun `provider operation replaces supplied context and derives fresh tags`() {
        val gate = authz(
            """permit(principal, action == Action::"context.tag::native-read", resource)
                when { context has native_operation && context.native_operation == "athena:GetQueryResults" };""",
            """permit(principal, action == Action::"native.invoke", resource)
                when { context has tags && context.tags.contains("native-read") && !(context has stmt_kind) };""",
        )
        assertTrue(allowed(gate, context = context.copy(nativeOperation = "forged", stmtKind = "select")))
        assertFalse(allowed(gate, operation = "unknown", context = context.copy(tags = setOf("native-read"))))
    }

    @Test
    fun `forbids and policy evaluation errors deny native invocations`() {
        val permit = """permit(principal, action == Action::"native.invoke", resource);"""
        assertFalse(allowed(authz(permit, """forbid(principal, action == Action::"native.invoke", resource in Datasource::"reports");""")))
        assertFalse(allowed(authz(permit, """forbid(principal, action == Action::"native.invoke", resource) when { 9223372036854775807 + 1 > 0 };""")))
    }

    @Test
    fun `invalid resource identity or absent operation denies despite broad permits`() {
        val gate = authz("""permit(principal, action == Action::"native.invoke", resource);""")
        for (invalid in listOf(
            resource.copy(datasourceName = ""), resource.copy(kind = ""), resource.copy(id = ""), resource.copy(owner = ""),
        )) assertFalse(allowed(gate, resource = invalid))
        assertFalse(allowed(gate, operation = ""))
        assertTrue(gate.authorizeAs("alice", setOf("reader"), AuthzAction.NATIVE_INVOKE, resource) is AuthzDecision.Deny)
    }

    @Test
    fun `native resource identifiers preserve delimiters without collisions`() {
        val gate = authz(
            """permit(principal, action == Action::"native.invoke", resource == NativeResource::"reports%2Fteam/query/query%2F123");""",
        )
        assertTrue(allowed(gate, resource = resource.copy(datasourceName = "reports/team", kind = "query")))
        assertFalse(allowed(gate, resource = resource.copy(datasourceName = "reports", kind = "team/query")))
        assertFalse(allowed(gate, resource = resource.copy(datasourceName = "reports%2Fteam", kind = "query")))
        assertTrue(allowed(authz("""permit(principal, action == Action::"native.invoke", resource);"""), resource = resource.copy(kind = "query/execution")))
    }

    @Test
    fun `optional native owner and operation require guards in policies`() {
        assertFalse(CedarSchema.validate("""permit(principal, action == Action::"native.invoke", resource) when { resource.owner == principal };""").isEmpty())
        assertFalse(CedarSchema.validate("""permit(principal, action == Action::"native.invoke", resource) when { context.native_operation == "athena:GetQueryResults" };""").isEmpty())
        assertEquals(emptyList(), CedarSchema.validate("""permit(principal, action == Action::"native.invoke", resource) when { resource has owner && resource.owner == principal };"""))
    }

    private fun allowed(
        gate: Authz,
        resource: AuthzResource.NativeResource = this.resource,
        roles: Set<String> = setOf("reader"),
        operation: String = "athena:GetQueryResults",
        context: AuthzContext = this.context,
    ) = gate.authorizeNativeResource("alice", roles, resource, operation, context) is AuthzDecision.Allow

    private fun authz(vararg policies: String) = Authz(
        CedarEngine(policies.mapIndexed { index, source -> index.toLong() + 1 to source }),
        CedarPolicyStore(
            Proxy.newProxyInstance(DataSource::class.java.classLoader, arrayOf(DataSource::class.java)) { _, _, _ ->
                error("native authorization must not access the store")
            } as DataSource,
        ),
        RoleSource { error("native authorization must use the resolved role snapshot") },
    )
}
