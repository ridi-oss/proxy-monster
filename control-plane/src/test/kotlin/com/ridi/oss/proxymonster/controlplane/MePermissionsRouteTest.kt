package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import javax.sql.DataSource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterEach
import kotlin.test.Test
import kotlin.test.assertEquals

class MePermissionsRouteTest {
    private val database: String by lazy {
        com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip()
        com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.freshDatabase("pm_me_permissions")
    }

    private val dataSource: DataSource by lazy {
        com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.hikari(database)
            .also { org.flywaydb.core.Flyway.configure().dataSource(it).load().migrate() }
    }

    private val rolePolicies = listOf(
        1L to """permit(principal in Role::"datasource-admin", action == Action::"admin.datasources", resource);""",
        2L to """permit(principal in Role::"policy-admin", action == Action::"admin.policies", resource);""",
        3L to """permit(principal in Role::"identity-admin", action == Action::"admin.identity", resource);""",
        4L to """permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };""",
        5L to """permit(principal in Role::"auditor", action == Action::"audit.read", resource);""",
    )

    private val principalRoles = mapOf(
        "datasource-only" to setOf("datasource-admin"),
        "policy-only" to setOf("policy-admin"),
        "identity-only" to setOf("identity-admin"),
        "auditor-only" to setOf("auditor"),
    )

    /** The Cedar policies and role assignments a test runs under. */
    private class Authz(val policies: List<Pair<Long, String>>, val roles: Map<String, Set<String>>)

    private fun authz(): Authz = Authz(rolePolicies, principalRoles)

    private fun config(authDebug: Boolean, trustedProxies: Set<String> = emptySet()) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = authDebug,
        secretToken = null,
        sessionSecret = "test-session-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
        trustedProxies = trustedProxies,
    )

    // An IP-gated admin.datasources permit: `isAdmin` is true ONLY when requester_ip is in the documentation
    // range 203.0.113.0/24 — so the /api/me/permissions decision is observably sensitive to the context arg.
    private fun ipGatedAdminAuthz(): Authz = Authz(
        listOf(
            1L to """permit(principal in Role::"system:admin", action == Action::"admin.datasources", resource)
                when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
        ),
        mapOf("edge-admin" to setOf("system:admin")),
    )

    private fun isAdmin(body: String): Boolean =
        Json.parseToJsonElement(body).jsonObject.getValue("isAdmin").jsonPrimitive.boolean

    @Test
    fun `requests require a session`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)

        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/me/permissions").status)
    }

    /**
     * A session is what authenticates, in either mode: `PM_AUTH_DEBUG` is a login METHOD, so turning it on
     * changes nothing about needing to log in first.
     */
    @Test
    fun `auth debug does not admit a caller without a session`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = true), authz(), dataSource)

        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/me/permissions").status)
    }

    /**
     * The capabilities reported are the ones Cedar actually grants the logged-in principal. Claiming admin
     * for a session signed in with a low-privilege role would render every admin affordance and each one
     * would 403 on click — the console has to describe the authority the routes will actually grant.
     */
    @Test
    fun `a principal holding no roles claims no capabilities`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = true), authz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/roleless").status)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        val payload = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(setOf("isAdmin", "canReadAllAudit", "canApprove"), payload.keys)
        assertEquals(false, payload.getValue("isAdmin").jsonPrimitive.boolean)
        assertEquals(false, payload.getValue("canReadAllAudit").jsonPrimitive.boolean)
        assertEquals(false, payload.getValue("canApprove").jsonPrimitive.boolean)
    }

    @Test
    fun `each independent admin action grants admin and approval but not audit collection access`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)

        for (principal in listOf("datasource-only", "policy-only", "identity-only")) {
            assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
            val response = client.get("/api/me/permissions")
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(
                MePermissions(isAdmin = true, canReadAllAudit = false, canApprove = true),
                response.body(),
            )
        }
    }

    @Test
    fun `auditor can read the audit collection without admin or approval capabilities`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/auditor-only").status)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            MePermissions(isAdmin = false, canReadAllAudit = true, canApprove = false),
            response.body(),
        )
    }

    @Test
    fun `requester_ip from a trusted edge reaches the me-permissions admin decision`() = testApplication {
        // With a trusted edge configured, X-Forwarded-For is honored, so requester_ip is the forwarded IP —
        // and the ip-gated admin permit fires (or not) accordingly. This pins the computeMePermissions context
        // argument as load-bearing at the actual route: drop it and the in-range case would no longer be admin.
        val client = wirePermissionsApp(config(authDebug = false, trustedProxies = setOf("localhost")), ipGatedAdminAuthz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/edge-admin").status)

        val inRange = client.get("/api/me/permissions") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.OK, inRange.status)
        assertEquals(true, isAdmin(inRange.bodyAsText()), "requester_ip in range -> the ip-gated admin permit fires")

        val outOfRange = client.get("/api/me/permissions") { header("X-Forwarded-For", "198.51.100.10") }
        assertEquals(false, isAdmin(outOfRange.bodyAsText()), "requester_ip out of range -> not admin")
    }

    @Test
    fun `an untrusted peer cannot spoof requester_ip via X-Forwarded-For at the me-permissions route`() = testApplication {
        // No trusted edge -> XFF is never honored -> requester_ip stays absent (the test-host peer 'localhost'
        // is not a valid IP either) -> the ip-gated admin permit never fires, even with a spoofed header.
        val client = wirePermissionsApp(config(authDebug = false, trustedProxies = emptySet()), ipGatedAdminAuthz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/edge-admin").status)

        val spoofed = client.get("/api/me/permissions") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(false, isAdmin(spoofed.bodyAsText()), "an untrusted caller cannot spoof requester_ip via X-Forwarded-For")
    }

    @Test
    fun `ordinary principal has no coarse capabilities`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/ordinary").status)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            MePermissions(isAdmin = false, canReadAllAudit = false, canApprove = false),
            response.body(),
        )
    }

    private val stacks = mutableListOf<CpGoStack>()

    @AfterEach
    fun closeStacks() {
        stacks.forEach(CpGoStack::close)
        stacks.clear()
    }

    /** cp-go in front of the Kotlin control plane, serving `/api/me/permissions` under [authz]'s policies and roles. */
    @Suppress("UnusedReceiverParameter")
    private fun ApplicationTestBuilder.wirePermissionsApp(config: Config, authz: Authz, dataSource: DataSource): HttpClient {
        val core = ControlPlaneCore(dataSource)
        core.cedarPolicyStore.list().forEach { core.cedarPolicyStore.setEnabled(it.id, false, null) }
        authz.policies.forEach { (id, src) -> core.cedarPolicyStore.create(CedarPolicyInput("me-permissions-${System.nanoTime()}-$id", src), null) }
        val sessionStore = PrincipalSessionStore(dataSource, null)
        for ((principal, held) in authz.roles) {
            core.userGroupStore.getUserByPrincipal(principal)
                ?: core.userGroupStore.createUser(AppUserInput(principal = principal), core.tokenStore, core.accessStore, sessionStore)
            for (name in held) {
                val role = core.policyStore.getRoleByName(name) ?: core.policyStore.createRole(RoleInput(name))
                if (core.policyStore.listAssignments(principal, role.id).isEmpty()) {
                    core.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
                }
            }
        }
        // The test host's peer is cp-go's loopback client, so a trusted edge here is 127.0.0.1 to cp-go.
        val env = if (config.trustedProxies.isEmpty()) emptyMap() else mapOf("PM_TRUSTED_PROXIES" to "127.0.0.1")
        val stack = CpGoStack(config, core, database, extraEnv = env) { routing { testLoginRoute(sessionStore, config) } }
        stacks += stack
        return stack.client()
    }
}
