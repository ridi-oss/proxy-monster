package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The decisions cp-go's audit routes ask for, run against the shipped policies. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InternalAuthorizeDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var authz: Authz

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_internal_authorize"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val policyStore = PolicyStore(dataSource)
        val roleResolver = RoleResolver(dataSource, UserGroupStore(dataSource), AccessStore(dataSource))
        policyStore.createAssignment(RoleAssignmentInput(principal = AUDITOR, roleId = policyStore.getRoleByName("system:admin")!!.id))
        val role = policyStore.createRole(RoleInput(name = "ip-auditor", description = "ip-gated audit read"))
        policyStore.createAssignment(RoleAssignmentInput(principal = EDGE_AUDITOR, roleId = role.id))
        val cedarPolicyStore = CedarPolicyStore(dataSource)
        cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ip-gated-audit-read",
                cedarSrc = """permit(principal in Role::"ip-auditor", action == Action::"audit.read", resource)
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        authz = Authz(CedarEngine(cedarPolicyStore), cedarPolicyStore, RoleSource { roleResolver.resolve(it) })
    }

    @Test
    fun `audit reads decide like the shipped policies`() = testApplication {
        val client = app()
        val cases = listOf(
            Triple(ALICE, InternalResource("AuditLog"), null) to false,
            Triple(ALICE, InternalResource("AuditRecord", ALICE), null) to true,
            Triple(ALICE, InternalResource("AuditRecord", BOB), null) to false,
            Triple(AUDITOR, InternalResource("AuditLog"), null) to true,
            Triple(AUDITOR, InternalResource("AuditRecord", BOB), null) to true,
            Triple(EDGE_AUDITOR, InternalResource("AuditLog"), "203.0.113.10") to true,
            Triple(EDGE_AUDITOR, InternalResource("AuditLog"), "198.51.100.10") to false,
            Triple(EDGE_AUDITOR, InternalResource("AuditLog"), null) to false,
        )
        for ((input, allow) in cases) {
            val (principal, resource, ip) = input
            val response = client.authorize(InternalAuthorizeRequest(principal, "audit.read", resource, ip))
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(allow, response.body<InternalAuthorizeResult>().allow, "$principal $resource $ip")
        }
    }

    @Test
    fun `the route needs the per-boot token`() = testApplication {
        val client = app()
        val request = InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("AuditLog"))
        assertEquals(HttpStatusCode.NotFound, client.authorize(request, token = null).status)
        assertEquals(HttpStatusCode.NotFound, client.authorize(request, token = "wrong").status)
    }

    @Test
    fun `without a configured token the route does not exist`() {
        for (configured in listOf(null, "")) {
            testApplication {
                val client = app(configured)
                val request = InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("AuditLog"))
                assertEquals(HttpStatusCode.NotFound, client.authorize(request, token = "").status)
                assertEquals(HttpStatusCode.NotFound, client.authorize(request, token = TOKEN).status)
            }
        }
    }

    @Test
    fun `an unknown action or resource is rejected`() = testApplication {
        val client = app()
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.write", InternalResource("AuditLog"))).status)
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("Datasource"))).status)
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("AuditRecord"))).status)
    }

    private fun ApplicationTestBuilder.app(token: String? = TOKEN): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }) }
            routing { internalAuthorizeRoute(token, authz) }
        }
        return createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private suspend fun HttpClient.authorize(request: InternalAuthorizeRequest, token: String? = TOKEN): HttpResponse =
        post("/internal/authorize") {
            token?.let { header(INTERNAL_TOKEN_HEADER, it) }
            contentType(ContentType.Application.Json)
            setBody(request)
        }

    private companion object {
        const val TOKEN = "per-boot-token"
        const val ALICE = "alice"
        const val BOB = "bob"
        const val AUDITOR = "auditor-user"
        const val EDGE_AUDITOR = "edge-auditor"
    }
}
