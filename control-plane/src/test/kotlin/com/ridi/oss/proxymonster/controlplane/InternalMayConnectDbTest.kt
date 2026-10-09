package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
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
import kotlin.test.assertEquals

/** cp-go's per-row datasource.connect question, over HTTP: principal, requester IP and row order arrive intact. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InternalMayConnectDbTest {
    private lateinit var core: ControlPlaneCore
    private var datasourceId = 0L

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_internal_may_connect"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        datasourceId = core.datasourceStore.create(DatasourceInput(name = "ip-ds", engine = "mysql", host = "h", port = 3306, dbName = "app")).id
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ip-gated-connect",
                cedarSrc = """permit(principal == User::"$EDGE", action == Action::"datasource.connect", resource == Datasource::"ip-ds")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
    }

    @Test
    fun `the decision follows the requester IP, per datasource in order`() = testApplication {
        val client = app()
        assertEquals(listOf(true, false), client.mayConnect(InternalMayConnectRequest(EDGE, listOf(datasourceId, Long.MAX_VALUE), "203.0.113.9")))
        assertEquals(listOf(false, false), client.mayConnect(InternalMayConnectRequest(EDGE, listOf(datasourceId, Long.MAX_VALUE), "198.51.100.9")))
        assertEquals(listOf(false), client.mayConnect(InternalMayConnectRequest(EDGE, listOf(datasourceId))))
        assertEquals(listOf(false), client.mayConnect(InternalMayConnectRequest("someone-else", listOf(datasourceId), "203.0.113.9")))
    }

    @Test
    fun `the route needs the per-boot token`() = testApplication {
        val response = app().post("/internal/may-connect") {
            header(INTERNAL_TOKEN_HEADER, "wrong")
            contentType(ContentType.Application.Json)
            setBody(InternalMayConnectRequest(EDGE, listOf(datasourceId), "203.0.113.9"))
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    private fun ApplicationTestBuilder.app(): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }) }
            routing { internalAuthorizeRoute(TOKEN, core.authz, core::mayConnectById) }
        }
        return createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private suspend fun HttpClient.mayConnect(request: InternalMayConnectRequest): List<Boolean> =
        post("/internal/may-connect") {
            header(INTERNAL_TOKEN_HEADER, TOKEN)
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body<InternalAuthorizeBatchResult>().allow

    private companion object {
        const val TOKEN = "per-boot-token"
        const val EDGE = "edge-connector"
    }
}
