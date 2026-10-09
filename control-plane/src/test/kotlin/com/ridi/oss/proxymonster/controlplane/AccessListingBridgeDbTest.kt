package com.ridi.oss.proxymonster.controlplane

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

/**
 * cp-go's access listings keep only the rows the batch bridge allows `task.read` on. The shipped seeds
 * decide it: `workflow.self-request` permits a request whose requester is the caller, `workflow.self-grant`
 * a grant it owns, so a stranger is denied both.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AccessListingBridgeDbTest {
    private lateinit var core: ControlPlaneCore
    private val owner = "owner@example.com"
    private val stranger = "stranger@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_access_listing_bridge"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val roleId = core.policyStore.createRole(RoleInput("listing-role")).id
        val request = core.accessStore.createRequest(owner, AccessRequestInput(roleId = roleId, requestedDurationSec = 3600))
        core.accessStore.approve(request.id, 3600, owner)
    }

    @Test
    fun `requests are readable by their requester only`() = testApplication {
        val client = app()
        val resources = core.accessStore.listRequests(null).map {
            InternalResource("ApprovalRequest", it.principal, approver = it.decidedBy, executedBy = it.executedBy, datasourceName = it.datasourceName, roleName = it.roleName)
        }
        assertEquals(1, resources.size)
        assertEquals(listOf(true), client.batch(owner, resources))
        assertEquals(listOf(false), client.batch(stranger, resources))
    }

    @Test
    fun `grants are readable by their owner only`() = testApplication {
        val client = app()
        val resources = core.accessStore.listGrants(null, false).map { InternalResource("AccessGrant", it.principal, id = it.id, roleName = it.roleName) }
        assertEquals(1, resources.size)
        assertEquals(listOf(true), client.batch(owner, resources))
        assertEquals(listOf(false), client.batch(stranger, resources))
    }

    @Test
    fun `decisions come back in resource order`() = testApplication {
        val own = core.accessStore.listGrants(owner, false).single()
        val resources = listOf(
            InternalResource("AccessGrant", stranger, id = 9_999, roleName = own.roleName),
            InternalResource("AccessGrant", owner, id = own.id, roleName = own.roleName),
            InternalResource("AccessGrant", stranger, id = 9_998, roleName = own.roleName),
        )
        assertEquals(listOf(false, true, false), app().batch(owner, resources))
    }

    @Test
    fun `the batch route needs the per-boot token`() = testApplication {
        val client = app()
        for (token in listOf(null, "wrong")) {
            val response = client.post("/internal/authorize-batch") {
                token?.let { header(INTERNAL_TOKEN_HEADER, it) }
                contentType(ContentType.Application.Json)
                setBody(InternalAuthorizeBatchRequest(owner, "task.read", listOf(InternalResource("AccessGrant", owner, id = 1))))
            }
            assertEquals(HttpStatusCode.NotFound, response.status)
        }
    }

    @Test
    fun `one unknown resource rejects the batch`() = testApplication {
        val response = app().post("/internal/authorize-batch") {
            header(INTERNAL_TOKEN_HEADER, TOKEN)
            contentType(ContentType.Application.Json)
            setBody(InternalAuthorizeBatchRequest(owner, "task.read", listOf(InternalResource("AccessGrant", owner, id = 1), InternalResource("AccessGrant", owner))))
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    private fun ApplicationTestBuilder.app(): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }) }
            routing { internalAuthorizeRoute(TOKEN, core.authz) }
        }
        return createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private suspend fun HttpClient.batch(principal: String, resources: List<InternalResource>): List<Boolean> =
        post("/internal/authorize-batch") {
            header(INTERNAL_TOKEN_HEADER, TOKEN)
            contentType(ContentType.Application.Json)
            setBody(InternalAuthorizeBatchRequest(principal, "task.read", resources))
        }.body<InternalAuthorizeBatchResult>().allow

    private companion object {
        const val TOKEN = "per-boot-token"
    }
}
