package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
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
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The signal cp-go sends after a policy write, so Kotlin's cached policy set catches up. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InternalPoliciesChangedDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var authz: Authz
    private lateinit var cedarPolicyStore: CedarPolicyStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_internal_policies_changed"))
        cedarPolicyStore = CedarPolicyStore(dataSource)
        authz = Authz(CedarEngine(cedarPolicyStore), cedarPolicyStore, RoleSource { emptySet() })
    }

    private fun mayReadLog() =
        authz.authorize(LATE, AuthzAction.AUDIT_READ, AuthzResource.AuditLog, AuthzContext()) == AuthzDecision.Allow

    @Test
    fun `a policy written behind Kotlin's back applies only after policies-changed`() = testApplication {
        val client = app()
        assertEquals(false, mayReadLog())
        dataSource.connection.use { c ->
            c.createStatement().use {
                it.executeUpdate("""INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('late-grant',
                    'permit(principal == User::"$LATE", action == Action::"audit.read", resource);', true, 'USER')""")
            }
        }
        assertEquals(false, mayReadLog(), "the cached policy set has not moved")
        assertEquals(HttpStatusCode.NoContent, client.signal().status)
        assertEquals(true, mayReadLog())
    }

    @Test
    fun `the route needs the per-boot token`() = testApplication {
        val client = app()
        assertEquals(HttpStatusCode.NotFound, client.signal(token = null).status)
        assertEquals(HttpStatusCode.NotFound, client.signal(token = "wrong").status)
    }

    @Test
    fun `without a configured token the route does not exist`() {
        for (configured in listOf(null, "")) {
            testApplication {
                val client = app(configured)
                assertEquals(HttpStatusCode.NotFound, client.signal(token = "").status)
                assertEquals(HttpStatusCode.NotFound, client.signal(token = TOKEN).status)
            }
        }
    }

    @Test
    fun `request-notified hands over the event and the CC it names`() = testApplication {
        val seen = mutableListOf<String>()
        application {
            install(ContentNegotiation) { json() }
            routing {
                internalSignalRoutes(TOKEN, {}, { id, event, principal -> seen += "$id:$event:$principal"; event != "bogus" })
            }
        }
        val client = createClient { expectSuccess = false }
        suspend fun notify(body: String) = client.post("/internal/request-notified") {
            header(INTERNAL_TOKEN_HEADER, TOKEN)
            contentType(ContentType.Application.Json)
            setBody(body)
        }.status
        assertEquals(HttpStatusCode.NoContent, notify("""{"id":7,"event":"cc-added","principal":"cc@example.com"}"""))
        assertEquals(HttpStatusCode.NoContent, notify("""{"id":7,"event":"commented"}"""))
        assertEquals(HttpStatusCode.BadRequest, notify("""{"id":7,"event":"bogus"}"""))
        assertEquals(listOf("7:cc-added:cc@example.com", "7:commented:null", "7:bogus:null"), seen)
    }

    private fun ApplicationTestBuilder.app(token: String? = TOKEN): HttpClient {
        application { routing { internalSignalRoutes(token, cedarPolicyStore::markCommittedMutation) } }
        return createClient { expectSuccess = false }
    }

    private suspend fun HttpClient.signal(token: String? = TOKEN): HttpResponse =
        post("/internal/policies-changed") { token?.let { header(INTERNAL_TOKEN_HEADER, it) } }

    private companion object {
        const val TOKEN = "per-boot-token"
        const val LATE = "late-auditor"
    }
}
