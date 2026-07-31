package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * OIDC discovery (docs/auth-model.md "resolve endpoints from OIDC discovery instead of hardcoding
 * provider-specific paths") against a REAL local HTTP server: correct field parsing (required +
 * optional), the trailing-slash-tolerant discovery URL, and that the document is fetched once and
 * cached for the lifetime of the [OidcDiscovery] instance.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcDiscoveryTest {
    private var port: Int = 0
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>
    private val requestCount = AtomicInteger(0)

    private val issuer: String get() = "http://127.0.0.1:$port"

    @BeforeAll
    fun setup() {
        port = ServerSocket(0).use { it.localPort }
        server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            routing {
                get("/.well-known/openid-configuration") {
                    requestCount.incrementAndGet()
                    call.respondText(
                        contentType = ContentType.Application.Json,
                        text = """
                            {"issuer":"$issuer","authorization_endpoint":"$issuer/authorize",
                             "token_endpoint":"$issuer/token","userinfo_endpoint":"$issuer/userinfo",
                             "jwks_uri":"$issuer/jwks","device_authorization_endpoint":"$issuer/device/authorize",
                             "code_challenge_methods_supported":["S256"]}
                        """.trimIndent(),
                    )
                }
                get("/minimal/.well-known/openid-configuration") {
                    call.respondText(
                        contentType = ContentType.Application.Json,
                        text = """{"issuer":"$issuer/minimal","authorization_endpoint":"$issuer/authorize",
                                    "token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks"}""",
                    )
                }
            }
        }.start(wait = false)
    }

    @AfterAll
    fun teardown() {
        server.stop(gracePeriodMillis = 0, timeoutMillis = 500)
    }

    @Test
    fun `document parses every field, required and optional`() = runBlocking {
        val discovery = OidcDiscovery(oidcHttpClient(), issuer)
        val doc = discovery.document()
        assertEquals(issuer, doc.issuer)
        assertEquals("$issuer/authorize", doc.authorization_endpoint)
        assertEquals("$issuer/token", doc.token_endpoint)
        assertEquals("$issuer/userinfo", doc.userinfo_endpoint)
        assertEquals("$issuer/jwks", doc.jwks_uri)
        assertEquals("$issuer/device/authorize", doc.device_authorization_endpoint)
        assertEquals(listOf("S256"), doc.code_challenge_methods_supported)
    }

    @Test
    fun `optional fields default to null when the IdP omits them`() = runBlocking {
        val discovery = OidcDiscovery(oidcHttpClient(), "$issuer/minimal")
        val doc = discovery.document()
        assertNull(doc.userinfo_endpoint)
        assertNull(doc.device_authorization_endpoint)
        assertNull(doc.code_challenge_methods_supported)
    }

    @Test
    fun `a trailing slash on the configured issuer is tolerated`() = runBlocking {
        val discovery = OidcDiscovery(oidcHttpClient(), "$issuer/")
        assertEquals(issuer, discovery.document().issuer)
    }

    @Test
    fun `the document is fetched once and cached across repeated calls`() = runBlocking {
        val before = requestCount.get()
        val discovery = OidcDiscovery(oidcHttpClient(), issuer)
        discovery.document()
        discovery.document()
        discovery.document()
        assertEquals(before + 1, requestCount.get(), "repeated document() calls must not re-fetch")
        assertTrue(requestCount.get() > before)
    }
}
