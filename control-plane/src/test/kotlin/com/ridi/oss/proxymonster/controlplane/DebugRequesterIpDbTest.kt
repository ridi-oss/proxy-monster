package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The development-only simulated source address chosen at debug login (Auth.kt `DebugLogin.requesterIp`).
 *
 * Every request on a development box arrives from loopback, so a Cedar tag rule keyed on a CIDR can never
 * fire and the behavior it gates cannot be reached at all. The login may therefore name an address the
 * session's decisions authorize under. That is only sound because it rides on a bypass that already lets
 * anyone log in as any principal with any roles — so the load-bearing property, and what this test exists
 * to pin, is that it is INERT the moment that bypass is off. A stored value surviving from an earlier
 * development run must never weaken a real deployment.
 *
 * The assertions read the ONE resolver every HTTP-path decision goes through
 * ([ApplicationCall.httpRequesterIp]) via a probe route, rather than an inner helper — the substitution is
 * only worth anything if it reaches that resolver, and a helper-level test would stay green if the wiring
 * into it were deleted.
 */
class DebugRequesterIpDbTest {
    private val principal = "dev@example.com"

    /** Written as an escape so the source file itself stays free of a literal NUL byte. */
    private val NUL = "\u0000"

    /** The datasource the tag rules below are evaluated against (pass 1 is datasource-scoped). */
    private val TAG_DS = "tagged-ds"

    /** Pass 1: the shipped producer's shape — an in-range requester_ip earns "trusted-network". */
    private val trustedNetworkRule = """permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };"""

    /** Pass 2: the consuming grant — fires only on the derived tag, never on the raw address. */
    private val tagGatedPermit = """permit(
        principal, action == Action::"task.approve", resource
    ) when { context has tags && context.tags.contains("trusted-network") };"""

    /**
     * Echoes what the decision path would see as this request's requester IP ("-" when absent), plus a
     * route that runs a REAL Cedar decision through the two-pass tag derivation — the difference between
     * "the resolver returns the address" and "the address actually changes an authorization outcome".
     */
    private fun ApplicationTestBuilder.probe(config: Config, core: ControlPlaneCore): HttpClient {
        application {
            module(config, core)
            routing {
                serverGet("/test/requester-ip") { call.respond(call.httpRequesterIp(config) ?: "-") }
                serverGet("/test/tag-gated") {
                                val decision = core.authz.authorizeWithContext(
                        call.parameters["principal"] ?: principal,
                        AuthzAction.TASK_APPROVE,
                        AuthzResource.ApprovalRequest(requester = "someone-else", datasourceName = TAG_DS),
                        call.httpAuthzContext(config),
                        TAG_DS,
                    )
                    call.respond(if (decision is AuthzDecision.Deny) "DENY" else "ALLOW")
                }
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private suspend fun HttpClient.debugLogin(ip: String?) = post("/auth/debug") {
        headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        setBody(DebugLogin(principal, emptyList(), ip))
    }

    private suspend fun HttpClient.observedIp(): String = get("/test/requester-ip").body()

    /** WEB session rows in the store — lets a test assert that a refused login minted nothing. */
    private fun webSessionCount(dataSource: DataSource): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM principal_session WHERE kind = 'WEB'").use { ps ->
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun storedIp(dataSource: DataSource): String? = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT debug_requester_ip FROM principal_session WHERE kind = 'WEB' ORDER BY id DESC LIMIT 1",
        ).use { ps ->
            ps.executeQuery().use { rs -> assertTrue(rs.next(), "no web session row was minted"); rs.getString(1) }
        }
    }

    @Test
    fun `a debug login's simulated address replaces the observed peer on the decision path`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_debug_requester_ip"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val client = probe(config, ControlPlaneCore(dataSource))

        // Baseline: with no simulated address the observed loopback peer is what a decision sees. Without
        // this the substitution assertion below would also pass an implementation that returns the constant.
        assertEquals(HttpStatusCode.OK, client.debugLogin(null).status)
        val realPeer = client.observedIp()
        assertTrue(realPeer != "100.100.1.10", "the socket peer must not already be the simulated address")
        assertNull(storedIp(dataSource), "an ordinary login stores no simulated address")

        assertEquals(HttpStatusCode.OK, client.debugLogin("100.100.1.10").status)
        assertEquals("100.100.1.10", storedIp(dataSource))
        assertEquals("100.100.1.10", client.observedIp(), "the decision path must see the simulated address")

        // The console shows which network its decisions are made from, so a reload must keep reporting it —
        // reading it back off the session row, not from a login response the reload never sees.
        assertEquals(
            UserSession(principal, emptyList(), "100.100.1.10"),
            client.get("/auth/me").body<UserSession>(),
        )

        // A later login without one CLEARS it rather than inheriting the previous session's: an address the
        // operator did not ask for is exactly the silently-wrong network this feature exists to make visible.
        assertEquals(HttpStatusCode.OK, client.debugLogin(null).status)
        assertNull(storedIp(dataSource))
        assertEquals(realPeer, client.observedIp())
    }

    @Test
    fun `a malformed address is refused rather than silently ignored`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_debug_requester_ip_bad"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val client = probe(config, ControlPlaneCore(dataSource))

        // Dropping it to null would present as "the tag rule does not work", sending the reader after a
        // policy bug that isn't there. The login fails, naming the input as the problem.
        val bad = listOf(
            "not-an-ip", "999.1.1.1", "100.100.1.10:5432", "100.100.1.0/24",
            // Both pass cedar-java's parse (its validator trims control characters) but are unstorable.
            // Surrounding whitespace is deliberately absent: trim() removes it, leaving a valid address.
            "100.100.1.10" + NUL, "100.100.1.10" + NUL + "12",
            "100.100.1.10\u200b",
            "fe80::1%lo0", "[::1]",
            // Accepted by cedar-java's regex, refused by the engine — which denies the whole request.
            "100.100.001.010", "010.1.1.1",
        )
        for (value in bad) {
            val response = client.debugLogin(value)
            assertEquals(HttpStatusCode.BadRequest, response.status, "'${value.escaped()}' must be refused")
            assertEquals(ApiError("auth.invalid_requester_ip"), response.body<ApiError>())
        }

        // Rejection must leave NOTHING behind. Every assertion above would also hold for a handler that
        // minted the session, rewrote the principal's roles, and only then returned 400 — leaving the
        // caller logged in under a request the server said it refused.
        assertEquals(0, webSessionCount(dataSource), "a refused login must mint no session")

        // The positive controls: the loop above must be rejecting these specific values rather than
        // rejecting everything. IPv6 and surrounding whitespace are here because they are exactly what a
        // too-eager tightening would break — an IPv4-only allowlist, or dropping the server-side trim,
        // would sail past every rejection assertion above.
        for (good in listOf("100.100.1.10", "  100.100.1.10  ", "::1", "2001:db8::1", "fe80::1")) {
            assertEquals(HttpStatusCode.OK, client.debugLogin(good).status, "'$good' must be accepted")
            assertEquals(good.trim(), storedIp(dataSource), "'$good' must be stored as typed, trimmed")
        }
    }

    /** Renders control characters visibly, so a failure message names the input instead of printing it raw. */
    private fun String.escaped(): String = map { c ->
        if (c.isLetterOrDigit() || c in ".:%[]/-") c.toString() else "\\u%04x".format(c.code)
    }.joinToString("")

    /**
     * The point of the whole feature: a simulated address must change a REAL authorization outcome, through
     * the two-pass tag derivation the shipped production preset uses.
     *
     * Everything else here asserts the resolver returns the address. That is necessary and not sufficient —
     * an implementation that resolves it correctly but never threads it into the decision context would keep
     * every other test green while the feature does nothing. This pins the property the feature exists for:
     * same principal, same action, same resource, and the ONLY difference is the address the session claims.
     */
    @Test
    fun `a simulated address changes a real Cedar decision through the derived tag`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_debug_requester_ip_cedar"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val core = ControlPlaneCore(dataSource)
        core.datasourceStore.create(
            DatasourceInput(name = TAG_DS, engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        core.cedarPolicyStore.create(CedarPolicyInput(name = "t-net-producer", cedarSrc = trustedNetworkRule), updatedBy = null)
        core.cedarPolicyStore.create(CedarPolicyInput(name = "t-net-consumer", cedarSrc = tagGatedPermit), updatedBy = null)

        // authDebug must stay ON — it is what honors the simulated address — but requireAuthz's own debug
        // short-circuit never runs here, because this route calls authorizeWithContext directly. So the
        // Cedar decision below is real.
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val client = probe(config, core)

        assertEquals(HttpStatusCode.OK, client.debugLogin("100.100.1.10").status)
        assertEquals("ALLOW", client.get("/test/tag-gated").body<String>(), "in-range address must earn the tag")

        // The negative control. Same principal, same policies, same resource — only the claimed address
        // differs, so an ALLOW here would mean the decision never saw the address at all.
        assertEquals(HttpStatusCode.OK, client.debugLogin("203.0.113.5").status)
        assertEquals("DENY", client.get("/test/tag-gated").body<String>(), "out-of-range address must not")

        // And with no simulated address the loopback peer is out of range too — so the ALLOW above came
        // from the simulation rather than from the test host happening to sit in the range.
        assertEquals(HttpStatusCode.OK, client.debugLogin(null).status)
        assertEquals("DENY", client.get("/test/tag-gated").body<String>(), "the observed peer is not in range")
    }

    /**
     * The risk this feature carries: a development session row keeps its simulated address, and something
     * later turns the bypass off — an operator flipping `PM_AUTH_DEBUG`, or a database promoted out of
     * development. The session is still live and its cookie still valid, so the row's address must simply
     * stop being consulted.
     *
     * Both halves therefore run against ONE database with ONE session secret, and the SAME cookie minted
     * under the bypass is replayed against a control plane running without it — the shape the risk actually
     * takes. Building a cookie by hand cannot substitute: the cookie carries an opaque session key that only
     * a real mint registers, so a forged one resolves to no session at all and the assertion passes for the
     * wrong reason, no matter what the resolver does.
     */
    @Test
    fun `the stored address is inert once the debug bypass is off`() = runBlocking {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_debug_requester_ip_off"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val secret = "debug-requester-ip-test-secret-0123456789"

        fun config(authDebug: Boolean) = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = authDebug, secretToken = null,
            sessionSecret = secret, oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            // testApplication has no real socket, so its peer resolves to absent. Trusting it as an edge
            // lets the bypass-off half assert a REAL resolved address (from XFF) rather than only "not the
            // simulated one" — see the assertion below for why that distinction has teeth.
            trustedProxies = setOf("localhost"),
        )

        // With the bypass ON: log in with a simulated address and keep the cookies a browser would hold.
        var cookies = ""
        testApplication {
            val client = probe(config(authDebug = true), ControlPlaneCore(dataSource))
            val login = client.debugLogin("100.100.1.10")
            assertEquals(HttpStatusCode.OK, login.status)
            assertEquals("100.100.1.10", storedIp(dataSource))
            assertEquals("100.100.1.10", client.observedIp(), "the bypass-on control is this test's premise")
            cookies = login.headers.getAll(HttpHeaders.SetCookie).orEmpty()
                .joinToString("; ") { it.substringBefore(';') }
        }

        // The SAME live session, replayed against a control plane running without the bypass.
        testApplication {
            val client = probe(config(authDebug = false), ControlPlaneCore(dataSource))
            // It must still AUTHENTICATE — otherwise the address goes absent because nothing resolved, not
            // because the resolver refused to honor it, and the assertion below would prove nothing.
            val me = client.get("/auth/me") { header(HttpHeaders.Cookie, cookies) }
            assertEquals(HttpStatusCode.OK, me.status, "the session must still be live with the bypass off")
            assertEquals(principal, me.body<UserSession>().principal)
            assertNull(
                me.body<UserSession>().requesterIp,
                "the console must not display a simulated address the decision path is ignoring",
            )
            // Asserted as EQUALITY to the observed peer, not merely "not the simulated address". A
            // resolver that returned null for every request — dropping requester_ip, and with it every
            // network-derived tag, across the whole deployment — would satisfy an inequality while being
            // catastrophically broken. The baseline peer comes from a cookie-less request to the same
            // probe, so it is measured rather than assumed.
            // The stored address must not reach the decision path. Asserted against a trusted-edge XFF
            // rather than the socket peer, because testApplication has no real socket and its peer resolves
            // to absent — so a plain "not the simulated address" would also hold for a resolver that
            // returned null for EVERY production request, dropping requester_ip and every network-derived
            // tag deployment-wide. Pinning an address production resolution must still produce closes that.
            val forwarded = client.get("/test/requester-ip") {
                header(HttpHeaders.Cookie, cookies)
                header("X-Forwarded-For", "198.51.100.7")
            }.body<String>()
            assertEquals(
                "198.51.100.7", forwarded,
                "with the bypass off the request's own attested address stands, not the session's stored one",
            )
            // And the route that writes one is gone entirely, so no new session can acquire one.
            assertEquals(HttpStatusCode.NotFound, client.debugLogin("100.100.1.10").status)
        }
    }
}
