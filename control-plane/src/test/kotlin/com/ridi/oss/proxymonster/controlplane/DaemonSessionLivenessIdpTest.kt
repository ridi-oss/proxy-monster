package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post as serverPost
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.net.ServerSocket
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DaemonSessionLivenessIdpTest {
    private lateinit var ds: DataSource
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var policyStore: PolicyStore
    private lateinit var roleResolver: RoleResolver
    private lateinit var rsaKey: RSAKey
    private var idpPort: Int = 0
    private lateinit var idp: io.ktor.server.engine.EmbeddedServer<*, *>
    private val tokenRequests = AtomicInteger()

    private val issuer: String get() = "http://127.0.0.1:$idpPort"
    private val clientId = "test-client"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_session_liveness_idp"))
        Flyway.configure().dataSource(ds).load().migrate()
        sessionStore = PrincipalSessionStore(ds, ResultCrypto(ByteArray(32) { it.toByte() }))
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        userGroupStore = UserGroupStore(ds)
        policyStore = PolicyStore(ds)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)
        rsaKey = RSAKeyGenerator(2048).keyID("session-liveness").generate()

        idpPort = ServerSocket(0).use { it.localPort }
        idp = embeddedServer(Netty, port = idpPort, host = "127.0.0.1") {
            routing {
                get("/.well-known/openid-configuration") {
                    call.respondText(discoveryJson(), ContentType.Application.Json)
                }
                get("/jwks") {
                    call.respondText(JWKSet(rsaKey.toPublicJWK()).toString(), ContentType.Application.Json)
                }
                serverPost("/token") {
                    tokenRequests.incrementAndGet()
                    val refreshToken = call.receiveParameters()["refresh_token"].orEmpty()
                    val response = tokenResponse(refreshToken)
                    call.respondText(response.body, ContentType.Application.Json, response.status)
                }
            }
        }.start(wait = false)
    }

    @AfterAll
    fun teardown() {
        idp.stop(gracePeriodMillis = 0, timeoutMillis = 500)
    }

    private data class FakeResponse(val status: HttpStatusCode, val body: String)

    private fun tokenResponse(refreshToken: String): FakeResponse = when {
        refreshToken == "rt-invalid-grant" ->
            FakeResponse(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}""")
        refreshToken == "rt-invalid-client" ->
            FakeResponse(HttpStatusCode.Unauthorized, """{"error":"invalid_client"}""")
        refreshToken == "rt-http-500" ->
            FakeResponse(HttpStatusCode.InternalServerError, """{"error":"server_error"}""")
        refreshToken.startsWith("rt-no-groups:") -> {
            val principal = refreshToken.removePrefix("rt-no-groups:")
            FakeResponse(
                HttpStatusCode.OK,
                """{"access_token":"unused","id_token":"${sign(principal, null)}"}""",
            )
        }
        else -> {
            require(refreshToken.startsWith("rt-active:")) { "unexpected refresh token: $refreshToken" }
            val parts = refreshToken.split(':', limit = 3)
            val principal = parts[1]
            val groups = parts.getOrElse(2) { "" }.split(',').filter(String::isNotBlank)
            FakeResponse(
                HttpStatusCode.OK,
                """{"access_token":"unused","id_token":"${sign(principal, groups)}"}""",
            )
        }
    }

    private fun sign(principal: String, groups: List<String>?): String {
        val builder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(principal)
            .audience(clientId)
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .claim("email", principal)
        if (groups != null) builder.claim("groups", groups)
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.keyID).build(), builder.build())
        jwt.sign(RSASSASigner(rsaKey))
        return jwt.serialize()
    }

    private fun discoveryJson(): String =
        """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks","device_authorization_endpoint":"$issuer/device/authorize"}"""

    private fun testConfig() = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "test-secret",
        oidc = OidcConfig(
            issuer = issuer,
            clientId = clientId,
            clientSecret = "test-secret",
            redirectUri = "http://unused/callback",
            scopes = "openid profile email groups offline_access",
            groupMapping = OidcGroupMapping(emptyMap(), null),
        ),
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 300,
        devMarker = true,
    )

    private fun sweep() = runBlocking {
        val config = testConfig()
        val http = oidcHttpClient()
        try {
            val discovery = OidcDiscovery(http, config.oidc!!.issuer)
            val validator = IdTokenValidator(discovery, config.oidc!!.issuer, config.oidc!!.clientId)
            sweepSessionLiveness(
                config,
                discovery,
                validator,
                http,
                sessionStore,
                userGroupStore,
                roleResolver,
                AuthAuditRecorder(AuditStore(ds)),
                LoggerFactory.getLogger("DaemonSessionLivenessIdpTest"),
            )
        } finally {
            http.close()
        }
    }

    private fun activeRefresh(principal: String, groups: List<String> = emptyList()): String =
        "rt-active:$principal:${groups.joinToString(",")}"

    private fun seedGroupRole(principal: String, groupName: String, roleName: String) {
        userGroupStore.provisionFromOidc(principal, principal, listOf(groupName))
        val group = userGroupStore.listGroups().first { it.name == groupName }
        val role = policyStore.createRole(RoleInput(roleName))
        userGroupStore.addGroupRole(group.id, role.id)
        assertEquals(setOf(roleName), roleResolver.resolve(principal))
    }

    private fun seedGrant(principal: String, roleName: String) {
        val role = policyStore.createRole(RoleInput(roleName))
        val request = accessStore.createRequest(principal, AccessRequestInput(roleId = role.id))
        accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com")
    }

    private fun groups(principal: String): Set<String> =
        userGroupStore.listUsers().first { it.principal == principal }.groups.map { it.name }.toSet()

    private fun snapshot(id: Long): SessionSnapshot = ds.connection.use { c ->
        c.prepareStatement(
            """SELECT kind, liveness_status, last_idp_check_at, ended_reason
               FROM principal_session WHERE id = ?""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                assertTrue(rs.next())
                SessionSnapshot(
                    kind = rs.getString("kind"),
                    livenessStatus = rs.getString("liveness_status"),
                    lastIdpCheckAt = rs.getTimestamp("last_idp_check_at")?.toInstant(),
                    endedReason = rs.getString("ended_reason"),
                )
            }
        }
    }

    private data class SessionSnapshot(
        val kind: String,
        val livenessStatus: String,
        val lastIdpCheckAt: Instant?,
        val endedReason: String?,
    )

    /** The (resource, detail, outcome, channel) of every `auth.session.expire` row for [principal]. */
    private fun expiryEvents(principal: String): List<List<String?>> = ds.connection.use { c ->
        c.prepareStatement(
            """SELECT resource, detail, outcome, channel FROM audit_event
               WHERE kind='auth' AND action=? AND principal=? ORDER BY id""",
        ).use { ps ->
            ps.setString(1, AuthAuditRecorder.ACTION_SESSION_EXPIRE)
            ps.setString(2, principal)
            ps.executeQuery().use { rs -> buildList { while (rs.next()) add((1..4).map(rs::getString)) } }
        }
    }

    @Test
    fun `fresh fewer groups end only the zero-role web session and preserve inactive liveness`() {
        val principal = "web-groups-removed@example.com"
        seedGroupRole(principal, "web-role-group", "web-group-role")
        userGroupStore.provisionFromOidc(principal, principal, listOf("web-role-group", "web-unmapped-group"))
        val webId = sessionStore.mintWeb(
            principal,
            activeRefresh(principal, listOf("web-unmapped-group")),
            3600,
            900,
            "web-groups-removed-device",
        )

        sweep()

        assertEquals(setOf("web-unmapped-group"), groups(principal))
        assertEquals(emptySet(), roleResolver.resolve(principal))
        assertNull(sessionStore.resolveWeb(webId, "web-groups-removed-device"))
        assertEquals(ENDED_GROUP_REVOKED, sessionStore.webEndedReason(webId))
        val after = snapshot(webId)
        assertEquals("WEB", after.kind)
        assertEquals(LIVENESS_INACTIVE, after.livenessStatus)
        assertNotNull(after.lastIdpCheckAt)
        // Group revocation is principal-global, so the event names the principal, not one session row.
        assertEquals(
            listOf(listOf("""User::"$principal"""", "group_revoked", "SUCCESS", AuthAuditRecorder.CHANNEL_SESSION)),
            expiryEvents(principal),
        )
    }

    @Test
    fun `still-grouped and direct-role web users survive with fresh checks`() {
        val groupedPrincipal = "web-group-kept@example.com"
        seedGroupRole(groupedPrincipal, "web-kept-group", "web-kept-role")
        val groupedWeb = sessionStore.mintWeb(
            groupedPrincipal,
            activeRefresh(groupedPrincipal, listOf("web-kept-group")),
            3600,
            900,
            "web-group-kept-device",
        )

        val directPrincipal = "web-direct-kept@example.com"
        userGroupStore.provisionFromOidc(directPrincipal, directPrincipal, listOf("web-direct-old-group"))
        val directRole = policyStore.createRole(RoleInput("web-direct-role"))
        policyStore.createAssignment(RoleAssignmentInput(directPrincipal, directRole.id))
        val directWeb = sessionStore.mintWeb(
            directPrincipal,
            activeRefresh(directPrincipal),
            3600,
            900,
            "web-direct-kept-device",
        )

        sweep()

        assertEquals(setOf("web-kept-role"), roleResolver.resolve(groupedPrincipal))
        assertNotNull(sessionStore.resolveWeb(groupedWeb, "web-group-kept-device"))
        assertNotNull(snapshot(groupedWeb).lastIdpCheckAt)
        assertEquals(emptySet(), groups(directPrincipal))
        assertEquals(setOf("web-direct-role"), roleResolver.resolve(directPrincipal))
        assertNotNull(sessionStore.resolveWeb(directWeb, "web-direct-kept-device"))
        assertNotNull(snapshot(directWeb).lastIdpCheckAt)
    }

    @Test
    fun `omitted groups claim is authoritative empty and removes old membership`() {
        val principal = "web-groups-omitted@example.com"
        seedGroupRole(principal, "web-omitted-old-group", "web-omitted-role")
        val webId = sessionStore.mintWeb(
            principal,
            "rt-no-groups:$principal",
            3600,
            900,
            "web-groups-omitted-device",
        )

        sweep()

        assertEquals(emptySet(), groups(principal))
        assertEquals(emptySet(), roleResolver.resolve(principal))
        assertNull(sessionStore.resolveWeb(webId, "web-groups-omitted-device"))
        assertEquals(ENDED_GROUP_REVOKED, sessionStore.webEndedReason(webId))
        assertNotNull(snapshot(webId).lastIdpCheckAt)
        assertEquals(
            listOf(listOf("""User::"$principal"""", "group_revoked", "SUCCESS", AuthAuditRecorder.CHANNEL_SESSION)),
            expiryEvents(principal),
        )
    }

    @Test
    fun `invalid grant closes only its daemon row while a valid sibling and credentials survive`() {
        val principal = "daemon-per-device@example.com"
        val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        seedGrant(principal, "daemon-per-device-grant-role")
        val rejected = sessionStore.create(principal, "daemon-rejected", "rt-invalid-grant", 3600, 900).row
        val valid = sessionStore.create(principal, "daemon-valid", activeRefresh(principal), 3600, 900).row

        sweep()

        val rejectedAfter = assertNotNull(sessionStore.getById(rejected.id))
        assertEquals(LIVENESS_INACTIVE, rejectedAfter.livenessStatus)
        assertTrue(rejectedAfter.sessionExpiresAt.isBefore(Instant.now()))
        val validAfter = assertNotNull(sessionStore.getById(valid.id))
        assertEquals(LIVENESS_ACTIVE, validAfter.livenessStatus)
        assertTrue(validAfter.sessionExpiresAt.isAfter(Instant.now()))
        assertNotNull(validAfter.lastIdpCheckAt)
        assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
        assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
        // Only the row the IdP rejected is recorded — the sibling it left open must not appear.
        assertEquals(
            listOf(listOf("""Session::"${rejected.id}"""", "idp_rejected", "SUCCESS", AuthAuditRecorder.CHANNEL_SESSION)),
            expiryEvents(principal),
        )
    }

    @Test
    fun `all rejected session tokens retire every row in one sweep without principal teardown`() {
        val principal = "all-sessions-rejected@example.com"
        val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        seedGrant(principal, "all-sessions-rejected-grant-role")
        val daemonA = sessionStore.create(principal, "all-rejected-a", "rt-invalid-grant", 3600, 900).row
        val daemonB = sessionStore.create(principal, "all-rejected-b", "rt-invalid-grant", 3600, 900).row
        val webId = sessionStore.mintWeb(principal, "rt-invalid-grant", 3600, 900, "all-rejected-web")

        sweep()

        for (daemon in listOf(daemonA, daemonB)) {
            val after = assertNotNull(sessionStore.getById(daemon.id))
            assertEquals(LIVENESS_INACTIVE, after.livenessStatus)
            assertTrue(after.sessionExpiresAt.isBefore(Instant.now()))
        }
        assertNull(sessionStore.resolveWeb(webId, "all-rejected-web"))
        assertEquals(ENDED_IDP_REJECTED, sessionStore.webEndedReason(webId))
        assertEquals(LIVENESS_INACTIVE, snapshot(webId).livenessStatus)
        assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
        assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
        // One row per session actually closed — both daemon rows and the web row, none doubled.
        assertEquals(
            listOf(daemonA.id, daemonB.id, webId).map {
                listOf("""Session::"$it"""", "idp_rejected", "SUCCESS", AuthAuditRecorder.CHANNEL_SESSION)
            }.toSet(),
            expiryEvents(principal).toSet(),
        )
    }

    @Test
    fun `transient invalid client and server errors preserve both session kinds and credentials`() {
        for ((suffix, refreshToken) in listOf(
            "invalid-client" to "rt-invalid-client",
            "http-500" to "rt-http-500",
        )) {
            val principal = "transient-$suffix@example.com"
            val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
            seedGrant(principal, "transient-$suffix-grant-role")
            val daemon = sessionStore.create(principal, "transient-$suffix-daemon", refreshToken, 3600, 900).row
            val webId = sessionStore.mintWeb(principal, refreshToken, 3600, 900, "transient-$suffix-web")

            sweep()

            val daemonAfter = assertNotNull(sessionStore.getById(daemon.id))
            assertEquals(LIVENESS_ACTIVE, daemonAfter.livenessStatus)
            assertNull(daemonAfter.lastIdpCheckAt)
            assertTrue(daemonAfter.sessionExpiresAt.isAfter(Instant.now()))
            assertNotNull(sessionStore.resolveWeb(webId, "transient-$suffix-web"))
            assertEquals(LIVENESS_ACTIVE, snapshot(webId).livenessStatus)
            assertNull(snapshot(webId).lastIdpCheckAt)
            assertNull(snapshot(webId).endedReason)
            assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
            assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
            // A transient IdP error revokes nothing, so it must not be recorded as an expiry.
            assertEquals(emptyList(), expiryEvents(principal))
        }
    }

    @Test
    fun `sessions without stored refresh tokens remain live and unstamped`() {
        val daemonPrincipal = "no-refresh-daemon@example.com"
        val webPrincipal = "no-refresh-web@example.com"
        val daemon = sessionStore.create(daemonPrincipal, "no-refresh-daemon", null, 3600, 900).row
        val webId = sessionStore.mintWeb(webPrincipal, null, 3600, 900, "no-refresh-web")

        sweep()

        val daemonAfter = assertNotNull(sessionStore.getById(daemon.id))
        assertEquals(LIVENESS_ACTIVE, daemonAfter.livenessStatus)
        assertNull(daemonAfter.lastIdpCheckAt)
        assertTrue(daemonAfter.sessionExpiresAt.isAfter(Instant.now()))
        assertNotNull(sessionStore.resolveWeb(webId, "no-refresh-web"))
        assertEquals(LIVENESS_ACTIVE, snapshot(webId).livenessStatus)
        assertNull(snapshot(webId).lastIdpCheckAt)
        assertNull(snapshot(webId).endedReason)
    }

    @Test
    fun `renew route never revalidates and only the timer sweep reaches the token endpoint`() = testApplication {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            routing {
                sessionRenewRoutes(testConfig(), sessionStore, tokenStore, userGroupStore, AuthAuditRecorder(AuditStore(ds)))
            }
        }
        val principal = "sole-revalidator@example.com"
        val created = sessionStore.create(
            principal,
            "sole-revalidator-daemon",
            activeRefresh(principal),
            windowSeconds = 3600,
            ttlSeconds = 900,
        )
        val beforeRenew = tokenRequests.get()

        val response = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(beforeRenew, tokenRequests.get(), "renew must not trigger an IdP refresh grant")

        sweep()

        assertTrue(tokenRequests.get() > beforeRenew, "the explicit timer sweep must perform the refresh grant")
        assertNotNull(sessionStore.getById(created.row.id)!!.lastIdpCheckAt)
    }
}
