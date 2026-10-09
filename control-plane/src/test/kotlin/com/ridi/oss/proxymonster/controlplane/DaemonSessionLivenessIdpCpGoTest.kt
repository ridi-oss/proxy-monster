package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonLogin
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.Timestamp
import java.time.Instant
import java.util.Date
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The IdP recheck is cp-go's timer sweep alone: `POST /auth/session/renew` never reaches the token endpoint. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DaemonSessionLivenessIdpCpGoTest {
    private lateinit var ds: DataSource
    private lateinit var crypto: ResultCrypto
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var policyStore: PolicyStore
    private lateinit var roleResolver: RoleResolver
    private lateinit var rsaKey: RSAKey
    private lateinit var idp: EmbeddedServer<*, *>
    private lateinit var stack: CpGoStack
    private var idpPort = 0
    private val refreshGrants = ConcurrentLinkedQueue<String>()
    private val sentinels = AtomicInteger()

    private val issuer: String get() = "http://127.0.0.1:$idpPort"
    private val clientId = "test-client"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_session_liveness_idp")
        ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        val resultKey = ByteArray(32) { it.toByte() }
        crypto = ResultCrypto(resultKey)
        sessionStore = PrincipalSessionStore(ds, crypto)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        userGroupStore = UserGroupStore(ds)
        policyStore = PolicyStore(ds)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)
        rsaKey = RSAKeyGenerator(2048).keyID("session-liveness").generate()
        idp = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            routing {
                get("/.well-known/openid-configuration") {
                    call.respondText(
                        """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks"}""",
                        ContentType.Application.Json,
                    )
                }
                get("/jwks") { call.respondText(JWKSet(rsaKey.toPublicJWK()).toString(), ContentType.Application.Json) }
                post("/token") {
                    val refreshToken = call.receiveParameters()["refresh_token"].orEmpty()
                    refreshGrants.add(refreshToken)
                    val response = tokenResponse(refreshToken)
                    call.respondText(response.body, ContentType.Application.Json, response.status)
                }
            }
        }.start(wait = false)
        idpPort = runBlocking { idp.engine.resolvedConnectors().first().port }

        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = resultKey, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 1, devMarker = true,
        )
        stack = CpGoStack(
            config, ControlPlaneCore(ds), database,
            extraEnv = mapOf(
                "PM_OIDC_ISSUER" to issuer,
                "PM_OIDC_CLIENT_ID" to clientId,
                "PM_OIDC_CLIENT_SECRET" to "test-secret",
                "PM_OIDC_REDIRECT_URI" to "http://unused/callback",
                "PM_OIDC_SCOPES" to "openid profile email groups offline_access",
            ),
        )
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
        if (::idp.isInitialized) idp.stop(gracePeriodMillis = 0, timeoutMillis = 500)
    }

    private data class FakeResponse(val status: HttpStatusCode, val body: String)

    // The 1s sweep also refreshes other tests' sessions, so a count must be for one principal.
    private fun refreshGrantsFor(principal: String): Int = refreshGrants.count { it.startsWith("rt-active:$principal:") }

    private fun tokenResponse(refreshToken: String): FakeResponse = when {
        refreshToken == "rt-invalid-grant" -> FakeResponse(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}""")
        refreshToken == "rt-invalid-client" -> FakeResponse(HttpStatusCode.Unauthorized, """{"error":"invalid_client"}""")
        refreshToken == "rt-http-500" -> FakeResponse(HttpStatusCode.InternalServerError, """{"error":"server_error"}""")
        refreshToken.startsWith("rt-no-groups:") ->
            FakeResponse(HttpStatusCode.OK, """{"access_token":"unused","id_token":"${sign(refreshToken.removePrefix("rt-no-groups:"), null)}"}""")
        else -> {
            require(refreshToken.startsWith("rt-active:")) { "unexpected refresh token: $refreshToken" }
            val parts = refreshToken.split(':', limit = 3)
            val groups = parts.getOrElse(2) { "" }.split(',').filter(String::isNotBlank)
            FakeResponse(HttpStatusCode.OK, """{"access_token":"unused","id_token":"${sign(parts[1], groups)}"}""")
        }
    }

    private fun sign(principal: String, groups: List<String>?): String {
        val builder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(principal)
            .audience(clientId)
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .claim("email", principal)
        if (groups != null) builder.claim("groups", groups)
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.keyID).build(), builder.build()).apply { sign(RSASSASigner(rsaKey)) }.serialize()
    }

    private fun activeRefresh(principal: String, groups: List<String> = emptyList()): String =
        "rt-active:$principal:${groups.joinToString(",")}"

    /** Returns once cp-go's timer has finished a whole sweep that began after every row seeded so far. */
    private suspend fun sweep() {
        repeat(2) {
            val sentinel = "sweep-sentinel-${sentinels.incrementAndGet()}@example.com"
            val row = ds.seedDaemonLogin(sentinel, sentinel, crypto.encrypt(activeRefresh(sentinel).toByteArray())).id
            withTimeout(15_000) { while (snapshot(row).lastIdpCheckAt == null) delay(100) }
        }
    }

    private fun daemon(principal: String, handle: String, refreshToken: String?): Long =
        ds.seedDaemonLogin(principal, handle, refreshToken?.let { crypto.encrypt(it.toByteArray()) }).id

    private fun seedGroups(principal: String, groupNames: List<String>) {
        val user = userGroupStore.getUserByPrincipal(principal)
            ?: userGroupStore.createUser(AppUserInput(principal = principal, email = principal), tokenStore, accessStore, sessionStore)
        for (name in groupNames) {
            val group = userGroupStore.getGroupByName(name) ?: userGroupStore.createGroup(AppGroupInput(name = name))
            userGroupStore.addMember(group.id, user.id)
        }
    }

    private fun seedGroupRole(principal: String, groupName: String, roleName: String) {
        seedGroups(principal, listOf(groupName))
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

    private data class SessionSnapshot(
        val kind: String,
        val livenessStatus: String,
        val lastIdpCheckAt: Instant?,
        val endedReason: String?,
        val absoluteExpiresAt: Instant,
    )

    private fun snapshot(id: Long): SessionSnapshot = ds.connection.use { c ->
        c.prepareStatement(
            """SELECT kind, liveness_status, last_idp_check_at, ended_reason, absolute_expires_at
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
                    absoluteExpiresAt = rs.getTimestamp("absolute_expires_at").toInstant(),
                )
            }
        }
    }

    /** The (resource, detail, outcome, channel) of every `auth.session.expire` row for [principal]. */
    private fun expiryEvents(principal: String): List<List<String?>> = ds.connection.use { c ->
        c.prepareStatement(
            """SELECT resource, detail, outcome, channel FROM audit_event
               WHERE kind='auth' AND action='auth.session.expire' AND principal=? ORDER BY id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> buildList { while (rs.next()) add((1..4).map(rs::getString)) } }
        }
    }

    private fun lastIdpCheckAt(id: Long): Instant? = ds.connection.use { c ->
        c.prepareStatement("SELECT last_idp_check_at FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getTimestamp(1)?.toInstant() }
        }
    }

    @Test
    fun `renew route never revalidates and only the timer sweep reaches the token endpoint`() = runBlocking<Unit> {
        val principal = "sole-revalidator@example.com"
        val created = ds.seedDaemonLogin(principal, "sole-revalidator-daemon", crypto.encrypt("rt-active:$principal:".toByteArray()))
        // Freshly checked, so the 1s timer cannot pick the row up between the two counts around renew.
        val checkedAt = Instant.now()
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET last_idp_check_at = ? WHERE id = ?").use { ps ->
                ps.setTimestamp(1, Timestamp.from(checkedAt))
                ps.setLong(2, created.id)
                ps.executeUpdate()
            }
        }
        val beforeRenew = refreshGrantsFor(principal)

        val response = stack.client().post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(beforeRenew, refreshGrantsFor(principal), "renew must not trigger an IdP refresh grant")

        withTimeout(15_000) {
            while (refreshGrantsFor(principal) <= beforeRenew || !assertNotNull(lastIdpCheckAt(created.id)).isAfter(checkedAt)) delay(100)
        }
        assertTrue(refreshGrantsFor(principal) > beforeRenew, "the timer sweep must perform the refresh grant")
        assertTrue(assertNotNull(lastIdpCheckAt(created.id)).isAfter(checkedAt))
    }

    @Test
    fun `fresh fewer groups end only the zero-role web session and preserve inactive liveness`() = runBlocking<Unit> {
        val principal = "web-groups-removed@example.com"
        seedGroupRole(principal, "web-role-group", "web-group-role")
        seedGroups(principal, listOf("web-role-group", "web-unmapped-group"))
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
        assertEquals(
            listOf(listOf("""User::"$principal"""", "group_revoked", "SUCCESS", "session")),
            expiryEvents(principal),
        )
    }

    @Test
    fun `still-grouped and direct-role web users survive with fresh checks`() = runBlocking<Unit> {
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
        seedGroups(directPrincipal, listOf("web-direct-old-group"))
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
    fun `omitted groups claim is authoritative empty and removes old membership`() = runBlocking<Unit> {
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
            listOf(listOf("""User::"$principal"""", "group_revoked", "SUCCESS", "session")),
            expiryEvents(principal),
        )
    }

    @Test
    fun `invalid grant closes only its daemon row while a valid sibling and credentials survive`() = runBlocking<Unit> {
        val principal = "daemon-per-device@example.com"
        val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        seedGrant(principal, "daemon-per-device-grant-role")
        val rejected = daemon(principal, "daemon-rejected", "rt-invalid-grant")
        val valid = daemon(principal, "daemon-valid", activeRefresh(principal))

        sweep()

        val rejectedAfter = snapshot(rejected)
        assertEquals(LIVENESS_INACTIVE, rejectedAfter.livenessStatus)
        assertTrue(rejectedAfter.absoluteExpiresAt.isBefore(Instant.now()))
        val validAfter = snapshot(valid)
        assertEquals(LIVENESS_ACTIVE, validAfter.livenessStatus)
        assertTrue(validAfter.absoluteExpiresAt.isAfter(Instant.now()))
        assertNotNull(validAfter.lastIdpCheckAt)
        assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
        assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
        assertEquals(
            listOf(listOf("""Session::"$rejected"""", "idp_rejected", "SUCCESS", "session")),
            expiryEvents(principal),
        )
    }

    @Test
    fun `all rejected session tokens retire every row in one sweep without principal teardown`() = runBlocking<Unit> {
        val principal = "all-sessions-rejected@example.com"
        val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
        seedGrant(principal, "all-sessions-rejected-grant-role")
        val daemonA = daemon(principal, "all-rejected-a", "rt-invalid-grant")
        val daemonB = daemon(principal, "all-rejected-b", "rt-invalid-grant")
        val webId = sessionStore.mintWeb(principal, "rt-invalid-grant", 3600, 900, "all-rejected-web")

        sweep()

        for (daemon in listOf(daemonA, daemonB)) {
            val after = snapshot(daemon)
            assertEquals(LIVENESS_INACTIVE, after.livenessStatus)
            assertTrue(after.absoluteExpiresAt.isBefore(Instant.now()))
        }
        assertNull(sessionStore.resolveWeb(webId, "all-rejected-web"))
        assertEquals("IDP_REJECTED", sessionStore.webEndedReason(webId))
        assertEquals(LIVENESS_INACTIVE, snapshot(webId).livenessStatus)
        assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
        assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
        assertEquals(
            listOf(daemonA, daemonB, webId).map {
                listOf("""Session::"$it"""", "idp_rejected", "SUCCESS", "session")
            }.toSet(),
            expiryEvents(principal).toSet(),
        )
    }

    @Test
    fun `transient invalid client and server errors preserve both session kinds and credentials`() = runBlocking<Unit> {
        for ((suffix, refreshToken) in listOf(
            "invalid-client" to "rt-invalid-client",
            "http-500" to "rt-http-500",
        )) {
            val principal = "transient-$suffix@example.com"
            val wireToken = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)
            seedGrant(principal, "transient-$suffix-grant-role")
            val daemon = daemon(principal, "transient-$suffix-daemon", refreshToken)
            val webId = sessionStore.mintWeb(principal, refreshToken, 3600, 900, "transient-$suffix-web")

            sweep()

            val daemonAfter = snapshot(daemon)
            assertEquals(LIVENESS_ACTIVE, daemonAfter.livenessStatus)
            assertNull(daemonAfter.lastIdpCheckAt)
            assertTrue(daemonAfter.absoluteExpiresAt.isAfter(Instant.now()))
            assertNotNull(sessionStore.resolveWeb(webId, "transient-$suffix-web"))
            assertEquals(LIVENESS_ACTIVE, snapshot(webId).livenessStatus)
            assertNull(snapshot(webId).lastIdpCheckAt)
            assertNull(snapshot(webId).endedReason)
            assertNull(tokenStore.get(wireToken.id)!!.revokedAt)
            assertEquals(1, accessStore.listGrants(principal, activeOnly = true).size)
            assertEquals(emptyList(), expiryEvents(principal))
        }
    }

    @Test
    fun `sessions without stored refresh tokens remain live and unstamped`() = runBlocking<Unit> {
        val daemonPrincipal = "no-refresh-daemon@example.com"
        val webPrincipal = "no-refresh-web@example.com"
        val daemon = daemon(daemonPrincipal, "no-refresh-daemon", null)
        val webId = sessionStore.mintWeb(webPrincipal, null, 3600, 900, "no-refresh-web")

        sweep()

        val daemonAfter = snapshot(daemon)
        assertEquals(LIVENESS_ACTIVE, daemonAfter.livenessStatus)
        assertNull(daemonAfter.lastIdpCheckAt)
        assertTrue(daemonAfter.absoluteExpiresAt.isAfter(Instant.now()))
        assertNotNull(sessionStore.resolveWeb(webId, "no-refresh-web"))
        assertEquals(LIVENESS_ACTIVE, snapshot(webId).livenessStatus)
        assertNull(snapshot(webId).lastIdpCheckAt)
        assertNull(snapshot(webId).endedReason)
    }
}
