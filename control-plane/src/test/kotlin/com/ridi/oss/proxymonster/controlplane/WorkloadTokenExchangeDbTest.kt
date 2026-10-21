package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_WORKLOAD_EXCHANGE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.PRINCIPAL_UNATTRIBUTED
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzPrincipal
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Serializable
private data class WorkloadTokenExchangeRequest(val token: String)

private const val WORKLOAD_TOKEN_TTL_SECONDS = 15 * 60L

/** CI OIDC exchange through its route, the WORKLOAD gate, and a claim-scoped Cedar `task.request` decision. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WorkloadTokenExchangeDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var policyStore: CedarPolicyStore
    private lateinit var authz: Authz
    private lateinit var issuer: CiOidcTestIssuer
    private lateinit var database: String
    private val stacks = mutableListOf<CpGoStack>()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.migratedDatabase("pm_workload")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        policyStore = CedarPolicyStore(dataSource)
        authz = Authz(CedarEngine(policyStore), policyStore, RoleSource { emptySet() })
        issuer = CiOidcTestIssuer()
    }

    @AfterAll
    fun teardown() {
        stacks.forEach { it.close() }
        if (::issuer.isInitialized) issuer.close()
    }

    private fun testConfig(issuers: List<CiOidcIssuer>) = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
        sessionSecret = "workload-test-secret-at-least-32-bytes", oidc = null, resultKey = null,
        scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        ciOidcIssuers = issuers,
    )

    /** cp-go in front of the Kotlin app, both trusting [config]'s issuers; [decideOn] adds `/test/decide` on that datasource. */
    private fun ApplicationTestBuilder.serve(config: Config, decideOn: String? = null): HttpClient {
        val env = config.ciOidcIssuers.takeIf { it.isNotEmpty() }?.let { issuers ->
            mapOf(
                "PM_CI_OIDC_ISSUERS" to issuers.joinToString(",") { "${it.name}=${it.issuer}" },
                "PM_CI_OIDC_AUDIENCE" to issuers.first().audience,
            )
        }.orEmpty()
        val stack = CpGoStack(config, core, database, extraEnv = env) {
            routing {
                serverGet("/test/workload") {
                    val w = call.requireWorkload(config, core.tokenStore) ?: return@serverGet
                    call.respond(mapOf("name" to w.name, "repository" to (w.claims["repository"] ?: "")))
                }
                if (decideOn != null) {
                    serverGet("/test/decide") {
                        val w = call.requireWorkload(config, core.tokenStore) ?: return@serverGet
                        val allowed = authz.authorizeDatasourceAction(w, AuthzAction.TASK_REQUEST, decideOn) is AuthzDecision.Allow
                        call.respond(mapOf("allowed" to allowed.toString()))
                    }
                }
            }
        }
        stacks += stack
        return stack.client()
    }

    private suspend fun HttpClient.exchange(jwt: String): HttpResponse = post("/api/workload/token") {
        contentType(ContentType.Application.Json)
        setBody(WorkloadTokenExchangeRequest(jwt))
    }

    private suspend fun HttpClient.whoami(token: String?): HttpResponse = get("/test/workload") {
        token?.let { header(HttpHeaders.Authorization, "Bearer $it") }
    }

    @Test
    fun `a verified CI token mints a WORKLOAD bearer that only the workload gate accepts`() = testApplication {
        val client = serve(testConfig(listOf(issuer.config)))
        val successes = "SELECT count(*) FROM audit_event WHERE kind='auth' AND action='$ACTION_WORKLOAD_EXCHANGE' " +
            "AND outcome='SUCCESS' AND principal='workload:github'"
        val before = count(successes)

        val response = client.exchange(issuer.sign())
        assertEquals(HttpStatusCode.OK, response.status)
        val issued: IssuedToken = response.body()
        assertEquals("WORKLOAD", issued.kind)
        assertTrue(issued.token.startsWith("pmw_"))
        assertTrue(Instant.parse(issued.expiresAt) <= Instant.now().plusSeconds(WORKLOAD_TOKEN_TTL_SECONDS + 60))
        assertEquals(before + 1, count(successes))

        val me = client.whoami(issued.token)
        assertEquals(HttpStatusCode.OK, me.status)
        assertEquals(mapOf("name" to "github", "repository" to "acme/shop"), me.body<Map<String, String>>())
        assertEquals(HttpStatusCode.Unauthorized, client.whoami(null).status)
        val session = core.tokenStore.issue(TokenKind.SESSION, "u@example.com", emptyList(), null, 600)
        assertEquals(HttpStatusCode.Unauthorized, client.whoami(session.token).status)

        assertNull(core.tokenStore.resolve(issued.token), "a WORKLOAD token must not resolve as a wire credential")
        assertNull(core.tokenStore.validate(issued.token), "a WORKLOAD token must not pass the wire handshake")
    }

    @Test
    fun `a removed issuer kills its outstanding workload tokens`() = testApplication {
        val issued = core.tokenStore.dataSource.inTx { c -> core.tokenStore.issueWorkload("github", emptyMap(), 600, c) }
        val client = serve(testConfig(listOf(CiOidcIssuer("gitlab", "https://gitlab.example.com", "aud"))))
        assertEquals(HttpStatusCode.Unauthorized, client.whoami(issued.token).status)
    }

    @Test
    fun `rejected CI tokens answer 401 and are audited as unattributed failures`() = testApplication {
        val client = serve(testConfig(listOf(issuer.config)))
        val failures = "SELECT count(*) FROM audit_event WHERE kind='auth' AND action='$ACTION_WORKLOAD_EXCHANGE' " +
            "AND outcome='FAILURE' AND principal='$PRINCIPAL_UNATTRIBUTED'"
        val before = count(failures)

        val forged = client.exchange(issuer.sign(signingKey = issuer.impostorKey()))
        assertEquals(HttpStatusCode.Unauthorized, forged.status)
        assertEquals(ApiError("common.invalid_token", mapOf("kind" to "ci_oidc")), forged.body<ApiError>())

        val untrusted = client.exchange(issuer.sign(issuer.claims(iss = "https://ci.example.com")))
        assertEquals(HttpStatusCode.Unauthorized, untrusted.status)
        assertEquals("workload.issuer_not_trusted", untrusted.body<ApiError>().code)

        assertEquals(before + 2, count(failures))

        val blank = client.exchange("")
        assertEquals(HttpStatusCode.BadRequest, blank.status)
        assertEquals(ApiError("common.field_required", mapOf("fields" to "token")), blank.body<ApiError>())
    }

    @Test
    fun `exchange is 404 when no CI issuer is configured`() = testApplication {
        val client = serve(testConfig(emptyList()))
        val response = client.exchange(issuer.sign())
        assertEquals(HttpStatusCode.NotFound, response.status)
        assertEquals("workload.not_configured", response.body<ApiError>().code)
    }

    @Test
    fun `a Cedar policy scopes task request on the workload's repository claim`() = testApplication {
        val workflowRequestDefault = -16L
        assertNotNull(policyStore.setEnabled(workflowRequestDefault, enabled = false, updatedBy = null))
        policyStore.create(
            CedarPolicyInput(
                "workload-by-repo",
                "permit(principal == Workload::\"github\", action == Action::\"task.request\", resource in Datasource::\"shop-ds\") " +
                    "when { principal has repository && principal.repository == \"acme/shop\" };",
            ),
            updatedBy = null,
        )
        fun decide(claims: Map<String, String>) = authz.authorizeDatasourceAction(
            AuthzPrincipal.Workload("github", issuer.url, claims), AuthzAction.TASK_REQUEST, "shop-ds",
        )
        assertIs<AuthzDecision.Allow>(decide(mapOf("repository" to "acme/shop")))
        assertIs<AuthzDecision.Deny>(decide(mapOf("repository" to "acme/other")))
        assertIs<AuthzDecision.Deny>(decide(emptyMap()))

        val config = testConfig(listOf(issuer.config))
        val client = serve(config, decideOn = "shop-ds")
        val issued: IssuedToken = client.exchange(issuer.sign()).body()
        val decided = client.get("/test/decide") { header(HttpHeaders.Authorization, "Bearer ${issued.token}") }
        assertEquals(mapOf("allowed" to "true"), decided.body<Map<String, String>>())
    }

    @Test
    fun `a Cedar policy scopes task request on the pull request's base_ref`() = testApplication {
        val workflowRequestDefault = -16L
        assertNotNull(policyStore.setEnabled(workflowRequestDefault, enabled = false, updatedBy = null))
        policyStore.create(
            CedarPolicyInput(
                "workload-by-base-ref",
                "permit(principal == Workload::\"github\", action == Action::\"task.request\", resource in Datasource::\"main-ds\") " +
                    "when { principal has repository && principal.repository == \"acme/shop\" && " +
                    "principal has base_ref && principal.base_ref == \"main\" };",
            ),
            updatedBy = null,
        )
        fun decide(claims: Map<String, String>) = authz.authorizeDatasourceAction(
            AuthzPrincipal.Workload("github", issuer.url, claims), AuthzAction.TASK_REQUEST, "main-ds",
        )
        assertIs<AuthzDecision.Allow>(decide(mapOf("repository" to "acme/shop", "base_ref" to "main")))
        assertIs<AuthzDecision.Deny>(decide(mapOf("repository" to "acme/shop", "base_ref" to "release")))
        assertIs<AuthzDecision.Deny>(decide(mapOf("repository" to "acme/shop")))

        val config = testConfig(listOf(issuer.config))
        val client = serve(config, decideOn = "main-ds")
        for ((baseRef, allowed) in listOf("main" to "true", "release" to "false", null to "false")) {
            val issued: IssuedToken = client.exchange(issuer.sign(issuer.claims(baseRef = baseRef))).body()
            val decided = client.get("/test/decide") { header(HttpHeaders.Authorization, "Bearer ${issued.token}") }
            assertEquals(mapOf("allowed" to allowed), decided.body<Map<String, String>>(), "base_ref=$baseRef")
        }
    }

    private fun count(sql: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
    }
}
