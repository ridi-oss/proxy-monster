package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.authz.CedarValidateResult
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

/** The decisions cp-go's routes ask for, run against the shipped policies. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InternalAuthorizeDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var authz: Authz
    private lateinit var cedarPolicyStore: CedarPolicyStore
    private lateinit var core: ControlPlaneCore

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
        cedarPolicyStore = CedarPolicyStore(dataSource)
        cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ip-gated-audit-read",
                cedarSrc = """permit(principal in Role::"ip-auditor", action == Action::"audit.read", resource)
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ctx-tag-rule",
                cedarSrc = """permit(principal, action == Action::"context.tag::ctx-x", resource == Datasource::"ctx-ds");""",
            ),
            updatedBy = null,
        )
        cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ctx-tag-gated-approve",
                cedarSrc = """permit(principal == User::"$CTX_APPROVER", action == Action::"task.approve", resource)
                    when { context has tags && context.tags.contains("ctx-x") };""",
            ),
            updatedBy = null,
        )
        authz = Authz(CedarEngine(cedarPolicyStore), cedarPolicyStore, RoleSource { roleResolver.resolve(it) })
        core = ControlPlaneCore(dataSource)
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
    fun `a policy written behind Kotlin's back applies only after policies-changed`() = testApplication {
        val client = app()
        val ask = InternalAuthorizeRequest(LATE, "audit.read", InternalResource("AuditLog"))
        assertEquals(false, client.authorize(ask).body<InternalAuthorizeResult>().allow)
        dataSource.connection.use { c ->
            c.createStatement().use {
                it.executeUpdate("""INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('late-grant',
                    'permit(principal == User::"$LATE", action == Action::"audit.read", resource);', true, 'USER')""")
            }
        }
        assertEquals(false, client.authorize(ask).body<InternalAuthorizeResult>().allow, "the cached policy set has not moved")
        val signal = client.post("/internal/policies-changed") { header(INTERNAL_TOKEN_HEADER, TOKEN) }
        assertEquals(HttpStatusCode.NoContent, signal.status)
        assertEquals(true, client.authorize(ask).body<InternalAuthorizeResult>().allow)
    }

    @Test
    fun `cedar-validate returns the validator's errors`() = testApplication {
        val client = app()
        suspend fun validate(src: String) = client.post("/internal/cedar-validate") {
            header(INTERNAL_TOKEN_HEADER, TOKEN)
            contentType(ContentType.Application.Json)
            setBody(InternalValidateRequest(src))
        }.body<CedarValidateResult>()
        assertEquals(CedarValidateResult(true, emptyList()), validate("""permit(principal, action == Action::"audit.read", resource);"""))
        val bad = validate("""permit(principal, action == Action::"audit.write", resource);""")
        assertEquals(false, bad.valid)
        assertEquals(CedarSchema.validate("""permit(principal, action == Action::"audit.write", resource);"""), bad.errors)
    }

    @Test
    fun `token decisions follow the shipped self-mint permit`() = testApplication {
        val client = app()
        suspend fun allow(principal: String, owner: String, kind: String?) =
            client.authorize(InternalAuthorizeRequest(principal, "token.mint", InternalResource("Token", owner, kind = kind))).body<InternalAuthorizeResult>().allow
        assertEquals(true, allow(ALICE, ALICE, "SESSION"))
        assertEquals(false, allow(ALICE, BOB, "SESSION"))
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(ALICE, "token.mint", InternalResource("Token", ALICE, kind = "NOPE"))).status)
    }

    @Test
    fun `contextDatasource derives that datasource's context tags`() = testApplication {
        val client = app()
        suspend fun allow(contextDatasource: String?) = client.authorize(
            InternalAuthorizeRequest(
                CTX_APPROVER, "task.approve", InternalResource("ApprovalRequest", ALICE, datasourceName = "ctx-ds"),
                contextDatasource = contextDatasource,
            ),
        ).body<InternalAuthorizeResult>().allow
        assertEquals(false, allow(null), "no datasource, no tag")
        assertEquals(true, allow("ctx-ds"))
        assertEquals(false, allow("other-ds"), "the tag rule is scoped to ctx-ds")
    }

    @Test
    fun `may-request answers task request on a live datasource`() = testApplication {
        val client = app(mayRequest = core::mayRequestById)
        val live = core.datasourceStore.create(DatasourceInput("may-request-live", "postgres"))
        val deleted = core.datasourceStore.create(DatasourceInput("may-request-deleted", "postgres"))
        core.datasourceStore.delete(deleted.id)
        suspend fun ask(datasourceId: Long, token: String? = TOKEN) = client.post("/internal/may-request") {
            token?.let { header(INTERNAL_TOKEN_HEADER, it) }
            contentType(ContentType.Application.Json)
            setBody(InternalMayRequestRequest(ALICE, datasourceId))
        }
        assertEquals(true, ask(live.id).body<InternalAuthorizeResult>().allow, "the shipped task.request permit")
        assertEquals(false, ask(deleted.id).body<InternalAuthorizeResult>().allow)
        assertEquals(false, ask(Long.MAX_VALUE).body<InternalAuthorizeResult>().allow)
        assertEquals(HttpStatusCode.NotFound, ask(live.id, token = null).status)
    }

    @Test
    fun `sessions-ended closes the principal's editor runs`() = testApplication {
        val ended = mutableListOf<String>()
        val client = app(sessionsEnded = { ended += it })
        suspend fun signal(token: String? = TOKEN) = client.post("/internal/sessions-ended") {
            token?.let { header(INTERNAL_TOKEN_HEADER, it) }
            contentType(ContentType.Application.Json)
            setBody(InternalPrincipalRequest(ALICE))
        }
        assertEquals(HttpStatusCode.NotFound, signal(token = null).status)
        assertEquals(emptyList(), ended)
        assertEquals(HttpStatusCode.NoContent, signal().status)
        assertEquals(listOf(ALICE), ended)
    }

    @Test
    fun `proxies-attached and datasource-deleted reach the in-memory state`() = testApplication {
        val deleted = mutableListOf<String>()
        val client = app(proxiesAttached = { setOf("b-ds", "a-ds") }, datasourceDeleted = { deleted += it })
        suspend fun call(path: String, body: Any, token: String? = TOKEN) = client.post(path) {
            token?.let { header(INTERNAL_TOKEN_HEADER, it) }
            contentType(ContentType.Application.Json)
            setBody(body)
        }
        assertEquals(listOf("a-ds", "b-ds"), call("/internal/proxies-attached", emptyMap<String, String>()).body<InternalNamesResult>().names)
        assertEquals(HttpStatusCode.NotFound, call("/internal/proxies-attached", emptyMap<String, String>(), token = null).status)
        assertEquals(HttpStatusCode.NotFound, call("/internal/datasource-deleted", InternalNameRequest("a-ds"), token = null).status)
        assertEquals(emptyList(), deleted)
        assertEquals(HttpStatusCode.NoContent, call("/internal/datasource-deleted", InternalNameRequest("a-ds")).status)
        assertEquals(listOf("a-ds"), deleted)
    }

    @Test
    fun `an unknown action or resource is rejected`() = testApplication {
        val client = app()
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.write", InternalResource("AuditLog"))).status)
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("Datasource"))).status)
        assertEquals(HttpStatusCode.BadRequest, client.authorize(InternalAuthorizeRequest(AUDITOR, "audit.read", InternalResource("AuditRecord"))).status)
    }

    private fun ApplicationTestBuilder.app(
        token: String? = TOKEN,
        mayRequest: (String, String?, Long) -> Boolean = { _, _, _ -> false },
        sessionsEnded: (String) -> Unit = {},
        proxiesAttached: () -> Set<String> = { emptySet() },
        datasourceDeleted: (String) -> Unit = {},
    ): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }) }
            routing {
                internalAuthorizeRoute(
                    token, authz, policiesChanged = cedarPolicyStore::markCommittedMutation, mayRequest = mayRequest,
                    sessionsEnded = sessionsEnded, proxiesAttached = proxiesAttached, datasourceDeleted = datasourceDeleted,
                )
            }
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
        const val LATE = "late-auditor"
        const val CTX_APPROVER = "ctx-approver"
    }
}
