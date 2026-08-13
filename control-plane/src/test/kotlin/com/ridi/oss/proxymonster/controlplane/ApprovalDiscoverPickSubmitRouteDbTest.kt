package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The web-side contract for role discovery (POST /api/approvals/discover-roles) + submit
 * (POST /api/approvals with the picked roleId) has NO web test harness; this is that contract's
 * coverage, driven at the HTTP layer against a real introspected catalog + real Cedar grants
 * ([EnforcementFixture.postgres]).
 *
 * It also carries ROUTE-level teeth for the R-ALONE preview, in the case that actually distinguishes
 * it: the requester here HOLDS an own role (`base-reader`, which runs `select id, ssn from users` with
 * `ssn` masked). Two candidates are seeded so the union and R-alone decisions genuinely diverge:
 *   * `full-reader` unmasks `ssn` ON ITS OWN → offered under both models (the positive round-trip pick);
 *   * `unmask-only` grants unmasked-`ssn` but NO datasource.connect/sql.select, so ALONE it DENYs, while
 *     `{base-reader, unmask-only}` would connect (via base-reader) and unmask `ssn`. A unioned
 *     preview would offer `unmask-only`; under R-alone it must NOT be — this test catches the union
 *     bug, unlike a no-own-roles fixture where `ownRoles + R == {R}` makes the two implementations equal.
 * The pure [RoleDiscoveryTest] covers the union-vs-alone logic directly; this pins the ROUTE wiring
 * (ownRoles resolution + per-candidate decideQuery through real Cedar) to the same behavior end to end.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalDiscoverPickSubmitRouteDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var runExecService: RunExecService
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var config: Config

    private val sql = "select id, ssn from users"
    private val requester = "dev@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        // Never exercised by discover-roles or the proactive-compose POST /api/approvals — both routes
        // stop at decideQuery / accessStore.createQueryRequest, well short of runExecService.
        runExecService = RunExecService(ControlPlaneCore(fx.dataSource))
        sessionStore = PrincipalSessionStore(fx.dataSource, null)

        // A datasource-scoped query-approval policy row (a global NULL-datasource row is already seeded
        // and unique, so this is scoped to fx.datasource — same shape as ApprovalExecuteRouteDbTest.setup
        // and ElevationContextRouteAuthzDbTest.setup): proactive-compose POST /api/approvals requires a
        // resolvable policy to exist (Approvals.kt's "no_policy_configured" gate) before it will create
        // the request; discover-roles itself doesn't consult it, but the end-to-end submit step does.
        seedRolesForUnionVsAloneTeeth()

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "discover-pick-submit-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
    }

    /**
     * Seed the own-role + two candidates whose union and R-alone previews diverge (see the class kdoc).
     * Mirrors [EnforcementFixture.seedPolicy]'s pattern (the `users` Table EUID + connect/select + read
     * grants). [com.ridi.oss.proxymonster.controlplane.authz.CedarEngine] rebuilds its cached PolicySet on
     * the next stateVersion, so grants created here (before the first request) are live for the test.
     */
    private fun seedRolesForUnionVsAloneTeeth() {
        val ds = fx.datasource
        // Postgres EUID shape used by EnforcementFixture.seedPolicy: "<ds>/<catalog>/<schema>/users".
        val usersEuid = "${ds.name}/${ds.dbName}/public/users"

        fun grant(name: String, src: String) =
            fx.cedarPolicyStore.create(CedarPolicyInput(name = name, cedarSrc = src), updatedBy = "discover-pick-submit-test")

        // The requester's OWN role: connects + selects, cleartext except pii, pii (ssn) masked → baseline MASK.
        val baseReader = fx.policyStore.createRole(RoleInput("base-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(requester, baseReader.id))
        grant("base-reader-connect-select", """permit(principal in Role::"base-reader", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${ds.name}");""")
        grant("base-reader-users-unmasked", """permit(principal in Role::"base-reader", action == Action::"result.read.unmasked", resource in Table::"$usersEuid") unless { resource in Tag::"pii" };""")
        grant("base-reader-users-masked-pii", """permit(principal in Role::"base-reader", action == Action::"result.read.masked", resource in Table::"$usersEuid") when { resource in Tag::"pii" };""")

        // Candidate `full-reader`: connects + selects + unmasks EVERY users column (no `unless pii`), so
        // ALONE it clears the query and unmasks ssn → offered regardless of the preview model.
        fx.policyStore.createRole(RoleInput("full-reader"))
        grant("full-reader-connect-select", """permit(principal in Role::"full-reader", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${ds.name}");""")
        grant("full-reader-users-unmasked", """permit(principal in Role::"full-reader", action == Action::"result.read.unmasked", resource in Table::"$usersEuid");""")

        // Candidate `unmask-only`: unmasks ssn but grants NO datasource.connect/sql.select. ALONE it DENYs
        // (can't even connect); only UNIONED with base-reader would it connect and unmask ssn — the trap.
        fx.policyStore.createRole(RoleInput("unmask-only"))
        grant("unmask-only-users-unmasked", """permit(principal in Role::"unmask-only", action == Action::"result.read.unmasked", resource in Table::"$usersEuid");""")
    }

    private suspend fun ApplicationTestBuilder.wire(): HttpClient {
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                testLoginRoute(sessionStore, config)
                approvalRoutes(
                    config, fx.accessStore, fx.auditStore, fx.datasourceStore, fx.policyStore,
                    fx.userGroupStore, null, fx.roleResolver,
                    fx.authz, runExecService,
                )
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$requester").status)
        return client
    }

    @Test
    fun `discover offers full-reader (R-alone) not unmask-only (union trap), pick it, submit carries roleId`() = testApplication {
        val client = wire()

        val discoverResponse = client.post("/api/approvals/discover-roles") {
            contentType(ContentType.Application.Json)
            setBody(DiscoverRolesRequest(datasourceId = fx.datasource.id, sql = sql))
        }
        assertEquals(HttpStatusCode.OK, discoverResponse.status)
        val discovered = discoverResponse.body<DiscoverRolesResponse>()
        assertTrue(
            discovered.baselineAllowed,
            "the requester holds base-reader, which runs the query with ssn masked -> the baseline is a masked ALLOW",
        )

        val offered = discovered.options.map { it.roleName }.toSet()
        // The teeth: `unmask-only` alone can't even connect (DENY), so R-alone must not offer it. A
        // unioned preview of {base-reader, unmask-only} WOULD connect (base-reader) and unmask ssn → offer it.
        assertFalse(
            "unmask-only" in offered,
            "unmask-only DENYs previewed ALONE (no connect/select) and must NOT be offered; the old unioned " +
                "preview would wrongly offer it. Offered: $offered",
        )
        val fullReader = discovered.options.singleOrNull { it.roleName == "full-reader" }
        assertTrue(
            fullReader != null,
            "full-reader unmasks ssn ON ITS OWN, improving on the masked baseline -> it must be offered. Offered: $offered",
        )
        assertEquals(listOf("ssn"), fullReader!!.unmasksColumns, "the offered role must report ssn as newly unmasked over the baseline")

        val submitResponse = client.post("/api/approvals") {
            contentType(ContentType.Application.Json)
            setBody(
                CreateApprovalInput(
                    datasourceId = fx.datasource.id, sql = sql, title = "need ssn",
                    reason = "investigating an incident", roleId = fullReader.roleId,
                ),
            )
        }
        assertEquals(HttpStatusCode.Created, submitResponse.status)
        val created = submitResponse.body<CreateApprovalResponse>()
        assertEquals(fullReader.roleId, created.request.roleId, "the picked roleId must be carried onto the created request")
        assertEquals("full-reader", created.request.roleName)

        val stored = fx.accessStore.getRequest(created.request.id)
        assertTrue(stored != null, "the created request must be readable back from the store")
        assertEquals(fullReader.roleId, stored!!.roleId, "the stored request's roleId must match what was picked/submitted")
    }

    /**
     * Route-level teeth for the proactive-compose validation mapping (Approvals.kt:456-457): a
     * `validateProactiveCompose` non-null field name must surface as `common.field_required{fields:<name>}`
     * — NOT `approval.invalid_mode` or a raw sentence. The pure [ValidateProactiveComposeTest] pins the
     * returned field name; this pins that the route wires that exact name through `call.fieldRequired(it)`.
     *
     * Parameterized over EVERY field reachable at this gate so a hardcoded `call.fieldRequired("title")`
     * regression is caught: `reason` is checked earlier (Approvals.kt:405) and never reaches
     * `validateProactiveCompose`, so the three HTTP-reachable branches are `datasourceId`, `sql`, `title`.
     * Each input clears the reason gate (non-blank reason) and lands in the proactive branch
     * (`datasourceId != null || sql != null`), blanking exactly one field so its name is returned.
     */
    @Test
    fun `a proactive compose missing a required field returns common field_required naming that field`() = testApplication {
        val client = wire()

        val cases = listOf(
            // datasourceId absent (but sql present -> still the proactive branch) -> "datasourceId".
            "datasourceId" to CreateApprovalInput(datasourceId = null, sql = sql, title = "need it", reason = "investigating"),
            // datasourceId present -> proactive branch; sql absent -> "sql".
            "sql" to CreateApprovalInput(datasourceId = fx.datasource.id, sql = null, title = "need it", reason = "investigating"),
            // datasourceId + sql present; title blank -> "title".
            "title" to CreateApprovalInput(datasourceId = fx.datasource.id, sql = sql, title = "  ", reason = "investigating"),
        )

        for ((expectedField, input) in cases) {
            val response = client.post("/api/approvals") {
                contentType(ContentType.Application.Json)
                setBody(input)
            }

            assertEquals(HttpStatusCode.BadRequest, response.status, "blanking $expectedField must be a 400")
            val error = response.body<ApiError>()
            assertEquals("common.field_required", error.code, "blanking $expectedField must map to common.field_required")
            assertEquals(mapOf("fields" to expectedField), error.params, "the response must name the actually-missing field ($expectedField)")
        }
    }

    @Test
    fun `a compose with all fields but no elevation role is rejected role_required (single execute-under-R path)`() = testApplication {
        val client = wire()
        // A complete proactive form clears field validation, then the missing elevation role R is what fails —
        // a query approval must run under R (execute-under-R); there is no requester-run / no-elevation mode.
        val response = client.post("/api/approvals") {
            contentType(ContentType.Application.Json)
            setBody(CreateApprovalInput(datasourceId = fx.datasource.id, sql = sql, title = "need it", reason = "investigating", roleId = null))
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("approval.role_required", response.body<ApiError>().code)
    }
}
