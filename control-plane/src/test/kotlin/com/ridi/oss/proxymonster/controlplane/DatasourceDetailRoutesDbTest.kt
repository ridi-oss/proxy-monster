package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The datasource row, its wire cert and the live list over HTTP: status, headers and body. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceDetailRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack
    private lateinit var token: String
    private val ids = mutableMapOf<Long, String>()

    private val connector = "dd-connector@example.com"
    private val stranger = "dd-stranger@example.com"
    private val former = "dd-former@example.com"
    private val chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_ds_detail_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        for ((name, cert) in listOf("dd-gated" to chain, "dd-bare" to null, "dd-other" to chain, "dd-gone" to chain)) {
            core.datasourceStore.register(
                name = name, engine = Engine.MYSQL, host = "db", port = 3306, dbName = "app", tags = listOf("team:dd"),
                advertiseAddr = "$name.example.com:6033", advertiseCertChain = cert, advertiseWireTls = true,
                description = "$name description",
            )
            ids[core.datasourceStore.getByName(name)!!.id] = name
        }
        dataSource.connection.use { c -> c.createStatement().use { it.execute("UPDATE datasource SET deleted_at = now() WHERE name = 'dd-gone'") } }
        val sessions = PrincipalSessionStore(dataSource, null)
        val role = core.policyStore.createRole(RoleInput("dd-connector"))
        for ((p, active) in listOf(connector to true, stranger to true, former to false)) {
            core.userGroupStore.createUser(AppUserInput(principal = p, active = active), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(connector, role.id))
        core.policyStore.createAssignment(RoleAssignmentInput(former, role.id))
        for (ds in listOf("dd-gated", "dd-bare", "dd-gone")) {
            core.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "$ds-connect",
                    cedarSrc = """permit(principal in Role::"dd-connector", action == Action::"datasource.connect", resource == Datasource::"$ds");""",
                ),
                updatedBy = null,
            )
        }
        token = core.tokenStore.issue(TokenKind.USER, connector, roles = emptyList(), name = "dd", ttlSeconds = 300).token
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "ds-detail-routes-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private suspend fun ApplicationTestBuilder.client(principal: String?): HttpClient {
        val client = cpGo.client()
        if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return client
    }

    private fun named(text: String) = ids.entries.fold(text) { acc, (id, name) ->
        acc.replace(Regex("""(/api/datasources/|"id":|datasource-)$id\b""")) { "${it.groupValues[1]}{$name}" }
    }

    @Test
    fun `row, wire cert and live`() = testApplication {
        val callers = listOf(
            "anonymous" to client(null),
            "stranger" to client(stranger),
            "former" to client(former),
            "connector" to client(connector),
            "bearer" to client(null),
        )
        val paths = ids.keys.sorted().flatMap { listOf("/api/datasources/$it", "/api/datasources/$it/wire-cert") } +
            listOf("/api/datasources/999999", "/api/datasources/999999/wire-cert", "/api/datasources/x", "/api/datasources/x/wire-cert", "/api/datasources/live")
        val lines = mutableListOf<String>()
        for ((who, client) in callers) {
            for (path in paths) {
                val res = client.get(path) { if (who == "bearer") header(HttpHeaders.Authorization, "Bearer $token") }
                val headers = listOf(HttpHeaders.ContentType, HttpHeaders.ContentDisposition).mapNotNull { h -> res.headers[h]?.let { "$h: $it" } }
                lines += named("$who GET $path -> ${res.status.value} ${headers.joinToString(" | ")} ${res.bodyAsText().replace("\n", "\\n")}")
            }
        }
        assertEquals(EXPECTED.trim(), lines.joinToString("\n").replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}""""))
    }
}

private const val EXPECTED = """
anonymous GET /api/datasources/{dd-gated} -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-gated}/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-bare} -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-bare}/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-other} -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-other}/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-gone} -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/{dd-gone}/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/999999 -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/999999/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/x -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/x/wire-cert -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
anonymous GET /api/datasources/live -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
stranger GET /api/datasources/{dd-gated} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-gated}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-bare} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-bare}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-other} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-other}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
stranger GET /api/datasources/{dd-gone} -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
stranger GET /api/datasources/{dd-gone}/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
stranger GET /api/datasources/999999 -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
stranger GET /api/datasources/999999/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
stranger GET /api/datasources/x -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
stranger GET /api/datasources/x/wire-cert -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
stranger GET /api/datasources/live -> 200 Content-Type: application/json []
former GET /api/datasources/{dd-gated} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-gated}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-bare} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-bare}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-other} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-other}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
former GET /api/datasources/{dd-gone} -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
former GET /api/datasources/{dd-gone}/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
former GET /api/datasources/999999 -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
former GET /api/datasources/999999/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
former GET /api/datasources/x -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
former GET /api/datasources/x/wire-cert -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
former GET /api/datasources/live -> 200 Content-Type: application/json []
connector GET /api/datasources/{dd-gated} -> 200 Content-Type: application/json {"id":{dd-gated},"name":"dd-gated","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":["team:dd"],"defaultSchemas":[],"advertiseAddr":"dd-gated.example.com:6033","advertiseCertChain":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","advertiseWireTls":true,"description":"dd-gated description","defaultSchemaSettable":true}
connector GET /api/datasources/{dd-gated}/wire-cert -> 200 Content-Type: application/x-pem-file | Content-Disposition: attachment; filename="datasource-{dd-gated}-wire-cert.pem" -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n
connector GET /api/datasources/{dd-bare} -> 200 Content-Type: application/json {"id":{dd-bare},"name":"dd-bare","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":["team:dd"],"defaultSchemas":[],"advertiseAddr":"dd-bare.example.com:6033","advertiseWireTls":true,"description":"dd-bare description","defaultSchemaSettable":true}
connector GET /api/datasources/{dd-bare}/wire-cert -> 404 Content-Type: application/json {"code":"datasource.no_wire_cert","params":{}}
connector GET /api/datasources/{dd-other} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
connector GET /api/datasources/{dd-other}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
connector GET /api/datasources/{dd-gone} -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
connector GET /api/datasources/{dd-gone}/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
connector GET /api/datasources/999999 -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
connector GET /api/datasources/999999/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
connector GET /api/datasources/x -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
connector GET /api/datasources/x/wire-cert -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
connector GET /api/datasources/live -> 200 Content-Type: application/json []
bearer GET /api/datasources/{dd-gated} -> 200 Content-Type: application/json {"id":{dd-gated},"name":"dd-gated","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":["team:dd"],"defaultSchemas":[],"advertiseAddr":"dd-gated.example.com:6033","advertiseCertChain":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","advertiseWireTls":true,"description":"dd-gated description","defaultSchemaSettable":true}
bearer GET /api/datasources/{dd-gated}/wire-cert -> 200 Content-Type: application/x-pem-file | Content-Disposition: attachment; filename="datasource-{dd-gated}-wire-cert.pem" -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n
bearer GET /api/datasources/{dd-bare} -> 200 Content-Type: application/json {"id":{dd-bare},"name":"dd-bare","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":["team:dd"],"defaultSchemas":[],"advertiseAddr":"dd-bare.example.com:6033","advertiseWireTls":true,"description":"dd-bare description","defaultSchemaSettable":true}
bearer GET /api/datasources/{dd-bare}/wire-cert -> 404 Content-Type: application/json {"code":"datasource.no_wire_cert","params":{}}
bearer GET /api/datasources/{dd-other} -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
bearer GET /api/datasources/{dd-other}/wire-cert -> 403 Content-Type: application/json {"code":"datasource.not_connectable","params":{}}
bearer GET /api/datasources/{dd-gone} -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
bearer GET /api/datasources/{dd-gone}/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
bearer GET /api/datasources/999999 -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
bearer GET /api/datasources/999999/wire-cert -> 404 Content-Type: application/json {"code":"common.not_found","params":{"resource":"datasource"}}
bearer GET /api/datasources/x -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
bearer GET /api/datasources/x/wire-cert -> 400 Content-Type: application/json {"code":"common.bad_id","params":{}}
bearer GET /api/datasources/live -> 401 Content-Type: application/json {"code":"common.unauthenticated","params":{}}
"""
