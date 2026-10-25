package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** GET /api/policies/schema over HTTP: the schema text with a declaration per stored context tag. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicySchemaRouteHttpDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var cpGo: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_policy_schema_route_http")
        dataSource = SharedPostgres.hikari(database)
        val core = ControlPlaneCore(dataSource)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "policy-schema-route-http-secret-32", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        val sessions = PrincipalSessionStore(dataSource, null)
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private suspend fun client(principal: String?): HttpClient = cpGo.client().also { client ->
        if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
    }

    @Test
    fun `policy schema route`() = runBlocking<Unit> {
        // {schema} and {decl} stand for exact text, so each line still compares the whole body.
        val schema = Json.encodeToString(String.serializer(), resource("/authz/schema.cedarschema")).removeSurrounding("\"")
        val lines = mutableListOf<String>()
        suspend fun get(who: String, client: HttpClient) {
            val response = client.get("/api/policies/schema")
            lines += "$who GET /api/policies/schema -> ${response.status.value} " +
                response.bodyAsText().replace(schema, "{schema}").replace(DECL, "{decl}")
        }
        exec("INSERT INTO principal_role (principal, role_id) SELECT 'admin@example.com', id FROM app_role WHERE name = 'system:admin'")
        val anon = client(null)
        val plain = client("plain@example.com")
        val admin = client("admin@example.com")

        get("anon", anon)
        get("plain", plain)
        get("admin", admin)
        exec(
            """INSERT INTO policy (name, cedar_src, enabled) VALUES
               ('zz-alias', 'permit (principal, action == Action::"context.tag::\u{61}lpha", resource);', false),
               ('zz-two', 'permit (principal, action in [Action::"context.tag::pii", Action::"context.tag::alpha"], resource);', false)""",
        )
        exec(
            """INSERT INTO policy (name, cedar_src, enabled, deleted_at) VALUES
               ('zz-gone', 'permit (principal, action == Action::"context.tag::zeta", resource);', false, now())""",
        )
        get("admin", admin)
        exec("""INSERT INTO policy (name, cedar_src, enabled) VALUES ('zz-bad', 'permit (principal, action == Action::"context.tag::bad\", resource);', false)""")
        get("admin", admin)
        exec("UPDATE policy SET deleted_at = now() WHERE name = 'zz-bad'")
        get("admin", admin)

        assertEquals(EXPECTED.trimIndent(), lines.joinToString("\n"))
    }

    private fun resource(path: String): String =
        PolicySchemaRouteHttpDbTest::class.java.getResourceAsStream(path)!!.bufferedReader().use { it.readText() }

    private companion object {
        const val DECL = """appliesTo { principal: [User, Role], resource: [Datasource], context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String>, native_operation?: String } };"""

        const val EXPECTED = """
            anon GET /api/policies/schema -> 401 {"code":"common.unauthenticated","params":{}}
            plain GET /api/policies/schema -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
            admin GET /api/policies/schema -> 200 {"schema":"{schema}\naction \"context.tag::trusted-network\" {decl}"}
            admin GET /api/policies/schema -> 200 {"schema":"{schema}\naction \"context.tag::\\u{61}lpha\" {decl}\naction \"context.tag::pii\" {decl}\naction \"context.tag::trusted-network\" {decl}"}
            admin GET /api/policies/schema -> 200 {"schema":"{schema}"}
            admin GET /api/policies/schema -> 200 {"schema":"{schema}\naction \"context.tag::\\u{61}lpha\" {decl}\naction \"context.tag::pii\" {decl}\naction \"context.tag::trusted-network\" {decl}"}
        """
    }
}
