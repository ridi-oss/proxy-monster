package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.grpc.CpEvent
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.channels.Channel
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** Datasource create, edit and delete over HTTP: status, body, and the rows each write leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceWriteRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val admin = "dw-admin@example.com"
    private val viewer = "dw-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_ds_write_routes")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(admin, viewer)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "ds-write-routes-secret", oidc = null, resultKey = null, scimToken = null,
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

    /** One line per request, `METHOD path -> status body`, so a failure shows every difference at once. */
    private class Transcript(private val client: HttpClient) {
        val lines = mutableListOf<String>()

        suspend fun send(method: String, path: String, body: String? = null): HttpResponse {
            val response = when (method) {
                "POST" -> client.post(path) { if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
                "PUT" -> client.put(path) { if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
                "DELETE" -> client.delete(path)
                else -> error(method)
            }
            val text = response.bodyAsText().replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
            lines += "$method $path -> ${response.status.value} $text"
            return response
        }
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun idOf(name: String): Long = rows("SELECT id FROM datasource WHERE name = '$name' AND deleted_at IS NULL").toLong()

    /** Seeds the in-memory catalog a proxy push leaves for [name], so a delete has something to drop. */
    private suspend fun seedConnectionCatalog(name: String) {
        val ds = core.datasourceStore.getByName(name)!!
        val opened = core.connectionCatalog.open(Binding(name, "dw-principal", "USER", ds.effectiveCatalog, ds.engine), ds.namespaces(listOf("app")))
        core.connectionCatalog.applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId
                datasourceName = name
                catalog = ds.effectiveCatalog
                schema = "app"
                contentHash = ByteString.copyFromUtf8("h1")
                backendGeneration = 1
                columns.add(column { catalog = ds.effectiveCatalog; this.schema = "app"; table = "users"; column = "id"; dataType = "bigint"; ordinal = 1; nullable = false })
            },
            ds,
        )
    }

    private fun connectionCatalogHeld(name: String): Boolean =
        core.connectionCatalog.authoritativeFor(name, namespace(core.datasourceStore.getByName(name)?.effectiveCatalog ?: "def", "app")) != null

    private fun named(text: String, names: Map<Long, String>) = names.entries.fold(text) { acc, (id, name) ->
        acc.replace(Regex("""(/api/datasources/|"id":|Datasource::")$id\b""")) { "${it.groupValues[1]}{$name}" }
    }

    @Test
    fun `create, edit and delete`() = testApplication {
        val t = Transcript(client(admin))
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()
        t.send("POST", "/api/datasources", """{"name":"dw-a","engine":"mysql","host":"db","port":3306,"dbName":"app"}""")
        val a = idOf("dw-a")
        t.send("POST", "/api/datasources", """{"name":"dw-b"}""")
        val b = idOf("dw-b")
        t.send("POST", "/api/datasources", """{"name":"dw-a","engine":"mysql"}""")
        t.send("POST", "/api/datasources", """{"name":" "}""")
        t.send("POST", "/api/datasources", """{"name":"dw-x","engine":"oracle"}""")
        t.send("POST", "/api/datasources", """{"name":"dw-x","engine":"MySQL"}""")
        t.send("POST", "/api/datasources", """{"engine":"mysql"}""")
        t.send("POST", "/api/datasources", """not json""")

        t.send("PUT", "/api/datasources/$a", """{"name":"dw-a2","engine":"mysql","host":"db2","port":3307,"dbName":"app"}""")
        exec("UPDATE datasource SET catalog_synced_at = now(), current_catalog_name = 'def', default_schemas = '[\"app\"]'::jsonb WHERE id = $a")
        val kept = rows("SELECT (catalog_synced_at IS NOT NULL) || ' ' || coalesce(current_catalog_name, '-') || ' ' || default_schemas FROM datasource WHERE id = $a")
        t.send("PUT", "/api/datasources/$a", """{"name":"dw-a2","engine":"mysql","host":"db2","port":3307,"dbName":"other"}""")
        val reset = rows("SELECT (catalog_synced_at IS NOT NULL) || ' ' || coalesce(current_catalog_name, '-') || ' ' || default_schemas FROM datasource WHERE id = $a")
        t.send("PUT", "/api/datasources/$a", """{"name":"dw-a2","engine":"postgres"}""")
        t.send("PUT", "/api/datasources/$a", """{"name":"dw-b","engine":"mysql"}""")
        t.send("PUT", "/api/datasources/$a", """{"name":" ","engine":"mysql"}""")
        t.send("PUT", "/api/datasources/999999", """{"name":"dw-nobody","engine":"mysql"}""")
        t.send("PUT", "/api/datasources/999999", """{"name":"dw-nobody","engine":"oracle"}""")
        t.send("PUT", "/api/datasources/abc", """{"name":"dw-nobody"}""")

        exec("INSERT INTO access_request (principal, kind, datasource_id, status, creator_kind) VALUES ('dw-requester', 'QUERY', $b, 'PENDING', 'WORKFLOW')")
        t.send("DELETE", "/api/datasources/$b")
        val channel = Channel<CpEvent>(capacity = 1)
        core.proxyEventsHub.register("dw-a2", channel)
        t.send("DELETE", "/api/datasources/$a")
        core.proxyEventsHub.deregister("dw-a2", channel)
        seedConnectionCatalog("dw-a2")
        val heldBefore = connectionCatalogHeld("dw-a2")
        t.send("DELETE", "/api/datasources/$a")
        val heldAfter = connectionCatalogHeld("dw-a2")
        t.send("DELETE", "/api/datasources/$a")
        t.send("DELETE", "/api/datasources/999999")
        t.send("DELETE", "/api/datasources/abc")
        t.send("POST", "/api/datasources", """{"name":"dw-a2","engine":"mysql"}""")
        val reused = idOf("dw-a2")

        val viewerT = Transcript(client(viewer))
        val anonT = Transcript(client(null))
        for (x in listOf(viewerT, anonT)) {
            x.send("POST", "/api/datasources", """{"name":"dw-y"}""")
            x.send("PUT", "/api/datasources/$b", """{"name":"dw-y"}""")
            x.send("DELETE", "/api/datasources/$b")
        }

        val names = mapOf(a to "a", b to "b", reused to "reused")
        val actual = listOf(
            named(t.lines.joinToString("\n"), names),
            "catalog after rename: $kept",
            "catalog after db change: $reset",
            "connection catalog before delete: $heldBefore, after: $heldAfter",
            named((viewerT.lines.map { "viewer $it" } + anonT.lines.map { "anonymous $it" }).joinToString("\n"), names),
            "rows:",
            rows("SELECT name || ' ' || engine || ' ' || host || ' ' || port || ' ' || db_name || ' ' || (deleted_at IS NOT NULL) FROM datasource WHERE name LIKE 'dw-%' ORDER BY id"),
            "audit:",
            named(rows("SELECT action || ' ' || resource || ' | ' || statement FROM audit_event WHERE kind = 'admin' AND id > $before ORDER BY id"), names),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
POST /api/datasources -> 201 {"id":{a},"name":"dw-a","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`"}
POST /api/datasources -> 201 {"id":{b},"name":"dw-b","engine":"postgres","host":"","port":0,"dbName":"","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"\""}
POST /api/datasources -> 500 {"code":"common.fallback","params":{}}
POST /api/datasources -> 400 {"code":"common.field_required","params":{"fields":"name"}}
POST /api/datasources -> 400 {"code":"datasource.invalid_engine","params":{"engine":"oracle"}}
POST /api/datasources -> 400 {"code":"datasource.invalid_engine","params":{"engine":"MySQL"}}
POST /api/datasources -> 500 {"code":"common.fallback","params":{}}
POST /api/datasources -> 500 {"code":"common.fallback","params":{}}
PUT /api/datasources/{a} -> 200 {"id":{a},"name":"dw-a2","engine":"mysql","host":"db2","port":3307,"dbName":"app","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`"}
PUT /api/datasources/{a} -> 200 {"id":{a},"name":"dw-a2","engine":"mysql","host":"db2","port":3307,"dbName":"other","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`"}
PUT /api/datasources/{a} -> 409 {"code":"datasource.engine_immutable","params":{}}
PUT /api/datasources/{a} -> 500 {"code":"common.fallback","params":{}}
PUT /api/datasources/{a} -> 400 {"code":"common.field_required","params":{"fields":"name"}}
PUT /api/datasources/999999 -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
PUT /api/datasources/999999 -> 400 {"code":"datasource.invalid_engine","params":{"engine":"oracle"}}
PUT /api/datasources/abc -> 400 {"code":"common.bad_id","params":{}}
DELETE /api/datasources/{b} -> 409 {"code":"datasource.in_use_active_requests","params":{}}
DELETE /api/datasources/{a} -> 409 {"code":"datasource.in_use_proxy_attached","params":{}}
DELETE /api/datasources/{a} -> 204 
DELETE /api/datasources/{a} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
DELETE /api/datasources/999999 -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
DELETE /api/datasources/abc -> 400 {"code":"common.bad_id","params":{}}
POST /api/datasources -> 201 {"id":{reused},"name":"dw-a2","engine":"mysql","host":"","port":0,"dbName":"","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`"}
catalog after rename: true def ["app"]
catalog after db change: false - []
connection catalog before delete: true, after: false
viewer POST /api/datasources -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
viewer PUT /api/datasources/{b} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
viewer DELETE /api/datasources/{b} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
anonymous POST /api/datasources -> 401 {"code":"common.unauthenticated","params":{}}
anonymous PUT /api/datasources/{b} -> 401 {"code":"common.unauthenticated","params":{}}
anonymous DELETE /api/datasources/{b} -> 401 {"code":"common.unauthenticated","params":{}}
rows:
dw-a2 mysql db2 3307 other true
dw-b postgres  0  false
dw-a2 mysql  0  false
audit:
admin.datasources Datasource::"dw-a" | create datasource 'dw-a'
admin.datasources Datasource::"dw-b" | create datasource 'dw-b'
admin.datasources Datasource::"dw-a2" | update datasource 'dw-a' -> 'dw-a2'
admin.datasources Datasource::"dw-a2" | update datasource 'dw-a2'
admin.datasources Datasource::"dw-a2" | delete datasource 'dw-a2'
admin.datasources Datasource::"dw-a2" | create datasource 'dw-a2'
"""
