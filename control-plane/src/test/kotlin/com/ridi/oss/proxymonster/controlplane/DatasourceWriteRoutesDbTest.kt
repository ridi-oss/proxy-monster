package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
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
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
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

/** Datasource delete over HTTP: status, body, and the rows each delete leaves. */
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

    /** One line per request, `DELETE path -> status body`, so a failure shows every difference at once. */
    private class Transcript(private val client: HttpClient) {
        val lines = mutableListOf<String>()

        suspend fun delete(path: String): HttpResponse {
            val response = client.delete(path)
            val text = response.bodyAsText().replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
            lines += "DELETE $path -> ${response.status.value} $text"
            return response
        }
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    /** Seeds the catalogs a proxy's pushes leave for [name], so a delete has something to drop. */
    private suspend fun seedConnectionCatalog(name: String) {
        val id = core.datasourceStore.getByName(name)!!.id
        core.datasourceStore.storePushedCatalog(id, listOf("app"), 0, "", CatalogSnapshot.getDefaultInstance(), currentCatalog = "def")
        val ds = core.datasourceStore.get(id)!!
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
        acc.replace(Regex("""(?m)(^|/api/datasources/|"id":|Datasource::")$id\b""")) { "${it.groupValues[1]}{$name}" }
    }

    @Test
    fun delete() = testApplication {
        val t = Transcript(client(admin))
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()
        val a = core.datasourceStore.seed("dw-a", "mysql").id
        val b = core.datasourceStore.seed("dw-b", "postgres").id

        exec("INSERT INTO access_request (principal, kind, datasource_id, status, creator_kind) VALUES ('dw-requester', 'QUERY', $b, 'PENDING', 'WORKFLOW')")
        t.delete("/api/datasources/$b")
        val channel = Channel<CpEvent>(capacity = 1)
        core.proxyEventsHub.register("dw-a", channel)
        t.delete("/api/datasources/$a")
        core.proxyEventsHub.deregister("dw-a", channel)
        seedConnectionCatalog("dw-a")
        val heldBefore = connectionCatalogHeld("dw-a")
        t.delete("/api/datasources/$a")
        val heldAfter = connectionCatalogHeld("dw-a")
        t.delete("/api/datasources/$a")
        t.delete("/api/datasources/999999")
        t.delete("/api/datasources/abc")
        val reused = core.datasourceStore.seed("dw-a", "mysql").id

        val viewerT = Transcript(client(viewer))
        val anonT = Transcript(client(null))
        for (x in listOf(viewerT, anonT)) x.delete("/api/datasources/$b")

        val names = mapOf(a to "a", b to "b", reused to "reused")
        val actual = listOf(
            named(t.lines.joinToString("\n"), names),
            "connection catalog before delete: $heldBefore, after: $heldAfter",
            named((viewerT.lines.map { "viewer $it" } + anonT.lines.map { "anonymous $it" }).joinToString("\n"), names),
            "rows:",
            named(rows("SELECT id || ' ' || name || ' ' || engine || ' ' || (deleted_at IS NOT NULL) FROM datasource WHERE name LIKE 'dw-%' ORDER BY id"), names),
            "audit:",
            named(rows("SELECT action || ' ' || resource || ' | ' || statement FROM audit_event WHERE kind = 'admin' AND id > $before ORDER BY id"), names),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
DELETE /api/datasources/{b} -> 409 {"code":"datasource.in_use_active_requests","params":{}}
DELETE /api/datasources/{a} -> 409 {"code":"datasource.in_use_proxy_attached","params":{}}
DELETE /api/datasources/{a} -> 204 
DELETE /api/datasources/{a} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
DELETE /api/datasources/999999 -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
DELETE /api/datasources/abc -> 400 {"code":"common.bad_id","params":{}}
connection catalog before delete: true, after: false
viewer DELETE /api/datasources/{b} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
anonymous DELETE /api/datasources/{b} -> 401 {"code":"common.unauthenticated","params":{}}
rows:
{a} dw-a mysql true
{b} dw-b postgres false
{reused} dw-a mysql false
audit:
admin.datasources Datasource::"dw-a" | delete datasource 'dw-a'
"""
