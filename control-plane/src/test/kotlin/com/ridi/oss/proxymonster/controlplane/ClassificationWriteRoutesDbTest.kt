package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
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

/** Column classification writes over HTTP: status, body, and the rows and audit each write leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClassificationWriteRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack
    private val ids = mutableMapOf<Long, String>()
    private var maskFn = 0L

    private val admin = "cw-admin@example.com"
    private val viewer = "cw-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_classification_writes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(admin, viewer)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        for ((name, engine) in listOf("cw-mysql" to Engine.MYSQL, "cw-pg" to Engine.POSTGRES, "cw-unknown" to Engine.MYSQL, "cw-nodefault" to Engine.POSTGRES, "cw-fresh" to Engine.MYSQL)) {
            core.datasourceStore.register(
                name = name, engine = engine, host = "db", port = 3306, dbName = "appdb", tags = emptyList(),
                advertiseAddr = "", advertiseCertChain = null, advertiseWireTls = false,
            )
            ids[core.datasourceStore.getByName(name)!!.id] = name
        }
        exec("UPDATE datasource SET engine_version = '8.0.36', mysql_lower_case_table_names = 0, default_schemas = '[\"App\"]' WHERE name = 'cw-mysql'")
        exec("UPDATE datasource SET engine_version = '16.4', default_schemas = '[\"pg_catalog\", \"public\"]' WHERE name = 'cw-pg'")
        exec("UPDATE datasource SET engine_version = '8.0.36', default_schemas = '[\"app\"]' WHERE name = 'cw-unknown'")
        exec("UPDATE datasource SET engine_version = '16.4' WHERE name = 'cw-nodefault'")
        maskFn = core.policyStore.createMaskFn(MaskFnInput(name = "cw-redact", kind = "REDACT")).id
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "classification-writes-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private suspend fun ApplicationTestBuilder.client(principal: String?): HttpClient {
        val client = cpGo.client()
        if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return client
    }

    private fun named(text: String) = ids.entries.fold(text.replace(Regex(""""maskFnId":$maskFn\b"""), """"maskFnId":{mask}""")) { acc, (id, name) ->
        acc.replace(Regex("""/api/datasources/$id\b""")) { "/api/datasources/{$name}" }
    }

    @Test
    fun `set and clear`() = testApplication {
        val a = client(admin)
        val v = client(viewer)
        val anon = client(null)
        val my = ids.entries.first { it.value == "cw-mysql" }.key
        val pg = ids.entries.first { it.value == "cw-pg" }.key
        val unknown = ids.entries.first { it.value == "cw-unknown" }.key
        val noDefault = ids.entries.first { it.value == "cw-nodefault" }.key
        val fresh = ids.entries.first { it.value == "cw-fresh" }.key
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()
        val lines = mutableListOf<String>()
        suspend fun send(who: String, c: HttpClient, method: String, id: Any, body: String) {
            val path = "/api/datasources/$id/classification"
            val res = if (method == "PUT") {
                c.put(path) { contentType(ContentType.Application.Json); setBody(body) }
            } else {
                c.delete(path) { contentType(ContentType.Application.Json); setBody(body) }
            }
            lines += "$who $method $path $body -> ${res.status.value} ${res.bodyAsText()}"
        }

        send("admin", a, "PUT", my, """{"schema":"App","table":"Users","column":"SSN","tags":["pii"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"App","table":"Users","column":"SSN","tags":["pii","email"],"maskFnId":$maskFn,"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"table":"orders","column":"card","tags":["pci"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"","table":"orders","column":"total","tags":["money"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"other"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":"a.b","column":"c","tags":["x"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":"t","column":"c","tags":["system:nope"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":" ","column":"c","tags":[],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":"t","column":"c","tags":[]}""")
        send("admin", a, "PUT", my, """not json""")
        send("admin", a, "PUT", pg, """{"table":"accounts","column":"iban","tags":null,"catalog":"appdb"}""")
        send("admin", a, "PUT", pg, """{"table":"accounts","column":"iban","tags":["pci",null],"catalog":"appdb"}""")
        send("admin", a, "PUT", pg, """{"schema":"Public","table":"\"Users\"","column":"Email","tags":["pii"],"catalog":"appdb"}""")
        send("admin", a, "PUT", pg, """{"table":"accounts","column":"iban","tags":["pci"],"catalog":"appdb"}""")
        send("admin", a, "PUT", unknown, """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("admin", a, "PUT", noDefault, """{"table":"t","column":"c","tags":["x"],"catalog":"appdb"}""")
        send("admin", a, "PUT", fresh, """{"table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("admin", a, "PUT", fresh, """{"schema":"","table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("admin", a, "PUT", my, """{"schema":"app","table":" ","column":"c","tags":null,"catalog":"def"}""")
        send("admin", a, "PUT", 999999, """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("admin", a, "PUT", "abc", """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("viewer", v, "PUT", my, """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"}""")
        send("anonymous", anon, "PUT", my, """{"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"}""")

        send("admin", a, "DELETE", my, """{"schema":"App","table":"Users","column":"SSN","catalog":"def"}""")
        send("admin", a, "DELETE", my, """{"schema":"App","table":"Users","column":"SSN","catalog":"def"}""")
        send("admin", a, "DELETE", my, """{"table":"orders","column":"card","catalog":"def"}""")
        send("admin", a, "DELETE", my, """{"schema":"app","table":"t","column":"c","catalog":"other"}""")
        send("admin", a, "DELETE", noDefault, """{"table":"t","column":"c","catalog":"appdb"}""")
        send("admin", a, "DELETE", fresh, """{"table":"t","column":"c","catalog":"def"}""")
        send("admin", a, "DELETE", unknown, """{"schema":"app","table":"t","column":"c","catalog":"def"}""")
        send("admin", a, "DELETE", 999999, """{"schema":"app","table":"t","column":"c","catalog":"def"}""")
        send("admin", a, "DELETE", "abc", """{"schema":"app","table":"t","column":"c","catalog":"def"}""")
        send("viewer", v, "DELETE", pg, """{"table":"accounts","column":"iban","catalog":"appdb"}""")
        send("anonymous", anon, "DELETE", pg, """{"table":"accounts","column":"iban","catalog":"appdb"}""")

        val actual = listOf(
            named(lines.joinToString("\n")),
            "rows:",
            named(rows("SELECT d.name || ' ' || c.catalog_name || '.' || c.schema_name || '.' || c.table_name || '.' || c.column_name || ' ' || c.tags::text || ' ' || coalesce(c.mask_fn_id::text, '-') FROM column_classification c JOIN datasource d ON d.id = c.datasource_id ORDER BY d.name, c.schema_name, c.table_name, c.column_name")),
            "audit:",
            rows("SELECT action || ' ' || resource || ' | ' || statement FROM audit_event WHERE kind = 'admin' AND id > $before ORDER BY id"),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"App","table":"Users","column":"SSN","tags":["pii"],"catalog":"def"} -> 200 {"schema":"App","table":"Users","column":"ssn","tags":["pii"],"catalog":"def"}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"App","table":"Users","column":"SSN","tags":["pii","email"],"maskFnId":{mask},"catalog":"def"} -> 200 {"schema":"App","table":"Users","column":"ssn","tags":["pii","email"],"maskFnId":{mask},"maskFnName":"cw-redact","catalog":"def"}
admin PUT /api/datasources/{cw-mysql}/classification {"table":"orders","column":"card","tags":["pci"],"catalog":"def"} -> 200 {"schema":"App","table":"orders","column":"card","tags":["pci"],"catalog":"def"}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"","table":"orders","column":"total","tags":["money"],"catalog":"def"} -> 200 {"schema":"App","table":"orders","column":"total","tags":["money"],"catalog":"def"}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"other"} -> 400 {"code":"datasource.invalid_catalog","params":{}}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"a.b","column":"c","tags":["x"],"catalog":"def"} -> 400 {"code":"common.invalid_value","params":{"field":"column"}}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","tags":["system:nope"],"catalog":"def"} -> 400 {"code":"datasource.reserved_tag","params":{"tag":"system:nope"}}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":" ","column":"c","tags":[],"catalog":"def"} -> 400 {"code":"common.field_required","params":{"fields":"table"}}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","tags":[]} -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/{cw-mysql}/classification not json -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/{cw-pg}/classification {"table":"accounts","column":"iban","tags":null,"catalog":"appdb"} -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/{cw-pg}/classification {"table":"accounts","column":"iban","tags":["pci",null],"catalog":"appdb"} -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/{cw-pg}/classification {"schema":"Public","table":"\"Users\"","column":"Email","tags":["pii"],"catalog":"appdb"} -> 200 {"schema":"public","table":"Users","column":"email","tags":["pii"],"catalog":"appdb"}
admin PUT /api/datasources/{cw-pg}/classification {"table":"accounts","column":"iban","tags":["pci"],"catalog":"appdb"} -> 200 {"schema":"public","table":"accounts","column":"iban","tags":["pci"],"catalog":"appdb"}
admin PUT /api/datasources/{cw-unknown}/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 400 {"code":"datasource.case_mode_unknown","params":{}}
admin PUT /api/datasources/{cw-nodefault}/classification {"table":"t","column":"c","tags":["x"],"catalog":"appdb"} -> 400 {"code":"datasource.schema_required","params":{}}
admin PUT /api/datasources/{cw-fresh}/classification {"table":"t","column":"c","tags":["x"],"catalog":"def"} -> 400 {"code":"datasource.schema_required","params":{}}
admin PUT /api/datasources/{cw-fresh}/classification {"schema":"","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":" ","column":"c","tags":null,"catalog":"def"} -> 500 {"code":"common.fallback","params":{}}
admin PUT /api/datasources/999999/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
admin PUT /api/datasources/abc/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 400 {"code":"common.bad_id","params":{}}
viewer PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
anonymous PUT /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","tags":["x"],"catalog":"def"} -> 401 {"code":"common.unauthenticated","params":{}}
admin DELETE /api/datasources/{cw-mysql}/classification {"schema":"App","table":"Users","column":"SSN","catalog":"def"} -> 204 
admin DELETE /api/datasources/{cw-mysql}/classification {"schema":"App","table":"Users","column":"SSN","catalog":"def"} -> 204 
admin DELETE /api/datasources/{cw-mysql}/classification {"table":"orders","column":"card","catalog":"def"} -> 204 
admin DELETE /api/datasources/{cw-mysql}/classification {"schema":"app","table":"t","column":"c","catalog":"other"} -> 400 {"code":"datasource.invalid_catalog","params":{}}
admin DELETE /api/datasources/{cw-nodefault}/classification {"table":"t","column":"c","catalog":"appdb"} -> 400 {"code":"datasource.schema_required","params":{}}
admin DELETE /api/datasources/{cw-fresh}/classification {"table":"t","column":"c","catalog":"def"} -> 400 {"code":"datasource.schema_required","params":{}}
admin DELETE /api/datasources/{cw-unknown}/classification {"schema":"app","table":"t","column":"c","catalog":"def"} -> 400 {"code":"datasource.case_mode_unknown","params":{}}
admin DELETE /api/datasources/999999/classification {"schema":"app","table":"t","column":"c","catalog":"def"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
admin DELETE /api/datasources/abc/classification {"schema":"app","table":"t","column":"c","catalog":"def"} -> 400 {"code":"common.bad_id","params":{}}
viewer DELETE /api/datasources/{cw-pg}/classification {"table":"accounts","column":"iban","catalog":"appdb"} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
anonymous DELETE /api/datasources/{cw-pg}/classification {"table":"accounts","column":"iban","catalog":"appdb"} -> 401 {"code":"common.unauthenticated","params":{}}
rows:
cw-mysql def.App.orders.total ["money"] -
cw-pg appdb.public.accounts.iban ["pci"] -
cw-pg appdb.public.Users.email ["pii"] -
audit:
admin.datasources Datasource::"cw-mysql" col App.Users.ssn | tag cw-mysql.App.Users.ssn [pii]
admin.datasources Datasource::"cw-mysql" col App.Users.ssn | tag cw-mysql.App.Users.ssn [pii, email]
admin.datasources Datasource::"cw-mysql" col App.orders.card | tag cw-mysql.App.orders.card [pci]
admin.datasources Datasource::"cw-mysql" col App.orders.total | tag cw-mysql.App.orders.total [money]
admin.datasources Datasource::"cw-pg" col public.Users.email | tag cw-pg.public.Users.email [pii]
admin.datasources Datasource::"cw-pg" col public.accounts.iban | tag cw-pg.public.accounts.iban [pci]
admin.datasources Datasource::"cw-mysql" col App.Users.ssn | clear tags on cw-mysql.App.Users.ssn
admin.datasources Datasource::"cw-mysql" col App.orders.card | clear tags on cw-mysql.App.orders.card
"""
