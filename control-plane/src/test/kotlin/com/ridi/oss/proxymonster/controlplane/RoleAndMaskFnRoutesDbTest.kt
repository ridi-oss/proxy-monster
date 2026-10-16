package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
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
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The role, role-assignment and mask-function write routes over HTTP: status, body and audit row per request. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RoleAndMaskFnRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val admin = "role-admin@example.com"
    private val viewer = "role-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_role_maskfn_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(admin, viewer)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "role-maskfn-routes-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    /** One client per entry, signed in as that principal or anonymous when null. */
    private suspend fun ApplicationTestBuilder.clients(vararg principals: String?): List<HttpClient> =
        principals.map { principal ->
            val client = cpGo.client()
            if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
            client
        }

    /** One line per request, `METHOD path -> status body`, so a failure shows every difference at once. */
    private class Transcript(private val client: HttpClient) {
        val lines = mutableListOf<String>()

        suspend fun send(method: String, path: String, json: String? = null): HttpResponse {
            val response = when (method) {
                "POST" -> client.post(path) { if (json != null) { contentType(ContentType.Application.Json); setBody(json) } }
                "PUT" -> client.put(path) { if (json != null) { contentType(ContentType.Application.Json); setBody(json) } }
                "DELETE" -> client.delete(path)
                else -> error(method)
            }
            lines += "$method $path -> ${response.status.value} ${response.bodyAsText()}"
            return response
        }

        fun text() = lines.joinToString("\n")
    }

    private fun idOf(response: HttpResponse, body: String): Long =
        Regex(""""id":(\d+)""").find(body)?.groupValues?.get(1)?.toLong() ?: error("no id in ${response.status} $body")

    private fun roleId(name: String) = core.policyStore.getRoleByName(name)!!.id

    /** The admin audit rows written after [afterId], as `action resource | statement`. */
    private fun auditSince(afterId: Long): String = dataSource.connection.use { c ->
        c.prepareStatement("SELECT action, resource, statement FROM audit_event WHERE kind='admin' AND id > ? ORDER BY id").use { ps ->
            ps.setLong(1, afterId)
            ps.executeQuery().use { rs -> buildList { while (rs.next()) add("${rs.getString(1)} ${rs.getString(2)} | ${rs.getString(3)}") } }
        }
    }.joinToString("\n")

    private fun lastAuditId(): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery("SELECT coalesce(max(id), 0) FROM audit_event").use { rs -> rs.next(); rs.getLong(1) } }
    }

    @Test
    fun `role writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val before = lastAuditId()
        val created = t.send("POST", "/api/roles", """{"name":"rt-a","description":"first"}""")
        val id = idOf(created, t.lines.last())
        t.send("POST", "/api/roles", """{"name":"rt-a"}""")
        t.send("POST", "/api/roles", """{"name":" "}""")
        t.send("PUT", "/api/roles/$id", """{"name":"rt-b"}""")
        t.send("PUT", "/api/roles/999999", """{"name":"rt-c"}""")
        t.send("PUT", "/api/roles/abc", """{"name":"rt-c"}""")
        t.send("PUT", "/api/roles/${roleId("system:admin")}", """{"name":"system:admin"}""")
        t.send("DELETE", "/api/roles/${roleId("system:admin")}")
        t.send("DELETE", "/api/roles/$id")
        t.send("DELETE", "/api/roles/$id")
        assertEquals(EXPECTED_ROLES.trim().replace("{id}", "$id").replace("{admin}", "${roleId("system:admin")}"), t.text())
        assertEquals(EXPECTED_ROLES_AUDIT.trim().replace("{id}", "$id"), auditSince(before))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `role assignment writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val role = core.policyStore.createRole(RoleInput("ra-role"))
        val before = lastAuditId()
        val created = t.send("POST", "/api/role-assignments", """{"principal":"ra@example.com","roleId":${role.id}}""")
        val id = idOf(created, t.lines.last())
        t.send("POST", "/api/role-assignments", """{"principal":"ra@example.com","roleId":${role.id}}""")
        t.send("POST", "/api/role-assignments", """{"principal":"ra@example.com","roleId":999999}""")
        t.send("POST", "/api/role-assignments", """{"principal":" ","roleId":${role.id}}""")
        t.send("DELETE", "/api/role-assignments/$id")
        t.send("DELETE", "/api/role-assignments/$id")
        t.send("DELETE", "/api/role-assignments/abc")
        assertEquals(EXPECTED_ASSIGNMENTS.trim().replace("{id}", "$id").replace("{role}", "${role.id}"), t.text())
        assertEquals(EXPECTED_ASSIGNMENTS_AUDIT.trim().replace("{id}", "$id").replace("{role}", "${role.id}"), auditSince(before))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `mask function writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val before = lastAuditId()
        val created = t.send("POST", "/api/mask-fns", """{"name":"mf-a","kind":"redact"}""")
        val id = idOf(created, t.lines.last())
        t.send("POST", "/api/mask-fns", """{"name":"mf-a","kind":"redact"}""")
        t.send("POST", "/api/mask-fns", """{"name":"mf-b","kind":" "}""")
        t.send("PUT", "/api/mask-fns/$id", """{"name":"mf-c","kind":"hash"}""")
        t.send("PUT", "/api/mask-fns/999999", """{"name":"mf-d","kind":"hash"}""")
        t.send("PUT", "/api/mask-fns/abc", """{"name":"mf-d","kind":"hash"}""")
        t.send("DELETE", "/api/mask-fns/$id")
        t.send("DELETE", "/api/mask-fns/$id")
        assertEquals(EXPECTED_MASK_FNS.trim().replace("{id}", "$id"), t.text())
        assertEquals(EXPECTED_MASK_FNS_AUDIT.trim().replace("{id}", "$id"), auditSince(before))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `every write needs a session and an admin`() = testApplication {
        val requests = listOf(
            "POST" to "/api/roles", "PUT" to "/api/roles/1", "DELETE" to "/api/roles/1",
            "POST" to "/api/role-assignments", "DELETE" to "/api/role-assignments/1",
            "POST" to "/api/mask-fns", "PUT" to "/api/mask-fns/1", "DELETE" to "/api/mask-fns/1",
        )
        val (anonymousClient, plainClient) = clients(null, viewer)
        val anonymous = Transcript(anonymousClient)
        val plain = Transcript(plainClient)
        val before = lastAuditId()
        for ((method, path) in requests) {
            val body = if (method == "DELETE") null else """{"name":"x","kind":"redact","principal":"x@example.com","roleId":1}"""
            anonymous.send(method, path, body)
            plain.send(method, path, body)
        }
        assertEquals(EXPECTED_GATES_ANONYMOUS.trim(), anonymous.text())
        assertEquals(EXPECTED_GATES_PLAIN.trim(), plain.text())
        assertEquals("", auditSince(before))
    }

    private companion object {
        const val EXPECTED_ROLES = """
POST /api/roles -> 201 {"id":{id},"name":"rt-a","description":"first"}
POST /api/roles -> 400 {"code":"common.already_exists","params":{"resource":"role","name":"rt-a"}}
POST /api/roles -> 400 {"code":"common.field_required","params":{"fields":"name"}}
PUT /api/roles/{id} -> 200 {"id":{id},"name":"rt-b"}
PUT /api/roles/999999 -> 404 {"code":"common.not_found","params":{"resource":"role"}}
PUT /api/roles/abc -> 400 {"code":"common.bad_id","params":{}}
PUT /api/roles/{admin} -> 409 {"code":"role.system_immutable","params":{}}
DELETE /api/roles/{admin} -> 409 {"code":"role.system_immutable","params":{}}
DELETE /api/roles/{id} -> 204 
DELETE /api/roles/{id} -> 404 {"code":"common.not_found","params":{"resource":"role"}}
"""
        const val EXPECTED_ROLES_AUDIT = """
admin.policies Role::"rt-a" | create role 'rt-a'
admin.policies Role::"rt-b" | update role 'rt-a' -> 'rt-b'
admin.policies Role::"rt-b" | delete role 'rt-b'
"""
        const val EXPECTED_ASSIGNMENTS = """
POST /api/role-assignments -> 201 {"id":{id},"principal":"ra@example.com","roleId":{role},"roleName":"ra-role"}
POST /api/role-assignments -> 201 {"id":{id},"principal":"ra@example.com","roleId":{role},"roleName":"ra-role"}
POST /api/role-assignments -> 404 {"code":"common.not_found","params":{"resource":"role"}}
POST /api/role-assignments -> 400 {"code":"common.field_required","params":{"fields":"principal"}}
DELETE /api/role-assignments/{id} -> 204 
DELETE /api/role-assignments/{id} -> 404 {"code":"common.not_found","params":{"resource":"role assignment"}}
DELETE /api/role-assignments/abc -> 400 {"code":"common.bad_id","params":{}}
"""
        const val EXPECTED_ASSIGNMENTS_AUDIT = """
admin.identity Role::"ra-role" | assign role 'ra-role' to 'ra@example.com'
admin.identity Role::"ra-role" | unassign role 'ra-role' from 'ra@example.com'
"""
        const val EXPECTED_MASK_FNS = """
POST /api/mask-fns -> 201 {"id":{id},"name":"mf-a","kind":"redact"}
POST /api/mask-fns -> 400 {"code":"common.already_exists","params":{"resource":"mask function","name":"mf-a"}}
POST /api/mask-fns -> 400 {"code":"common.field_required","params":{"fields":"kind"}}
PUT /api/mask-fns/{id} -> 200 {"id":{id},"name":"mf-c","kind":"hash"}
PUT /api/mask-fns/999999 -> 404 {"code":"common.not_found","params":{"resource":"mask function"}}
PUT /api/mask-fns/abc -> 400 {"code":"common.bad_id","params":{}}
DELETE /api/mask-fns/{id} -> 204 
DELETE /api/mask-fns/{id} -> 404 {"code":"common.not_found","params":{"resource":"mask function"}}
"""
        const val EXPECTED_MASK_FNS_AUDIT = """
admin.policies MaskFn::"mf-a" | create mask function 'mf-a'
admin.policies MaskFn::"mf-c" | update mask function 'mf-a' -> 'mf-c'
admin.policies MaskFn::"mf-c" | delete mask function 'mf-c'
"""
        const val EXPECTED_GATES_ANONYMOUS = """
POST /api/roles -> 401 {"code":"common.unauthenticated","params":{}}
PUT /api/roles/1 -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/roles/1 -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/role-assignments -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/role-assignments/1 -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/mask-fns -> 401 {"code":"common.unauthenticated","params":{}}
PUT /api/mask-fns/1 -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/mask-fns/1 -> 401 {"code":"common.unauthenticated","params":{}}
"""
        const val EXPECTED_GATES_PLAIN = """
POST /api/roles -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
PUT /api/roles/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/roles/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/role-assignments -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/role-assignments/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/mask-fns -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
PUT /api/mask-fns/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/mask-fns/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
"""
    }
}
