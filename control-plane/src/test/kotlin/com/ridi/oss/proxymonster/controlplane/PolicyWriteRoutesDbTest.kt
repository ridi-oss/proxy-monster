package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
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

/** The Cedar policy write routes over HTTP: status, body and audit row per request, and the decisions they change. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicyWriteRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val admin = "policy-admin@example.com"
    private val viewer = "policy-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_policy_write_routes")
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
            sessionSecret = "policy-write-routes-secret", oidc = null, resultKey = null, scimToken = null,
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
                "GET" -> client.get(path)
                else -> error(method)
            }
            val body = response.bodyAsText().replace(Regex(""""updatedAt":"[^"]+""""), """"updatedAt":"{at}"""")
            lines += "$method $path -> ${response.status.value} $body"
            return response
        }

        fun text() = lines.joinToString("\n")
    }

    private fun idOf(response: HttpResponse, body: String): Long =
        Regex(""""id":(\d+)""").find(body)?.groupValues?.get(1)?.toLong() ?: error("no id in ${response.status} $body")

    private fun systemPolicyId(): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery("SELECT min(id) FROM policy WHERE origin = 'SYSTEM' AND deleted_at IS NULL").use { rs -> rs.next(); rs.getLong(1) } }
    }

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

    private fun json(name: String, src: String, enabled: Boolean? = null) =
        """{"name":"$name","cedarSrc":"${src.replace("\"", "\\\"")}"""" + (if (enabled == null) "" else ""","enabled":$enabled""") + "}"

    @Test
    fun `policy writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val sys = systemPolicyId()
        val before = lastAuditId()
        val created = t.send("POST", "/api/policies", json("pw-a", AUDIT_READ))
        val id = idOf(created, t.lines.last())
        t.send("POST", "/api/policies", json("pw-a", AUDIT_READ))
        t.send("POST", "/api/policies", json("pw-b", """permit(principal, action == Action::"no.such.action", resource);"""))
        t.send("POST", "/api/policies", json("pw-c", "not cedar"))
        t.send("POST", "/api/policies", json(" ", AUDIT_READ))
        t.send("POST", "/api/policies", json("pw-d", " "))
        t.send("POST", "/api/policies", json("system:pw", AUDIT_READ))
        val off = idOf(t.send("POST", "/api/policies", json("pw-off", AUDIT_READ, enabled = false)), t.lines.last())
        t.send("PUT", "/api/policies/$id", json("pw-a", AUDIT_READ.replace("resource", "resource ")))
        t.send("PUT", "/api/policies/$id", json("pw-a2", AUDIT_READ))
        t.send("PUT", "/api/policies/$id", json("pw-off", AUDIT_READ))
        t.send("PUT", "/api/policies/$id", json("pw-a3", "not cedar"))
        t.send("PUT", "/api/policies/$sys", json("system:pw", AUDIT_READ))
        t.send("PUT", "/api/policies/999999", json("pw-z", AUDIT_READ))
        t.send("PUT", "/api/policies/abc", json("pw-z", AUDIT_READ))
        t.send("POST", "/api/policies/$off/enable")
        t.send("POST", "/api/policies/$off/disable")
        t.send("POST", "/api/policies/$off/disable")
        t.send("POST", "/api/policies/999999/enable")
        t.send("POST", "/api/policies/abc/disable")
        t.send("DELETE", "/api/policies/$sys")
        t.send("DELETE", "/api/policies/$off")
        t.send("DELETE", "/api/policies/$off")
        t.send("POST", "/api/policies/$off/enable")
        t.send("PUT", "/api/policies/$off", json("pw-off", AUDIT_READ))
        t.send("DELETE", "/api/policies/abc")
        t.send("POST", "/api/policies", json("pw-off", AUDIT_READ))
        assertEquals(EXPECTED_POLICIES.trim().replace("{id}", "$id").replace("{off}", "$off").replace("{sys}", "$sys").replace("{new}", "${off + 1}"), t.text())
        assertEquals(EXPECTED_POLICIES_AUDIT.trim().replace("{id}", "$id").replace("{off}", "$off").replace("{new}", "${off + 1}"), auditSince(before))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `policy validation`() = testApplication {
        val t = Transcript(clients(admin).single())
        t.send("POST", "/api/policies/validate", """{"cedarSrc":"${AUDIT_READ.replace("\"", "\\\"")}"}""")
        t.send("POST", "/api/policies/validate", """{"cedarSrc":"not cedar"}""")
        t.send("POST", "/api/policies/validate", """{"cedarSrc":"permit(principal, action == Action::\"no.such.action\", resource);"}""")
        assertEquals(EXPECTED_VALIDATE.trim(), t.text())
    }

    @Test
    fun `a write changes the next decision`() = testApplication {
        val (adminClient, viewerClient) = clients(admin, viewer)
        val t = Transcript(adminClient)
        val v = Transcript(viewerClient)
        v.send("GET", "/api/me/permissions")
        val id = idOf(t.send("POST", "/api/policies", json("pw-viewer-policies", VIEWER_POLICIES)), t.lines.last())
        v.send("GET", "/api/me/permissions")
        t.send("POST", "/api/policies/$id/disable")
        v.send("GET", "/api/me/permissions")
        t.send("POST", "/api/policies/$id/enable")
        v.send("GET", "/api/me/permissions")
        t.send("DELETE", "/api/policies/$id")
        v.send("GET", "/api/me/permissions")
        assertEquals(EXPECTED_DECISIONS.trim(), v.text())
    }

    @Test
    fun `every write needs a session and an admin`() = testApplication {
        val requests = listOf(
            "POST" to "/api/policies", "PUT" to "/api/policies/1", "DELETE" to "/api/policies/1",
            "POST" to "/api/policies/1/enable", "POST" to "/api/policies/1/disable", "POST" to "/api/policies/validate",
        )
        val (anonymousClient, plainClient) = clients(null, viewer)
        val anonymous = Transcript(anonymousClient)
        val plain = Transcript(plainClient)
        val before = lastAuditId()
        for ((method, path) in requests) {
            val body = if (method == "DELETE" || path.endsWith("able")) null else json("pw-gate", AUDIT_READ)
            anonymous.send(method, path, body)
            plain.send(method, path, body)
        }
        assertEquals(EXPECTED_GATES_ANONYMOUS.trim(), anonymous.text())
        assertEquals(EXPECTED_GATES_PLAIN.trim(), plain.text())
        assertEquals("", auditSince(before))
    }

    companion object {
        const val AUDIT_READ = """permit(principal == User::"nobody@example.com", action == Action::"audit.read", resource);"""
        const val VIEWER_POLICIES = """permit(principal == User::"policy-viewer@example.com", action == Action::"admin.policies", resource);"""
        const val EXPECTED_POLICIES = """
POST /api/policies -> 201 {"id":{id},"origin":"USER","name":"pw-a","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":true,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
POST /api/policies -> 400 {"code":"common.already_exists","params":{"resource":"policy"}}
POST /api/policies -> 400 {"errors":["for policy `candidate`, unrecognized action `Action::\"no.such.action\"`","for policy `candidate`, unable to find an applicable action given the policy scope constraints"]}
POST /api/policies -> 400 {"errors":["failed to parse policy with id `candidate` from string: unexpected token `cedar`"]}
POST /api/policies -> 400 {"code":"common.field_required","params":{"fields":"name"}}
POST /api/policies -> 400 {"code":"common.field_required","params":{"fields":"cedarSrc"}}
POST /api/policies -> 400 {"code":"policy.reserved_name","params":{}}
POST /api/policies -> 201 {"id":{off},"origin":"USER","name":"pw-off","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":false,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
PUT /api/policies/{id} -> 200 {"id":{id},"origin":"USER","name":"pw-a","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource );","enabled":true,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
PUT /api/policies/{id} -> 200 {"id":{id},"origin":"USER","name":"pw-a2","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":true,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
PUT /api/policies/{id} -> 400 {"code":"common.already_exists","params":{"resource":"policy"}}
PUT /api/policies/{id} -> 400 {"errors":["failed to parse policy with id `candidate` from string: unexpected token `cedar`"]}
PUT /api/policies/{sys} -> 409 {"code":"policy.system_immutable","params":{}}
PUT /api/policies/999999 -> 404 {"code":"common.not_found","params":{"resource":"policy"}}
PUT /api/policies/abc -> 400 {"code":"common.bad_id","params":{}}
POST /api/policies/{off}/enable -> 200 {"id":{off},"origin":"USER","name":"pw-off","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":true,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
POST /api/policies/{off}/disable -> 200 {"id":{off},"origin":"USER","name":"pw-off","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":false,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
POST /api/policies/{off}/disable -> 200 {"id":{off},"origin":"USER","name":"pw-off","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":false,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
POST /api/policies/999999/enable -> 404 {"code":"common.not_found","params":{"resource":"policy"}}
POST /api/policies/abc/disable -> 400 {"code":"common.bad_id","params":{}}
DELETE /api/policies/{sys} -> 409 {"code":"policy.system_immutable","params":{}}
DELETE /api/policies/{off} -> 204 
DELETE /api/policies/{off} -> 404 {"code":"common.not_found","params":{"resource":"policy"}}
POST /api/policies/{off}/enable -> 404 {"code":"common.not_found","params":{"resource":"policy"}}
PUT /api/policies/{off} -> 404 {"code":"common.not_found","params":{"resource":"policy"}}
DELETE /api/policies/abc -> 400 {"code":"common.bad_id","params":{}}
POST /api/policies -> 201 {"id":{new},"origin":"USER","name":"pw-off","cedarSrc":"permit(principal == User::\"nobody@example.com\", action == Action::\"audit.read\", resource);","enabled":true,"updatedBy":"policy-admin@example.com","updatedAt":"{at}"}
"""
        const val EXPECTED_POLICIES_AUDIT = """
admin.policies Policy::"{id}" | create policy 'pw-a'
admin.policies Policy::"{off}" | create policy 'pw-off'
admin.policies Policy::"{id}" | update policy 'pw-a'
admin.policies Policy::"{id}" | update policy 'pw-a' -> 'pw-a2'
admin.policies Policy::"{off}" | enable policy 'pw-off'
admin.policies Policy::"{off}" | disable policy 'pw-off'
admin.policies Policy::"{off}" | disable policy 'pw-off'
admin.policies Policy::"{off}" | delete policy 'pw-off'
admin.policies Policy::"{new}" | create policy 'pw-off'
"""
        const val EXPECTED_VALIDATE = """
POST /api/policies/validate -> 200 {"valid":true,"errors":[]}
POST /api/policies/validate -> 200 {"valid":false,"errors":["failed to parse policy with id `candidate` from string: unexpected token `cedar`"]}
POST /api/policies/validate -> 200 {"valid":false,"errors":["for policy `candidate`, unrecognized action `Action::\"no.such.action\"`","for policy `candidate`, unable to find an applicable action given the policy scope constraints"]}
"""
        const val EXPECTED_DECISIONS = """
GET /api/me/permissions -> 200 {"isAdmin":false,"canReadAllAudit":false,"canApprove":false}
GET /api/me/permissions -> 200 {"isAdmin":true,"canReadAllAudit":false,"canApprove":true}
GET /api/me/permissions -> 200 {"isAdmin":false,"canReadAllAudit":false,"canApprove":false}
GET /api/me/permissions -> 200 {"isAdmin":true,"canReadAllAudit":false,"canApprove":true}
GET /api/me/permissions -> 200 {"isAdmin":false,"canReadAllAudit":false,"canApprove":false}
"""
        const val EXPECTED_GATES_ANONYMOUS = """
POST /api/policies -> 401 {"code":"common.unauthenticated","params":{}}
PUT /api/policies/1 -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/policies/1 -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/policies/1/enable -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/policies/1/disable -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/policies/validate -> 401 {"code":"common.unauthenticated","params":{}}
"""
        const val EXPECTED_GATES_PLAIN = """
POST /api/policies -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
PUT /api/policies/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/policies/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/policies/1/enable -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/policies/1/disable -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/policies/validate -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
"""
    }
}
