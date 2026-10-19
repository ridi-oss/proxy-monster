package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
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
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The access-request and grant write routes over HTTP: status, body, and the rows each write leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AccessWriteRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val admin = "access-admin@example.com"
    private val alice = "access-alice@example.com"
    private val viewer = "access-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_access_write_routes")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(admin, alice, viewer)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "access-write-routes-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        seed()
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
                "GET" -> client.get(path)
                "POST" -> client.post(path) { if (json != null) { contentType(ContentType.Application.Json); setBody(json) } }
                "PUT" -> client.put(path) { if (json != null) { contentType(ContentType.Application.Json); setBody(json) } }
                "DELETE" -> client.delete(path)
                else -> error(method)
            }
            val body = response.bodyAsText().replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
            lines += "$method $path -> ${response.status.value} $body"
            return response
        }

        fun text() = lines.joinToString("\n")
    }

    private fun idOf(response: HttpResponse, body: String): Long =
        Regex(""""id":(\d+)""").find(body)?.groupValues?.get(1)?.toLong() ?: error("no id in ${response.status} $body")

    /** The admin audit rows written after [afterId], as `action resource | statement`. */
    private fun auditSince(afterId: Long): String = rows(
        "SELECT action || ' ' || resource || ' | ' || statement FROM audit_event WHERE kind='admin' AND id > $afterId ORDER BY id",
    )

    private fun lastAuditId(): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery("SELECT coalesce(max(id), 0) FROM audit_event").use { rs -> rs.next(); rs.getLong(1) } }
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    /** A request's timeline, as `kind actor origin revision body`. */
    private fun events(requestId: Long): String = rows(
        "SELECT kind || ' ' || coalesce(actor, '-') || ' ' || origin || ' ' || coalesce(revision::text, '-') || ' ' || coalesce(body, '-') FROM request_event WHERE request_id = $requestId ORDER BY id",
    )

    /** A request's grants, as `principal role granted_by revoked expires_in_seconds`. */
    private fun grants(requestId: Long): String = rows(
        """SELECT g.principal || ' ' || r.name || ' ' || g.granted_by || ' ' || (g.revoked_at IS NOT NULL) || ' ' ||
                  round(extract(epoch FROM g.expires_at - g.granted_at)) FROM access_grant g JOIN app_role r ON r.id = g.role_id
           WHERE g.request_id = $requestId ORDER BY g.id""",
    )

    /** A request's participants, as `kind principal`. */
    private fun participants(requestId: Long): String =
        rows("SELECT kind || ' ' || principal FROM request_participant WHERE request_id = $requestId ORDER BY kind, principal")

    private fun request(json: String) = """{"roleId":${core.policyStore.getRoleByName(ROLE)!!.id}$json}"""

    @Test
    fun `access request writes`() = testApplication {
        val (adminClient, aliceClient, viewerClient) = clients(admin, alice, viewer)
        val a = Transcript(aliceClient)
        val ad = Transcript(adminClient)
        val v = Transcript(viewerClient)
        val before = lastAuditId()
        val created = a.send("POST", "/api/access-requests", request(""","reason":"need it","requestedDurationSec":600"""))
        val id = idOf(created, a.lines.last())
        val withDs = idOf(a.send("POST", "/api/access-requests", request(""","datasourceId":$openDs""")), a.lines.last())
        a.send("POST", "/api/access-requests", request(""","datasourceId":$closedDs"""))
        a.send("POST", "/api/access-requests", request(""","datasourceId":999999"""))
        a.send("POST", "/api/access-requests", """{"roleId":999999}""")
        a.send("POST", "/api/access-requests/$id/approve")
        ad.send("POST", "/api/access-requests/999999/approve")
        ad.send("POST", "/api/access-requests/abc/approve")
        ad.send("POST", "/api/access-requests/$queryRequest/approve")
        ad.send("POST", "/api/access-requests/$id/approve", """{"durationSec":120}""")
        ad.send("POST", "/api/access-requests/$id/approve")
        val second = idOf(a.send("POST", "/api/access-requests", request(""","reason":"again"""")), a.lines.last())
        a.send("POST", "/api/access-requests/$second/reject", """{"reason":"self"}""")
        ad.send("POST", "/api/access-requests/999999/reject", """{"reason":"x"}""")
        ad.send("POST", "/api/access-requests/$second/reject", """{"reason":"not now"}""")
        ad.send("POST", "/api/access-requests/$second/reject", """{"reason":"twice"}""")
        ad.send("POST", "/api/access-requests/$second/approve")
        val grant = rows("SELECT id FROM access_grant WHERE request_id = $id").toLong()
        v.send("POST", "/api/access-grants/$grant/revoke")
        a.send("POST", "/api/access-grants/$grant/revoke")
        ad.send("POST", "/api/access-grants/999999/revoke")
        ad.send("POST", "/api/access-grants/abc/revoke")
        ad.send("POST", "/api/access-grants/$grant/revoke")
        ad.send("POST", "/api/access-grants/$grant/revoke")
        val requests = mapOf(id to "{id}", second to "{second}", withDs to "{withDs}", queryRequest to "{query}")
        val role = core.policyStore.getRoleByName(ROLE)!!.id
        fun ids(text: String) = text
            .replace(Regex("""/api/access-requests/(\d+)/""")) { "/api/access-requests/${requests[it.groupValues[1].toLong()] ?: it.groupValues[1]}/" }
            .replace(Regex(""""id":(\d+),"principal"""")) { "\"id\":${requests[it.groupValues[1].toLong()] ?: it.groupValues[1]},\"principal\"" }
            .replace(Regex("""access grant #$grant\b"""), "access grant #{grant}")
            .replace(Regex("""(#|AccessRequest::")(\d+)""")) { it.groupValues[1] + (requests[it.groupValues[2].toLong()] ?: it.groupValues[2]) }
            .replace(Regex("""(/api/access-grants/|AccessGrant::")$grant\b""")) { "${it.groupValues[1]}{grant}" }
            .replace("\"roleId\":$role", "\"roleId\":{role}")
            .replace("\"datasourceId\":$openDs", "\"datasourceId\":{open}").replace("\"datasourceId\":$closedDs", "\"datasourceId\":{closed}")
        assertEquals(EXPECTED_WRITES.trim(), ids((a.lines + listOf("--- admin") + ad.lines + listOf("--- viewer") + v.lines).joinToString("\n")))
        assertEquals(EXPECTED_AUDIT.trim(), ids(auditSince(before)))
        assertEquals(EXPECTED_EVENTS.trim(), ids(events(id) + "\n---\n" + events(second)))
        assertEquals(EXPECTED_GRANTS.trim(), ids(grants(id) + "\n---\n" + grants(second)).trim())
        assertEquals(EXPECTED_PARTICIPANTS.trim(), ids(participants(id) + "\n---\n" + participants(second)))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `every write needs a session`() = testApplication {
        val t = Transcript(clients(null).single())
        val before = lastAuditId()
        t.send("POST", "/api/access-requests", request(""))
        t.send("POST", "/api/access-requests/1/approve")
        t.send("POST", "/api/access-requests/1/reject", """{"reason":"x"}""")
        t.send("POST", "/api/access-grants/999999/revoke")
        assertEquals(EXPECTED_ANONYMOUS.trim(), t.text())
        assertEquals("", auditSince(before))
    }

    private var openDs = 0L
    private var closedDs = 0L
    private var queryRequest = 0L

    private fun seed() {
        core.policyStore.createRole(RoleInput(ROLE))
        openDs = core.datasourceStore.create(DatasourceInput(name = "aw-open", engine = "mysql", host = "h", port = 3306, dbName = "app")).id
        closedDs = core.datasourceStore.create(DatasourceInput(name = "aw-closed", engine = "mysql", host = "h", port = 3306, dbName = "app")).id
        core.cedarPolicyStore.create(
            CedarPolicyInput("aw-no-request", """forbid(principal, action == Action::"task.request", resource == Datasource::"aw-closed");"""),
            updatedBy = "test",
        )
        queryRequest = core.accessStore.createQueryRequest(alice, openDs, listOf("SELECT 1"), null, null, "q", null, null).id
    }

    companion object {
        const val ROLE = "aw-role"
        const val EXPECTED_WRITES = """
POST /api/access-requests -> 201 {"id":{id},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"need it","requestedDurationSec":600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests -> 201 {"id":{withDs},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","datasourceId":{open},"datasourceName":"aw-open","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests -> 403 {"code":"approval.request_not_permitted","params":{}}
POST /api/access-requests -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
POST /api/access-requests -> 500 {"code":"common.fallback","params":{}}
POST /api/access-requests/{id}/approve -> 403 {"code":"approval.not_approver","params":{}}
POST /api/access-requests -> 201 {"id":{second},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"again","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests/{second}/reject -> 403 {"code":"approval.not_approver","params":{}}
POST /api/access-grants/{grant}/revoke -> 204 
--- admin
POST /api/access-requests/999999/approve -> 404 {"code":"common.not_found","params":{"resource":"access request"}}
POST /api/access-requests/abc/approve -> 400 {"code":"common.bad_id","params":{}}
POST /api/access-requests/{query}/approve -> 400 {"code":"approval.use_query_approval_endpoint","params":{}}
POST /api/access-requests/{id}/approve -> 200 {"id":{id},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"need it","requestedDurationSec":600,"status":"APPROVED","decidedBy":"access-admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests/{id}/approve -> 200 {"id":{id},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"need it","requestedDurationSec":600,"status":"APPROVED","decidedBy":"access-admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests/999999/reject -> 404 {"code":"common.not_found","params":{"resource":"access request"}}
POST /api/access-requests/{second}/reject -> 200 {"id":{second},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"again","requestedDurationSec":3600,"status":"REJECTED","decidedBy":"access-admin@example.com","decidedAt":"{at}","rejectionReason":"not now","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests/{second}/reject -> 200 {"id":{second},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"again","requestedDurationSec":3600,"status":"REJECTED","decidedBy":"access-admin@example.com","decidedAt":"{at}","rejectionReason":"not now","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-requests/{second}/approve -> 200 {"id":{second},"principal":"access-alice@example.com","roleId":{role},"roleName":"aw-role","reason":"again","requestedDurationSec":3600,"status":"REJECTED","decidedBy":"access-admin@example.com","decidedAt":"{at}","rejectionReason":"not now","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
POST /api/access-grants/999999/revoke -> 404 {"code":"common.not_found","params":{"resource":"access grant"}}
POST /api/access-grants/abc/revoke -> 400 {"code":"common.bad_id","params":{}}
POST /api/access-grants/{grant}/revoke -> 404 {"code":"common.not_found","params":{"resource":"access grant"}}
POST /api/access-grants/{grant}/revoke -> 404 {"code":"common.not_found","params":{"resource":"access grant"}}
--- viewer
POST /api/access-grants/{grant}/revoke -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
"""
        const val EXPECTED_AUDIT = """
task.request AccessRequest::"{id}" | open access request #{id} for role 'aw-role'
task.request AccessRequest::"{withDs}" | open access request #{withDs} for role 'aw-role'
task.approve AccessGrant::"{grant}" | approve access request #{id}: grant role 'aw-role' to 'access-alice@example.com' for 120s
task.request AccessRequest::"{second}" | open access request #{second} for role 'aw-role'
task.approve AccessRequest::"{second}" | reject access request #{second} from 'access-alice@example.com'
grant.revoke AccessGrant::"{grant}" | revoke access grant #{grant} (role 'aw-role' from 'access-alice@example.com')
"""
        const val EXPECTED_EVENTS = """
requested access-alice@example.com console 1 -
approved access-admin@example.com console 1 -
---
requested access-alice@example.com console 1 -
rejected access-admin@example.com console 1 not now
"""
        const val EXPECTED_GRANTS = """
access-alice@example.com aw-role access-admin@example.com true 120
---

"""
        const val EXPECTED_PARTICIPANTS = """
approver access-admin@example.com
---
approver access-admin@example.com
"""
        const val EXPECTED_ANONYMOUS = """
POST /api/access-requests -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/access-requests/1/approve -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/access-requests/1/reject -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/access-grants/999999/revoke -> 404 {"code":"common.not_found","params":{"resource":"access grant"}}
"""
    }
}
