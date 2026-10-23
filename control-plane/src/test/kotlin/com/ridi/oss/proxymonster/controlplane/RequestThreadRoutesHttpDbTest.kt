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
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The request-thread routes over HTTP: thread, comments, CCs, close and the involved list, with their rows. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestThreadRoutesHttpDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var cpGo: CpGoStack
    private lateinit var core: ControlPlaneCore

    private val requester = "req@example.com"
    private val admin = "admin@example.com"
    private val cc = "cc@example.com"
    private val outsider = "out@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_request_thread_routes_http")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "request-thread-routes-http-secret-32", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        val sessions = PrincipalSessionStore(dataSource, null)
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    /** One line per request, `who METHOD path [note] -> status body`, with timestamps masked. */
    private class Transcript {
        val lines = mutableListOf<String>()

        suspend fun record(label: String, response: HttpResponse) {
            lines += "$label -> ${response.status.value} ${response.bodyAsText()}".trimEnd()
                .replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
                .replace(Regex("""(.)\1{49,}""")) { "${it.value[0]}{${it.value.length}}" }
        }
    }

    private inner class Caller(private val who: String, private val client: HttpClient, private val t: Transcript) {
        suspend fun get(path: String) = t.record("$who GET $path", client.get(path))

        suspend fun post(path: String, body: String? = null, note: String = body.orEmpty()) =
            t.record("$who POST $path $note".trimEnd(), client.post(path) {
                if (body != null) {
                    contentType(ContentType.Application.Json)
                    setBody(body)
                }
            })

        suspend fun delete(path: String) = t.record("$who DELETE $path", client.delete(path))
    }

    private suspend fun caller(who: String, principal: String?, t: Transcript): Caller {
        val client = cpGo.client()
        if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return Caller(who, client, t)
    }

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun id(sql: String): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> rs.next(); rs.getLong(1) } }
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s ->
            s.executeQuery(sql).use { rs ->
                buildList { while (rs.next()) add((1..rs.metaData.columnCount).joinToString(" | ") { rs.getString(it).orEmpty() }) }
            }
        }
    }.joinToString("\n")

    @Test
    fun `request thread routes`() = runBlocking<Unit> {
        exec(
            """INSERT INTO app_user (principal, email) VALUES ('$requester', '$requester'), ('$cc', 'CC-Mail@Example.com'),
               ('twin-a', 'twin@example.com'), ('twin-b', 'twin@example.com')""",
        )
        exec("INSERT INTO principal_role (principal, role_id) SELECT '$admin', id FROM app_role WHERE name = 'system:admin'")
        val ds = id("INSERT INTO datasource (name, host, port, db_name, tags) VALUES ('threads-ds', 'h', 1, 'd', '[\"prod\"]') RETURNING id")
        val role = id("INSERT INTO app_role (name) VALUES ('threads-role') RETURNING id")
        val pending = core.accessStore.createRequest(requester, AccessRequestInput(roleId = role, reason = "need it")).id
        val granted = core.accessStore.createRequest(requester, AccessRequestInput(roleId = role, reason = "granted")).id
        exec("UPDATE access_request SET status = 'APPROVED', decided_by = '$admin', decided_at = now() WHERE id = $granted")
        val flagged = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = ds, statements = listOf("select email from users where id = 1"),
            denyReason = "policy denies", sourceDecisionId = null, reason = "flagged", title = "t",
            evaluatedDecision = "DENY", carriesProtectedLiteral = true,
        ).id
        val cleared = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = ds, statements = listOf("select id from users"),
            denyReason = "policy denies", sourceDecisionId = null, reason = "cleared", title = "t",
            evaluatedDecision = "DENY", carriesProtectedLiteral = false,
        ).id
        exec("UPDATE access_request SET status = 'APPROVED', decided_by = '$admin', decided_at = now(), approved_at = now() WHERE id = $cleared")
        val editor = id(
            "INSERT INTO access_request (principal, kind, datasource_id, creator_kind) VALUES ('$requester', 'QUERY', $ds, 'EDITOR') RETURNING id",
        )
        exec(
            """INSERT INTO request_participant (request_id, principal, kind) VALUES ($flagged, '$admin', 'approver'),
               ($cleared, '$cc', 'cc')""",
        )
        val before = id("SELECT coalesce(max(id), 0) FROM audit_event")

        val t = Transcript()
        val anon = caller("anon", null, t)
        val r = caller("req", requester, t)
        val a = caller("admin", admin, t)
        val c = caller("cc", cc, t)
        val o = caller("out", outsider, t)
        val thread = "/api/requests/$pending/thread"
        val comments = "/api/requests/$pending/comments"
        val ccs = "/api/requests/$pending/ccs"

        r.get("/api/requests/x/thread")
        anon.get(thread)
        r.get("/api/requests/$editor/thread")
        r.get("/api/requests/99999/thread")
        o.get(thread)
        r.get(thread)
        a.get(thread)

        r.post("/api/requests/x/comments", """{"body":"hi"}""")
        anon.post(comments, """{"body":"hi"}""")
        r.post(comments, "{}")
        r.post(comments, """{"body":"   "}""")
        r.post(comments, """{"body":"${"a".repeat(4001)}"}""", note = "4001 chars")
        r.post("/api/requests/99999/comments", """{"body":"hi"}""")
        r.post("/api/requests/$editor/comments", """{"body":"hi"}""")
        o.post(comments, """{"body":"hi"}""")
        r.post(comments, """{"body":"  looks fine  "}""")
        a.post(comments, """{"lgtm":true}""")
        a.post(comments, """{"body":"${"b".repeat(4000)}","lgtm":true}""", note = "4000 chars lgtm")

        r.post("/api/requests/x/ccs", """{"principal":"$cc"}""")
        o.post(ccs, """{"principal":"$cc"}""")
        r.post(ccs, """{"principal":"nobody@example.com"}""")
        r.post(ccs, """{"principal":"twin@example.com"}""")
        a.post(ccs, """{"principal":" $requester "}""")
        r.post(ccs, """{"principal":" cc-mail@example.COM "}""")
        a.post(ccs, """{"principal":"$cc"}""")
        c.get(thread)
        c.post(comments, """{"body":"as a cc"}""")
        o.delete("$ccs/$cc")
        a.delete("$ccs/$cc")
        a.delete("$ccs/$cc")
        a.delete("$ccs/ghost")
        c.get(thread)

        r.post("/api/requests/x/close")
        anon.post("/api/requests/$pending/close")
        r.post("/api/requests/99999/close")
        o.post("/api/requests/$pending/close")
        r.post("/api/requests/$granted/close")
        r.post("/api/requests/$pending/close")
        r.post("/api/requests/$pending/close")
        r.get(thread)
        r.post("/api/requests/$cleared/close")

        anon.get("/api/requests/involved")
        r.get("/api/requests/involved")
        a.get("/api/requests/involved")
        c.get("/api/requests/involved")
        o.get("/api/requests/involved")

        assertEquals(EXPECTED.trimIndent(), t.lines.joinToString("\n"))
        assertEquals(
            EXPECTED_EVENTS.trimIndent(),
            rows("SELECT request_id, kind, coalesce(actor, ''), coalesce(left(body, 20), ''), revision, origin FROM request_event ORDER BY id"),
        )
        assertEquals(
            EXPECTED_PARTICIPANTS.trimIndent(),
            rows("SELECT request_id, principal, kind FROM request_participant ORDER BY request_id, principal, kind"),
        )
        assertEquals(
            EXPECTED_AUDIT.trimIndent(),
            rows(
                """SELECT kind, principal, action, resource, statement, coalesce(client_addr, ''), channel
                   FROM audit_event WHERE id > $before ORDER BY id""",
            ),
        )
        verifyAuditChain(dataSource)
    }

    private companion object {
        const val EXPECTED = """
            req GET /api/requests/x/thread -> 400 {"code":"common.bad_id","params":{}}
            anon GET /api/requests/1/thread -> 401 {"code":"common.unauthenticated","params":{}}
            req GET /api/requests/5/thread -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            req GET /api/requests/99999/thread -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            out GET /api/requests/1/thread -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            req GET /api/requests/1/thread -> 200 {"requestId":1,"ccs":[],"participants":[],"timeline":[],"canComment":true,"canCc":true,"canClose":true,"canDecide":false,"people":{"req@example.com":{"email":"req@example.com"}}}
            admin GET /api/requests/1/thread -> 200 {"requestId":1,"ccs":[],"participants":[],"timeline":[],"canComment":true,"canCc":true,"canClose":true,"canDecide":true,"people":{"req@example.com":{"email":"req@example.com"}}}
            req POST /api/requests/x/comments {"body":"hi"} -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/requests/1/comments {"body":"hi"} -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/requests/1/comments {} -> 400 {"code":"common.field_required","params":{"fields":"body"}}
            req POST /api/requests/1/comments {"body":"   "} -> 400 {"code":"common.field_required","params":{"fields":"body"}}
            req POST /api/requests/1/comments 4001 chars -> 400 {"code":"approval.comment_too_long","params":{"max":"4000"}}
            req POST /api/requests/99999/comments {"body":"hi"} -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            req POST /api/requests/5/comments {"body":"hi"} -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            out POST /api/requests/1/comments {"body":"hi"} -> 403 {"code":"approval.comment_forbidden","params":{}}
            req POST /api/requests/1/comments {"body":"  looks fine  "} -> 201 {"id":3,"kind":"comment","actor":"req@example.com","body":"looks fine","revision":1,"origin":"console","createdAt":"{at}","deleted":false}
            admin POST /api/requests/1/comments {"lgtm":true} -> 201 {"id":4,"kind":"lgtm","actor":"admin@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}
            admin POST /api/requests/1/comments 4000 chars lgtm -> 201 {"id":5,"kind":"lgtm","actor":"admin@example.com","body":"b{4000}","revision":1,"origin":"console","createdAt":"{at}","deleted":false}
            req POST /api/requests/x/ccs {"principal":"cc@example.com"} -> 400 {"code":"common.bad_id","params":{}}
            out POST /api/requests/1/ccs {"principal":"cc@example.com"} -> 403 {"code":"approval.cc_forbidden","params":{}}
            req POST /api/requests/1/ccs {"principal":"nobody@example.com"} -> 400 {"code":"approval.unknown_user","params":{}}
            req POST /api/requests/1/ccs {"principal":"twin@example.com"} -> 400 {"code":"approval.unknown_user","params":{}}
            admin POST /api/requests/1/ccs {"principal":" req@example.com "} -> 400 {"code":"approval.cc_requester","params":{}}
            req POST /api/requests/1/ccs {"principal":" cc-mail@example.COM "} -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":["cc@example.com"]}
            admin POST /api/requests/1/ccs {"principal":"cc@example.com"} -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":["cc@example.com"]}
            cc GET /api/requests/1/thread -> 200 {"requestId":1,"ccs":["cc@example.com"],"participants":["cc@example.com"],"timeline":[{"id":3,"kind":"comment","actor":"req@example.com","body":"looks fine","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":4,"kind":"lgtm","actor":"admin@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":5,"kind":"lgtm","actor":"admin@example.com","body":"b{4000}","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":6,"kind":"cc_added","actor":"req@example.com","body":"cc@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"canComment":true,"canCc":true,"canClose":false,"canDecide":false,"people":{"cc@example.com":{"email":"CC-Mail@Example.com"},"req@example.com":{"email":"req@example.com"}}}
            cc POST /api/requests/1/comments {"body":"as a cc"} -> 201 {"id":7,"kind":"comment","actor":"cc@example.com","body":"as a cc","revision":1,"origin":"console","createdAt":"{at}","deleted":false}
            out DELETE /api/requests/1/ccs/cc@example.com -> 403 {"code":"approval.cc_forbidden","params":{}}
            admin DELETE /api/requests/1/ccs/cc@example.com -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
            admin DELETE /api/requests/1/ccs/cc@example.com -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
            admin DELETE /api/requests/1/ccs/ghost -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
            cc GET /api/requests/1/thread -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            req POST /api/requests/x/close -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/requests/1/close -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/requests/99999/close -> 404 {"code":"common.not_found","params":{"resource":"request"}}
            out POST /api/requests/1/close -> 403 {"code":"approval.cancel_forbidden","params":{}}
            req POST /api/requests/2/close -> 409 {"code":"approval.not_cancelable","params":{}}
            req POST /api/requests/1/close -> 200 {"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"CANCELLED","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}
            req POST /api/requests/1/close -> 409 {"code":"approval.not_cancelable","params":{}}
            req GET /api/requests/1/thread -> 200 {"requestId":1,"ccs":[],"participants":[],"timeline":[{"id":3,"kind":"comment","actor":"req@example.com","body":"looks fine","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":4,"kind":"lgtm","actor":"admin@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":5,"kind":"lgtm","actor":"admin@example.com","body":"b{4000}","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":6,"kind":"cc_added","actor":"req@example.com","body":"cc@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":7,"kind":"comment","actor":"cc@example.com","body":"as a cc","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":8,"kind":"cc_removed","actor":"admin@example.com","body":"cc@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":9,"kind":"closed","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"canComment":true,"canCc":true,"canClose":false,"canDecide":false,"people":{"cc@example.com":{"email":"CC-Mail@Example.com"},"req@example.com":{"email":"req@example.com"}}}
            req POST /api/requests/4/close -> 200 {"id":4,"principal":"req@example.com","datasourceId":1,"datasourceName":"threads-ds","reason":"cleared","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"denyReason":"policy denies","title":"t","evaluatedDecision":"DENY","approvedAt":"{at}","executeAs":[],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"forceRun":false,"ccs":["cc@example.com"]}
            anon GET /api/requests/involved -> 401 {"code":"common.unauthenticated","params":{}}
            req GET /api/requests/involved -> 200 [{"id":4,"principal":"req@example.com","datasourceId":1,"datasourceName":"threads-ds","reason":"cleared","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"denyReason":"policy denies","title":"t","evaluatedDecision":"DENY","approvedAt":"{at}","executeAs":[],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"forceRun":false,"ccs":["cc@example.com"]},{"id":3,"principal":"req@example.com","datasourceId":1,"datasourceName":"threads-ds","reason":"flagged","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select email from users where id = 1","sqlHash":"2acf90e885c492584a862bd14e0129aea11eb05f7f73f6cf483395c9533a63eb","statementCount":1,"denyReason":"policy denies","title":"t","evaluatedDecision":"DENY","executeAs":[],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"forceRun":false,"ccs":[]},{"id":2,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"granted","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]},{"id":1,"principal":"req@example.com","roleId":16,"roleName":"threads-role","reason":"need it","requestedDurationSec":3600,"status":"CANCELLED","createdAt":"{at}","kind":"ROLE","statementCount":0,"executeAs":[],"creatorKind":"WORKFLOW","source":"console","revision":1,"forceRun":false,"ccs":[]}]
            admin GET /api/requests/involved -> 200 [{"id":3,"principal":"req@example.com","datasourceId":1,"datasourceName":"threads-ds","reason":"flagged","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sqlHash":"2acf90e885c492584a862bd14e0129aea11eb05f7f73f6cf483395c9533a63eb","statementCount":1,"denyReason":"policy denies","title":"t","evaluatedDecision":"DENY","executeAs":[],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"forceRun":false,"ccs":[]}]
            cc GET /api/requests/involved -> 200 [{"id":4,"principal":"req@example.com","datasourceId":1,"datasourceName":"threads-ds","reason":"cleared","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"admin@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"denyReason":"policy denies","title":"t","evaluatedDecision":"DENY","approvedAt":"{at}","executeAs":[],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"forceRun":false,"ccs":["cc@example.com"]}]
            out GET /api/requests/involved -> 200 []
        """
        const val EXPECTED_EVENTS = """
            3 | requested | req@example.com |  | 1 | console
            4 | requested | req@example.com |  | 1 | console
            1 | comment | req@example.com | looks fine | 1 | console
            1 | lgtm | admin@example.com |  | 1 | console
            1 | lgtm | admin@example.com | bbbbbbbbbbbbbbbbbbbb | 1 | console
            1 | cc_added | req@example.com | cc@example.com | 1 | console
            1 | comment | cc@example.com | as a cc | 1 | console
            1 | cc_removed | admin@example.com | cc@example.com | 1 | console
            1 | closed | req@example.com |  | 1 | console
            4 | closed | req@example.com |  | 1 | console
        """
        const val EXPECTED_PARTICIPANTS = """
            3 | admin@example.com | approver
            4 | cc@example.com | cc
        """
        const val EXPECTED_AUDIT = """
            admin | req@example.com | task.cancel | AccessRequest::"1" | close request #1 | 127.0.0.1 | console
            admin | req@example.com | task.cancel | AccessRequest::"4" | close request #4 | 127.0.0.1 | console
        """
    }
}
