package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
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
import java.sql.DriverManager
import javax.sql.DataSource
import kotlin.test.assertEquals

/**
 * The approval routes over HTTP: create, discover-roles, inbox, detail, approve, reject, unapprove, edit, cancel, and
 * the error answers of execute, result and force-run, with their rows.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalRoutesHttpDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var cpGo: CpGoStack
    private lateinit var core: ControlPlaneCore
    private lateinit var mysql: Datasource
    private lateinit var pg: Datasource
    private lateinit var locked: Datasource
    private lateinit var gone: Datasource
    private lateinit var target: String
    private var reader = 0L
    private var full = 0L

    private val requester = "req@example.com"
    private val approver = "appr@example.com"
    private val outsider = "out@example.com"
    private val admin = "admin@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_approval_routes_http")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        target = SharedMySql.freshDatabase("pm_approval_target")
        DriverManager.getConnection(SharedMySql.jdbcUrlFor(target), SharedMySql.username(), SharedMySql.password()).use { c ->
            c.createStatement().use { st ->
                st.execute("CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(64), ssn VARCHAR(32))")
                st.execute("CREATE TABLE orders (id BIGINT PRIMARY KEY, amount BIGINT)")
            }
        }
        mysql = core.datasourceStore.create(
            DatasourceInput(name = "approvals-mysql", engine = "mysql", host = SharedMySql.host(), port = SharedMySql.port(), dbName = target),
        )
        core.datasourceStore.pushTestCatalog(mysql, SharedMySql.jdbcUrlFor(target), SharedMySql.username(), SharedMySql.password())
        mysql = core.datasourceStore.get(mysql.id)!!
        pg = core.datasourceStore.create(DatasourceInput(name = "approvals-pg", engine = "postgres", host = "h", port = 5432, dbName = "app"))
        locked = core.datasourceStore.create(DatasourceInput(name = "approvals-locked", engine = "mysql", host = "h", port = 3306, dbName = "app"))
        gone = core.datasourceStore.create(DatasourceInput(name = "approvals-gone", engine = "mysql", host = "h", port = 3306, dbName = "app"))

        val catalog = mysql.engine.catalogName(mysql.dbName)
        val schema = mysql.engine.defaultSchema(mysql.dbName)
        val users = "${mysql.name}/$catalog/$schema/users"
        val mask = core.policyStore.createMaskFn(MaskFnInput("last4", "LAST_N"))
        core.datasourceStore.upsertClassification(
            mysql.id,
            ClassificationInput(schema = schema, table = "users", column = "ssn", tags = listOf("pii"), maskFnId = mask.id, catalog = catalog),
        )
        reader = core.policyStore.createRole(RoleInput("approvals-reader")).id
        full = core.policyStore.createRole(RoleInput("approvals-full")).id
        core.policyStore.createRole(RoleInput("approvals-unmask-only"))
        core.policyStore.createAssignment(RoleAssignmentInput(requester, reader))
        fun policy(name: String, src: String) = core.cedarPolicyStore.create(CedarPolicyInput(name = name, cedarSrc = src), updatedBy = null)
        val connect = """action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${mysql.name}""""
        policy("reader-connect", """permit(principal in Role::"approvals-reader", $connect);""")
        policy("reader-unmasked", """permit(principal in Role::"approvals-reader", action == Action::"result.read.unmasked", resource in Table::"$users") unless { resource in Tag::"pii" };""")
        policy("reader-masked", """permit(principal in Role::"approvals-reader", action == Action::"result.read.masked", resource in Table::"$users") when { resource in Tag::"pii" };""")
        policy("full-connect", """permit(principal in Role::"approvals-full", $connect);""")
        policy("full-unmasked", """permit(principal in Role::"approvals-full", action == Action::"result.read.unmasked", resource in Table::"$users");""")
        policy("unmask-only", """permit(principal in Role::"approvals-unmask-only", action == Action::"result.read.unmasked", resource in Table::"$users");""")
        policy(
            "approver",
            """permit(principal == User::"$approver", action in [Action::"task.approve", Action::"task.read", Action::"task.run"], resource);""",
        )
        policy("locked", """forbid(principal, action == Action::"task.request", resource == Datasource::"${locked.name}");""")

        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "approval-routes-http-secret-of-32-chars", oidc = null, resultKey = ByteArray(32) { it.toByte() },
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        val sessions = PrincipalSessionStore(dataSource, null)
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    /** One line per request, `who METHOD path [note] -> status body`, with timestamps and the target database masked. */
    private inner class Transcript {
        val lines = mutableListOf<String>()

        suspend fun record(label: String, response: HttpResponse) {
            lines += "$label -> ${response.status.value} ${response.bodyAsText()}".trimEnd()
                .replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
                .replace(target, "{target}")
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
    }

    private suspend fun caller(who: String, principal: String?, t: Transcript): Caller {
        val client = cpGo.client()
        if (principal != null) assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return Caller(who, client, t)
    }

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s ->
            s.executeQuery(sql).use { rs ->
                buildList { while (rs.next()) add((1..rs.metaData.columnCount).joinToString(" | ") { rs.getString(it).orEmpty() }.trimEnd()) }
            }
        }
    }.joinToString("\n").replace(target, "{target}")

    private fun seed(statements: List<String>, ds: Datasource = mysql, source: String = "console", origin: RequestOrigin? = null): Long =
        core.accessStore.createQueryRequest(
            principal = requester, datasourceId = ds.id, statements = statements, denyReason = null, sourceDecisionId = null,
            reason = "seeded", title = "seeded", evaluatedDecision = "ALLOW", roleId = reader, carriesProtectedLiteral = false,
            source = source, contentHash = contentHash(statements.joinToString(";\n"), ds),
            rawHash = rawSqlHash(statements.joinToString(";\n")), origin = origin,
        ).id

    @Test
    fun `approval routes`() = runBlocking<Unit> {
        val denied = core.auditStore.insert(
            AuditEvent(principal = requester, datasource = mysql.name, statement = "select ssn from users", decision = Decision.DENY, detail = "ssn is pii"),
        )
        val allowed = core.auditStore.insert(
            AuditEvent(principal = requester, datasource = mysql.name, statement = "select id from users", decision = Decision.ALLOW),
        )
        val others = core.auditStore.insert(
            AuditEvent(principal = outsider, datasource = mysql.name, statement = "select ssn from users", decision = Decision.DENY),
        )
        val orphan = core.auditStore.insert(
            AuditEvent(principal = requester, datasource = "no-such-ds", statement = "select 1", decision = Decision.DENY),
        )
        val roleRequest = core.accessStore.createRequest(requester, AccessRequestInput(roleId = reader, reason = "role")).id
        val editorTask = core.accessStore.createEditorTask(requester, mysql.id, listOf("select 1"), listOf("approvals-reader"), requester).id
        val lockedRequest = seed(listOf("select 1"), locked)
        val goneRequest = seed(listOf("select 1"), gone)
        val github = seed(
            listOf("select id from users"), source = "github",
            origin = RequestOrigin(
                scope = "s", fileKey = "1", contentHash = "c", changeKey = "k",
                pullRequest = PullRequestRef(repository = "acme/db", pr = 7, prUrl = "https://example.com/pr/7", path = "sql/1.sql", headSha = "abc"),
            ),
        )
        val running = seed(listOf("select id from users", "select email from users"))
        exec("UPDATE access_request SET status = 'EXECUTING', decided_by = '$approver', decided_at = now(), approved_at = now(), executing_at = now() WHERE id = $running")
        exec("UPDATE query_result SET status = 'RUNNING', executed_by = '$approver' WHERE task_id = $running AND ordinal = 0")
        val executed = seed(listOf("select id from users"))
        exec("UPDATE access_request SET status = 'EXECUTED', decided_by = '$approver', decided_at = now(), approved_at = now() WHERE id = $executed")
        exec(
            """UPDATE query_result SET status = 'DONE', executed_by = '$approver', executed_at = now(), row_count = 2,
               columns = '["id"]', expires_at = now() + interval '1 day' WHERE task_id = $executed""",
        )
        val stale = seed(listOf("select id from users"))
        exec("UPDATE access_request SET status = 'APPROVED', decided_by = '$approver', decided_at = now(), approved_at = now() - interval '2 days' WHERE id = $stale")
        val droppedRole = core.policyStore.createRole(RoleInput("approvals-dropped")).id
        val dropped = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = mysql.id, statements = listOf("select id from users"), denyReason = null,
            sourceDecisionId = null, reason = "seeded", title = "seeded", evaluatedDecision = "ALLOW", roleId = droppedRole,
            carriesProtectedLiteral = false,
        ).id
        exec("UPDATE access_request SET status = 'APPROVED', decided_by = '$approver', decided_at = now(), approved_at = now() WHERE id = $dropped")
        exec("UPDATE app_role SET deleted_at = now() WHERE id = $droppedRole")
        exec("INSERT INTO principal_role (principal, role_id) SELECT '$admin', id FROM app_role WHERE name = 'system:admin'")
        exec("UPDATE datasource SET deleted_at = now() WHERE id = ${gone.id}")
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event")

        val t = Transcript()
        val anon = caller("anon", null, t)
        val r = caller("req", requester, t)
        val a = caller("appr", approver, t)
        val o = caller("out", outsider, t)
        val ad = caller("admin", admin, t)

        // discover-roles
        anon.post("/api/approvals/discover-roles", """{"datasourceId":${mysql.id},"sql":"select 1"}""")
        r.post("/api/approvals/discover-roles", "not json")
        r.post("/api/approvals/discover-roles", "{}")
        r.post("/api/approvals/discover-roles", """{"datasourceId":99999,"sql":"select 1"}""")
        r.post("/api/approvals/discover-roles", """{"datasourceId":${gone.id},"sql":"select 1"}""")
        r.post("/api/approvals/discover-roles", """{"datasourceId":${mysql.id},"sql":"select 'open"}""")
        r.post("/api/approvals/discover-roles", """{"datasourceId":${mysql.id},"sql":"select id, ssn from users"}""")
        r.post("/api/approvals/discover-roles", """{"datasourceId":${mysql.id},"sql":"select id from users; select ssn from users"}""")
        o.post("/api/approvals/discover-roles", """{"datasourceId":${mysql.id},"sql":"select id from orders"}""")

        // create
        anon.post("/api/approvals", """{"reason":"r"}""")
        r.post("/api/approvals", "not json")
        r.post("/api/approvals", "{}")
        r.post("/api/approvals", """{"reason":"  "}""")
        r.post("/api/approvals", """{"reason":"r"}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":$denied,"datasourceId":${mysql.id}}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":99999}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":$others}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":$allowed}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":$orphan}""")
        r.post("/api/approvals", """{"reason":"r","sourceDecisionId":$denied}""")
        r.post("/api/approvals", """{"reason":" from a denial ","sourceDecisionId":$denied,"roleId":$full,"title":"  "}""")
        r.post("/api/approvals", """{"reason":"again","sourceDecisionId":$denied,"roleId":$full}""")
        r.post("/api/approvals", """{"reason":"r","sql":"select 1"}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${mysql.id}}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${mysql.id},"sql":"  "}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${mysql.id},"sql":"select 1"}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":99999,"sql":"select 1","title":"t"}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${gone.id},"sql":"select 1","title":"t"}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${locked.id},"sql":"select 1","title":"t","roleId":$full}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${mysql.id},"sql":"select 1","title":"t"}""")
        r.post("/api/approvals", """{"reason":"r","datasourceId":${mysql.id},"sql":"select 'open","title":"t","roleId":$full}""")
        r.post("/api/approvals", """{"reason":" plain ","datasourceId":${mysql.id},"sql":"select id from users","title":" ids ","roleId":$full}""")
        r.post("/api/approvals", """{"reason":"masked","datasourceId":${mysql.id},"sql":"select id, ssn from users where ssn = '1'","title":"ssn","roleId":$full,"requestedDurationSec":60}""")
        r.post("/api/approvals", """{"reason":"denied","datasourceId":${mysql.id},"sql":"select id from orders;\nselect id from users","title":"batch","roleId":$full}""")
        r.post("/api/approvals", """{"reason":"pg","datasourceId":${pg.id},"sql":"select \"id\" from t; select 2","title":"pg","roleId":$reader}""")
        val plain = rows("SELECT id FROM access_request WHERE reason = 'plain'").toLong()
        val masked = rows("SELECT id FROM access_request WHERE reason = 'masked'").toLong()
        val batch = rows("SELECT id FROM access_request WHERE reason = 'denied'").toLong()

        // inbox and detail
        anon.get("/api/approvals/inbox")
        r.get("/api/approvals/inbox")
        a.get("/api/approvals/inbox")
        o.get("/api/approvals/inbox")
        r.get("/api/approvals/x")
        anon.get("/api/approvals/$plain")
        r.get("/api/approvals/99999")
        r.get("/api/approvals/$roleRequest")
        r.get("/api/approvals/$editorTask")
        o.get("/api/approvals/$plain")
        r.get("/api/approvals/$plain")
        a.get("/api/approvals/$plain")
        a.get("/api/approvals/$executed")
        r.get("/api/approvals/$executed")
        a.get("/api/approvals/$stale")
        a.get("/api/approvals/$github")
        r.get("/api/approvals/$running")

        // approve
        a.post("/api/approvals/x/approve", """{"revision":1}""")
        anon.post("/api/approvals/$plain/approve", """{"revision":1}""")
        a.post("/api/approvals/$plain/approve")
        a.post("/api/approvals/$plain/approve", """{"revision":"one"}""")
        a.post("/api/approvals/99999/approve", """{"revision":1}""")
        a.post("/api/approvals/$editorTask/approve", """{"revision":1}""")
        o.post("/api/approvals/$plain/approve", """{"revision":1}""")
        r.post("/api/approvals/$plain/approve", """{"revision":1}""")
        a.post("/api/approvals/$plain/approve", """{"revision":2}""")
        a.post("/api/approvals/$plain/approve", """{"revision":1}""")
        a.post("/api/approvals/$plain/approve", """{"revision":1}""")
        a.post("/api/approvals/$masked/approve", """{"revision":1}""")
        a.post("/api/approvals/$executed/approve", """{"revision":1}""")
        a.get("/api/approvals/$plain")
        r.get("/api/approvals/$plain")

        // unapprove
        a.post("/api/approvals/x/unapprove")
        anon.post("/api/approvals/$plain/unapprove")
        a.post("/api/approvals/99999/unapprove")
        o.post("/api/approvals/$plain/unapprove")
        r.post("/api/approvals/$plain/unapprove")
        a.post("/api/approvals/$batch/unapprove")
        a.post("/api/approvals/$github/unapprove")
        a.post("/api/approvals/$plain/unapprove")
        a.post("/api/approvals/$plain/unapprove")

        // reject
        a.post("/api/approvals/x/reject", """{"reason":"no"}""")
        anon.post("/api/approvals/$batch/reject", """{"reason":"no"}""")
        a.post("/api/approvals/$batch/reject")
        a.post("/api/approvals/$batch/reject", "{}")
        a.post("/api/approvals/$batch/reject", """{"reason":"  "}""")
        a.post("/api/approvals/99999/reject", """{"reason":"no"}""")
        o.post("/api/approvals/$batch/reject", """{"reason":"no"}""")
        a.post("/api/approvals/$executed/reject", """{"reason":"no"}""")
        a.post("/api/approvals/$batch/reject", """{"reason":" not now "}""")
        a.post("/api/approvals/$batch/reject", """{"reason":"again"}""")
        a.post("/api/approvals/$masked/reject", """{"reason":"after approval"}""")

        // edit
        r.post("/api/approvals/x/edit", """{"sql":"select 1"}""")
        anon.post("/api/approvals/$plain/edit", """{"sql":"select 1"}""")
        r.post("/api/approvals/$plain/edit")
        r.post("/api/approvals/$plain/edit", "{}")
        r.post("/api/approvals/99999/edit", """{"sql":"select 1"}""")
        o.post("/api/approvals/$plain/edit", """{"sql":"select 1"}""")
        r.post("/api/approvals/$github/edit", """{"sql":"select 1"}""")
        r.post("/api/approvals/$batch/edit", """{"sql":"select 1"}""")
        r.post("/api/approvals/$plain/edit", """{"sql":"  "}""")
        r.post("/api/approvals/$plain/edit", """{"sql":"select 1","reason":" "}""")
        r.post("/api/approvals/$goneRequest/edit", """{"sql":"select 1"}""")
        r.post("/api/approvals/$lockedRequest/edit", """{"sql":"select 2"}""")
        r.post("/api/approvals/$plain/edit", """{"sql":"select 'open"}""")
        a.post("/api/approvals/$plain/approve", """{"revision":1}""")
        r.post("/api/approvals/$plain/edit", """{"sql":"SELECT id\nFROM users -- same\n","title":" same sql ","reason":" kept "}""")
        r.post("/api/approvals/$plain/edit", """{"sql":"select id, email from users; select ssn from users","title":"  "}""")
        a.post("/api/approvals/$plain/approve", """{"revision":1}""")
        a.post("/api/approvals/$plain/approve", """{"revision":2}""")
        r.get("/api/approvals/$plain")

        // execute, result and force-run
        a.post("/api/approvals/x/execute")
        anon.post("/api/approvals/$stale/execute")
        a.post("/api/approvals/99999/execute")
        o.post("/api/approvals/$stale/execute")
        a.post("/api/approvals/$github/execute")
        a.post("/api/approvals/$executed/execute")
        a.post("/api/approvals/$batch/execute")
        a.post("/api/approvals/$stale/execute")
        a.post("/api/approvals/$dropped/execute")
        a.get("/api/approvals/x/result")
        a.get("/api/approvals/$executed/result?statement=-1")
        anon.get("/api/approvals/$executed/result")
        a.get("/api/approvals/99999/result")
        o.get("/api/approvals/$executed/result")
        a.get("/api/approvals/$executed/result")
        a.get("/api/approvals/$executed/result?statement=1")
        a.get("/api/approvals/$batch/result")
        a.post("/api/approvals/x/force-run")
        a.post("/api/approvals/$github/force-run")
        ad.post("/api/approvals/$batch/force-run")
        ad.post("/api/approvals/$github/force-run")
        ad.post("/api/approvals/$github/force-run")

        // cancel
        r.post("/api/approvals/x/cancel")
        anon.post("/api/approvals/$plain/cancel")
        r.post("/api/approvals/99999/cancel")
        o.post("/api/approvals/$plain/cancel")
        r.post("/api/approvals/$executed/cancel")
        r.post("/api/approvals/$batch/cancel")
        r.post("/api/approvals/$github/cancel")
        r.post("/api/approvals/$plain/cancel")
        r.post("/api/approvals/$plain/cancel")
        r.post("/api/approvals/$running/cancel")
        r.get("/api/approvals/$running")

        assertEquals(EXPECTED.trimIndent(), t.lines.joinToString("\n"))
        assertEquals(
            EXPECTED_REQUESTS.trimIndent(),
            rows(
                """SELECT id, status, revision, coalesce(title, ''), coalesce(reason, ''), coalesce(role_id::text, ''), execute_as,
                          coalesce(source_decision_id::text, ''), coalesce(deny_reason, ''), coalesce(evaluated_decision, ''),
                          coalesce(statement_carries_protected_literal::text, ''), coalesce(content_hash, ''), coalesce(decided_by, ''),
                          coalesce(rejection_reason, ''), requested_duration_sec, source
                   FROM access_request ORDER BY id""",
            ),
        )
        assertEquals(
            EXPECTED_STATEMENTS.trimIndent(),
            rows("SELECT task_id, ordinal, sql, sql_hash, coalesce(status, ''), coalesce(error_code, '') FROM query_result ORDER BY task_id, ordinal"),
        )
        assertEquals(
            EXPECTED_EVENTS.trimIndent(),
            rows("SELECT request_id, kind, coalesce(actor, ''), coalesce(body, ''), revision, origin FROM request_event ORDER BY id"),
        )
        assertEquals(
            EXPECTED_PARTICIPANTS.trimIndent(),
            rows("SELECT request_id, principal, kind FROM request_participant ORDER BY request_id, principal, kind"),
        )
        assertEquals(
            EXPECTED_AUDIT.trimIndent(),
            rows(
                """SELECT kind, principal, coalesce(action, ''), coalesce(resource, ''), statement, coalesce(client_addr, ''),
                          coalesce(channel, ''), coalesce(detail, ''), decision
                   FROM audit_event WHERE id > $before ORDER BY id""",
            ),
        )
        verifyAuditChain(dataSource)
    }

    private companion object {
        const val EXPECTED = """
            anon POST /api/approvals/discover-roles {"datasourceId":1,"sql":"select 1"} -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/approvals/discover-roles not json -> 500 {"code":"common.fallback","params":{}}
            req POST /api/approvals/discover-roles {} -> 500 {"code":"common.fallback","params":{}}
            req POST /api/approvals/discover-roles {"datasourceId":99999,"sql":"select 1"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals/discover-roles {"datasourceId":4,"sql":"select 1"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals/discover-roles {"datasourceId":1,"sql":"select 'open"} -> 400 {"code":"approval.unsplittable_sql","params":{}}
            req POST /api/approvals/discover-roles {"datasourceId":1,"sql":"select id, ssn from users"} -> 200 {"options":[{"roleId":17,"roleName":"approvals-full","decision":"ALLOW","maskedColumns":[]},{"roleId":16,"roleName":"approvals-reader","decision":"MASK","maskedColumns":["ssn"]}]}
            req POST /api/approvals/discover-roles {"datasourceId":1,"sql":"select id from users; select ssn from users"} -> 200 {"options":[{"roleId":17,"roleName":"approvals-full","decision":"ALLOW","maskedColumns":[]},{"roleId":16,"roleName":"approvals-reader","decision":"MASK","maskedColumns":["ssn"]}]}
            out POST /api/approvals/discover-roles {"datasourceId":1,"sql":"select id from orders"} -> 200 {"options":[]}
            anon POST /api/approvals {"reason":"r"} -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/approvals not json -> 500 {"code":"common.fallback","params":{}}
            req POST /api/approvals {} -> 400 {"code":"common.field_required","params":{"fields":"reason"}}
            req POST /api/approvals {"reason":"  "} -> 400 {"code":"common.field_required","params":{"fields":"reason"}}
            req POST /api/approvals {"reason":"r"} -> 400 {"code":"approval.exactly_one_source_required","params":{}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":1,"datasourceId":1} -> 400 {"code":"approval.exactly_one_source_required","params":{}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":99999} -> 404 {"code":"common.not_found","params":{"resource":"decision"}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":3} -> 404 {"code":"common.not_found","params":{"resource":"decision"}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":2} -> 400 {"code":"approval.only_denied_queries","params":{}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":4} -> 409 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals {"reason":"r","sourceDecisionId":1} -> 400 {"code":"approval.role_required","params":{}}
            req POST /api/approvals {"reason":" from a denial ","sourceDecisionId":1,"roleId":17,"title":"  "} -> 201 {"request":{"id":10,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"from a denial","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select ssn from users","sqlHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","statementCount":1,"denyReason":"ssn is pii","sourceDecisionId":1,"evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","source":"console","revision":1,"contentHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","rawHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","forceRun":false,"ccs":[]},"wouldAllow":false}
            req POST /api/approvals {"reason":"again","sourceDecisionId":1,"roleId":17} -> 409 {"code":"approval.pending_request_exists","params":{}}
            req POST /api/approvals {"reason":"r","sql":"select 1"} -> 400 {"code":"common.field_required","params":{"fields":"datasourceId"}}
            req POST /api/approvals {"reason":"r","datasourceId":1} -> 400 {"code":"common.field_required","params":{"fields":"sql"}}
            req POST /api/approvals {"reason":"r","datasourceId":1,"sql":"  "} -> 400 {"code":"common.field_required","params":{"fields":"sql"}}
            req POST /api/approvals {"reason":"r","datasourceId":1,"sql":"select 1"} -> 400 {"code":"common.field_required","params":{"fields":"title"}}
            req POST /api/approvals {"reason":"r","datasourceId":99999,"sql":"select 1","title":"t"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals {"reason":"r","datasourceId":4,"sql":"select 1","title":"t"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals {"reason":"r","datasourceId":3,"sql":"select 1","title":"t","roleId":17} -> 403 {"code":"common.forbidden","params":{}}
            req POST /api/approvals {"reason":"r","datasourceId":1,"sql":"select 1","title":"t"} -> 400 {"code":"approval.role_required","params":{}}
            req POST /api/approvals {"reason":"r","datasourceId":1,"sql":"select 'open","title":"t","roleId":17} -> 400 {"code":"approval.unsplittable_sql","params":{}}
            req POST /api/approvals {"reason":" plain ","datasourceId":1,"sql":"select id from users","title":" ids ","roleId":17} -> 201 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"wouldAllow":true}
            req POST /api/approvals {"reason":"masked","datasourceId":1,"sql":"select id, ssn from users where ssn = '1'","title":"ssn","roleId":17,"requestedDurationSec":60} -> 201 {"request":{"id":12,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"masked","requestedDurationSec":60,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id, ssn from users where ssn = '1'","sqlHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","statementCount":1,"denyReason":"protected column def.{target}.users.ssn appears in a position that cannot be masked (a write payload or a subquery/reference)","title":"ssn","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"contentHash":"36988b23b0499a371bc0481b0a355a5606a7cb4fb37a81854f7cbd415a3081e1","rawHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","forceRun":false,"ccs":[]},"wouldAllow":false}
            req POST /api/approvals {"reason":"denied","datasourceId":1,"sql":"select id from orders;\nselect id from users","title":"batch","roleId":17} -> 201 {"request":{"id":13,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"denied","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from orders;\nselect id from users","sqlHash":"f862b21b54f2f156b019e23a6cf2e3e9020c755cf31b28c0bb0a70c18b52c140","statementCount":2,"denyReason":"policy denies column def.{target}.orders.id","title":"batch","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"3f3a3eb8ac96b14add82ede633e696294b632e7f13720b732e61fe6c5ce5a00d","rawHash":"dd60771e1b549bf2d8e2a664aa7fc4d95151c520cdffb3ac32bbd2211e15b6ba","forceRun":false,"ccs":[]},"wouldAllow":false}
            req POST /api/approvals {"reason":"pg","datasourceId":2,"sql":"select \"id\" from t; select 2","title":"pg","roleId":16} -> 201 {"request":{"id":14,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":2,"datasourceName":"approvals-pg","reason":"pg","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select \"id\" from t;\nselect 2","sqlHash":"c3703e0786c683c2cf64c02cbcd12b161eb9cbcb69d62eadf1933edd4411399d","statementCount":2,"denyReason":"no access to datasource 'approvals-pg'","title":"pg","evaluatedDecision":"DENY","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","source":"console","revision":1,"contentHash":"a72624240ecbbcb7cac2a73ec57fd3042dfac7b394ee61d3efe6a92487cee228","rawHash":"098b1cfebe91572ef0c8a55e37678044c74f680fbdb2f63864f77cddb9c8988d","forceRun":false,"ccs":[]},"wouldAllow":false}
            anon GET /api/approvals/inbox -> 401 {"code":"common.unauthenticated","params":{}}
            req GET /api/approvals/inbox -> 200 []
            appr GET /api/approvals/inbox -> 200 [{"id":14,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":2,"datasourceName":"approvals-pg","reason":"pg","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select \"id\" from t;\nselect 2","sqlHash":"c3703e0786c683c2cf64c02cbcd12b161eb9cbcb69d62eadf1933edd4411399d","statementCount":2,"denyReason":"no access to datasource 'approvals-pg'","title":"pg","evaluatedDecision":"DENY","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","source":"console","revision":1,"contentHash":"a72624240ecbbcb7cac2a73ec57fd3042dfac7b394ee61d3efe6a92487cee228","rawHash":"098b1cfebe91572ef0c8a55e37678044c74f680fbdb2f63864f77cddb9c8988d","forceRun":false,"ccs":[]},{"id":13,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"denied","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from orders;\nselect id from users","sqlHash":"f862b21b54f2f156b019e23a6cf2e3e9020c755cf31b28c0bb0a70c18b52c140","statementCount":2,"denyReason":"policy denies column def.{target}.orders.id","title":"batch","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"3f3a3eb8ac96b14add82ede633e696294b632e7f13720b732e61fe6c5ce5a00d","rawHash":"dd60771e1b549bf2d8e2a664aa7fc4d95151c520cdffb3ac32bbd2211e15b6ba","forceRun":false,"ccs":[]},{"id":12,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"masked","requestedDurationSec":60,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id, ssn from users where ssn = '1'","sqlHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","statementCount":1,"denyReason":"protected column def.{target}.users.ssn appears in a position that cannot be masked (a write payload or a subquery/reference)","title":"ssn","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"contentHash":"36988b23b0499a371bc0481b0a355a5606a7cb4fb37a81854f7cbd415a3081e1","rawHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","forceRun":false,"ccs":[]},{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},{"id":10,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"from a denial","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select ssn from users","sqlHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","statementCount":1,"denyReason":"ssn is pii","sourceDecisionId":1,"evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","source":"console","revision":1,"contentHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","rawHash":"89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28","forceRun":false,"ccs":[]},{"id":5,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"github","scope":"s","fileKey":"1","changeKey":"k","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","pullRequest":{"repository":"acme/db","pr":7,"prUrl":"https://example.com/pr/7","path":"sql/1.sql","headSha":"abc","prAutoMerge":false},"forceRun":false,"ccs":[]},{"id":4,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":4,"datasourceName":"approvals-gone","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select 1","sqlHash":"822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"rawHash":"822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f","forceRun":false,"ccs":[]},{"id":3,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":3,"datasourceName":"approvals-locked","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select 1","sqlHash":"822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"rawHash":"822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f","forceRun":false,"ccs":[]}]
            out GET /api/approvals/inbox -> 200 []
            req GET /api/approvals/x -> 400 {"code":"common.bad_id","params":{}}
            anon GET /api/approvals/11 -> 401 {"code":"common.unauthenticated","params":{}}
            req GET /api/approvals/99999 -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            req GET /api/approvals/1 -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            req GET /api/approvals/2 -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out GET /api/approvals/11 -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            req GET /api/approvals/11 -> 200 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":true,"canComment":true,"canCc":true,"timeline":[{"id":9,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":false,"canCancel":false,"canEdit":true,"canForceRun":false}
            appr GET /api/approvals/11 -> 200 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":true,"canApproveAndRun":true,"canReject":true,"canUnapprove":false,"canClose":false,"canComment":false,"canCc":false,"timeline":[{"id":9,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
            appr GET /api/approvals/7 -> 200 {"request":{"id":7,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"EXECUTED","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":false,"canComment":false,"canCc":false,"timeline":[{"id":5,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":7,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","rowCount":2,"expiresAt":"{at}","status":"DONE","columns":["id"]},"statements":[{"taskId":7,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","rowCount":2,"expiresAt":"{at}","status":"DONE","columns":["id"]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
            req GET /api/approvals/7 -> 200 {"request":{"id":7,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"EXECUTED","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":false,"canComment":true,"canCc":true,"timeline":[{"id":5,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":7,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","rowCount":2,"expiresAt":"{at}","status":"DONE","columns":["id"]},"statements":[{"taskId":7,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","rowCount":2,"expiresAt":"{at}","status":"DONE","columns":["id"]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
            appr GET /api/approvals/8 -> 200 {"request":{"id":8,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":true,"canUnapprove":true,"canClose":true,"canComment":false,"canCc":false,"timeline":[{"id":6,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":8,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":8,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
            appr GET /api/approvals/5 -> 200 {"request":{"id":5,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"github","scope":"s","fileKey":"1","changeKey":"k","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","pullRequest":{"repository":"acme/db","pr":7,"prUrl":"https://example.com/pr/7","path":"sql/1.sql","headSha":"abc","prAutoMerge":false},"forceRun":false,"ccs":[]},"canDecide":true,"canApproveAndRun":false,"canReject":true,"canUnapprove":false,"canClose":false,"canComment":false,"canCc":false,"timeline":[{"id":3,"kind":"requested","actor":"req@example.com","revision":1,"origin":"github","createdAt":"{at}","deleted":false}],"result":{"taskId":5,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":5,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
            req GET /api/approvals/6 -> 200 {"request":{"id":6,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"EXECUTING","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users;\nselect email from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":2,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executingAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"697089ba498b85181cc9c46ecec39cf87fdca87c94e8035293ad3e524e6a12b2","rawHash":"2ea4689a79863a88a9663785fdd554af8486b957110844ae96ea89bc6959c92a","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":false,"canComment":true,"canCc":true,"timeline":[{"id":4,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":6,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","status":"RUNNING","columns":[]},"statements":[{"taskId":6,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","status":"RUNNING","columns":[]},{"taskId":6,"ordinal":1,"sql":"select email from users","executedAt":"{at}","columns":[]}],"canExecute":false,"canCancel":true,"canEdit":false,"canForceRun":false}
            appr POST /api/approvals/x/approve {"revision":1} -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/11/approve {"revision":1} -> 401 {"code":"common.unauthenticated","params":{}}
            appr POST /api/approvals/11/approve -> 400 {"code":"common.field_required","params":{"fields":"revision"}}
            appr POST /api/approvals/11/approve {"revision":"one"} -> 400 {"code":"common.field_required","params":{"fields":"revision"}}
            appr POST /api/approvals/99999/approve {"revision":1} -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            appr POST /api/approvals/2/approve {"revision":1} -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/11/approve {"revision":1} -> 403 {"code":"approval.not_approver","params":{}}
            req POST /api/approvals/11/approve {"revision":1} -> 403 {"code":"approval.not_approver","params":{}}
            appr POST /api/approvals/11/approve {"revision":2} -> 409 {"code":"approval.request_changed","params":{}}
            appr POST /api/approvals/11/approve {"revision":1} -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]}
            appr POST /api/approvals/11/approve {"revision":1} -> 409 {"code":"approval.already_decided","params":{}}
            appr POST /api/approvals/12/approve {"revision":1} -> 200 {"id":12,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"masked","requestedDurationSec":60,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id, ssn from users where ssn = '1'","sqlHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","statementCount":1,"denyReason":"protected column def.{target}.users.ssn appears in a position that cannot be masked (a write payload or a subquery/reference)","title":"ssn","evaluatedDecision":"DENY","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"contentHash":"36988b23b0499a371bc0481b0a355a5606a7cb4fb37a81854f7cbd415a3081e1","rawHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","forceRun":false,"ccs":[]}
            appr POST /api/approvals/7/approve {"revision":1} -> 409 {"code":"approval.already_decided","params":{}}
            appr GET /api/approvals/11 -> 200 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":true,"canUnapprove":true,"canClose":true,"canComment":false,"canCc":false,"timeline":[{"id":9,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":13,"kind":"approved","actor":"appr@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":true,"canCancel":false,"canEdit":false,"canForceRun":false}
            req GET /api/approvals/11 -> 200 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":true,"canComment":true,"canCc":true,"timeline":[{"id":9,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":13,"kind":"approved","actor":"appr@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":11,"ordinal":0,"sql":"select id from users","executedAt":"{at}","columns":[]}],"canExecute":true,"canCancel":false,"canEdit":true,"canForceRun":false}
            appr POST /api/approvals/x/unapprove -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/11/unapprove -> 401 {"code":"common.unauthenticated","params":{}}
            appr POST /api/approvals/99999/unapprove -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/11/unapprove -> 403 {"code":"approval.not_approver","params":{}}
            req POST /api/approvals/11/unapprove -> 403 {"code":"approval.not_approver","params":{}}
            appr POST /api/approvals/13/unapprove -> 409 {"code":"approval.not_approved","params":{}}
            appr POST /api/approvals/5/unapprove -> 409 {"code":"approval.not_approved","params":{}}
            appr POST /api/approvals/11/unapprove -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]}
            appr POST /api/approvals/11/unapprove -> 409 {"code":"approval.not_approved","params":{}}
            appr POST /api/approvals/x/reject {"reason":"no"} -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/13/reject {"reason":"no"} -> 401 {"code":"common.unauthenticated","params":{}}
            appr POST /api/approvals/13/reject -> 500 {"code":"common.fallback","params":{}}
            appr POST /api/approvals/13/reject {} -> 500 {"code":"common.fallback","params":{}}
            appr POST /api/approvals/13/reject {"reason":"  "} -> 400 {"code":"common.field_required","params":{"fields":"reason"}}
            appr POST /api/approvals/99999/reject {"reason":"no"} -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/13/reject {"reason":"no"} -> 403 {"code":"approval.not_approver","params":{}}
            appr POST /api/approvals/7/reject {"reason":"no"} -> 409 {"code":"approval.already_decided","params":{}}
            appr POST /api/approvals/13/reject {"reason":" not now "} -> 200 {"id":13,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"denied","requestedDurationSec":3600,"status":"REJECTED","decidedBy":"appr@example.com","decidedAt":"{at}","rejectionReason":"not now","createdAt":"{at}","kind":"QUERY","sql":"select id from orders;\nselect id from users","sqlHash":"f862b21b54f2f156b019e23a6cf2e3e9020c755cf31b28c0bb0a70c18b52c140","statementCount":2,"denyReason":"policy denies column def.{target}.orders.id","title":"batch","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"3f3a3eb8ac96b14add82ede633e696294b632e7f13720b732e61fe6c5ce5a00d","rawHash":"dd60771e1b549bf2d8e2a664aa7fc4d95151c520cdffb3ac32bbd2211e15b6ba","forceRun":false,"ccs":[]}
            appr POST /api/approvals/13/reject {"reason":"again"} -> 409 {"code":"approval.already_decided","params":{}}
            appr POST /api/approvals/12/reject {"reason":"after approval"} -> 200 {"id":12,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"masked","requestedDurationSec":60,"status":"REJECTED","decidedBy":"appr@example.com","decidedAt":"{at}","rejectionReason":"after approval","createdAt":"{at}","kind":"QUERY","sql":"select id, ssn from users where ssn = '1'","sqlHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","statementCount":1,"denyReason":"protected column def.{target}.users.ssn appears in a position that cannot be masked (a write payload or a subquery/reference)","title":"ssn","evaluatedDecision":"DENY","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":true,"source":"console","revision":1,"contentHash":"36988b23b0499a371bc0481b0a355a5606a7cb4fb37a81854f7cbd415a3081e1","rawHash":"dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930","forceRun":false,"ccs":[]}
            req POST /api/approvals/x/edit {"sql":"select 1"} -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/11/edit {"sql":"select 1"} -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/approvals/11/edit -> 500 {"code":"common.fallback","params":{}}
            req POST /api/approvals/11/edit {} -> 500 {"code":"common.fallback","params":{}}
            req POST /api/approvals/99999/edit {"sql":"select 1"} -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/11/edit {"sql":"select 1"} -> 403 {"code":"approval.edit_forbidden","params":{}}
            req POST /api/approvals/5/edit {"sql":"select 1"} -> 409 {"code":"approval.github_edit_by_push","params":{}}
            req POST /api/approvals/13/edit {"sql":"select 1"} -> 409 {"code":"approval.not_editable","params":{}}
            req POST /api/approvals/11/edit {"sql":"  "} -> 400 {"code":"common.field_required","params":{"fields":"sql"}}
            req POST /api/approvals/11/edit {"sql":"select 1","reason":" "} -> 400 {"code":"common.field_required","params":{"fields":"reason"}}
            req POST /api/approvals/4/edit {"sql":"select 1"} -> 404 {"code":"common.not_found","params":{"resource":"datasource"}}
            req POST /api/approvals/3/edit {"sql":"select 2"} -> 403 {"code":"common.forbidden","params":{}}
            req POST /api/approvals/11/edit {"sql":"select 'open"} -> 400 {"code":"approval.unsplittable_sql","params":{}}
            appr POST /api/approvals/11/approve {"revision":1} -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"plain","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"ids","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]}
            req POST /api/approvals/11/edit {"sql":"SELECT id\nFROM users -- same\n","title":" same sql ","reason":" kept "} -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"same sql","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]}
            req POST /api/approvals/11/edit {"sql":"select id, email from users; select ssn from users","title":"  "} -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id, email from users;\nselect ssn from users","sqlHash":"26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c","statementCount":2,"title":"same sql","evaluatedDecision":"MASK","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":2,"revisedAt":"{at}","contentHash":"5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde","rawHash":"69b9664c7941ee378679690428bff2f94ec216eab742c1a4049f9678509ca3f9","forceRun":false,"ccs":[]}
            appr POST /api/approvals/11/approve {"revision":1} -> 409 {"code":"approval.request_changed","params":{}}
            appr POST /api/approvals/11/approve {"revision":2} -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id, email from users;\nselect ssn from users","sqlHash":"26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c","statementCount":2,"title":"same sql","evaluatedDecision":"MASK","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":2,"revisedAt":"{at}","contentHash":"5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde","rawHash":"69b9664c7941ee378679690428bff2f94ec216eab742c1a4049f9678509ca3f9","forceRun":false,"ccs":[]}
            req GET /api/approvals/11 -> 200 {"request":{"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"APPROVED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id, email from users;\nselect ssn from users","sqlHash":"26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c","statementCount":2,"title":"same sql","evaluatedDecision":"MASK","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":2,"revisedAt":"{at}","contentHash":"5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde","rawHash":"69b9664c7941ee378679690428bff2f94ec216eab742c1a4049f9678509ca3f9","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":true,"canComment":true,"canCc":true,"timeline":[{"id":9,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":13,"kind":"approved","actor":"appr@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":15,"kind":"unapproved","actor":"appr@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":18,"kind":"approved","actor":"appr@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":19,"kind":"edited","actor":"req@example.com","revision":2,"origin":"console","createdAt":"{at}","deleted":false},{"id":20,"kind":"approved","actor":"appr@example.com","revision":2,"origin":"console","createdAt":"{at}","deleted":false}],"result":{"taskId":11,"ordinal":0,"sql":"select id, email from users","executedAt":"{at}","columns":[]},"statements":[{"taskId":11,"ordinal":0,"sql":"select id, email from users","executedAt":"{at}","columns":[]},{"taskId":11,"ordinal":1,"sql":"select ssn from users","executedAt":"{at}","columns":[]}],"canExecute":true,"canCancel":false,"canEdit":true,"canForceRun":false}
            appr POST /api/approvals/x/execute -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/8/execute -> 401 {"code":"common.unauthenticated","params":{}}
            appr POST /api/approvals/99999/execute -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/8/execute -> 403 {"code":"approval.not_runner","params":{}}
            appr POST /api/approvals/5/execute -> 409 {"code":"approval.github_runs_on_merge","params":{}}
            appr POST /api/approvals/7/execute -> 409 {"code":"approval.already_executed","params":{}}
            appr POST /api/approvals/13/execute -> 409 {"code":"approval.not_approved","params":{}}
            appr POST /api/approvals/8/execute -> 409 {"code":"approval.expired","params":{}}
            appr POST /api/approvals/9/execute -> 409 {"code":"approval.no_execute_role","params":{}}
            appr GET /api/approvals/x/result -> 400 {"code":"common.bad_id","params":{}}
            appr GET /api/approvals/7/result?statement=-1 -> 400 {"code":"common.bad_id","params":{}}
            anon GET /api/approvals/7/result -> 401 {"code":"common.unauthenticated","params":{}}
            appr GET /api/approvals/99999/result -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out GET /api/approvals/7/result -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            appr GET /api/approvals/7/result -> 410 {"code":"approval.result_expired","params":{}}
            appr GET /api/approvals/7/result?statement=1 -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            appr GET /api/approvals/13/result -> 409 {"code":"approval.result_not_ready","params":{}}
            appr POST /api/approvals/x/force-run -> 400 {"code":"common.bad_id","params":{}}
            appr POST /api/approvals/5/force-run -> 403 {"code":"approval.not_approver","params":{}}
            admin POST /api/approvals/13/force-run -> 409 {"code":"approval.already_decided","params":{}}
            admin POST /api/approvals/5/force-run -> 200 {"id":5,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"github","scope":"s","fileKey":"1","changeKey":"k","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","pullRequest":{"repository":"acme/db","pr":7,"prUrl":"https://example.com/pr/7","path":"sql/1.sql","headSha":"abc","prAutoMerge":false},"forceRun":true,"forceRunBy":"admin@example.com","ccs":[]}
            admin POST /api/approvals/5/force-run -> 200 {"id":5,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"PENDING","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"github","scope":"s","fileKey":"1","changeKey":"k","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","pullRequest":{"repository":"acme/db","pr":7,"prUrl":"https://example.com/pr/7","path":"sql/1.sql","headSha":"abc","prAutoMerge":false},"forceRun":true,"forceRunBy":"admin@example.com","ccs":[]}
            req POST /api/approvals/x/cancel -> 400 {"code":"common.bad_id","params":{}}
            anon POST /api/approvals/11/cancel -> 401 {"code":"common.unauthenticated","params":{}}
            req POST /api/approvals/99999/cancel -> 404 {"code":"common.not_found","params":{"resource":"query approval request"}}
            out POST /api/approvals/11/cancel -> 403 {"code":"approval.cancel_forbidden","params":{}}
            req POST /api/approvals/7/cancel -> 200 {"id":7,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"EXECUTED","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":1,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","rawHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","forceRun":false,"ccs":[]}
            req POST /api/approvals/13/cancel -> 409 {"code":"approval.not_cancelable","params":{}}
            req POST /api/approvals/5/cancel -> 409 {"code":"approval.not_cancelable","params":{}}
            req POST /api/approvals/11/cancel -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id, email from users;\nselect ssn from users","sqlHash":"26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c","statementCount":2,"title":"same sql","evaluatedDecision":"MASK","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":2,"revisedAt":"{at}","contentHash":"5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde","rawHash":"69b9664c7941ee378679690428bff2f94ec216eab742c1a4049f9678509ca3f9","forceRun":false,"ccs":[]}
            req POST /api/approvals/11/cancel -> 200 {"id":11,"principal":"req@example.com","roleId":17,"roleName":"approvals-full","datasourceId":1,"datasourceName":"approvals-mysql","reason":"kept","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id, email from users;\nselect ssn from users","sqlHash":"26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c","statementCount":2,"title":"same sql","evaluatedDecision":"MASK","approvedAt":"{at}","executeAs":["approvals-full"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":2,"revisedAt":"{at}","contentHash":"5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde","rawHash":"69b9664c7941ee378679690428bff2f94ec216eab742c1a4049f9678509ca3f9","forceRun":false,"ccs":[]}
            req POST /api/approvals/6/cancel -> 200 {"id":6,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users;\nselect email from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":2,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executingAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"697089ba498b85181cc9c46ecec39cf87fdca87c94e8035293ad3e524e6a12b2","rawHash":"2ea4689a79863a88a9663785fdd554af8486b957110844ae96ea89bc6959c92a","forceRun":false,"ccs":[]}
            req GET /api/approvals/6 -> 200 {"request":{"id":6,"principal":"req@example.com","roleId":16,"roleName":"approvals-reader","datasourceId":1,"datasourceName":"approvals-mysql","reason":"seeded","requestedDurationSec":3600,"status":"CANCELLED","decidedBy":"appr@example.com","executedBy":"appr@example.com","decidedAt":"{at}","createdAt":"{at}","kind":"QUERY","sql":"select id from users;\nselect email from users","sqlHash":"9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1","statementCount":2,"title":"seeded","evaluatedDecision":"ALLOW","approvedAt":"{at}","executingAt":"{at}","executeAs":["approvals-reader"],"creatorKind":"WORKFLOW","statementCarriesProtectedLiteral":false,"source":"console","revision":1,"contentHash":"697089ba498b85181cc9c46ecec39cf87fdca87c94e8035293ad3e524e6a12b2","rawHash":"2ea4689a79863a88a9663785fdd554af8486b957110844ae96ea89bc6959c92a","forceRun":false,"ccs":[]},"canDecide":false,"canApproveAndRun":false,"canReject":false,"canUnapprove":false,"canClose":false,"canComment":true,"canCc":true,"timeline":[{"id":4,"kind":"requested","actor":"req@example.com","revision":1,"origin":"console","createdAt":"{at}","deleted":false},{"id":22,"kind":"cancelled","revision":1,"origin":"system","createdAt":"{at}","deleted":false}],"result":{"taskId":6,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","expiresAt":"{at}","status":"CANCELLED","errorCode":"approval.canceled","columns":[]},"statements":[{"taskId":6,"ordinal":0,"sql":"select id from users","executedBy":"appr@example.com","executedAt":"{at}","expiresAt":"{at}","status":"CANCELLED","errorCode":"approval.canceled","columns":[]},{"taskId":6,"ordinal":1,"sql":"select email from users","executedAt":"{at}","expiresAt":"{at}","status":"SKIPPED","columns":[]}],"canExecute":false,"canCancel":false,"canEdit":false,"canForceRun":false}
        """
        const val EXPECTED_REQUESTS = """
            1 | PENDING | 1 |  | role | 16 |  |  |  |  |  |  |  |  | 3600 | console
            2 | APPROVED | 1 |  |  |  | ["approvals-reader"] |  |  |  |  |  | req@example.com |  | 3600 | console
            3 | PENDING | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false |  |  |  | 3600 | console
            4 | PENDING | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false |  |  |  | 3600 | console
            5 | PENDING | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 |  |  | 3600 | github
            6 | CANCELLED | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false | 697089ba498b85181cc9c46ecec39cf87fdca87c94e8035293ad3e524e6a12b2 | appr@example.com |  | 3600 | console
            7 | EXECUTED | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 | appr@example.com |  | 3600 | console
            8 | APPROVED | 1 | seeded | seeded | 16 | ["approvals-reader"] |  |  | ALLOW | false | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 | appr@example.com |  | 3600 | console
            9 | APPROVED | 1 | seeded | seeded | 19 | ["approvals-dropped"] |  |  | ALLOW | false |  | appr@example.com |  | 3600 | console
            10 | PENDING | 1 |  | from a denial | 17 | ["approvals-full"] | 1 | ssn is pii | DENY |  | 89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28 |  |  | 3600 | console
            11 | CANCELLED | 2 | same sql | kept | 17 | ["approvals-full"] |  |  | MASK | false | 5ecb202cb2dc907d3ef5d9e2f77d43855ec7208b77029c9a61047d84c0bf9dde | appr@example.com |  | 3600 | console
            12 | REJECTED | 1 | ssn | masked | 17 | ["approvals-full"] |  | protected column def.{target}.users.ssn appears in a position that cannot be masked (a write payload or a subquery/reference) | DENY | true | 36988b23b0499a371bc0481b0a355a5606a7cb4fb37a81854f7cbd415a3081e1 | appr@example.com | after approval | 60 | console
            13 | REJECTED | 1 | batch | denied | 17 | ["approvals-full"] |  | policy denies column def.{target}.orders.id | DENY | false | 3f3a3eb8ac96b14add82ede633e696294b632e7f13720b732e61fe6c5ce5a00d | appr@example.com | not now | 3600 | console
            14 | PENDING | 1 | pg | pg | 16 | ["approvals-reader"] |  | no access to datasource 'approvals-pg' | DENY |  | a72624240ecbbcb7cac2a73ec57fd3042dfac7b394ee61d3efe6a92487cee228 |  |  | 3600 | console
        """
        const val EXPECTED_STATEMENTS = """
            2 | 0 | select 1 | 822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f |  |
            3 | 0 | select 1 | 822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f |  |
            4 | 0 | select 1 | 822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f |  |
            5 | 0 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 |  |
            6 | 0 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 | CANCELLED | approval.canceled
            6 | 1 | select email from users | 2cae92e65aadfe981daf573de984d2c6c4e30b48e3c2bd9bd484f47d190e2629 | SKIPPED |
            7 | 0 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 | DONE |
            8 | 0 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 |  |
            9 | 0 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 |  |
            10 | 0 | select ssn from users | 89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28 |  |
            11 | 0 | select id, email from users | 26b363c79caf4e90fdd40fb8c5b726ad2473aad255f2c62e37ddf8d31f4b7b1c |  |
            11 | 1 | select ssn from users | 89c36f077e3e8aa2ec3bb301382a8151da8e86ce4c99583676353a6f36fd6c28 |  |
            12 | 0 | select id, ssn from users where ssn = '1' | dc43f9cfecbdff06e4e23d338e82dd0cbc858c2b37d088fc7f22462474160930 |  |
            13 | 0 | select id from orders | f862b21b54f2f156b019e23a6cf2e3e9020c755cf31b28c0bb0a70c18b52c140 |  |
            13 | 1 | select id from users | 9ab0bfb70351312e24242cd3b72094a32421ccae07ed3ead140a8499d36a13d1 |  |
            14 | 0 | select "id" from t | c3703e0786c683c2cf64c02cbcd12b161eb9cbcb69d62eadf1933edd4411399d |  |
            14 | 1 | select 2 | 3cf988cc782b44bc24ceb17e445d9c3cfd06b6c848ecfff949e1bfdb9f705a61 |  |
        """
        const val EXPECTED_EVENTS = """
            3 | requested | req@example.com |  | 1 | console
            4 | requested | req@example.com |  | 1 | console
            5 | requested | req@example.com |  | 1 | github
            6 | requested | req@example.com |  | 1 | console
            7 | requested | req@example.com |  | 1 | console
            8 | requested | req@example.com |  | 1 | console
            9 | requested | req@example.com |  | 1 | console
            10 | requested | req@example.com |  | 1 | console
            11 | requested | req@example.com |  | 1 | console
            12 | requested | req@example.com |  | 1 | console
            13 | requested | req@example.com |  | 1 | console
            14 | requested | req@example.com |  | 1 | console
            11 | approved | appr@example.com |  | 1 | console
            12 | approved | appr@example.com |  | 1 | console
            11 | unapproved | appr@example.com |  | 1 | console
            13 | rejected | appr@example.com | not now | 1 | console
            12 | rejected | appr@example.com | after approval | 1 | console
            11 | approved | appr@example.com |  | 1 | console
            11 | edited | req@example.com |  | 2 | console
            11 | approved | appr@example.com |  | 2 | console
            11 | closed | req@example.com |  | 2 | console
            6 | cancelled |  |  | 1 | system
        """
        const val EXPECTED_PARTICIPANTS = """
            11 | appr@example.com | approver
            12 | appr@example.com | approver
            13 | appr@example.com | approver
        """
        const val EXPECTED_AUDIT = """
            admin | req@example.com | task.request | AccessRequest::"10" | open query request #10 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"11" | open query request #11 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"12" | open query request #12 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"13" | open query request #13 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"14" | open query request #14 under role 'approvals-reader' | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"11" | approve query request #11 revision 1 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"12" | approve query request #12 revision 1 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"11" | withdraw the approval of query request #11 (unapproved by appr@example.com) | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"13" | reject query request #13 revision 1 | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"12" | reject query request #12 revision 1 | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"11" | approve query request #11 revision 1 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"11" | edit query request #11 at revision 1 (same sql) | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.request | AccessRequest::"11" | edit query request #11 to revision 2 (sql 1c2bf9df786c) | 127.0.0.1 | console |  | ALLOW
            admin | appr@example.com | task.approve | AccessRequest::"11" | approve query request #11 revision 2 under role 'approvals-full' | 127.0.0.1 | console |  | ALLOW
            admin | admin@example.com | task.force_run | AccessRequest::"5" | force-run query request #5 past the scope checks | 127.0.0.1 | console |  | ALLOW
            admin | req@example.com | task.cancel | AccessRequest::"11" | close request #11 | 127.0.0.1 | console |  | ALLOW
            approval_lifecycle | req@example.com |  |  | approval #6 result-canceled |  | workflow-executor | APPROVER_EXEC result-canceled | ALLOW
        """
    }
}
