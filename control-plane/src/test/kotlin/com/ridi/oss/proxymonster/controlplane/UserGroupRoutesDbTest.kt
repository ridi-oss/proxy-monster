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
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The user and group admin routes over HTTP: status, body, and the rows each write leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserGroupRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val admin = "ug-admin@example.com"
    private val viewer = "ug-viewer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_user_group_routes")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(admin, viewer)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        core.policyStore.createRole(RoleInput(ROLE))
        core.userGroupStore.createUser(AppUserInput(principal = MEMBER), core.tokenStore, core.accessStore, sessions)
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "user-group-routes-secret", oidc = null, resultKey = null, scimToken = null,
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

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    /** The rows of the users the user test writes, as `principal source active`. */
    private fun users(): String = rows(
        "SELECT principal || ' ' || source || ' ' || active FROM app_user WHERE principal IN ('ug-bob@example.com', 'ug-carol@example.com', 'ug-robert@example.com') ORDER BY principal",
    )

    /** Every group row whose name starts with `ug-`, with its members and roles. */
    private fun groups(): String = rows(
        """SELECT g.name || ' ' || g.source || ' ' || coalesce(g.description, '-') || ' members=' ||
                  coalesce((SELECT string_agg(u.principal, ',' ORDER BY u.principal) FROM group_member m JOIN app_user u ON u.id = m.user_id WHERE m.group_id = g.id), '-') ||
                  ' roles=' || coalesce((SELECT string_agg(r.name, ',' ORDER BY r.name) FROM group_role gr JOIN app_role r ON r.id = gr.role_id WHERE gr.group_id = g.id), '-')
           FROM app_group g WHERE g.name LIKE 'ug-%' AND g.deleted_at IS NULL ORDER BY g.name""",
    )

    /** The live credentials [principal] holds, as `tokens grants sessions`. */
    private fun credentials(principal: String): String = rows(
        """SELECT (SELECT count(*) FROM proxy_token WHERE principal = '$principal' AND revoked_at IS NULL) || ' ' ||
                  (SELECT count(*) FROM access_grant WHERE principal = '$principal' AND revoked_at IS NULL) || ' ' ||
                  (SELECT count(*) FROM principal_session WHERE principal = '$principal' AND ended_at IS NULL AND liveness_status = 'ACTIVE')""",
    )

    /** A token, a JIT grant and a web session for [principal], so a deactivation has something to revoke. */
    private fun holdCredentials(principal: String) {
        val role = core.policyStore.getRoleByName(ROLE)!!.id
        exec("""INSERT INTO proxy_token (token_hash, kind, principal, expires_at) VALUES (md5(random()::text), 'USER', '$principal', now() + interval '1 hour')""")
        exec("""INSERT INTO access_grant (principal, role_id, granted_by, granted_at, expires_at) VALUES ('$principal', $role, 'seed', now(), now() + interval '1 hour')""")
        exec("""INSERT INTO principal_session (kind, principal, session_key, absolute_expires_at) VALUES ('WEB', '$principal', md5(random()::text), now() + interval '1 hour')""")
    }

    private fun ids(text: String, names: Map<Long, String>) = names.entries.sortedByDescending { it.key }.fold(text) { acc, (id, name) ->
        acc.replace(Regex("""(/api/(?:users|groups)/|/members/|/roles/|"id":|"userId":|"roleId":|User::"|Group::"|Role::"|#)$id\b""")) { "${it.groupValues[1]}{$name}" }
    }

    @Test
    fun `user writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val before = lastAuditId()
        val created = t.send("POST", "/api/users", """{"principal":"ug-bob@example.com","displayName":"Bob","email":"bob@example.com"}""")
        val bob = idOf(created, t.lines.last())
        t.send("POST", "/api/users", """{"principal":"ug-bob@example.com"}""")
        t.send("POST", "/api/users", """{"principal":" "}""")
        val carol = idOf(t.send("POST", "/api/users", """{"principal":"ug-carol@example.com","active":false}"""), t.lines.last())
        holdCredentials("ug-bob@example.com")
        t.send("PUT", "/api/users/$bob", """{"principal":"ug-bob@example.com","displayName":"Robert","email":"bob@example.com"}""")
        val held = credentials("ug-bob@example.com")
        t.send("PUT", "/api/users/$bob", """{"principal":"ug-bob@example.com","displayName":"Robert","active":false}""")
        val deactivated = credentials("ug-bob@example.com")
        t.send("PUT", "/api/users/$bob", """{"principal":"ug-bob@example.com","displayName":"Robert","active":true}""")
        holdCredentials("ug-bob@example.com")
        t.send("PUT", "/api/users/$bob", """{"principal":"ug-robert@example.com","displayName":"Robert","active":true}""")
        val renamedFrom = credentials("ug-bob@example.com")
        t.send("PUT", "/api/users/$bob", """{"principal":"ug-carol@example.com"}""")
        t.send("PUT", "/api/users/999999", """{"principal":"ug-nobody@example.com"}""")
        t.send("PUT", "/api/users/abc", """{"principal":"ug-nobody@example.com"}""")
        t.send("PUT", "/api/users/$bob", """{"principal":" "}""")
        t.send("GET", "/api/users")
        holdCredentials("ug-robert@example.com")
        t.send("DELETE", "/api/users/$bob")
        val deprovisioned = credentials("ug-robert@example.com")
        t.send("DELETE", "/api/users/$bob")
        t.send("DELETE", "/api/users/999999")
        t.send("DELETE", "/api/users/abc")
        val others = rows("SELECT id || ' ' || split_part(principal, '@', 1) FROM app_user WHERE id NOT IN ($bob, $carol)")
            .lines().associate { it.substringBefore(' ').toLong() to it.substringAfter(' ') }
        val names = others + mapOf(bob to "bob", carol to "carol")
        assertEquals(EXPECTED_USERS.trim(), ids(t.text().lines().filterNot { it.startsWith("GET /api/users ->") }.joinToString("\n"), names))
        assertEquals(EXPECTED_USER_LIST.trim(), ids(t.lines.single { it.startsWith("GET /api/users ->") }, names))
        assertEquals(EXPECTED_USER_ROWS.trim(), users())
        assertEquals(EXPECTED_CREDENTIALS.trim(), "held $held\ndeactivated $deactivated\nrenamed-from $renamedFrom\ndeprovisioned $deprovisioned")
        assertEquals(EXPECTED_USER_AUDIT.trim(), ids(auditSince(before), names))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `group writes`() = testApplication {
        val t = Transcript(clients(admin).single())
        val member = rows("SELECT id FROM app_user WHERE principal = '$MEMBER'").toLong()
        val role = core.policyStore.getRoleByName(ROLE)!!.id
        val system = rows("SELECT id FROM app_group WHERE source = 'SYSTEM' ORDER BY id LIMIT 1").toLong()
        val before = lastAuditId()
        val g = idOf(t.send("POST", "/api/groups", """{"name":"ug-eng","description":"engineering"}"""), t.lines.last())
        t.send("POST", "/api/groups", """{"name":"ug-eng"}""")
        t.send("POST", "/api/groups", """{"name":" "}""")
        t.send("PUT", "/api/groups/$g", """{"name":"ug-engineering","description":"renamed"}""")
        t.send("PUT", "/api/groups/$system", """{"name":"ug-system"}""")
        t.send("PUT", "/api/groups/999999", """{"name":"ug-x"}""")
        t.send("POST", "/api/groups/$g/members", """{"userId":$member}""")
        t.send("POST", "/api/groups/$g/members", """{"userId":$member}""")
        t.send("POST", "/api/groups/$g/members", """{"userId":999999}""")
        t.send("POST", "/api/groups/999999/members", """{"userId":$member}""")
        t.send("GET", "/api/groups/$g/members")
        t.send("GET", "/api/groups/999999/members")
        t.send("POST", "/api/groups/$g/roles", """{"roleId":$role}""")
        t.send("POST", "/api/groups/$g/roles", """{"roleId":$role}""")
        t.send("POST", "/api/groups/$g/roles", """{"roleId":999999}""")
        t.send("GET", "/api/groups/$g/roles")
        val withMembers = groups()
        t.send("DELETE", "/api/groups/$g/members/$member")
        t.send("DELETE", "/api/groups/$g/members/$member")
        t.send("DELETE", "/api/groups/$g/members/abc")
        t.send("DELETE", "/api/groups/$g/roles/$role")
        t.send("DELETE", "/api/groups/$g/roles/$role")
        t.send("DELETE", "/api/groups/$g/roles/abc")
        t.send("DELETE", "/api/groups/$system")
        t.send("DELETE", "/api/groups/$g")
        t.send("DELETE", "/api/groups/$g")
        t.send("DELETE", "/api/groups/abc")
        val names = mapOf(g to "group", member to "member", role to "role", system to "system")
        assertEquals(EXPECTED_GROUPS.trim(), ids(t.text(), names))
        assertEquals(EXPECTED_GROUP_ROWS.trim(), (withMembers + "\n---\n" + groups()).trim())
        assertEquals(EXPECTED_GROUP_AUDIT.trim(), ids(auditSince(before), names))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `every route needs a session and an admin`() = testApplication {
        val requests = listOf(
            "GET" to "/api/users", "POST" to "/api/users", "PUT" to "/api/users/1", "DELETE" to "/api/users/1",
            "GET" to "/api/groups", "POST" to "/api/groups", "PUT" to "/api/groups/1", "DELETE" to "/api/groups/1",
            "GET" to "/api/groups/1/members", "POST" to "/api/groups/1/members", "DELETE" to "/api/groups/1/members/1",
            "GET" to "/api/groups/1/roles", "POST" to "/api/groups/1/roles", "DELETE" to "/api/groups/1/roles/1",
        )
        val (anonymousClient, plainClient) = clients(null, viewer)
        val anonymous = Transcript(anonymousClient)
        val plain = Transcript(plainClient)
        val before = lastAuditId()
        for ((method, path) in requests) {
            val body = if (method == "POST" || method == "PUT") """{"principal":"ug-x@example.com","name":"ug-x","userId":1,"roleId":1}""" else null
            anonymous.send(method, path, body)
            plain.send(method, path, body)
        }
        assertEquals(EXPECTED_ANONYMOUS.trim(), anonymous.text())
        assertEquals(EXPECTED_PLAIN.trim(), plain.text())
        assertEquals("", auditSince(before))
    }

    companion object {
        const val ROLE = "ug-role"
        const val MEMBER = "ug-member@example.com"
        const val EXPECTED_USERS = """
POST /api/users -> 201 {"id":{bob},"principal":"ug-bob@example.com","displayName":"Bob","email":"bob@example.com","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]}
POST /api/users -> 400 {"code":"common.already_exists","params":{"resource":"principal","name":"ug-bob@example.com"}}
POST /api/users -> 400 {"code":"common.field_required","params":{"fields":"principal"}}
POST /api/users -> 201 {"id":{carol},"principal":"ug-carol@example.com","source":"LOCAL","active":false,"createdAt":"{at}","groups":[]}
PUT /api/users/{bob} -> 200 {"id":{bob},"principal":"ug-bob@example.com","displayName":"Robert","email":"bob@example.com","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]}
PUT /api/users/{bob} -> 200 {"id":{bob},"principal":"ug-bob@example.com","displayName":"Robert","source":"LOCAL","active":false,"createdAt":"{at}","groups":[]}
PUT /api/users/{bob} -> 200 {"id":{bob},"principal":"ug-bob@example.com","displayName":"Robert","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]}
PUT /api/users/{bob} -> 200 {"id":{bob},"principal":"ug-robert@example.com","displayName":"Robert","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]}
PUT /api/users/{bob} -> 400 {"code":"common.already_exists","params":{"resource":"principal","name":"ug-carol@example.com"}}
PUT /api/users/999999 -> 404 {"code":"common.not_found","params":{"resource":"user"}}
PUT /api/users/abc -> 400 {"code":"common.bad_id","params":{}}
PUT /api/users/{bob} -> 400 {"code":"common.field_required","params":{"fields":"principal"}}
DELETE /api/users/{bob} -> 204 
DELETE /api/users/{bob} -> 204 
DELETE /api/users/999999 -> 404 {"code":"common.not_found","params":{"resource":"user"}}
DELETE /api/users/abc -> 400 {"code":"common.bad_id","params":{}}
"""
        const val EXPECTED_USER_LIST = """
GET /api/users -> 200 [{"id":{ug-admin},"principal":"ug-admin@example.com","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]},{"id":{ug-bob},"principal":"ug-bob@example.com","source":"SCIM","active":false,"createdAt":"{at}","groups":[]},{"id":{carol},"principal":"ug-carol@example.com","source":"LOCAL","active":false,"createdAt":"{at}","groups":[]},{"id":{ug-member},"principal":"ug-member@example.com","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]},{"id":{bob},"principal":"ug-robert@example.com","displayName":"Robert","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]},{"id":{ug-viewer},"principal":"ug-viewer@example.com","source":"LOCAL","active":true,"createdAt":"{at}","groups":[]}]
"""
        const val EXPECTED_USER_ROWS = """
ug-bob@example.com SCIM false
ug-carol@example.com LOCAL false
ug-robert@example.com LOCAL false
"""
        const val EXPECTED_CREDENTIALS = """
held 1 1 1
deactivated 0 0 0
renamed-from 0 0 0
deprovisioned 0 0 0
"""
        const val EXPECTED_USER_AUDIT = """
admin.identity User::"ug-bob@example.com" | create user 'ug-bob@example.com'
admin.identity User::"ug-carol@example.com" | create user 'ug-carol@example.com'
admin.identity User::"ug-bob@example.com" | update user 'ug-bob@example.com'
admin.identity User::"ug-bob@example.com" | update user 'ug-bob@example.com'
admin.identity User::"ug-bob@example.com" | update user 'ug-bob@example.com'
admin.identity User::"ug-robert@example.com" | update user 'ug-bob@example.com' -> 'ug-robert@example.com'
admin.identity User::"ug-robert@example.com" | deprovision user 'ug-robert@example.com'
admin.identity User::"ug-robert@example.com" | deprovision user 'ug-robert@example.com'
"""
        const val EXPECTED_GROUPS = """
POST /api/groups -> 201 {"id":{group},"name":"ug-eng","description":"engineering","source":"LOCAL","memberCount":0,"roles":[]}
POST /api/groups -> 400 {"code":"common.already_exists","params":{"resource":"group","name":"ug-eng"}}
POST /api/groups -> 400 {"code":"common.field_required","params":{"fields":"name"}}
PUT /api/groups/{group} -> 200 {"id":{group},"name":"ug-engineering","description":"renamed","source":"LOCAL","memberCount":0,"roles":[]}
PUT /api/groups/{system} -> 409 {"code":"group.system_immutable","params":{}}
PUT /api/groups/999999 -> 404 {"code":"common.not_found","params":{"resource":"group"}}
POST /api/groups/{group}/members -> 201 {"userId":{member},"principal":"ug-member@example.com"}
POST /api/groups/{group}/members -> 201 {"userId":{member},"principal":"ug-member@example.com"}
POST /api/groups/{group}/members -> 404 {"code":"common.not_found","params":{"resource":"user"}}
POST /api/groups/999999/members -> 404 {"code":"common.not_found","params":{"resource":"group"}}
GET /api/groups/{group}/members -> 200 [{"userId":{member},"principal":"ug-member@example.com"}]
GET /api/groups/999999/members -> 404 {"code":"common.not_found","params":{"resource":"group"}}
POST /api/groups/{group}/roles -> 201 {"roleId":{role},"roleName":"ug-role"}
POST /api/groups/{group}/roles -> 201 {"roleId":{role},"roleName":"ug-role"}
POST /api/groups/{group}/roles -> 404 {"code":"common.not_found","params":{"resource":"role"}}
GET /api/groups/{group}/roles -> 200 [{"roleId":{role},"roleName":"ug-role"}]
DELETE /api/groups/{group}/members/{member} -> 204 
DELETE /api/groups/{group}/members/{member} -> 404 {"code":"common.not_found","params":{"resource":"group member"}}
DELETE /api/groups/{group}/members/abc -> 400 {"code":"common.bad_id","params":{}}
DELETE /api/groups/{group}/roles/{role} -> 204 
DELETE /api/groups/{group}/roles/{role} -> 404 {"code":"common.not_found","params":{"resource":"group role mapping"}}
DELETE /api/groups/{group}/roles/abc -> 400 {"code":"common.bad_id","params":{}}
DELETE /api/groups/{system} -> 409 {"code":"group.system_immutable","params":{}}
DELETE /api/groups/{group} -> 204 
DELETE /api/groups/{group} -> 404 {"code":"common.not_found","params":{"resource":"group"}}
DELETE /api/groups/abc -> 400 {"code":"common.bad_id","params":{}}
"""
        const val EXPECTED_GROUP_ROWS = """
ug-engineering LOCAL renamed members=ug-member@example.com roles=ug-role
---
"""
        const val EXPECTED_GROUP_AUDIT = """
admin.identity Group::"ug-eng" | create group 'ug-eng'
admin.identity Group::"ug-engineering" | update group 'ug-eng' -> 'ug-engineering'
admin.identity Group::"ug-engineering" | add 'ug-member@example.com' to group 'ug-engineering'
admin.identity Group::"ug-engineering" | add role 'ug-role' to group 'ug-engineering'
admin.identity Group::"ug-engineering" | remove 'ug-member@example.com' from group 'ug-engineering'
admin.identity Group::"ug-engineering" | remove role 'ug-role' from group 'ug-engineering'
admin.identity Group::"ug-engineering" | delete group 'ug-engineering'
"""
        const val EXPECTED_ANONYMOUS = """
GET /api/users -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/users -> 401 {"code":"common.unauthenticated","params":{}}
PUT /api/users/1 -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/users/1 -> 401 {"code":"common.unauthenticated","params":{}}
GET /api/groups -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/groups -> 401 {"code":"common.unauthenticated","params":{}}
PUT /api/groups/1 -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/groups/1 -> 401 {"code":"common.unauthenticated","params":{}}
GET /api/groups/1/members -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/groups/1/members -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/groups/1/members/1 -> 401 {"code":"common.unauthenticated","params":{}}
GET /api/groups/1/roles -> 401 {"code":"common.unauthenticated","params":{}}
POST /api/groups/1/roles -> 401 {"code":"common.unauthenticated","params":{}}
DELETE /api/groups/1/roles/1 -> 401 {"code":"common.unauthenticated","params":{}}
"""
        const val EXPECTED_PLAIN = """
GET /api/users -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/users -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
PUT /api/users/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/users/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
GET /api/groups -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/groups -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
PUT /api/groups/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/groups/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
GET /api/groups/1/members -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/groups/1/members -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/groups/1/members/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
GET /api/groups/1/roles -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
POST /api/groups/1/roles -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
DELETE /api/groups/1/roles/1 -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
"""
    }
}
