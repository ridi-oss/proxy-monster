package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The web-session routes over HTTP: status, body, the cookies they set, and the rows they leave. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WebSessionAuthRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var cpGo: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_web_session_auth_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        for (role in listOf("ws-analyst", "ws-auditor")) core.policyStore.createRole(RoleInput(role))
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "web-session-auth-routes-secret-32b", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database)
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    /** One line per request, `who METHOD path -> status [headers] body`, with session ids, cookie values and times replaced. */
    private class Transcript {
        val lines = mutableListOf<String>()

        suspend fun send(who: String, client: HttpClient, method: String, path: String, body: String? = null, device: String? = null): HttpResponse {
            val response = when (method) {
                "GET" -> client.get(path) { device?.let { header(HttpHeaders.Cookie, "pm_did=$it") } }
                "POST" -> client.post(path) { if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
                else -> error(method)
            }
            val cookies = response.headers.getAll(HttpHeaders.SetCookie).orEmpty()
                .map { it.replace(Regex("""^(pm_session|pm_did)=[^;]+"""), "$1={value}").replace(Regex("""Expires=[^;]+"""), "Expires={at}") }
            val cache = response.headers[HttpHeaders.CacheControl]?.let { " cache=$it" } ?: ""
            val text = response.bodyAsText()
                .replace(Regex(""""(now|idleExpiresAt|absoluteExpiresAt)":"[^"]+""""), """"$1":"{at}"""")
            lines += "$who $method $path -> ${response.status.value}$cache ${cookies.joinToString(" | ")} $text".replace("  ", " ")
            return response
        }
    }

    private fun sessionIdOf(body: String) = Regex(""""sessionId":(\d+)""").find(body)!!.groupValues[1].toLong()

    @Test
    fun `config, debug login, me, status, heartbeat and logout`() = testApplication {
        val t = Transcript()
        val alice = cpGo.client()
        val alice2 = cpGo.client()
        val bob = cpGo.client()
        val anon = cpGo.client()
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()

        t.send("anonymous", anon, "GET", "/auth/config")
        t.send("anonymous", anon, "GET", "/auth/me")
        t.send("anonymous", anon, "GET", "/auth/session/status")
        t.send("anonymous", anon, "POST", "/auth/session/heartbeat")
        t.send("anonymous", anon, "POST", "/auth/logout")
        t.send("anonymous", anon, "POST", "/auth/debug", """{"principal":"ws-x@example.com","requesterIp":"not-an-ip"}""")
        t.send("anonymous", anon, "POST", "/auth/debug", """{"principal":"ws-x@example.com","roles":["ws-missing"]}""")
        t.send("anonymous", anon, "POST", "/auth/debug", """{"roles":[]}""")
        t.send("anonymous", anon, "POST", "/auth/debug", "not json")

        t.send("alice", alice, "POST", "/auth/debug", """{"principal":"ws-alice@example.com","roles":["ws-analyst"," ws-auditor ","ws-analyst",""],"requesterIp":" 10.1.2.3 "}""")
        t.send("alice", alice, "GET", "/auth/me")
        val first = sessionIdOf(t.send("alice", alice, "GET", "/auth/session/status").bodyAsText())
        t.send("alice", alice, "POST", "/auth/session/heartbeat")
        t.send("alice", alice, "POST", "/auth/debug", """{"principal":"ws-alice@example.com","roles":["ws-analyst"]}""")
        val second = sessionIdOf(t.send("alice", alice, "GET", "/auth/session/status").bodyAsText())
        t.send("alice2", alice2, "POST", "/auth/debug", """{"principal":"ws-alice@example.com"}""")
        val third = sessionIdOf(t.send("alice2", alice2, "GET", "/auth/session/status").bodyAsText())
        t.send("alice", alice, "GET", "/auth/me")
        t.send("alice", alice, "GET", "/auth/session/status")

        t.send("bob", bob, "POST", "/auth/debug", """{"principal":"ws-bob@example.com"}""")
        val bobs = sessionIdOf(t.send("bob", bob, "GET", "/auth/session/status").bodyAsText())
        t.send("bob", bob, "POST", "/auth/logout", """{"sessionId":${bobs + 1000}}""")
        t.send("bob", bob, "GET", "/auth/me")
        t.send("bob", bob, "POST", "/auth/logout", """{"sessionId":$bobs}""")
        t.send("bob", bob, "GET", "/auth/me")
        t.send("bob", bob, "POST", "/auth/logout")
        t.send("alice2", alice2, "POST", "/auth/logout")
        t.send("alice2", alice2, "GET", "/auth/session/status")

        val names = mapOf(first to "first", second to "second", third to "third", bobs to "bob")
        val named = { s: String ->
            names.entries.fold(s) { acc, (id, name) -> acc.replace(Regex("""("sessionId":|Session::"|"sessionId":\s?)$id\b""")) { "${it.groupValues[1]}{$name}" } }
                .replace(Regex(""""sessionId":${bobs + 1000}\b"""), """"sessionId":{other}""")
        }
        val actual = listOf(
            named(t.lines.joinToString("\n")),
            "sessions:",
            named(
                rows(
                    """SELECT id || ' ' || principal || ' ' || coalesce(ended_reason, 'live') || ' ' || coalesce(debug_requester_ip, '-')
                       FROM principal_session WHERE kind = 'WEB' AND principal LIKE 'ws-%' ORDER BY id""",
                ),
            ).replace(Regex("""^(\d+) """, RegexOption.MULTILINE)) { "{${names[it.groupValues[1].toLong()]}} " },
            "roles:",
            rows(
                """SELECT ra.principal || ' ' || r.name FROM principal_role ra JOIN app_role r ON r.id = ra.role_id
                   WHERE ra.principal LIKE 'ws-%' ORDER BY ra.principal, r.name""",
            ),
            "audit:",
            named(
                rows(
                    """SELECT kind || ' ' || principal || ' ' || action || ' ' || resource || ' | ' || statement || ' | ' ||
                              coalesce(client_addr, '-') || ' ' || channel
                       FROM audit_event WHERE id > $before AND kind <> 'decision' ORDER BY id""",
                ),
            ),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
anonymous GET /auth/config -> 200 {"oidcEnabled":false,"authDebug":true,"session":{"heartbeatMs":90000,"idleWarnLeadMs":60000,"absoluteWarnLeadMs":300000,"absoluteCapAmount":2,"absoluteCapUnit":"hours"}}
anonymous GET /auth/me -> 401 cache=no-store {"reason":"none"}
anonymous GET /auth/session/status -> 401 cache=no-store {"reason":"none"}
anonymous POST /auth/session/heartbeat -> 401 cache=no-store {"reason":"none"}
anonymous POST /auth/logout -> 200 {"ended":true}
anonymous POST /auth/debug -> 400 {"code":"auth.invalid_requester_ip","params":{}}
anonymous POST /auth/debug -> 404 pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"code":"common.not_found","params":{"resource":"role 'ws-missing'"}}
anonymous POST /auth/debug -> 500 {"code":"common.fallback","params":{}}
anonymous POST /auth/debug -> 500 {"code":"common.fallback","params":{}}
alice POST /auth/debug -> 200 pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"principal":"ws-alice@example.com","roles":["ws-analyst","ws-auditor"],"requesterIp":"10.1.2.3"}
alice GET /auth/me -> 200 cache=no-store {"principal":"ws-alice@example.com","roles":["ws-analyst","ws-auditor"],"requesterIp":"10.1.2.3"}
alice GET /auth/session/status -> 200 cache=no-store {"now":"{at}","idleExpiresAt":"{at}","absoluteExpiresAt":"{at}","principal":"ws-alice@example.com","sessionId":{first}}
alice POST /auth/session/heartbeat -> 200 cache=no-store {"now":"{at}","idleExpiresAt":"{at}","absoluteExpiresAt":"{at}","principal":"ws-alice@example.com","sessionId":{first}}
alice POST /auth/debug -> 200 pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"principal":"ws-alice@example.com","roles":["ws-analyst"]}
alice GET /auth/session/status -> 200 cache=no-store {"now":"{at}","idleExpiresAt":"{at}","absoluteExpiresAt":"{at}","principal":"ws-alice@example.com","sessionId":{second}}
alice2 POST /auth/debug -> 200 pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"principal":"ws-alice@example.com","roles":[]}
alice2 GET /auth/session/status -> 200 cache=no-store {"now":"{at}","idleExpiresAt":"{at}","absoluteExpiresAt":"{at}","principal":"ws-alice@example.com","sessionId":{third}}
alice GET /auth/me -> 401 cache=no-store {"reason":"displaced"}
alice GET /auth/session/status -> 401 cache=no-store {"reason":"displaced"}
bob POST /auth/debug -> 200 pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"principal":"ws-bob@example.com","roles":[]}
bob GET /auth/session/status -> 200 cache=no-store {"now":"{at}","idleExpiresAt":"{at}","absoluteExpiresAt":"{at}","principal":"ws-bob@example.com","sessionId":{bob}}
bob POST /auth/logout -> 200 {"ended":false}
bob GET /auth/me -> 200 cache=no-store {"principal":"ws-bob@example.com","roles":[]}
bob POST /auth/logout -> 200 pm_session=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ended":true}
bob GET /auth/me -> 401 cache=no-store {"reason":"none"}
bob POST /auth/logout -> 200 {"ended":true}
alice2 POST /auth/logout -> 200 pm_session=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ended":true}
alice2 GET /auth/session/status -> 401 cache=no-store {"reason":"none"}
sessions:
{first} ws-alice@example.com DISPLACED 10.1.2.3
{second} ws-alice@example.com DISPLACED -
{third} ws-alice@example.com SIGNED_OUT -
{bob} ws-bob@example.com SIGNED_OUT -
roles:

audit:
admin ws-alice@example.com admin.identity User::"ws-alice@example.com" | replace direct roles of 'ws-alice@example.com' [ws-analyst, ws-auditor] | 10.1.2.3 console
admin ws-alice@example.com admin.identity User::"ws-alice@example.com" | replace direct roles of 'ws-alice@example.com' [ws-analyst] | 10.1.2.3 console
admin ws-alice@example.com admin.identity User::"ws-alice@example.com" | replace direct roles of 'ws-alice@example.com' [] | 127.0.0.1 console
admin ws-bob@example.com admin.identity User::"ws-bob@example.com" | replace direct roles of 'ws-bob@example.com' [] | 127.0.0.1 console
auth ws-bob@example.com auth.logout Session::"{bob}" | Web session signed out | 127.0.0.1 session
auth ws-alice@example.com auth.logout Session::"{third}" | Web session signed out | 127.0.0.1 session
"""
