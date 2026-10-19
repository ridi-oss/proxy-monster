package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
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
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** pmon's device login and daemon session routes over HTTP: status, redirects, bodies and the rows they leave. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var cpGo: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_device_login_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf("dl-alice@example.com", "dl-gone@example.com")) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "device-login-routes-secret-32-bytes", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 7200, idpRecheckIntervalSeconds = 600, devMarker = true,
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

    /** Random secrets, codes, handles and times replaced by what they are, so a transcript compares exactly. */
    private fun scrub(text: String) = text
        .replace(Regex(""""(\w*(?:At|Until))":"[^"]+""""), """"$1":"{at}"""")
        .replace(Regex("""(pm[a-z])_[A-Za-z0-9_-]+"""), "$1_{secret}")
        .replace(Regex("""dvc_[A-Za-z0-9_-]+"""), "dvc_{handle}")
        .replace(Regex("""[A-Z0-9]{4}-[A-Z0-9]{4}"""), "{code}")
        .replace(Regex("""127\.0\.0\.1:\d+"""), "{host}")

    private class Transcript(val scrub: (String) -> String) {
        val lines = mutableListOf<String>()

        suspend fun send(who: String, client: HttpClient, method: String, path: String, body: String? = null, bearer: String? = null): HttpResponse {
            val response = when (method) {
                "GET" -> client.get(path)
                "POST" -> client.post(path) {
                    bearer?.let { header(HttpHeaders.Authorization, it) }
                    if (body != null) { contentType(ContentType.Application.Json); setBody(body) }
                }
                else -> error(method)
            }
            val location = response.headers[HttpHeaders.Location]?.let { " -> $it" } ?: ""
            val cookies = response.headers.getAll(HttpHeaders.SetCookie).orEmpty()
                .map { it.replace(Regex("""^(\w+)=[^;]+"""), "$1={value}").replace(Regex("""Expires=[^;]+"""), "Expires={at}") }
                .sorted()
            val text = response.bodyAsText()
            lines += scrub("$who $method $path -> ${response.status.value}$location${cookies.joinToString("") { " | $it" }} $text").trimEnd()
            return response
        }
    }

    private fun field(body: String, name: String) = Regex(""""$name":"([^"]+)"""").find(body)!!.groupValues[1]

    @Test
    fun `start, confirm, authorize, poll, renew, mcp-token and logout`() = testApplication {
        val t = Transcript(::scrub)
        val pmon = cpGo.client()
        val browser = cpGo.client()
        val anon = cpGo.client()
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()

        t.send("pmon", pmon, "POST", "/auth/device/start", """{"scopes":[]}""")
        t.send("pmon", pmon, "POST", "/auth/device/start", """{"scopes":["mcp:read","mcp:nope"]}""")
        val started = t.send("pmon", pmon, "POST", "/auth/device/start", "{}").bodyAsText()
        val code = field(started, "userCode")
        val handle = field(started, "handle")
        val elevatedStart = t.send("pmon", pmon, "POST", "/auth/device/start", """{"scopes":["mcp:read"," mcp:tokens ","mcp:read"],"ttlSeconds":900}""").bodyAsText()

        t.send("anonymous", anon, "POST", "/auth/device/confirm", """{"userCode":"$code"}""")
        t.send("pmon", pmon, "POST", "/auth/device/poll", """{"handle":"$handle"}""")
        t.send("pmon", pmon, "POST", "/auth/device/poll", """{"handle":"dvc_nope"}""")
        browser.post("/test/session/dl-alice@example.com")
        t.send("browser", browser, "POST", "/auth/device/confirm", """{"userCode":"WRNG-CODE"}""")
        t.send("browser", browser, "GET", "/auth/device/authorize?user_code=$code")
        t.send("browser", browser, "POST", "/auth/device/confirm", """{"userCode":"${code.lowercase().replace("-", "")}"}""")
        t.send("browser", browser, "POST", "/auth/device/confirm", """{"userCode":"${field(elevatedStart, "userCode")}"}""")
        t.send("browser", browser, "POST", "/auth/device/confirm", """{"userCode":"$code"}""")
        t.send("browser", browser, "GET", "/auth/device/authorize?user_code=$code")
        val polled = t.send("pmon", pmon, "POST", "/auth/device/poll", """{"handle":"$handle"}""").bodyAsText()
        t.send("pmon", pmon, "POST", "/auth/device/poll", """{"handle":"$handle"}""")
        val renewal = field(polled, "renewalToken")

        t.send("pmon", pmon, "POST", "/auth/session/renew")
        t.send("pmon", pmon, "POST", "/auth/session/renew", bearer = "Bearer pmr_not-a-session")
        t.send("pmon", pmon, "POST", "/auth/session/renew", bearer = "Bearer $renewal")
        t.send("pmon", pmon, "POST", "/auth/session/mcp-token", bearer = "Bearer $renewal")
        t.send("pmon", pmon, "POST", "/auth/session/logout", bearer = "Bearer pmr_not-a-session")
        t.send("pmon", pmon, "POST", "/auth/session/logout?replaced=true", bearer = "Bearer $renewal")
        t.send("pmon", pmon, "POST", "/auth/session/renew", bearer = "Bearer $renewal")
        t.send("pmon", pmon, "POST", "/auth/session/logout", bearer = "Bearer $renewal")

        val gone = cpGo.client()
        val goneStart = t.send("pmon", pmon, "POST", "/auth/device/start", "{}").bodyAsText()
        gone.post("/test/session/dl-gone@example.com")
        t.send("gone", gone, "POST", "/auth/device/confirm", """{"userCode":"${field(goneStart, "userCode")}"}""")
        t.send("gone", gone, "GET", "/auth/device/authorize?user_code=${field(goneStart, "userCode")}")
        core.userGroupStore.setUserActive("dl-gone@example.com", false)
        t.send("pmon", pmon, "POST", "/auth/device/poll", """{"handle":"${field(goneStart, "handle")}"}""")

        val actual = listOf(
            t.lines.joinToString("\n"),
            "logins:",
            rows("SELECT status || ' ' || coalesce(principal, '-') || ' ' || scopes || ' ' || ttl_seconds || ' ' || (elevated_until IS NOT NULL) FROM device_login ORDER BY id"),
            "daemon sessions:",
            rows(
                """SELECT principal || ' ' || coalesce(ended_reason, 'live') || ' ' || liveness_status || ' ' || coalesce(scopes, '-') || ' ' ||
                          (absolute_expires_at > now()) FROM principal_session WHERE kind = 'DAEMON' ORDER BY id""",
            ),
            "tokens:",
            rows(
                """SELECT principal || ' ' || kind || ' ' || coalesce(client_id, '-') || ' ' || coalesce(scope, '-') || ' ' ||
                          (revoked_at IS NOT NULL) || ' ' || (retired_at IS NOT NULL)
                   FROM proxy_token WHERE principal LIKE 'dl-%' ORDER BY id""",
            ),
            "audit:",
            scrub(
                rows(
                    """SELECT principal || ' ' || action || ' ' || regexp_replace(resource, '\d+', '{id}') || ' | ' || statement || ' | ' ||
                              coalesce(detail, '-') || ' | ' || outcome || ' ' || channel
                       FROM audit_event WHERE id > $before AND kind = 'auth' ORDER BY id""",
                ),
            ),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
pmon POST /auth/device/start -> 400 {"code":"device.no_scopes","params":{}}
pmon POST /auth/device/start -> 400 {"code":"device.unknown_scope","params":{"scope":"mcp:nope"}}
pmon POST /auth/device/start -> 200 {"verificationUri":"http://{host}/device","verificationUriComplete":"http://{host}/device?user_code={code}","userCode":"{code}","handle":"dvc_{handle}","interval":2}
pmon POST /auth/device/start -> 200 {"verificationUri":"http://{host}/device","verificationUriComplete":"http://{host}/device?user_code={code}","userCode":"{code}","handle":"dvc_{handle}","interval":2}
anonymous POST /auth/device/confirm -> 401 {"code":"common.unauthenticated","params":{}}
pmon POST /auth/device/poll -> 202 {"status":"authorization_pending"}
pmon POST /auth/device/poll -> 400 {"code":"device.unknown_or_expired_login","params":{}}
browser POST /auth/device/confirm -> 400 {"code":"device.unknown_or_expired_login","params":{}}
browser GET /auth/device/authorize?user_code={code} -> 302 -> /device?user_code={code}
browser POST /auth/device/confirm -> 200 | pm_device_verify={value}; Max-Age=600; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ok":true,"scopes":["mcp:query","mcp:read"]}
browser POST /auth/device/confirm -> 200 | pm_device_verify={value}; Max-Age=600; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ok":true,"scopes":["mcp:read","mcp:tokens"],"elevatedTtlSeconds":3600}
browser POST /auth/device/confirm -> 200 | pm_device_verify={value}; Max-Age=600; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ok":true,"scopes":["mcp:query","mcp:read"]}
browser GET /auth/device/authorize?user_code={code} -> 302 -> /device/success | pm_device_verify=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
pmon POST /auth/device/poll -> 200 {"token":"pmt_{secret}","expiresAt":"{at}","principal":"dl-alice@example.com","sessionExpiresAt":"{at}","renewalToken":"pmr_{secret}","scopes":["mcp:query","mcp:read"]}
pmon POST /auth/device/poll -> 400 {"code":"device.login_already_completed","params":{}}
pmon POST /auth/session/renew -> 401 {"code":"auth.missing_renewal_token","params":{}}
pmon POST /auth/session/renew -> 401 {"code":"common.unauthenticated","params":{}}
pmon POST /auth/session/renew -> 200 {"token":"pmt_{secret}","expiresAt":"{at}"}
pmon POST /auth/session/mcp-token -> 200 {"accessToken":"pma_{secret}","expiresAt":"{at}","scope":"mcp:query mcp:read"}
pmon POST /auth/session/logout -> 204
pmon POST /auth/session/logout?replaced=true -> 204
pmon POST /auth/session/renew -> 401 {"code":"auth.session_window_expired","params":{}}
pmon POST /auth/session/logout -> 204
pmon POST /auth/device/start -> 200 {"verificationUri":"http://{host}/device","verificationUriComplete":"http://{host}/device?user_code={code}","userCode":"{code}","handle":"dvc_{handle}","interval":2}
gone POST /auth/device/confirm -> 200 | pm_device_verify={value}; Max-Age=600; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING {"ok":true,"scopes":["mcp:query","mcp:read"]}
gone GET /auth/device/authorize?user_code={code} -> 302 -> /device/success | pm_device_verify=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
pmon POST /auth/device/poll -> 403 {"code":"auth.principal_deprovisioned","params":{}}
logins:
CONSUMED dl-alice@example.com mcp:query mcp:read 43200 false
PENDING - mcp:read mcp:tokens 900 false
APPROVED dl-gone@example.com mcp:query mcp:read 43200 false
daemon sessions:
dl-alice@example.com SIGNED_OUT INACTIVE mcp:query mcp:read false
tokens:
dl-alice@example.com SESSION - - false true
dl-alice@example.com SESSION - - false true
dl-alice@example.com MCP_ACCESS pmon mcp:query mcp:read true false
audit:
dl-alice@example.com auth.device.approve DeviceLogin::"{id}" | Device login approved | - | SUCCESS device
dl-alice@example.com auth.device.mint Token::"{id}" | Device login minted SESSION token | - | SUCCESS device
dl-alice@example.com auth.session.renew Token::"{id}" | Daemon session renewed SESSION token | - | SUCCESS pmon
dl-alice@example.com auth.session.mcp_token Token::"{id}" | pmon session minted MCP access token | scope=mcp:query mcp:read | SUCCESS pmon
dl-alice@example.com auth.logout Session::"{id}" | pmon session replaced by a new login | - | SUCCESS pmon
dl-gone@example.com auth.device.approve DeviceLogin::"{id}" | Device login approved | - | SUCCESS device
"""
