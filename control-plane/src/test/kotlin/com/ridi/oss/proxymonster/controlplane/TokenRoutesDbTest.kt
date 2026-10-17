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
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** The wire-token routes over HTTP: status, body, and the token and audit rows each call leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var cpGo: CpGoStack

    private val owner = "tk-owner@example.com"
    private val admin = "tk-admin@example.com"
    private val stranger = "tk-stranger@example.com"
    private val former = "tk-former@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_token_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val sessions = PrincipalSessionStore(dataSource, null)
        for (p in listOf(owner, admin, stranger, former)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessions)
        }
        core.userGroupStore.setUserActive(former, false)
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "token-routes-secret", oidc = null, resultKey = null, scimToken = null,
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

    /** One line per request, `who METHOD path -> status body`, with secrets and times replaced. */
    private class Transcript {
        val lines = mutableListOf<String>()

        suspend fun send(who: String, client: HttpClient, method: String, path: String, body: String? = null): HttpResponse {
            val response = when (method) {
                "GET" -> client.get(path)
                "POST" -> client.post(path) { if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
                "DELETE" -> client.delete(path)
                else -> error(method)
            }
            val text = response.bodyAsText()
                .replace(Regex(""""(\w+At)":"[^"]+""""), """"$1":"{at}"""")
                .replace(Regex(""""token":"(pm[a-z]_)[^"]+""""), """"token":"$1{secret}"""")
            lines += "$who $method $path -> ${response.status.value} $text"
            return response
        }
    }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    private fun named(text: String, ids: Map<Long, String>) = ids.entries.sortedByDescending { it.key }.fold(text) { acc, (id, name) ->
        acc.replace(Regex("""(/api/tokens/|"id":|Token::")$id\b""")) { "${it.groupValues[1]}{$name}" }
    }

    private fun tokenIds(): Map<Long, String> =
        rows("SELECT id || ' ' || principal || '-' || kind || '-' || row_number() OVER (PARTITION BY principal, kind ORDER BY id) FROM proxy_token ORDER BY id")
            .lines().filter { it.isNotBlank() }.associate { it.substringBefore(' ').toLong() to it.substringAfter(' ').removePrefix("tk-").replace("@example.com", "") }

    @Test
    fun `mint, list and revoke`() = testApplication {
        val t = Transcript()
        val o = client(owner)
        val a = client(admin)
        val s = client(stranger)
        val f = client(former)
        val anon = client(null)
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()

        t.send("owner", o, "POST", "/api/wire-tokens", "{}")
        t.send("owner", o, "POST", "/api/wire-tokens", """{"ttlSeconds":60}""")
        t.send("owner", o, "POST", "/api/tokens", """{"name":"ci","ttlSeconds":3600}""")
        t.send("owner", o, "POST", "/api/tokens", """{"name":" "}""")
        t.send("owner", o, "POST", "/api/tokens", "{}")
        t.send("owner", o, "POST", "/api/tokens", "not json")
        t.send("stranger", s, "POST", "/api/tokens", """{"name":"mine"}""")
        t.send("former", f, "POST", "/api/wire-tokens", "{}")
        t.send("former", f, "POST", "/api/tokens", "{}")
        t.send("anonymous", anon, "POST", "/api/wire-tokens", "{}")
        t.send("anonymous", anon, "POST", "/api/tokens", "{}")

        t.send("owner", o, "GET", "/api/tokens")
        t.send("owner", o, "GET", "/api/tokens?principal=$stranger")
        t.send("admin", a, "GET", "/api/tokens?principal=$owner")
        t.send("anonymous", anon, "GET", "/api/tokens")

        val ids = tokenIds()
        val ownerUser = ids.entries.first { it.value == "owner-USER-1" }.key
        val ownerSession = ids.entries.first { it.value == "owner-SESSION-1" }.key
        val strangerUser = ids.entries.first { it.value == "stranger-USER-1" }.key
        t.send("owner", o, "DELETE", "/api/tokens/$strangerUser")
        t.send("anonymous", anon, "DELETE", "/api/tokens/$ownerUser")
        t.send("anonymous", anon, "DELETE", "/api/tokens/999999")
        t.send("owner", o, "DELETE", "/api/tokens/$ownerUser")
        t.send("owner", o, "DELETE", "/api/tokens/$ownerUser")
        t.send("owner", o, "DELETE", "/api/tokens/999999")
        t.send("owner", o, "DELETE", "/api/tokens/abc")
        t.send("admin", a, "DELETE", "/api/tokens/$strangerUser")
        t.send("admin", a, "DELETE", "/api/tokens/$ownerSession")
        t.send("owner", o, "GET", "/api/tokens")

        val actual = listOf(
            named(t.lines.joinToString("\n"), ids),
            "rows:",
            named(rows("SELECT id || ' ' || principal || ' ' || kind || ' ' || coalesce(name, '-') || ' ' || (revoked_at IS NOT NULL) || ' ' || roles::text || ' ' || extract(epoch FROM expires_at - created_at)::bigint FROM proxy_token ORDER BY id"), ids)
                .replace(Regex("""^(\d+) """, RegexOption.MULTILINE)) { "{${ids[it.groupValues[1].toLong()]}} " },
            "audit:",
            named(rows("SELECT kind || ' ' || principal || ' ' || action || ' ' || resource || ' | ' || statement || ' | ' || channel FROM audit_event WHERE id > $before AND kind <> 'decision' ORDER BY id"), ids),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
owner POST /api/wire-tokens -> 200 {"token":"pmt_{secret}","id":{owner-SESSION-1},"kind":"SESSION","expiresAt":"{at}"}
owner POST /api/wire-tokens -> 200 {"token":"pmt_{secret}","id":{owner-SESSION-2},"kind":"SESSION","expiresAt":"{at}"}
owner POST /api/tokens -> 201 {"token":"pmk_{secret}","id":{owner-USER-1},"kind":"USER","name":"ci","expiresAt":"{at}"}
owner POST /api/tokens -> 201 {"token":"pmk_{secret}","id":{owner-USER-2},"kind":"USER","expiresAt":"{at}"}
owner POST /api/tokens -> 201 {"token":"pmk_{secret}","id":{owner-USER-3},"kind":"USER","expiresAt":"{at}"}
owner POST /api/tokens -> 500 {"code":"common.fallback","params":{}}
stranger POST /api/tokens -> 201 {"token":"pmk_{secret}","id":{stranger-USER-1},"kind":"USER","name":"mine","expiresAt":"{at}"}
former POST /api/wire-tokens -> 403 {"code":"auth.principal_deprovisioned","params":{}}
former POST /api/tokens -> 403 {"code":"auth.principal_deprovisioned","params":{}}
anonymous POST /api/wire-tokens -> 401 {"code":"common.unauthenticated","params":{}}
anonymous POST /api/tokens -> 401 {"code":"common.unauthenticated","params":{}}
owner GET /api/tokens -> 200 [{"id":{owner-USER-3},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-2},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-1},"kind":"USER","principal":"tk-owner@example.com","name":"ci","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-SESSION-2},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-SESSION-1},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"}]
owner GET /api/tokens?principal=tk-stranger@example.com -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
admin GET /api/tokens?principal=tk-owner@example.com -> 200 [{"id":{owner-USER-3},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-2},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-1},"kind":"USER","principal":"tk-owner@example.com","name":"ci","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-SESSION-2},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-SESSION-1},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"}]
anonymous GET /api/tokens -> 401 {"code":"common.unauthenticated","params":{}}
owner DELETE /api/tokens/{stranger-USER-1} -> 403 {"code":"common.forbidden","params":{"detail":"no policy permits this action"}}
anonymous DELETE /api/tokens/{owner-USER-1} -> 401 {"code":"common.unauthenticated","params":{}}
anonymous DELETE /api/tokens/999999 -> 404 {"code":"common.not_found","params":{"resource":"token"}}
owner DELETE /api/tokens/{owner-USER-1} -> 204 
owner DELETE /api/tokens/{owner-USER-1} -> 404 {"code":"common.not_found","params":{"resource":"token"}}
owner DELETE /api/tokens/999999 -> 404 {"code":"common.not_found","params":{"resource":"token"}}
owner DELETE /api/tokens/abc -> 400 {"code":"common.bad_id","params":{}}
admin DELETE /api/tokens/{stranger-USER-1} -> 204 
admin DELETE /api/tokens/{owner-SESSION-1} -> 204 
owner GET /api/tokens -> 200 [{"id":{owner-USER-3},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-2},"kind":"USER","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-USER-1},"kind":"USER","principal":"tk-owner@example.com","name":"ci","createdAt":"{at}","expiresAt":"{at}","revokedAt":"{at}"},{"id":{owner-SESSION-2},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}"},{"id":{owner-SESSION-1},"kind":"SESSION","principal":"tk-owner@example.com","createdAt":"{at}","expiresAt":"{at}","revokedAt":"{at}"}]
rows:
{owner-SESSION-1} tk-owner@example.com SESSION - true [] 43200
{owner-SESSION-2} tk-owner@example.com SESSION - false [] 60
{owner-USER-1} tk-owner@example.com USER ci true [] 3600
{owner-USER-2} tk-owner@example.com USER - false [] 3600
{owner-USER-3} tk-owner@example.com USER - false [] 3600
{stranger-USER-1} tk-stranger@example.com USER mine true [] 3600
audit:
auth tk-owner@example.com auth.token.mint Token::"{owner-SESSION-1}" | Minted SESSION wire token | wire
auth tk-owner@example.com auth.token.mint Token::"{owner-SESSION-2}" | Minted SESSION wire token | wire
auth tk-owner@example.com auth.token.mint Token::"{owner-USER-1}" | Minted USER wire token | wire
auth tk-owner@example.com auth.token.mint Token::"{owner-USER-2}" | Minted USER wire token | wire
auth tk-owner@example.com auth.token.mint Token::"{owner-USER-3}" | Minted USER wire token | wire
auth tk-stranger@example.com auth.token.mint Token::"{stranger-USER-1}" | Minted USER wire token | wire
auth tk-owner@example.com auth.token.revoke Token::"{owner-USER-1}" | Revoked USER wire token owned by tk-owner@example.com | wire
auth tk-admin@example.com auth.token.revoke Token::"{stranger-USER-1}" | Revoked USER wire token owned by tk-stranger@example.com | wire
auth tk-admin@example.com auth.token.revoke Token::"{owner-SESSION-1}" | Revoked SESSION wire token owned by tk-owner@example.com | wire
"""
