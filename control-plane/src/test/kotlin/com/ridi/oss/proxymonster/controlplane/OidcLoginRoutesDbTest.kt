package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.FakeOidcIdp
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.parseQueryString
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.delay
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** OIDC login and the IdP recheck through the real stack: redirects, cookies, provisioned rows, sessions and audit. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcLoginRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var cpGo: CpGoStack
    private val idp = FakeOidcIdp()
    private val groups = mapOf("idp-eng" to "oi-eng")

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_oidc_login_routes")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        exec(
            """INSERT INTO app_role (name) VALUES ('oi-analyst');
               INSERT INTO app_group (name) VALUES ('oi-eng');
               INSERT INTO group_role (group_id, role_id)
               SELECT g.id, r.id FROM app_group g, app_role r WHERE g.name = 'oi-eng' AND r.name = 'oi-analyst'""",
        )
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "oidc-login-routes-secret-32-bytes!", oidc = idp.config(groups, "okta-"),
            resultKey = ByteArray(32) { it.toByte() }, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 1, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database, extraEnv = idp.env(groups, "okta-"))
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
        idp.close()
    }

    private fun exec(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun rows(sql: String): String = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
    }.joinToString("\n")

    /** One line per request: status, Location with its query sorted and random values replaced, and the cookies set, sorted. */
    private class Transcript {
        val lines = mutableListOf<String>()

        suspend fun send(who: String, client: HttpClient, path: String): HttpResponse {
            val response = client.get(path)
            val location = response.headers[HttpHeaders.Location]?.let { loc ->
                val url = Url(loc)
                val query = url.parameters.entries().sortedBy { it.key }.joinToString("&") { (k, v) ->
                    "$k=" + if (k in setOf("state", "nonce", "code_challenge")) "{$k}" else v.joinToString(",")
                }
                " -> " + loc.substringBefore('?').replace(Regex("""127\.0\.0\.1:\d+"""), "{idp}") + if (query.isEmpty()) "" else "?$query"
            } ?: ""
            val cookies = response.headers.getAll(HttpHeaders.SetCookie).orEmpty()
                .map { it.replace(Regex("""^(\w+)=[^;]+"""), "$1={value}").replace(Regex("""Expires=[^;]+"""), "Expires={at}") }
                .sorted()
            val body = response.bodyAsText().takeIf { it.isNotEmpty() }?.let { " $it" } ?: ""
            lines += "$who GET ${path.substringBefore("&state=")} -> ${response.status.value}$location${cookies.joinToString("") { " | $it" }}$body"
            return response
        }
    }

    /** Starts a login on [client] and returns its state and nonce. */
    private suspend fun Transcript.start(who: String, client: HttpClient, returnTo: String? = null): Pair<String, String> {
        val path = "/auth/oidc/login" + (returnTo?.let { "?return_to=" + java.net.URLEncoder.encode(it, "UTF-8") } ?: "")
        val query = parseQueryString(assertNotNull(send(who, client, path).headers[HttpHeaders.Location]).substringAfter('?'))
        return assertNotNull(query["state"]) to assertNotNull(query["nonce"])
    }

    private suspend fun awaitEnded(principal: String) {
        repeat(100) {
            if (rows("SELECT count(*) FROM principal_session WHERE principal = '$principal' AND ended_at IS NULL") == "0") return
            delay(200)
        }
    }

    @Test
    fun `oidc login, callback outcomes and the IdP recheck`() = testApplication {
        val t = Transcript()
        val before = rows("SELECT coalesce(max(id), 0) FROM audit_event").toLong()

        val stranger = cpGo.client()
        t.start("stranger", stranger)
        t.send("stranger", stranger, "/auth/oidc/callback?code=c0&state=wrong")

        val denied = cpGo.client()
        val (deniedState, _) = t.start("denied", denied)
        t.send("denied", denied, "/auth/oidc/callback?error=access_denied&state=$deniedState")

        val nobody = cpGo.client()
        val (nobodyState, nobodyNonce) = t.start("nobody", nobody)
        idp.next(FakeOidcIdp.Identity("s-nobody", "oi-nobody@example.com", listOf("idp-other")), nobodyNonce)
        t.send("nobody", nobody, "/auth/oidc/callback?code=c1&state=$nobodyState")

        val first = cpGo.client()
        val (firstState, firstNonce) = t.start("alice", first, "/device?user_code=ABCD-1234")
        idp.next(FakeOidcIdp.Identity("s-alice", "oi-alice@example.com", listOf("idp-eng", "okta-oi-extra")), firstNonce)
        t.send("alice", first, "/auth/oidc/callback?code=c2&state=$firstState")
        t.send("alice", first, "/auth/me")

        val second = cpGo.client()
        val (secondState, secondNonce) = t.start("alice2", second)
        idp.next(FakeOidcIdp.Identity("s-alice", "oi-alice@example.com", listOf("idp-eng")), secondNonce)
        t.send("alice2", second, "/auth/oidc/callback?code=c3&state=$secondState")
        t.send("alice", first, "/auth/me")
        t.send("alice2", second, "/auth/me")

        idp.rejectRefresh("rt-s-alice-3")
        awaitEnded("oi-alice@example.com")
        t.send("alice2", second, "/auth/me")

        val actual = listOf(
            t.lines.joinToString("\n"),
            "users:",
            rows("SELECT principal || ' ' || source || ' ' || coalesce(email, '-') FROM app_user WHERE principal LIKE 'oi-%' ORDER BY principal"),
            "groups:",
            rows(
                """SELECT g.name || ' ' || u.principal FROM group_member m JOIN app_group g ON g.id = m.group_id
                   JOIN app_user u ON u.id = m.user_id WHERE u.principal LIKE 'oi-%' ORDER BY g.name, u.principal""",
            ),
            "sessions:",
            rows(
                """SELECT principal || ' ' || coalesce(ended_reason, 'live') || ' ' || (refresh_token_enc IS NOT NULL)
                   FROM principal_session WHERE principal LIKE 'oi-%' ORDER BY id""",
            ),
            "audit:",
            rows(
                """SELECT kind || ' ' || principal || ' ' || action || ' ' || regexp_replace(resource, '\d+', '{id}') || ' | ' ||
                          statement || ' | ' || coalesce(detail, '-') || ' | ' || outcome || ' ' || channel
                   FROM audit_event WHERE id > $before AND kind = 'auth' ORDER BY id""",
            ),
        ).joinToString("\n")
        assertEquals(EXPECTED.trim(), actual)
        verifyAuditChain(dataSource)
    }
}

private const val EXPECTED = """
stranger GET /auth/oidc/login -> 302 -> http://{idp}/authorize?client_id=fake-oidc-client&code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}&redirect_uri=http://control-plane.test/auth/oidc/callback&response_type=code&scope=openid email groups offline_access&state={state} | pm_oauth_nonce={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
stranger GET /auth/oidc/callback?code=c0 -> 302 -> /login?error=state | pm_oauth_nonce=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
denied GET /auth/oidc/login -> 302 -> http://{idp}/authorize?client_id=fake-oidc-client&code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}&redirect_uri=http://control-plane.test/auth/oidc/callback&response_type=code&scope=openid email groups offline_access&state={state} | pm_oauth_nonce={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
denied GET /auth/oidc/callback?error=access_denied -> 302 -> /login?error=oidc | pm_oauth_nonce=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
nobody GET /auth/oidc/login -> 302 -> http://{idp}/authorize?client_id=fake-oidc-client&code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}&redirect_uri=http://control-plane.test/auth/oidc/callback&response_type=code&scope=openid email groups offline_access&state={state} | pm_oauth_nonce={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
nobody GET /auth/oidc/callback?code=c1 -> 302 -> /login?error=no_access | pm_oauth_nonce=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
alice GET /auth/oidc/login?return_to=%2Fdevice%3Fuser_code%3DABCD-1234 -> 302 -> http://{idp}/authorize?client_id=fake-oidc-client&code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}&redirect_uri=http://control-plane.test/auth/oidc/callback&response_type=code&scope=openid email groups offline_access&state={state} | pm_oauth_nonce={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
alice GET /auth/oidc/callback?code=c2 -> 302 -> /device?user_code=ABCD-1234 | pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_nonce=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
alice GET /auth/me -> 200 {"principal":"oi-alice@example.com","roles":["oi-analyst"]}
alice2 GET /auth/oidc/login -> 302 -> http://{idp}/authorize?client_id=fake-oidc-client&code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}&redirect_uri=http://control-plane.test/auth/oidc/callback&response_type=code&scope=openid email groups offline_access&state={state} | pm_oauth_nonce={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier={value}; Max-Age=300; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
alice2 GET /auth/oidc/callback?code=c3 -> 302 -> / | pm_did={value}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_nonce=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_state=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_oauth_verifier=; Max-Age=0; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING | pm_session={value}; Max-Age=7200; Expires={at}; Path=/; HttpOnly; SameSite=Lax; ${"$"}x-enc=URI_ENCODING
alice GET /auth/me -> 401 {"reason":"displaced"}
alice2 GET /auth/me -> 200 {"principal":"oi-alice@example.com","roles":["oi-analyst"]}
alice2 GET /auth/me -> 401 {"reason":"expired"}
users:
oi-alice@example.com OIDC oi-alice@example.com
oi-nobody@example.com OIDC oi-nobody@example.com
groups:
idp-other oi-nobody@example.com
oi-eng oi-alice@example.com
sessions:
oi-alice@example.com DISPLACED true
oi-alice@example.com IDP_REJECTED true
audit:
auth unknown auth.oidc.login Client::"fake-oidc-client" | OIDC login failed | invalid_state | FAILURE oidc
auth unknown auth.oidc.login Client::"fake-oidc-client" | OIDC login failed | idp_error=access_denied | FAILURE oidc
auth oi-nobody@example.com auth.oidc.login User::"oi-nobody@example.com" | OIDC login failed | no_effective_roles | FAILURE oidc
auth oi-alice@example.com auth.oidc.login Session::"{id}" | OIDC login established session | - | SUCCESS oidc
auth oi-alice@example.com auth.oidc.login Session::"{id}" | OIDC login established session | - | SUCCESS oidc
auth oi-alice@example.com auth.session.expire Session::"{id}" | IdP rejected web session | idp_rejected | SUCCESS session
"""
