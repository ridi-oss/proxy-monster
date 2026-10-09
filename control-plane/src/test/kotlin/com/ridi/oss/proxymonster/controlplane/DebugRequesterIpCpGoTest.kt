package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** `POST /auth/debug`'s simulated requester address as cp-go validates it. */
class DebugRequesterIpCpGoTest {
    @Serializable
    private data class DebugLogin(val principal: String, val roles: List<String> = emptyList(), val requesterIp: String? = null)

    private val principal = "dev@example.com"

    /** Written as an escape so the source file itself stays free of a literal NUL byte. */
    private val NUL = "\u0000"

    private suspend fun HttpClient.debugLogin(ip: String?) = post("/auth/debug") {
        headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        setBody(DebugLogin(principal, emptyList(), ip))
    }

    private fun webSessionCount(dataSource: DataSource): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM principal_session WHERE kind = 'WEB'").use { ps ->
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun storedIp(dataSource: DataSource): String? = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT debug_requester_ip FROM principal_session WHERE kind = 'WEB' ORDER BY id DESC LIMIT 1",
        ).use { ps ->
            ps.executeQuery().use { rs -> assertTrue(rs.next(), "no web session row was minted"); rs.getString(1) }
        }
    }

    /** Renders control characters visibly, so a failure message names the input instead of printing it raw. */
    private fun String.escaped(): String = map { c ->
        if (c.isLetterOrDigit() || c in ".:%[]/-") c.toString() else "\\u%04x".format(c.code)
    }.joinToString("")

    @Test
    fun `a malformed address is refused rather than silently ignored`() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_debug_requester_ip_bad")
        val dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        CpGoStack(config, ControlPlaneCore(dataSource), database).use { stack ->
            runBlocking<Unit> {
                val client = stack.client()

                // Dropping it to null would present as "the tag rule does not work"; the login names the input instead.
                val bad = listOf(
                    "not-an-ip", "999.1.1.1", "100.100.1.10:5432", "100.100.1.0/24",
                    // Surrounding whitespace is deliberately absent: trim() removes it, leaving a valid address.
                    "100.100.1.10" + NUL, "100.100.1.10" + NUL + "12",
                    "100.100.1.10​",
                    "fe80::1%lo0", "[::1]",
                    // Accepted by cedar-java's regex, refused by the engine.
                    "100.100.001.010", "010.1.1.1",
                )
                for (value in bad) {
                    val response = client.debugLogin(value)
                    assertEquals(HttpStatusCode.BadRequest, response.status, "'${value.escaped()}' must be refused")
                    assertEquals(ApiError("auth.invalid_requester_ip"), response.body<ApiError>())
                }

                // A refused login must leave nothing behind.
                assertEquals(0, webSessionCount(dataSource), "a refused login must mint no session")

                // Positive controls: IPv6 and surrounding whitespace are what a too-eager tightening would break.
                for (good in listOf("100.100.1.10", "  100.100.1.10  ", "::1", "2001:db8::1", "fe80::1")) {
                    assertEquals(HttpStatusCode.OK, client.debugLogin(good).status, "'$good' must be accepted")
                    assertEquals(good.trim(), storedIp(dataSource), "'$good' must be stored as typed, trimmed")
                }
            }
        }
    }
}
