package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.DeviceConfirmAck
import com.ridi.oss.proxymonster.controlplane.DevicePollResult
import com.ridi.oss.proxymonster.controlplane.DeviceStartResponse
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.assertEquals

/** A clock a test moves by hand. */
class TestClock(@Volatile var now: Instant = Instant.now()) : Clock() {
    override fun instant(): Instant = now
    override fun getZone(): ZoneId = ZoneOffset.UTC
    override fun withZone(zone: ZoneId): Clock = this
    fun advance(by: Duration) { now = now.plus(by) }
}

suspend fun HttpClient.deviceStart(scopes: List<String>?): HttpResponse = post("/auth/device/start") {
    contentType(ContentType.Application.Json)
    setBody(
        buildJsonObject {
            if (scopes != null) putJsonArray("scopes") { scopes.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) } }
        }.toString(),
    )
}

/** Confirm [userCode] as the signed-in browser does. */
suspend fun HttpClient.deviceConfirm(userCode: String): DeviceConfirmAck {
    val res = post("/auth/device/confirm") { contentType(ContentType.Application.Json); setBody("""{"userCode":"$userCode"}""") }
    assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
    return MCP_TEST_JSON.decodeFromString(res.bodyAsText())
}

/** A whole pmon device login for [principal] through the production routes: start, confirm, approve, poll. */
suspend fun HttpClient.pmonLogin(principal: String, scopes: List<String>? = null): DevicePollResult {
    val start = deviceStart(scopes)
    assertEquals(HttpStatusCode.OK, start.status, start.bodyAsText())
    val started = MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(start.bodyAsText())
    login(principal)
    deviceConfirm(started.userCode)
    get("/auth/device/authorize?user_code=${started.userCode}")
    val poll = post("/auth/device/poll") { contentType(ContentType.Application.Json); setBody("""{"handle":"${started.handle}"}""") }
    assertEquals(HttpStatusCode.OK, poll.status, poll.bodyAsText())
    return MCP_TEST_JSON.decodeFromString(poll.bodyAsText())
}
