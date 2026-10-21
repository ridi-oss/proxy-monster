package com.ridi.oss.proxymonster.controlplane.support

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
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlin.test.assertEquals

@Serializable
data class DeviceStartResponse(
    val verificationUri: String,
    val verificationUriComplete: String,
    val userCode: String,
    val handle: String,
    val interval: Int,
)

@Serializable
data class DeviceConfirmAck(val ok: Boolean = true, val scopes: List<String> = emptyList(), val elevatedTtlSeconds: Long? = null)

@Serializable
data class DevicePollResult(
    val token: String,
    val expiresAt: String,
    val principal: String,
    val sessionExpiresAt: String,
    val renewalToken: String,
    val scopes: List<String> = emptyList(),
    val elevatedUntil: String? = null,
)

@Serializable
data class RenewSessionResponse(val token: String, val expiresAt: String)

@Serializable
data class PmonMcpTokenResponse(val accessToken: String, val expiresAt: String, val scope: String)

suspend fun HttpClient.deviceStart(scopes: List<String>?): HttpResponse = post("/auth/device/start") {
    contentType(ContentType.Application.Json)
    setBody(
        buildJsonObject {
            if (scopes != null) putJsonArray("scopes") { scopes.forEach { add(JsonPrimitive(it)) } }
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

suspend fun HttpClient.bearerPost(path: String, secret: String): HttpResponse = post(path) {
    header(HttpHeaders.Authorization, "Bearer $secret")
}
