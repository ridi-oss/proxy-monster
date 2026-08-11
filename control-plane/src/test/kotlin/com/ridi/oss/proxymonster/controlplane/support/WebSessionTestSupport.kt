package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStorage
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.SESSION_COOKIE
import com.ridi.oss.proxymonster.controlplane.WebSessionRef
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ensureDeviceCookie
import com.ridi.oss.proxymonster.controlplane.jsonSessionSerializer
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import io.ktor.server.sessions.CookieIdSessionBuilder
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.SessionsConfig
import io.ktor.server.sessions.cookie

fun SessionsConfig.webSessionCookie(
    store: PrincipalSessionStore,
    secret: String,
    configure: CookieIdSessionBuilder<WebSessionRef>.() -> Unit = {},
) {
    val serializer = jsonSessionSerializer<WebSessionRef>()
    cookie<WebSessionRef>(SESSION_COOKIE, PrincipalSessionStorage(store, serializer)) {
        cookie.path = "/"
        cookie.httpOnly = true
        this.serializer = serializer
        transform(SessionTransportTransformerMessageAuthentication(secret.toByteArray()))
        configure()
    }
}

/**
 * A `POST /test/session/{principal}` route that mints a real web session and sets its cookie, so a suite
 * can sign in as any principal in one call. `PM_AUTH_DEBUG` authenticates nobody on its own — it enables a
 * login method — so a route test has to log in exactly like the console does.
 *
 * Install inside `routing { }` alongside the routes under test, then call it before the requests that need
 * a caller. The test client needs a cookie jar (`install(HttpCookies)`) for the cookie to be carried.
 */
fun Route.testLoginRoute(store: PrincipalSessionStore, config: Config) {
    post("/test/session/{principal}") {
        val deviceId = call.ensureDeviceCookie(secure = false)
        call.sessions.set(
            WebSessionRef(
                store.mintWeb(
                    requireNotNull(call.parameters["principal"]),
                    null,
                    config.webSessionAbsoluteSeconds,
                    config.webSessionIdleSeconds,
                    deviceId,
                ),
            ),
        )
        call.respond(HttpStatusCode.NoContent)
    }
}
