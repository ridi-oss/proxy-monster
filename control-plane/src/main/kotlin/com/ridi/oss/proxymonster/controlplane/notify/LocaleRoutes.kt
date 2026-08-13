package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.requireApi
import com.ridi.oss.proxymonster.controlplane.userSession
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.put
import kotlinx.serialization.Serializable

@Serializable
data class LocaleInput(val locale: String)

/**
 * The caller's own display language, which notification delivery reads (docs/notifications.md, "Language").
 *
 * Self-service by construction: it writes the CALLER's row and takes no principal parameter, so there is no
 * admin surface here. It is a display preference, never an authorization input — no policy reads it.
 */
fun Route.localeRoutes(config: Config, store: NotificationStore) {
    put("/api/me/locale") {
        val principal = call.requireApi() ?: return@put
        val locale = call.receive<LocaleInput>().locale.trim().lowercase()
        // Validated against the same closed set the catalog carries: an unknown locale has no messages, and
        // storing one would fall every message back to the default forever.
        if (locale !in MessageCatalog.LOCALES) {
            return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.invalid_value", mapOf("field" to "locale")))
        }
        // A principal with no directory row has nowhere to store this; it is not an error — delivery falls
        // back to the instance default, which is what they had.
        store.setLocale(principal, locale)
        call.respond(HttpStatusCode.NoContent)
    }
}
