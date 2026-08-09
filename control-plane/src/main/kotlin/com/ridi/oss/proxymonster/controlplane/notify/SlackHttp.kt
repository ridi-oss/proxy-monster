package com.ridi.oss.proxymonster.controlplane.notify

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.websocket.WebSockets

/**
 * The Slack HTTP client. Separate from the OIDC client on purpose: that one sets `expectSuccess = true` and
 * would throw on any non-2xx, but a transport must READ Slack's error body to decide retry-vs-drop.
 * WebSockets are installed for the inbound Socket Mode connection.
 */
fun slackHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = false
    install(WebSockets)
}
