package com.ridi.oss.proxymonster.controlplane.source

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout

/** `expectSuccess = false`: the adapter reads GitHub's status and body itself to raise a typed [GitHubException]. */
fun githubHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = false
    install(HttpTimeout) {
        requestTimeoutMillis = 30_000
        connectTimeoutMillis = 10_000
    }
}
