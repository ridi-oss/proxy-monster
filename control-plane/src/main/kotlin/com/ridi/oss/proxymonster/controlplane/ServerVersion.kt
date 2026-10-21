package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** The server release, rewritten by release-please (release-please-config.json extra-files). */
val SERVER_VERSION: String by lazy {
    val text = checkNotNull(Thread.currentThread().contextClassLoader.getResource("proxymonster/server-version.json")) {
        "server-version.json is missing from the classpath"
    }.readText()
    Json.parseToJsonElement(text).jsonObject.getValue("version").jsonPrimitive.content
}
