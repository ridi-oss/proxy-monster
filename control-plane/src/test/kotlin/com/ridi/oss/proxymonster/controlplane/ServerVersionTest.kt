package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ServerVersionTest {
    private val repoRoot: Path = Path.of("..").toAbsolutePath().normalize()

    @Test
    fun `the server version is the released one, and release-please rewrites its file`() {
        val manifest = Json.parseToJsonElement(repoRoot.resolve(".release-please-manifest.json").readText()).jsonObject
        assertEquals(manifest.getValue(".").jsonPrimitive.content, SERVER_VERSION)

        val config = Json.parseToJsonElement(repoRoot.resolve("release-please-config.json").readText()).jsonObject
        val extraFiles = config.getValue("packages").jsonObject.getValue(".").jsonObject.getValue("extra-files").jsonArray
        assertTrue(
            extraFiles.any {
                it.jsonObject["path"]?.jsonPrimitive?.content == "control-plane/src/main/resources/proxymonster/server-version.json"
            },
            "release-please must rewrite server-version.json, or the reported version freezes at this release",
        )
    }
}
