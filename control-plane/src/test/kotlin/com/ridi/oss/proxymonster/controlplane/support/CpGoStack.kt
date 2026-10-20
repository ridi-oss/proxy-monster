package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.module
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.plugins.defaultRequest
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.File
import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * The control plane as it runs in production: the Kotlin module on loopback with cp-go in front, so a test
 * drives the Go implementation of every route and RPC cp-go owns, and Kotlin for the rest.
 */
class CpGoStack(
    config: Config,
    core: ControlPlaneCore,
    database: String,
    extraEnv: Map<String, String> = emptyMap(),
    withGrpc: Boolean = false,
    configure: Application.() -> Unit = {},
) : AutoCloseable {
    private val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(24).also(SecureRandom()::nextBytes))
    private val kotlinConfig = config.copy(internalToken = token, trustedProxies = setOf("127.0.0.1"), bindHost = "127.0.0.1")
    private val kotlin: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> =
        embeddedServer(Netty, host = "127.0.0.1", port = 0) {
            module(kotlinConfig, core)
            configure()
        }.start()
    private val kotlinGrpc: GrpcServer? =
        if (withGrpc) GrpcServer(0, ControlPlaneGrpcService(core), kotlinConfig.secretToken, host = "127.0.0.1").also { it.start() } else null

    var httpPort = 0
        private set
    var grpcPort = 0
        private set
    val baseUrl get() = "http://127.0.0.1:$httpPort"
    private lateinit var process: Process
    private lateinit var log: File

    init {
        val kotlinPort = runBlocking { kotlin.engine.resolvedConnectors().first().port }
        val childGrpcPort = kotlinGrpc?.boundPort ?: freePort()
        // cp-go takes explicit ports, so another test JVM can take one between freePort() and cp-go's bind.
        for (attempt in 1..3) {
            httpPort = freePort()
            grpcPort = freePort()
            log = File(System.getProperty("pm.cpgo.logs", "build/cp-go-test"), "cp-go-$httpPort.log").also { it.parentFile.mkdirs() }
            val env = baseEnv(config) + dbEnv(database) + extraEnv + mapOf(
                "PM_CP_ATTACH" to "true",
                "PM_CP_INTERNAL_TOKEN" to token,
                "PM_CP_CHILD_HTTP_PORT" to kotlinPort.toString(),
                "PM_CP_CHILD_GRPC_PORT" to childGrpcPort.toString(),
                "PM_HTTP_PORT" to httpPort.toString(),
                "PM_GRPC_PORT" to grpcPort.toString(),
                // A wildcard listener on macOS silently shares its port with another process's 127.0.0.1 one.
                "PM_BIND_HOST" to "127.0.0.1",
            )
            process = ProcessBuilder(cpGoBinary())
                .redirectErrorStream(true)
                .redirectOutput(log)
                .also { it.environment().putAll(env) }
                .start()
            if (awaitHealthy(lastAttempt = attempt == 3)) break
        }
    }

    /** A client for cp-go's HTTP port that keeps cookies and, unless [followRedirects], reports redirects as they come. */
    fun client(followRedirects: Boolean = false): HttpClient = HttpClient(CIO) {
        expectSuccess = false
        this.followRedirects = followRedirects
        install(HttpCookies)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        defaultRequest { url(baseUrl) }
    }

    /** Everything cp-go has logged so far. */
    fun logText(): String = log.readText()

    /** A plaintext channel to cp-go's gRPC port. */
    fun channel(): ManagedChannel = NettyChannelBuilder.forAddress("127.0.0.1", grpcPort).usePlaintext().build()

    override fun close() {
        process.destroy()
        if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly()
        kotlinGrpc?.let { it.beginShutdown(); it.awaitTerminated() }
        kotlin.stop(0, 0)
    }

    /** False when cp-go exited before serving, which a port taken by another process causes. */
    private fun awaitHealthy(lastAttempt: Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        var last = "no answer"
        while (System.nanoTime() < deadline) {
            if (!process.isAlive) {
                if (!lastAttempt && log.readText().contains("address already in use")) return false
                error("cp-go exited (${process.exitValue()}); see ${log.path}:\n${log.readText().takeLast(4000)}")
            }
            last = runCatching {
                (URI("$baseUrl/health").toURL().openConnection() as HttpURLConnection).run {
                    connectTimeout = 500
                    readTimeout = 2000
                    responseCode.toString().also { disconnect() }
                }
            }.getOrElse { it.toString() }
            if (last == "200") return true
            Thread.sleep(100)
        }
        close()
        error("cp-go did not become healthy (last /health: $last); see ${log.path}")
    }

    companion object {
        private fun freePort(): Int = ServerSocket(0).use { it.localPort }

        private fun cpGoBinary(): String = System.getProperty("pm.cpgo.bin")
            ?.takeIf { File(it).canExecute() }
            ?: error("pm.cpgo.bin is unset; run the tests through Gradle, which builds cp-go first")

        /** The settings cp-go shares with the Kotlin process, taken from the test's [Config]. */
        private fun dbEnv(database: String) = mapOf(
            "PM_DB_URL" to SharedPostgres.jdbcUrlFor(database),
            "PM_DB_USER" to SharedPostgres.username(),
            "PM_DB_PASSWORD" to SharedPostgres.password(),
        )

        private fun baseEnv(c: Config): Map<String, String> = buildMap {
            put("PM_AUTH_DEBUG", c.authDebug.toString())
            put("PM_SESSION_SECRET", c.sessionSecret)
            c.secretToken?.let { put("PM_SECRET_TOKEN", it) }
            c.resultKey?.let { put("PM_RESULT_KEY", Base64.getEncoder().encodeToString(it)) }
            put("PM_MCP_RESOURCE", c.mcpResource)
            put("PM_WEB_ORIGIN", c.webOrigin)
            put("PM_INSTANCE_NAME", c.instanceName)
            put("PM_SESSION_WINDOW", c.sessionWindowSeconds.toString())
            put("PM_WEB_SESSION_ABSOLUTE", c.webSessionAbsoluteSeconds.toString())
            put("PM_WEB_SESSION_IDLE", c.webSessionIdleSeconds.toString())
            put("PM_WEB_SESSION_SLIDE", c.webSessionSlideSeconds.toString())
            put("PM_WEB_SESSION_IDLE_WARN_LEAD", c.webSessionIdleWarnLeadSeconds.toString())
            put("PM_WEB_SESSION_ABSOLUTE_WARN_LEAD", c.webSessionAbsoluteWarnLeadSeconds.toString())
            put("PM_WEB_SESSION_HEARTBEAT", c.webSessionHeartbeatSeconds.toString())
            put("PM_IDP_RECHECK_INTERVAL", c.idpRecheckIntervalSeconds.toString())
            put("PM_OAUTH_ACCESS_TTL", c.mcpAccessTtlSeconds.toString())
            put("PM_ELEVATED_SCOPE_TTL", c.elevatedScopeTtlSeconds.toString())
        }
    }
}
