import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// :control-plane — Ktor HTTP service backed by Postgres (plain JDBC + HikariCP + Flyway).
// Owns the catalog/policy/grants/audit store, auth (debug + OIDC), and serves the web UI.
plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

val ktorVersion = "3.2.0"
val flywayVersion = "13.0.0"
val testcontainersVersion = "1.20.4"
// 0.10.0 is the last official kotlin-sdk line built on Ktor 3.2.x (3.2.3); newer releases require
// Ktor 3.3/3.4. It provides the official stateless Streamable HTTP server/client and structured tools.
val mcpVersion = "0.10.0"
// Cedar (cedar-policy/cedar-java) — the authz decision engine (docs/authz-model.md). The plain jar
// ships no native lib; the "uber" classifier bundles the JNI natives for macOS/Linux/Windows
// (x86_64 + aarch64), verified empirically to load on macOS aarch64 (Apple Silicon dev machines).
val cedarVersion = "4.3.1"

dependencies {
    implementation(project(":engine"))
    implementation(project(":auth"))
    implementation("io.modelcontextprotocol:kotlin-sdk-server:$mcpVersion")
    // gRPC wire protocol shared with the data-plane proxy (the Go `goproxy` module;
    // docs/datasource-registration.md). Brings in the generated messages/stubs plus
    // grpc-protobuf/stub/kotlin runtime transitively (api scope).
    implementation(project(":proto"))
    // The gRPC server transport for the control-plane's ControlPlane service (netty, shaded to
    // avoid clashing with Ktor's own Netty on the classpath).
    implementation("io.grpc:grpc-netty-shaded:1.68.1")

    // Ktor server
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    implementation("io.ktor:ktor-server-auth:$ktorVersion")
    implementation("io.ktor:ktor-server-sessions:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages:$ktorVersion")
    implementation("io.ktor:ktor-server-call-logging:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")

    // Ktor client (OIDC discovery/token/userinfo exchange)
    implementation("io.ktor:ktor-client-core:$ktorVersion")
    implementation("io.ktor:ktor-client-cio:$ktorVersion")
    implementation("io.ktor:ktor-client-okhttp:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation:$ktorVersion")

    // JOSE/JWT (id_token signature + JWKS validation, docs/auth-model.md) — no JOSE lib existed
    // in this module before; the prior Okta.kt flow trusted userinfo instead of validating id_token.
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")

    // Control-plane store: PostgreSQL only (plain JDBC + Hikari pooling + Flyway migrations).
    // Db.kt hardcodes org.postgresql.Driver; there is no MySQL store variant.
    implementation("com.zaxxer:HikariCP:7.1.0")
    implementation("org.postgresql:postgresql:42.7.4")
    // Target databases (what the proxy protects) are a separate axis from the store above.
    // MySQL is the primary target engine. Connector/J drives the MySQL-target DB-backed tests;
    // the control plane itself opens no JDBC connection to a target (the Go proxy introspects).
    implementation("com.mysql:mysql-connector-j:9.1.0")
    implementation("org.flywaydb:flyway-core:$flywayVersion")
    implementation("org.flywaydb:flyway-database-postgresql:$flywayVersion")

    implementation("ch.qos.logback:logback-classic:1.5.12")

    // Cedar policy engine (authz decision service, docs/authz-model.md). `uber` classifier bundles
    // the per-platform JNI native libs (jne/<os>/<arch>/libcedar_java_ffi.*) that the plain jar lacks.
    // Requesting an explicit classifier makes Gradle do artifact-only (Ivy-style) resolution for this
    // dependency, which does NOT pull in the runtime deps declared in its Gradle Module Metadata —
    // verified empirically (`cedar-java:4.3.1` resolves as a leaf with no children otherwise). Add
    // them explicitly, pinned to the versions cedar-java 4.3.1's POM declares.
    implementation("com.cedarpolicy:cedar-java:$cedarVersion:uber")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8:2.18.2")
    implementation("com.fizzed:jne:4.3.0")
    implementation("com.google.guava:guava:33.4.0-jre")

    testImplementation(kotlin("test"))
    // Route-level gate tests (requireAdmin wired into cedarPolicyRoutes) exercise real Ktor routing.
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.modelcontextprotocol:kotlin-sdk-client:$mcpVersion")
    // The mock Slack server the transport/socket tests run against is a real embedded server on an ephemeral
    // port, so they exercise their true wire encoding (form vs JSON, the Socket Mode WebSocket). Netty is
    // already on the main classpath; only the server-side WebSockets plugin is test-only.
    testImplementation("io.ktor:ktor-server-websockets:$ktorVersion")
    // DB-backed tests run enforcement/stores against real MySQL + Postgres via Testcontainers.
    // Containers are launched once and reused across the module's tests (see support/TestDatabases.kt).
    testImplementation("org.testcontainers:testcontainers:$testcontainersVersion")
    testImplementation("org.testcontainers:postgresql:$testcontainersVersion")
    testImplementation("org.testcontainers:mysql:$testcontainersVersion")
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_24)
    }
}

application {
    mainClass.set("com.ridi.oss.proxymonster.controlplane.MainKt")
}


tasks.test {
    useJUnitPlatform()
    // DbSupportMatrixTest reads these from outside the source tree, so Gradle cannot infer them.
    // Undeclared, the test task stays UP-TO-DATE after a supported version is added or removed and the
    // guard never re-runs — it would report the previous run's pass against the new declaration.
    inputs.file(rootProject.file("db-support.json"))
    inputs.dir(rootProject.file(".github/workflows")).optional()
    // The image env vars select which database version the DB-backed tests run against, so a run under
    // a different version is a different run. Without this Gradle would treat the second version's run
    // as UP-TO-DATE and skip it, and the matrix would test one version while reporting several.
    inputs.property("pmTestPostgresImage", System.getenv("PM_TEST_POSTGRES_IMAGE") ?: "")
    inputs.property("pmTestMysqlImage", System.getenv("PM_TEST_MYSQL_IMAGE") ?: "")
    // Testcontainers Docker discovery. On macOS Docker Desktop the default socket
    // (~/.docker/run/docker.sock) is a CLI proxy that returns HTTP 400 to docker-java's /info probe,
    // so DB-backed tests silently skip. Point the forked test JVM at an explicit DOCKER_HOST if set,
    // otherwise the raw engine socket (Docker Desktop) or the standard Linux/CI socket. Set once here
    // so it reaches the worker regardless of the (possibly long-lived) Gradle daemon's own env.
    if (System.getenv("DOCKER_HOST") == null) {
        val home = System.getProperty("user.home")
        val rawSock = file("$home/Library/Containers/com.docker.docker/Data/docker.raw.sock")
        val candidate = when {
            rawSock.exists() -> "unix://${rawSock.absolutePath}"
            file("/var/run/docker.sock").exists() -> "unix:///var/run/docker.sock"
            else -> null
        }
        if (candidate != null) environment("DOCKER_HOST", candidate)
    }
    // docker-java defaults to Docker API v1.32, which modern engines reject with HTTP 400
    // ("client version 1.32 is too old. Minimum supported API version is 1.40") — the real cause of
    // the "no valid Docker environment" skip. docker-java reads this from the `api.version` system
    // property (not the DOCKER_API_VERSION env), so pin a version both sides support.
    systemProperty("api.version", System.getenv("DOCKER_API_VERSION") ?: "1.44")
    // Ryuk (the resource reaper) can't attach to the Desktop raw socket cleanly; the shared-container
    // singletons never stop mid-run and the JVM exit frees them, so disable it.
    environment("TESTCONTAINERS_RYUK_DISABLED", "true")
    // The FFM binding's native-access jvmArg is added to every module's Test task in the root build;
    // :control-plane depends (transitively) on :analyzer:jvm, whose processResources builds the lib.
}
