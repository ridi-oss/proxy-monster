import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}

val ktorVersion = "3.5.1"
val testcontainersVersion = "1.21.4"

dependencies {
    implementation("io.ktor:ktor-client-core:$ktorVersion")
    implementation("io.ktor:ktor-client-cio:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")
    implementation("org.slf4j:slf4j-api:2.0.18")
    implementation("org.postgresql:postgresql:42.7.13")

    testImplementation(kotlin("test"))
    testImplementation("com.zaxxer:HikariCP:7.1.0")
    testImplementation("org.testcontainers:testcontainers:$testcontainersVersion")
    testImplementation("org.testcontainers:postgresql:$testcontainersVersion")
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_24)
    }
}

tasks.test {
    useJUnitPlatform()
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
    systemProperty("api.version", System.getenv("DOCKER_API_VERSION") ?: "1.44")
    environment("TESTCONTAINERS_RYUK_DISABLED", "true")
}
