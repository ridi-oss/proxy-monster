
// Root build for the proxy-monster multi-module project.
// Modules: :engine (parse+lineage), :auth (shared OIDC/OAuth primitives), :control-plane, :proto
// (the gRPC wire contract), and :analyzer:jvm (the sqlglot-go probe's JVM binding). Each module
// applies the Kotlin plugin without a version.
plugins {
    kotlin("jvm") version "2.4.10" apply false
    kotlin("plugin.serialization") version "2.4.10" apply false
}

// The build requires JDK 24 or newer: Kotlin's jvmTarget is JVM_24 in each module, and the Java
// compiler is pinned to release 24 below so compileJava and compileKotlin agree — an older JDK fails
// with "release version 24 not supported". The analyzer calls sqlglot-go's probe through the Foreign
// Function & Memory API (java.lang.foreign), which JDK 24 provides. No Java toolchain is set on
// purpose: that would also pin the run/test JDK, which mise already fixes (mise.toml pins temurin-24).
// Two Gradle invocations in one project directory fight over `build/` — the second deletes the
// classes the first is compiling into ("Unable to delete directory .../classes/kotlin/test"). Running
// the DB-version matrix legs concurrently needs each leg writing somewhere else, so `-Ppm.buildDir`
// relocates the whole build tree. Absent the property nothing changes, so ordinary builds keep using
// `build/` and stay incrementally cached.
val pmBuildDir: String? = providers.gradleProperty("pm.buildDir").orNull

subprojects {
    if (pmBuildDir != null) {
        layout.buildDirectory.set(rootProject.layout.projectDirectory.dir(pmBuildDir).dir(path.removePrefix(":").replace(':', '/')))
    }
    tasks.withType<org.gradle.api.tasks.compile.JavaCompile>().configureEach {
        options.release.set(24)
    }
    // The analyzer runs via sqlglot-go's JVM binding (java.lang.foreign → a Go c-shared lib), so every
    // JVM that touches it (tests + the dev-loop `run`) must enable native access, else the FFM downcall
    // warns/denies.
    tasks.withType<Test>().configureEach {
        jvmArgs("--enable-native-access=ALL-UNNAMED")
    }
    tasks.withType<JavaExec>().configureEach {
        jvmArgs("--enable-native-access=ALL-UNNAMED")
    }
}
