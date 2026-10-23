
// Root build for the proxy-monster multi-module project.
// Modules: :engine (parse+lineage), :auth (shared OIDC/OAuth primitives), :control-plane, :proto
// (the gRPC wire contract), and :analyzer:jvm (the sqlglot-go probe's JVM binding). Each module
// applies the Kotlin plugin without a version.
plugins {
    kotlin("jvm") version "2.4.21" apply false
    kotlin("plugin.serialization") version "2.4.21" apply false
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

// -Ppm.testShard=i/n runs the i-th of n disjoint slices of every module's test classes, split by class name.
val pmTestShard: Pair<Int, Int>? = providers.gradleProperty("pm.testShard").orNull?.let { spec ->
    val parts = spec.split("/").mapNotNull { it.toIntOrNull() }
    require(parts.size == 2 && parts[1] >= 1 && parts[0] in 1..parts[1]) { "pm.testShard must be i/n with 1 <= i <= n, got $spec" }
    parts[0] to parts[1]
}

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
        // In CI every test runs on every commit, so a green check never stands on a cached result.
        if (providers.environmentVariable("CI").isPresent) {
            outputs.cacheIf { false }
            outputs.upToDateWhen { false }
        }
        pmTestShard?.let { (index, count) ->
            inputs.property("pmTestShard", "$index/$count")
            // A small module can fall wholly into another shard.
            failOnNoDiscoveredTests = false
            // A nested class goes with its outer class.
            exclude { e ->
                !e.isDirectory && e.name.endsWith(".class") &&
                    Math.floorMod(e.relativePath.pathString.removeSuffix(".class").substringBefore('$').hashCode(), count) != index - 1
            }
        }
    }
    tasks.withType<JavaExec>().configureEach {
        jvmArgs("--enable-native-access=ALL-UNNAMED")
    }
}
