import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// :engine — SQL parse + field-level lineage via the sqlglot-go probe, called in-process through its
// JVM binding (:analyzer:jvm, FFM → a Go c-shared lib). The analysis core shared by the proxy
// (audit/enforcement decisions) and the control plane (policy evaluation). Bytecode targets JVM 24
// (the root build pins Java --release 24), so building it needs JDK 24 or newer.
plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-serialization-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    // Layer-1 analyzer: the column-lineage probe via its in-repo JVM binding (FFM → Go c-shared lib).
    // The probe (analyzer/) and this binding (analyzer/jvm) live in this repo; see settings.gradle.kts.
    implementation(project(":analyzer:jvm"))
    // The gRPC wire types are used AS the data classes across the engine and control plane (proto types
    // are safe beyond the gRPC boundary): ColumnMask is proto ColumnMask, so masking speaks proto directly.
    api(project(":proto"))
    testImplementation(kotlin("test"))
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_24)
    }
}

tasks.test {
    useJUnitPlatform()
    // The native-access jvmArg the FFM binding needs is configured for every module's Test task in the
    // root build; :engine depends on :analyzer:jvm, whose processResources builds + bundles the lib.
}
