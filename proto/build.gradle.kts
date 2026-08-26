import com.google.protobuf.gradle.id
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// :proto — the single source of truth for the protobuf contracts: the proxy<->control-plane gRPC
// wire protocol (controlplane.proto, docs/datasource-registration.md), the analyzer FFM boundary
// (analyzer.proto), and the shared engine.proto. Generates Java + Kotlin message types and
// grpc-java + grpc-kotlin stubs for the JVM modules that depend on it — :control-plane (the gRPC
// server), :engine (which uses the proto types as its data classes), and :analyzer:jvm's tests. The
// data plane is the Go `goproxy` module, not a Gradle subproject: it generates its own stubs from
// the same controlplane.proto (goproxy/buf.gen.yaml → goproxy/internal/pb).
plugins {
    kotlin("jvm")
    id("com.google.protobuf") version "0.10.0"
}

val protobufVersion = "4.36.0"
val grpcVersion = "1.83.1"
val grpcKotlinVersion = "1.5.0"

dependencies {
    // `api` so downstream modules get the runtime types + stubs transitively.
    api("com.google.protobuf:protobuf-java:$protobufVersion")
    api("com.google.protobuf:protobuf-kotlin:$protobufVersion")
    api("io.grpc:grpc-protobuf:$grpcVersion")
    api("io.grpc:grpc-stub:$grpcVersion")
    api("io.grpc:grpc-kotlin-stub:$grpcKotlinVersion")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    // grpc-java generated code references javax.annotation.Generated (not shipped in the JDK).
    api("javax.annotation:javax.annotation-api:1.3.2")
}

protobuf {
    protoc { artifact = "com.google.protobuf:protoc:$protobufVersion" }
    plugins {
        id("grpc") { artifact = "io.grpc:protoc-gen-grpc-java:$grpcVersion" }
        id("grpckt") { artifact = "io.grpc:protoc-gen-grpc-kotlin:$grpcKotlinVersion:jdk8@jar" }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.plugins {
                id("grpc")
                id("grpckt")
            }
            task.builtins {
                id("kotlin")
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_24)
    }
}
