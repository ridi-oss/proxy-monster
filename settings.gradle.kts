rootProject.name = "proxy-monster"

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

include(":engine")
include(":auth")
include(":control-plane")

// :proto — single source of truth for the proxy<->control-plane gRPC wire protocol
// (controlplane.proto). Generates Java+Kotlin messages and grpc-java+grpc-kotlin stubs for
// :control-plane; the data-plane proxy is the Go `goproxy` module, which generates its own stubs
// from the same controlplane.proto (goproxy/buf.gen.yaml → goproxy/internal/pb).
include(":proto")

// :analyzer:jvm — the Layer-1 analyzer's parse/lineage engine. proxy-monster owns the Go probe
// (analyzer/engines, analyzer/cmd/libsqlglot) and this JVM binding (FFM → a Go c-shared lib); the
// `buildNativeLib` task compiles the native lib for the host on first build. analyzer/ is a Go module
// depending on sqlglot-go purely as a parser/optimizer library (see analyzer/go.mod). (:analyzer is an
// implicit container for the Go module dir — it has no build script and builds nothing.)
include(":analyzer:jvm")
