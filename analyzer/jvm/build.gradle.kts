import org.gradle.api.tasks.Exec
import org.gradle.language.jvm.tasks.ProcessResources
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// :analyzer:jvm — the in-process JVM binding to the sqlglot-go lineage probe (FFM → a Go c-shared lib
// built from ../cmd/libsqlglot). A regular subproject of proxy-monster: the Kotlin plugin version, the
// JDK (mise-provided, no toolchain pin), repositories, and the native-access jvmArgs on Test tasks all
// come from the root build. Bytecode targets JVM 24, so building and running it needs JDK 24+, which
// also provides the FFM API (java.lang.foreign) this binding is built on.
plugins {
    kotlin("jvm")
    `java-library`
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_24) } }

dependencies {
    // Production code stays proto-agnostic (raw ByteArray in/out — see Sqlglot.kt's doc comment); the
    // test suite needs the actual analyzer.proto message types to exercise the binding meaningfully.
    testImplementation(project(":proto"))
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// ---- Native libraries: build cmd/libsqlglot (Go, c-shared) per target and bundle as resources ----
// The Go module root (analyzer/) is the parent of this Gradle project (analyzer/jvm/).
//
// One build produces libs for all supported targets so a single (fat) jar runs on any of them:
// the host's own target is always a plain native cgo build; every OTHER target is cross-compiled
// with Zig as the C compiler (`zig cc -target …`), pinned to an old glibc for forward compatibility.
// A Linux target is therefore native (no Zig) when the build itself runs on matching Linux — e.g. the
// control-plane/Dockerfile container build or Linux CI — and cross-compiled only when building from
// macOS. (The Go data-plane proxy, goproxy/Dockerfile, does not use the analyzer and builds no native
// lib.) The FFM wrapper selects `native/<os>-<arch>/libsqlglot.<ext>` at runtime.
//
//   ./gradlew --no-daemon :analyzer:jvm:build                            -> host lib only (fast; dev)
//   ./gradlew --no-daemon :analyzer:jvm:build -Psqlglot.native.all=true  -> all targets (needs `zig` on PATH); the distributable jar
//
// Cross-building the darwin target from a non-darwin host is NOT supported (needs the macOS SDK),
// so the all-targets build must run on macOS/arm64. CI does exactly that.
private val goModuleDir = projectDir.parentFile
private val nativeResourcesDir = layout.buildDirectory.dir("native-resources")
private val zigExe = (findProperty("zig") as String?) ?: "zig"

// (os, arch, ext, zigTarget). zigTarget == null => build natively (host only, no cross toolchain).
data class NativeTarget(val os: String, val arch: String, val ext: String, val zigTarget: String?)

val nativeTargets = listOf(
    NativeTarget("darwin", "arm64", "dylib", null),
    NativeTarget("linux", "amd64", "so", "x86_64-linux-gnu.2.17"),
    NativeTarget("linux", "arm64", "so", "aarch64-linux-gnu.2.17"),
)

fun hostOsArch(): Pair<String, String> {
    val osName = System.getProperty("os.name").lowercase()
    val os = when {
        osName.contains("mac") || osName.contains("darwin") -> "darwin"
        osName.contains("linux") -> "linux"
        else -> error("unsupported build OS: $osName")
    }
    val arch = when (val a = System.getProperty("os.arch").lowercase()) {
        "aarch64", "arm64" -> "arm64"
        "x86_64", "amd64" -> "amd64"
        else -> error("unsupported build arch: $a")
    }
    return os to arch
}

val (hostOs, hostArch) = hostOsArch()

val nativeTasks = nativeTargets.associateWith { t ->
    tasks.register<Exec>("buildNativeLib_${t.os}_${t.arch}") {
        group = "build"
        description = "Builds cmd/libsqlglot (c-shared) for ${t.os}/${t.arch}."
        val outFile = nativeResourcesDir.get().dir("native/${t.os}-${t.arch}").file("libsqlglot.${t.ext}").asFile
        workingDir = goModuleDir
        environment("CGO_ENABLED", "1")
        environment("GOOS", t.os)
        environment("GOARCH", t.arch)
        // Zig is a CROSS C compiler — only needed when this target differs from the actual build
        // host (e.g. cross-building linux/arm64 from macOS). A linux target built by a linux build
        // host of the same arch (a container build, CI on a Linux runner, ...) is a plain native
        // cgo build via the host's own gcc/clang — no zig required.
        val isCross = t.zigTarget != null && (t.os != hostOs || t.arch != hostArch)
        if (isCross) {
            environment("CC", "$zigExe cc -target ${t.zigTarget}")
            environment("CXX", "$zigExe c++ -target ${t.zigTarget}")
        }
        commandLine("go", "build", "-buildmode=c-shared", "-o", outFile.absolutePath, "./cmd/libsqlglot")
        doFirst { outFile.parentFile.mkdirs() }
        inputs.files(
            fileTree(goModuleDir) {
                include("**/*.go", "go.mod", "go.sum")
                exclude("jvm/**", ".reference/**", ".git/**")
            },
        ).withPathSensitivity(PathSensitivity.RELATIVE)
        if (isCross) inputs.property("zig", zigExe)
        outputs.file(outFile)
    }
}

val hostTarget = nativeTargets.firstOrNull { it.os == hostOs && it.arch == hostArch }
    ?: error("no native target defined for host $hostOs/$hostArch")

val buildNativeLib by tasks.registering {
    group = "build"
    description = "Builds the c-shared lib for the host platform only (fast; used by the default build)."
    dependsOn(nativeTasks[hostTarget])
}

val buildAllNativeLibs by tasks.registering {
    group = "build"
    description = "Builds c-shared libs for ALL targets (host native + Linux via Zig). Run on macOS/arm64."
    dependsOn(nativeTasks.values)
}

private val bundleAllNatives = (findProperty("sqlglot.native.all") as String?)?.toBoolean() ?: false

sourceSets.named("main") { resources.srcDir(nativeResourcesDir) }
tasks.named<ProcessResources>("processResources") {
    dependsOn(if (bundleAllNatives) buildAllNativeLibs else buildNativeLib)
    exclude("**/*.h") // the cgo header is emitted next to the lib; not needed at runtime
}

tasks.test {
    useJUnitPlatform()
    // FFM restricted methods (libraryLookup / reinterpret) — grant native access. The root build also
    // adds this to every subproject's Test task; kept here too so this module's tests are self-contained.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
