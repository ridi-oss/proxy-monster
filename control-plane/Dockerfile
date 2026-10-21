# control-plane — Ktor HTTP API (catalog/policy/grants/audit store, auth, serves the web UI's API).
#
# Build context is the REPO ROOT, not this directory — the multi-module Gradle build's
# settings.gradle.kts includes :engine, :auth, :control-plane, :proto, and :analyzer:jvm, so Gradle's
# configuration phase needs every module present even though this image only runs :control-plane.
# (The data-plane proxy is the separate Go `goproxy` module — goproxy/Dockerfile — not built here.)
# Build from the repo root:
#   docker build -f control-plane/Dockerfile -t proxy-monster-control-plane .
#
# Runtime env contract: see deploy/README.md (PM_HTTP_PORT, PM_DB_URL/USER/PASSWORD, PM_AUTH_DEBUG,
# PM_SESSION_SECRET, PM_RESULT_KEY, PM_OIDC_*, ...). PM_AUTH_DEBUG defaults to true (it's a dev auth
# bypass) — the app itself refuses to boot with it on in a production-looking context unless PM_DEV
# is also set, but set PM_AUTH_DEBUG=false explicitly for any real deployment regardless.

# Go toolchain for the analyzer's native lib (cmd/libsqlglot, cgo c-shared build). Pulled from the
# official Go image rather than apt/curl so the version matches mise.toml's `go = "1.26"` exactly
# and multi-arch (amd64/arm64) resolution is automatic.
FROM golang:1.26-bookworm AS go

# eclipse-temurin's Debian ("noble") variant, not alpine: the analyzer's native lib is built for
# glibc (analyzer/jvm/build.gradle.kts's zig targets are explicitly *-linux-gnu), and cedar-java's
# bundled JNI natives are glibc-linked too — musl (alpine) won't load either.
FROM eclipse-temurin:24-jdk-noble AS build
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# gcc: the analyzer's native lib build is plain cgo here (this build runs natively on Linux, inside
# the container — no Zig cross-compiler needed; see analyzer/jvm/build.gradle.kts).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Gradle/module build files first (better layer caching: dependency resolution reruns only when
# these change, not on every source edit).
COPY gradlew gradlew.bat build.gradle.kts settings.gradle.kts gradle.properties ./
COPY gradle ./gradle
COPY engine/build.gradle.kts engine/build.gradle.kts
COPY analyzer/jvm/build.gradle.kts analyzer/jvm/build.gradle.kts
COPY auth/build.gradle.kts auth/build.gradle.kts
COPY control-plane/build.gradle.kts control-plane/build.gradle.kts
COPY proto/build.gradle.kts proto/build.gradle.kts
RUN chmod +x gradlew

# Full sources for the modules this image actually needs.
COPY analyzer ./analyzer
COPY engine ./engine
COPY auth ./auth
COPY proto ./proto
COPY control-plane ./control-plane
COPY docs/guides/usage.md docs/guides/admin.md ./docs/guides/

RUN ./gradlew --no-daemon :control-plane:installDist -x test

# pmon-auto-approver-agent, the auto-approval agent cp-go runs once per review (auto-approver/), as one self-contained binary.
FROM oven/bun:1.3.14 AS agent
WORKDIR /workspace/auto-approver
COPY auto-approver/package.json auto-approver/bun.lock ./
RUN bun install --frozen-lockfile
COPY auto-approver/tsconfig.json ./
COPY auto-approver/src ./src
RUN bun build --compile src/main.ts --outfile /out/pmon-auto-approver-agent

# cp-go, the front door that owns the public ports and runs the Kotlin control plane as its child.
FROM go AS cpgo
WORKDIR /workspace/cpgo
COPY auditmon /workspace/auditmon
COPY analyzer /workspace/analyzer
COPY cpgo ./
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOWORK=off
RUN go build -trimpath -o /out/cp-go ./cmd/cp-go

# ---- Runtime ----
FROM eclipse-temurin:24-jre-noble

# curl: used by the HEALTHCHECK below. Also handy for ECS/EKS-native container health checks that
# exec a command inside the container (Kubernetes httpGet probes hit the pod over the network
# instead and don't need this at all).
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# CVE-2026-111943: the JDK's own cacerts still trusts emSign ECC Root CA - G3, whose intermediates' keys leaked.
RUN alias="$(keytool -list -cacerts -storepass changeit | grep -i '^cn_emsign_ecc_root_ca__g3' | sed 's/, [A-Z][a-z][a-z] [0-9].*//')" \
    && if [ -n "$alias" ]; then keytool -delete -cacerts -storepass changeit -alias "$alias"; fi \
    && ! keytool -list -cacerts -storepass changeit | grep -qi 'emsign_ecc_root_ca__g3'

RUN groupadd --system --gid 10001 pm && useradd --system --uid 10001 --gid pm --create-home pm
WORKDIR /app
COPY --from=build /workspace/control-plane/build/install/control-plane ./
COPY --from=cpgo /out/cp-go ./bin/cp-go
COPY --from=agent /out/pmon-auto-approver-agent ./bin/pmon-auto-approver-agent
RUN chown -R pm:pm /app
USER pm

# JDK_JAVA_OPTIONS, not JAVA_OPTS: the java launcher reads it on its own, so an operator's JAVA_OPTS
# adds to these flags instead of dropping the analyzer's FFM grant (--enable-native-access).
# 60% of RAM leaves room for the analyzer's native memory and cp-go; exit on OOM so the container is replaced.
# Override PM_HTTP_PORT via env; the healthcheck reads it back.
ENV JDK_JAVA_OPTIONS="--enable-native-access=ALL-UNNAMED -XX:MaxRAMPercentage=60 -XX:+ExitOnOutOfMemoryError"
ENV PM_HTTP_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS "http://127.0.0.1:${PM_HTTP_PORT}/health" || exit 1

ENTRYPOINT ["./bin/cp-go"]
