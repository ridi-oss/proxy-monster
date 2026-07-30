# goproxy — native-wire (Postgres/MySQL) enforcing broker. The Go rewrite of the former Kotlin :proxy
# module. One image, two engines: PM_ENGINE selects postgres or mysql at runtime. Deploy one task/pod
# PER DATASOURCE (a separate pg-proxy and mysql-proxy process each), each with its own
# PM_ENGINE / PM_DATASOURCE_NAME / PM_PROXY_PORT / PM_TARGET_* (+ PM_CONTROL_PLANE_GRPC, PM_SECRET_TOKEN,
# optional PM_TLS_CERT/PM_TLS_KEY) — see deploy/README.md.
#
# Build context is the REPO ROOT: goproxy depends on the sibling `mysqlwire` module via a replace
# directive, so both must be in the context. The generated proto stubs (goproxy/internal/pb) are
# committed, so no codegen runs at build time. Build from the repo root:
#   docker build -f goproxy/Dockerfile -t proxy-monster-proxy .

FROM golang:1.26-bookworm AS build
WORKDIR /workspace
# goproxy's go.mod resolves ../mysqlwire and ../analyzer via `replace` directives; copy all three modules.
COPY mysqlwire ./mysqlwire
COPY analyzer ./analyzer
COPY goproxy ./goproxy
WORKDIR /workspace/goproxy
# GOTOOLCHAIN=local pins the module's go 1.26 (no network toolchain fetch); CGO off → a static binary,
# so the runtime image needs no libc beyond the base.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -o /out/goproxy ./cmd/goproxy

# ---- Runtime ----
# debian-slim (rather than scratch/distroless) so the TCP health check below has a shell; the binary is
# statically linked, so nothing else from the base is required.
FROM debian:bookworm-slim

RUN groupadd --system --gid 10001 pm && useradd --system --uid 10001 --gid pm --create-home pm
COPY --from=build /out/goproxy /usr/local/bin/goproxy
USER pm

# Informational only (the actual bind port is PM_PROXY_PORT, engine-dependent) — the Postgres / MySQL
# defaults respectively. Always set PM_ENGINE + PM_PROXY_PORT explicitly per deployment.
EXPOSE 6432 6033

# No HTTP surface to probe (this is a raw wire-protocol broker) — a bare TCP connect is the health
# signal, same as the former :proxy image. PM_TARGET_* reachability and control-plane connectivity are
# NOT checked here; those surface as query-time errors, not a dead process.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/${PM_PROXY_PORT:-6432}' || exit 1

ENTRYPOINT ["/usr/local/bin/goproxy"]
