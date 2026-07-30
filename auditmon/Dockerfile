# auditmon — the control-plane-independent audit monitor. Reads the committed audit trail read-only,
# re-verifies its tamper-evident hash chain, exports redacted event batches to a WORM object store, and
# periodically signs an off-box anchor. It never writes to the DB and has no inbound surface.
#
# A self-contained Go module (its own go.mod, no in-repo `replace` deps), so the build context is THIS
# directory. Build from auditmon/:
#   docker build -t proxy-monster-auditmon .
#
# Runtime env (see INSTALL.md): AUDITMON_CONFIG (path to the YAML; default /etc/auditmon/auditmon.yaml),
# AUDITMON_DB_DSN (the read-only Postgres DSN named by the config's db_dsn_env), AWS_REGION + a task IAM
# role for S3 + KMS, and any webhook URL env the alert sinks reference (e.g. SECOPS_WEBHOOK_URL).

FROM golang:1.26-bookworm AS build
WORKDIR /workspace
COPY . .
# All deps are pure Go (pgx, aws-sdk-go-v2), so CGO off → a fully static binary and the runtime image
# needs no libc. GOTOOLCHAIN=local pins the module's go 1.26 (no network toolchain fetch).
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -o /out/auditmon ./cmd/auditmon

# ---- Runtime ----
# debian-slim (rather than scratch/distroless) so there's a shell for ops; the binary is statically
# linked, so only ca-certificates is needed — auditmon makes outbound TLS to S3 / KMS / alert webhooks.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 pm && useradd --system --uid 10001 --gid pm --create-home pm \
    && mkdir -p /etc/auditmon && chown pm:pm /etc/auditmon

COPY --from=build /out/auditmon /usr/local/bin/auditmon
USER pm

# The monitor config is provided at runtime (a mounted file and/or AUDITMON_MONITOR_* env overrides), not
# baked — it varies per install and names its secrets by env-var. Point AUDITMON_CONFIG at it.
ENV AUDITMON_CONFIG=/etc/auditmon/auditmon.yaml

# No inbound surface (read-only daemon): a dead process exits the container, which is the failure signal,
# and there is no port to probe — so no HEALTHCHECK. On boot the monitor does a full from-genesis
# re-verification; a proven-tampered chain halts export/signing but the process stays up (fail-visible).
ENTRYPOINT ["/usr/local/bin/auditmon"]
