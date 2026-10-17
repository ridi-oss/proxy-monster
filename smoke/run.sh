#!/usr/bin/env bash
# End-to-end smoke: datastores from compose, a freshly built control plane, one wire proxy per engine,
# and pmon, all from this checkout; then smoke.py drives every leg and prints a PASS/FAIL table.
#
#   smoke/run.sh                 full run, tears everything down at the end
#   smoke/run.sh --keep          leave the stack up for debugging (prints how to stop it)
#   smoke/run.sh --no-build      reuse the binaries from the last run
#   smoke/run.sh --only wire     run one leg (editor|browser|wire|pmon|workflow|audit|rate|github|names)
#   smoke/run.sh --engine mysql  run one matrix row (mysql|mysql-lctn1|postgres|athena)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SMOKE_DIR="${SMOKE_DIR:-${TMPDIR:-/tmp}/pm-smoke}"
PROJECT="${SMOKE_COMPOSE_PROJECT:-pm-smoke}"
export SMOKE_CP_DB_PORT="${SMOKE_CP_DB_PORT:-17010}"
export SMOKE_MYSQL_PORT="${SMOKE_MYSQL_PORT:-17011}"
export SMOKE_PG_PORT="${SMOKE_PG_PORT:-17012}"
export SMOKE_ATHENA_PORT="${SMOKE_ATHENA_PORT:-17013}"
export SMOKE_MYSQL_LCTN1_PORT="${SMOKE_MYSQL_LCTN1_PORT:-17015}"
CP_HTTP="${SMOKE_CP_HTTP_PORT:-17000}"
CP_GRPC="${SMOKE_CP_GRPC_PORT:-17001}"
CP_CHILD_HTTP="${SMOKE_CP_CHILD_HTTP_PORT:-17030}"
CP_CHILD_GRPC="${SMOKE_CP_CHILD_GRPC_PORT:-17031}"
PROXY_MYSQL="${SMOKE_PROXY_MYSQL_PORT:-17002}"
PROXY_PG="${SMOKE_PROXY_PG_PORT:-17003}"
PROXY_ATHENA="${SMOKE_PROXY_ATHENA_PORT:-17014}"
PROXY_MYSQL_LCTN1="${SMOKE_PROXY_MYSQL_LCTN1_PORT:-17016}"
PMON_BASE="${SMOKE_PMON_PORT_BASE:-17020}"
GITHUB_TLS="${SMOKE_GITHUB_PORT:-17040}"
GITHUB_HTTP="${SMOKE_GITHUB_TOKEN_PORT:-17041}"
WEB="${SMOKE_WEB_PORT:-17004}"

KEEP=0; BUILD=1; ONLY=""; ENGINE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --no-build) BUILD=0 ;;
    --only) ONLY="$2"; shift ;;
    --engine) ENGINE="$2"; shift ;;
    *) echo "unknown flag $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$SMOKE_DIR/logs" "$SMOKE_DIR/bin" "$SMOKE_DIR/pmon" "$SMOKE_DIR/athena" "$SMOKE_DIR/github"
chmod 700 "$SMOKE_DIR/pmon" "$SMOKE_DIR/athena" "$SMOKE_DIR/github"
echo "smoke: logs in $SMOKE_DIR/logs"

compose() { docker compose -p "$PROJECT" -f "$ROOT/smoke/docker-compose.yml" "$@"; }
pids=()
cleanup() {
  status=$?
  for p in "${pids[@]:-}"; do [ -n "$p" ] && { pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; } || true; done
  if [ -x "$SMOKE_DIR/bin/pmon" ]; then
    PMON_CONFIG_DIR="$SMOKE_DIR/pmon" "$SMOKE_DIR/bin/pmon" stop -f >/dev/null 2>&1 || true
  fi
  if [ "$KEEP" = 1 ]; then
    echo "smoke: stack left up (--keep); stop it with: docker compose -p $PROJECT -f smoke/docker-compose.yml down -v"
  else
    compose down -v >/dev/null 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT

echo "smoke: starting datastores (compose project $PROJECT)"
compose down -v >/dev/null 2>&1 || true
compose up -d --wait > "$SMOKE_DIR/logs/compose.log" 2>&1 &
compose_pid=$!
pids+=("$compose_pid")

if [ "$BUILD" = 1 ]; then
  echo "smoke: building control plane, cp-go, goproxy, pmon, pm-ci"
  builds=()
  (cd "$ROOT" && ./gradlew --no-daemon -q :control-plane:installDist) > "$SMOKE_DIR/logs/build-cp.log" 2>&1 &
  builds+=($!)
  pids+=($!)
  for target in cpgo:cp-go:./cmd/cp-go goproxy:goproxy:./cmd/goproxy pmon:pmon:. sql-action:pm-ci:.; do
    IFS=: read -r dir bin pkg <<< "$target"
    (cd "$ROOT/$dir" && go build -o "$SMOKE_DIR/bin/$bin" "$pkg") > "$SMOKE_DIR/logs/build-$bin.log" 2>&1 &
    builds+=($!)
    pids+=($!)
  done
  for b in "${builds[@]}"; do
    wait "$b" || { echo "smoke: a build failed; see $SMOKE_DIR/logs/build-*.log" >&2; exit 1; }
  done
fi
wait "$compose_pid" || { echo "smoke: the datastores did not come up; see $SMOKE_DIR/logs/compose.log" >&2; exit 1; }

# next dev takes seconds to start, so the console starts now and is awaited once the proxies are up.
echo "smoke: starting the console on :$WEB"
(
  cd "$ROOT/web" && exec env PM_PROXY_TARGET="http://127.0.0.1:$CP_HTTP" PM_WEB_DEV_ORIGINS=127.0.0.1,localhost \
    pnpm exec next dev -p "$WEB" -H 127.0.0.1 > "$SMOKE_DIR/logs/web.log" 2>&1
) &
pids+=($!)

# The fake GitHub (smoke/fake_github.py, run inside smoke.py): its HTTPS cert, which cp-go (PM_GITHUB_CA_FILE) and the
# Kotlin control plane (a throwaway truststore) trust, the key that signs its CI tokens, and the App key cp-go signs with.
GH="$SMOKE_DIR/github"
rm -f "$GH"/*
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=smoke-github" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -keyout "$GH/tls-key.pem" -out "$GH/tls-cert.pem" 2>/dev/null
openssl genrsa -out "$GH/oidc-key.pem" 2048 2>/dev/null
openssl genrsa -out "$GH/app-key.pem" 2048 2>/dev/null
keytool -importcert -noprompt -alias smoke-github -file "$GH/tls-cert.pem" \
  -keystore "$GH/truststore.p12" -storetype PKCS12 -storepass smoke-github >/dev/null 2>&1

RESULT_KEY=$(openssl rand -base64 32)
SECRET=smoke-$(openssl rand -hex 8)
echo "smoke: starting control plane on :$CP_HTTP"
(
  cd "$ROOT/control-plane" && exec env \
    PM_DB_URL="jdbc:postgresql://127.0.0.1:$SMOKE_CP_DB_PORT/proxymonster" \
    PM_HTTP_PORT="$CP_HTTP" PM_GRPC_PORT="$CP_GRPC" \
    PM_CP_CHILD_HTTP_PORT="$CP_CHILD_HTTP" PM_CP_CHILD_GRPC_PORT="$CP_CHILD_GRPC" \
    PM_CP_CHILD="$ROOT/control-plane/build/install/control-plane/bin/control-plane" \
    PM_DEV=true PM_AUTH_DEBUG=true PM_SECRET_TOKEN="$SECRET" PM_RESULT_KEY="$RESULT_KEY" \
    PM_GITHUB_APP_ID=1 PM_GITHUB_APP_PRIVATE_KEY_FILE="$GH/app-key.pem" PM_GITHUB_API_URL="https://127.0.0.1:$GITHUB_TLS" \
    PM_GITHUB_IDENTITY=commit-email \
    PM_CI_OIDC_ISSUERS="smoke=https://127.0.0.1:$GITHUB_TLS" PM_CI_OIDC_AUDIENCE=smoke-github \
    PM_GITHUB_CA_FILE="$GH/tls-cert.pem" \
    JAVA_OPTS="-Djavax.net.ssl.trustStore=$GH/truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=smoke-github" \
    "$SMOKE_DIR/bin/cp-go" > "$SMOKE_DIR/logs/control-plane.log" 2>&1
) &
pids+=($!)
for _ in $(seq 1 120); do
  curl -sf -m 2 "http://127.0.0.1:$CP_HTTP/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf -m 2 "http://127.0.0.1:$CP_HTTP/health" >/dev/null || { echo "smoke: control plane did not come up; see $SMOKE_DIR/logs/control-plane.log" >&2; exit 1; }

proxy() {
  local engine=$1 name=$2 port=$3 target_port=$4 row=${5:-$1}
  env PM_ENGINE="$engine" PM_DATASOURCE_NAME="$name" PM_DATASOURCE_TAGS=system:production \
    PM_PROXY_PORT="$port" PM_TARGET_HOST=127.0.0.1 PM_TARGET_PORT="$target_port" \
    PM_TARGET_DB=acme PM_TARGET_USER=acme PM_TARGET_PASSWORD=acme \
    PM_CONTROL_PLANE_GRPC="127.0.0.1:$CP_GRPC" PM_SECRET_TOKEN="$SECRET" \
    PM_ADVERTISE_ADDR="127.0.0.1:$port" \
    "$SMOKE_DIR/bin/goproxy" > "$SMOKE_DIR/logs/proxy-$row.log" 2>&1 &
  pids+=($!)
}
# The Athena proxy talks to the emulator (self-signed HTTPS) through the SDK's endpoint override, and serves
# its own HTTPS wire with a throwaway cert that pmon and the smoke clients trust through the advertised chain.
athena_proxy() {
  compose exec -T athena cat /tmp/ministack-tls/server.crt > "$SMOKE_DIR/athena/emulator-ca.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=smoke-athena" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -keyout "$SMOKE_DIR/athena/wire-key.pem" -out "$SMOKE_DIR/athena/wire-cert.pem" 2>/dev/null
  env PM_ENGINE=athena PM_DATASOURCE_NAME=smoke-athena PM_DATASOURCE_TAGS=system:production \
    PM_PROXY_PORT="$PROXY_ATHENA" PM_TARGET_DB=acme \
    PM_ATHENA_CONTEXT_PATH="$SMOKE_DIR/athena/contexts.db" \
    PM_CONTROL_PLANE_GRPC="127.0.0.1:$CP_GRPC" PM_SECRET_TOKEN="$SECRET" \
    PM_ADVERTISE_ADDR="127.0.0.1:$PROXY_ATHENA" \
    PM_TLS_CERT="$SMOKE_DIR/athena/wire-cert.pem" PM_TLS_KEY="$SMOKE_DIR/athena/wire-key.pem" \
    AWS_ENDPOINT_URL="https://127.0.0.1:$SMOKE_ATHENA_PORT" AWS_CA_BUNDLE="$SMOKE_DIR/athena/emulator-ca.pem" \
    AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
    "$SMOKE_DIR/bin/goproxy" > "$SMOKE_DIR/logs/proxy-athena.log" 2>&1 &
  pids+=($!)
}
echo "smoke: starting proxies on :$PROXY_MYSQL (mysql), :$PROXY_MYSQL_LCTN1 (mysql-lctn1), :$PROXY_PG (postgres), :$PROXY_ATHENA (athena)"
proxy mysql smoke-mysql "$PROXY_MYSQL" "$SMOKE_MYSQL_PORT"
proxy mysql smoke-mysql-lctn1 "$PROXY_MYSQL_LCTN1" "$SMOKE_MYSQL_LCTN1_PORT" mysql-lctn1
proxy postgres smoke-postgres "$PROXY_PG" "$SMOKE_PG_PORT"
athena_proxy
for _ in $(seq 1 60); do
  n=$(grep -l "datasource registered + catalog pushed" "$SMOKE_DIR"/logs/proxy-{mysql,mysql-lctn1,postgres,athena}.log 2>/dev/null | wc -l | tr -d ' ' || true)
  [ "$n" = 4 ] && break
  sleep 1
done
[ "$n" = 4 ] || { echo "smoke: a proxy did not register; see $SMOKE_DIR/logs/proxy-*.log" >&2; exit 1; }

for _ in $(seq 1 90); do
  curl -sf -m 3 -o /dev/null "http://127.0.0.1:$WEB/login" 2>/dev/null && break
  sleep 2
done
curl -sf -m 3 -o /dev/null "http://127.0.0.1:$WEB/login" || { echo "smoke: the console did not come up; see $SMOKE_DIR/logs/web.log" >&2; exit 1; }

# SMOKE_WAIT_FOR names a file a background browser install writes its exit status to.
if [ -n "${SMOKE_WAIT_FOR:-}" ]; then
  for _ in $(seq 1 300); do [ -s "$SMOKE_WAIT_FOR" ] && break; sleep 1; done
  [ "$(cat "$SMOKE_WAIT_FOR" 2>/dev/null)" = 0 ] || { echo "smoke: the browser install failed or timed out" >&2; exit 1; }
fi

args=(--cp "http://127.0.0.1:$CP_HTTP" --web "http://127.0.0.1:$WEB" --root "$ROOT" --cp-db "postgresql://proxymonster:proxymonster@127.0.0.1:$SMOKE_CP_DB_PORT/proxymonster" --pmon "$SMOKE_DIR/bin/pmon" --pmon-dir "$SMOKE_DIR/pmon" --pmon-port-base "$PMON_BASE" --logs "$SMOKE_DIR/logs")
args+=(--github "$GITHUB_TLS,$GITHUB_HTTP,$GH/tls-cert.pem,$GH/tls-key.pem,$GH/oidc-key.pem,1" --pm-ci "$SMOKE_DIR/bin/pm-ci")
args+=(--datasource "mysql:smoke-mysql:$PROXY_MYSQL" --datasource "mysql:smoke-mysql-lctn1:$PROXY_MYSQL_LCTN1:mysql-lctn1" --datasource "postgres:smoke-postgres:$PROXY_PG" --datasource "athena:smoke-athena:$PROXY_ATHENA")
[ -n "$ONLY" ] && args+=(--only "$ONLY")
[ -n "$ENGINE" ] && args+=(--engine "$ENGINE")
python3 "$ROOT/smoke/smoke.py" "${args[@]}"
