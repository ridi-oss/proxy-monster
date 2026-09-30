#!/usr/bin/env bash
# End-to-end smoke: datastores from compose, a freshly built control plane, one wire proxy per engine,
# and pmon, all from this checkout; then smoke.py drives every leg and prints a PASS/FAIL table.
#
#   smoke/run.sh                 full run, tears everything down at the end
#   smoke/run.sh --keep          leave the stack up for debugging (prints how to stop it)
#   smoke/run.sh --no-build      reuse the binaries from the last run
#   smoke/run.sh --only wire     run one leg (editor|browser|wire|pmon|workflow|audit|rate)
#   smoke/run.sh --engine mysql  run one engine (mysql|postgres)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SMOKE_DIR="${SMOKE_DIR:-${TMPDIR:-/tmp}/pm-smoke}"
PROJECT="${SMOKE_COMPOSE_PROJECT:-pm-smoke}"
export SMOKE_CP_DB_PORT="${SMOKE_CP_DB_PORT:-47010}"
export SMOKE_MYSQL_PORT="${SMOKE_MYSQL_PORT:-47011}"
export SMOKE_PG_PORT="${SMOKE_PG_PORT:-47012}"
CP_HTTP="${SMOKE_CP_HTTP_PORT:-47000}"
CP_GRPC="${SMOKE_CP_GRPC_PORT:-47001}"
PROXY_MYSQL="${SMOKE_PROXY_MYSQL_PORT:-47002}"
PROXY_PG="${SMOKE_PROXY_PG_PORT:-47003}"
PMON_BASE="${SMOKE_PMON_PORT_BASE:-47020}"
WEB="${SMOKE_WEB_PORT:-47004}"

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

mkdir -p "$SMOKE_DIR/logs" "$SMOKE_DIR/bin" "$SMOKE_DIR/pmon"
chmod 700 "$SMOKE_DIR/pmon"
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

if [ "$BUILD" = 1 ]; then
  echo "smoke: building control plane, goproxy, pmon"
  (cd "$ROOT" && ./gradlew --no-daemon -q :control-plane:installDist) > "$SMOKE_DIR/logs/build-cp.log" 2>&1
  (cd "$ROOT/goproxy" && go build -o "$SMOKE_DIR/bin/goproxy" ./cmd/goproxy)
  (cd "$ROOT/pmon" && go build -o "$SMOKE_DIR/bin/pmon" .)
fi

echo "smoke: starting datastores (compose project $PROJECT)"
compose down -v >/dev/null 2>&1 || true
compose up -d --wait > "$SMOKE_DIR/logs/compose.log" 2>&1

RESULT_KEY=$(openssl rand -base64 32)
SECRET=smoke-$(openssl rand -hex 8)
echo "smoke: starting control plane on :$CP_HTTP"
(
  cd "$ROOT/control-plane" && exec env \
    PM_DB_URL="jdbc:postgresql://127.0.0.1:$SMOKE_CP_DB_PORT/proxymonster" \
    PM_HTTP_PORT="$CP_HTTP" PM_GRPC_PORT="$CP_GRPC" \
    PM_DEV=true PM_AUTH_DEBUG=true PM_SECRET_TOKEN="$SECRET" PM_RESULT_KEY="$RESULT_KEY" \
    "$ROOT/control-plane/build/install/control-plane/bin/control-plane" > "$SMOKE_DIR/logs/control-plane.log" 2>&1
) &
pids+=($!)
for _ in $(seq 1 120); do
  curl -sf -m 2 "http://127.0.0.1:$CP_HTTP/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf -m 2 "http://127.0.0.1:$CP_HTTP/health" >/dev/null || { echo "smoke: control plane did not come up; see $SMOKE_DIR/logs/control-plane.log" >&2; exit 1; }

proxy() {
  local engine=$1 name=$2 port=$3 target_port=$4
  env PM_ENGINE="$engine" PM_DATASOURCE_NAME="$name" PM_DATASOURCE_TAGS=system:production \
    PM_PROXY_PORT="$port" PM_TARGET_HOST=127.0.0.1 PM_TARGET_PORT="$target_port" \
    PM_TARGET_DB=acme PM_TARGET_USER=acme PM_TARGET_PASSWORD=acme \
    PM_CONTROL_PLANE_GRPC="127.0.0.1:$CP_GRPC" PM_SECRET_TOKEN="$SECRET" \
    PM_ADVERTISE_ADDR="127.0.0.1:$port" \
    "$SMOKE_DIR/bin/goproxy" > "$SMOKE_DIR/logs/proxy-$engine.log" 2>&1 &
  pids+=($!)
}
echo "smoke: starting proxies on :$PROXY_MYSQL (mysql) and :$PROXY_PG (postgres)"
proxy mysql smoke-mysql "$PROXY_MYSQL" "$SMOKE_MYSQL_PORT"
proxy postgres smoke-postgres "$PROXY_PG" "$SMOKE_PG_PORT"
for _ in $(seq 1 60); do
  n=$(grep -l "datasource registered + catalog pushed" "$SMOKE_DIR/logs/proxy-mysql.log" "$SMOKE_DIR/logs/proxy-postgres.log" 2>/dev/null | wc -l | tr -d ' ' || true)
  [ "$n" = 2 ] && break
  sleep 1
done
[ "$n" = 2 ] || { echo "smoke: a proxy did not register; see $SMOKE_DIR/logs/proxy-*.log" >&2; exit 1; }

echo "smoke: starting the console on :$WEB"
(
  cd "$ROOT/web" && exec env PM_PROXY_TARGET="http://127.0.0.1:$CP_HTTP" PM_WEB_DEV_ORIGINS=127.0.0.1,localhost \
    pnpm exec next dev -p "$WEB" -H 127.0.0.1 > "$SMOKE_DIR/logs/web.log" 2>&1
) &
pids+=($!)
for _ in $(seq 1 90); do
  curl -sf -m 3 -o /dev/null "http://127.0.0.1:$WEB/login" 2>/dev/null && break
  sleep 2
done
curl -sf -m 3 -o /dev/null "http://127.0.0.1:$WEB/login" || { echo "smoke: the console did not come up; see $SMOKE_DIR/logs/web.log" >&2; exit 1; }

args=(--cp "http://127.0.0.1:$CP_HTTP" --web "http://127.0.0.1:$WEB" --root "$ROOT" --cp-db "postgresql://proxymonster:proxymonster@127.0.0.1:$SMOKE_CP_DB_PORT/proxymonster" --pmon "$SMOKE_DIR/bin/pmon" --pmon-dir "$SMOKE_DIR/pmon" --pmon-port-base "$PMON_BASE" --logs "$SMOKE_DIR/logs")
args+=(--datasource "mysql:smoke-mysql:$PROXY_MYSQL" --datasource "postgres:smoke-postgres:$PROXY_PG")
[ -n "$ONLY" ] && args+=(--only "$ONLY")
[ -n "$ENGINE" ] && args+=(--engine "$ENGINE")
python3 "$ROOT/smoke/smoke.py" "${args[@]}"
