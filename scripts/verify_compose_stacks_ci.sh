#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
ROOT_PROJECT="${ROOT_PROJECT:-pcsmoke-root-$RANDOM}"
DEPLOY_PROJECT="${DEPLOY_PROJECT:-pcsmoke-deploy-$RANDOM}"
SKIP_COMPOSE_BUILD="${SKIP_COMPOSE_BUILD:-0}"

ROOT_NODE1_PORT="${ROOT_NODE1_PORT:-28081}"
ROOT_NODE2_PORT="${ROOT_NODE2_PORT:-28082}"
ROOT_NODE3_PORT="${ROOT_NODE3_PORT:-28083}"
ROOT_PROMETHEUS_PORT="${ROOT_PROMETHEUS_PORT:-19090}"
ROOT_GRAFANA_PORT="${ROOT_GRAFANA_PORT:-13000}"

DEPLOY_NODE1_PORT="${DEPLOY_NODE1_PORT:-38081}"
DEPLOY_NODE2_PORT="${DEPLOY_NODE2_PORT:-38082}"
DEPLOY_NODE3_PORT="${DEPLOY_NODE3_PORT:-38083}"
DEPLOY_PROMETHEUS_PORT="${DEPLOY_PROMETHEUS_PORT:-29090}"

ROOT_NODE1_TOKEN="${ROOT_NODE1_TOKEN:-root-compose-token-1}"
ROOT_NODE2_TOKEN="${ROOT_NODE2_TOKEN:-root-compose-token-2}"
ROOT_NODE3_TOKEN="${ROOT_NODE3_TOKEN:-root-compose-token-3}"
DEPLOY_NODE1_TOKEN="${DEPLOY_NODE1_TOKEN:-deploy-compose-token-1}"
DEPLOY_NODE2_TOKEN="${DEPLOY_NODE2_TOKEN:-deploy-compose-token-2}"
DEPLOY_NODE3_TOKEN="${DEPLOY_NODE3_TOKEN:-deploy-compose-token-3}"
GRAFANA_USER="${GRAFANA_USER:-compose-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-compose-strong-password-123}"

cleanup() {
  root_compose logs --no-color > "$WORK_DIR/root-compose.log" 2>&1 || true
  deploy_compose logs --no-color > "$WORK_DIR/deploy-compose.log" 2>&1 || true
  root_compose down -v --remove-orphans >/dev/null 2>&1 || true
  deploy_compose down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "${KEEP_WORK_DIR:-0}" != "1" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

wait_http_ok() {
  local url="$1"
  local attempts="${2:-120}"
  for _ in $(seq 1 "$attempts"); do
    if curl --silent --show-error --fail "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for $url" >&2
  return 1
}

wait_http_status() {
  local expected="$1"
  local url="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "$attempts"); do
    local code
    code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$url" || true)"
    if [ "$code" = "$expected" ]; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for $url to return $expected" >&2
  return 1
}

wait_prometheus_targets() {
  local port="$1"
  local expected="$2"
  local attempts="${3:-120}"
  local url="http://127.0.0.1:${port}/api/v1/targets"
  for _ in $(seq 1 "$attempts"); do
    local body
    body="$(curl --silent --show-error --fail "$url" || true)"
    if [ -n "$body" ] && python3 - "$expected" <<'PY' <<<"$body"; then
import json
import sys

expected = int(sys.argv[1])
payload = json.load(sys.stdin)
targets = payload["data"]["activeTargets"]
matching = [
    t for t in targets
    if t.get("labels", {}).get("job") == "phantom-status"
    and t.get("health") == "up"
]
sys.exit(0 if len(matching) >= expected else 1)
PY
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for Prometheus phantom-status targets on port $port" >&2
  return 1
}

check_network_ids() {
  local token1="$1"
  local token2="$2"
  local token3="$3"
  local port1="$4"
  local port2="$5"
  local port3="$6"
  local out="$7"
  curl --silent --show-error --fail -H "Authorization: Bearer ${token1}" "http://127.0.0.1:${port1}/status" > "${out}-node1.json"
  curl --silent --show-error --fail -H "Authorization: Bearer ${token2}" "http://127.0.0.1:${port2}/status" > "${out}-node2.json"
  curl --silent --show-error --fail -H "Authorization: Bearer ${token3}" "http://127.0.0.1:${port3}/status" > "${out}-node3.json"
  python3 - "${out}-node1.json" "${out}-node2.json" "${out}-node3.json" <<'PY'
import json
import sys
from pathlib import Path

docs = [json.loads(Path(p).read_text()) for p in sys.argv[1:]]
def extract_network_id(doc):
    if "network_id" in doc:
        return doc["network_id"]
    genesis = doc.get("genesis")
    if isinstance(genesis, dict) and "network_id" in genesis:
        return genesis["network_id"]
    raise KeyError("network_id")

network_ids = {extract_network_id(doc) for doc in docs}
assert len(network_ids) == 1, docs
for doc in docs:
    assert doc["ok"] is True, doc
PY
}

root_compose() {
  (
    cd "$ROOT_DIR"
    env \
      NODE1_STATUS_AUTH_TOKEN="$ROOT_NODE1_TOKEN" \
      NODE2_STATUS_AUTH_TOKEN="$ROOT_NODE2_TOKEN" \
      NODE3_STATUS_AUTH_TOKEN="$ROOT_NODE3_TOKEN" \
      NODE1_PORT="$ROOT_NODE1_PORT" \
      NODE2_PORT="$ROOT_NODE2_PORT" \
      NODE3_PORT="$ROOT_NODE3_PORT" \
      PROMETHEUS_PORT="$ROOT_PROMETHEUS_PORT" \
      GRAFANA_PORT="$ROOT_GRAFANA_PORT" \
      GRAFANA_USER="$GRAFANA_USER" \
      GRAFANA_PASSWORD="$GRAFANA_PASSWORD" \
      RUST_LOG="${RUST_LOG:-info}" \
      docker compose -p "$ROOT_PROJECT" "$@"
  )
}

deploy_compose() {
  (
    cd "$ROOT_DIR"
    env \
      NODE1_STATUS_AUTH_TOKEN="$DEPLOY_NODE1_TOKEN" \
      NODE2_STATUS_AUTH_TOKEN="$DEPLOY_NODE2_TOKEN" \
      NODE3_STATUS_AUTH_TOKEN="$DEPLOY_NODE3_TOKEN" \
      NODE1_PORT="$DEPLOY_NODE1_PORT" \
      NODE2_PORT="$DEPLOY_NODE2_PORT" \
      NODE3_PORT="$DEPLOY_NODE3_PORT" \
      PROMETHEUS_PORT="$DEPLOY_PROMETHEUS_PORT" \
      RUST_LOG="${RUST_LOG:-info}" \
      docker compose -f deploy/docker-compose.yml -p "$DEPLOY_PROJECT" "$@"
  )
}

require_cmd docker
require_cmd curl
require_cmd python3

docker info >/dev/null 2>&1

root_compose down -v --remove-orphans >/dev/null 2>&1 || true
deploy_compose down -v --remove-orphans >/dev/null 2>&1 || true

if [ "$SKIP_COMPOSE_BUILD" != "1" ]; then
  root_compose build genesis node1 node2 node3 node1-status node2-status node3-status
fi
root_compose --profile observability up -d
wait_http_ok "http://127.0.0.1:${ROOT_NODE1_PORT}/healthz"
wait_http_ok "http://127.0.0.1:${ROOT_NODE2_PORT}/healthz"
wait_http_ok "http://127.0.0.1:${ROOT_NODE3_PORT}/healthz"
wait_http_status 401 "http://127.0.0.1:${ROOT_NODE1_PORT}/validator/control"
root_compose exec -T node1 test -s /data/mempool/genesis_note.bin
root_compose exec -T node2 test -s /data/mempool/genesis_note.bin
root_compose exec -T node3 test -s /data/mempool/genesis_note.bin
if root_compose logs --no-color node1 node2 node3 | grep -q 'Finalitäts-Verifikation deaktiviert'; then
  echo "compose root stack unexpectedly disabled finality verification despite canonical genesis" >&2
  exit 1
fi
check_network_ids "$ROOT_NODE1_TOKEN" "$ROOT_NODE2_TOKEN" "$ROOT_NODE3_TOKEN" "$ROOT_NODE1_PORT" "$ROOT_NODE2_PORT" "$ROOT_NODE3_PORT" "$WORK_DIR/root-status"
wait_http_ok "http://127.0.0.1:${ROOT_PROMETHEUS_PORT}/-/healthy"
wait_http_ok "http://127.0.0.1:${ROOT_GRAFANA_PORT}/api/health"
wait_prometheus_targets "$ROOT_PROMETHEUS_PORT" 3
printf 'PASS root_compose_smoke\n'

root_compose down -v --remove-orphans

if [ "$SKIP_COMPOSE_BUILD" != "1" ]; then
  deploy_compose build genesis node1 node2 node3 node1-status node2-status node3-status
fi
deploy_compose --profile observability up -d
wait_http_ok "http://127.0.0.1:${DEPLOY_NODE1_PORT}/healthz"
wait_http_ok "http://127.0.0.1:${DEPLOY_NODE2_PORT}/healthz"
wait_http_ok "http://127.0.0.1:${DEPLOY_NODE3_PORT}/healthz"
wait_http_status 401 "http://127.0.0.1:${DEPLOY_NODE1_PORT}/validator/control"
deploy_compose exec -T node1 test -s /data/mempool/genesis_note.bin
deploy_compose exec -T node2 test -s /data/mempool/genesis_note.bin
deploy_compose exec -T node3 test -s /data/mempool/genesis_note.bin
if deploy_compose logs --no-color node1 node2 node3 | grep -q 'Finalitäts-Verifikation deaktiviert'; then
  echo "compose deploy stack unexpectedly disabled finality verification despite canonical genesis" >&2
  exit 1
fi
check_network_ids "$DEPLOY_NODE1_TOKEN" "$DEPLOY_NODE2_TOKEN" "$DEPLOY_NODE3_TOKEN" "$DEPLOY_NODE1_PORT" "$DEPLOY_NODE2_PORT" "$DEPLOY_NODE3_PORT" "$WORK_DIR/deploy-status"
wait_http_ok "http://127.0.0.1:${DEPLOY_PROMETHEUS_PORT}/-/healthy"
wait_prometheus_targets "$DEPLOY_PROMETHEUS_PORT" 3
printf 'PASS deploy_compose_smoke\n'

printf 'ALL_COMPOSE_SMOKE_CHECKS_PASSED\n'
