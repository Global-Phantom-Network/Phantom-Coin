#!/usr/bin/env bash
set -euo pipefail

# Phantom-Coin localnet starter
# - Startet Phantom-Node QUIC-Listener und Prometheus/Grafana Observability
# - Erzeugt eine genesis.toml, falls nicht vorhanden (benötigt: openssl, b3sum)
# - Exponiert Metriken unter 127.0.0.1:9100 und startet Prometheus/Grafana per Docker Compose

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
GENESIS_TOML="${ROOT_DIR}/genesis.toml"
STATE_ROOT="${PHANTOM_LOCAL_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/localnet}"
STORE_DIR="${STATE_ROOT}/node"
METRICS_LOG="${STATE_ROOT}/metrics.log"
METRICS_PID="${STATE_ROOT}/metrics.pid"
QUIC_LOG="${STATE_ROOT}/quic_listen.log"
QUIC_PID="${STATE_ROOT}/quic_listen.pid"
COMPOSE_FILE="${ROOT_DIR}/docs/observability/docker-compose.yml"

check_prereqs() {
  command -v cargo >/dev/null 2>&1 || { echo "cargo nicht gefunden"; exit 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl nicht gefunden (für genesis_note)"; exit 1; }
  command -v b3sum >/dev/null 2>&1 || { echo "b3sum nicht gefunden (für commitment). Installiere z. B. via 'brew install b3sum'"; exit 1; }
  command -v docker >/dev/null 2>&1 || { echo "docker nicht gefunden"; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "docker compose plugin nicht gefunden"; exit 1; }
}

ensure_build() {
  if ! command -v phantom-node >/dev/null 2>&1; then
    echo "Baue phantom-node (release) ..."
    (cd "$ROOT_DIR" && cargo build --workspace --release)
    export PATH="$ROOT_DIR/target/release:$PATH"
  fi
}

ensure_genesis() {
  if [[ ! -f "$GENESIS_TOML" ]]; then
    echo "Erzeuge genesis.toml ..."
    GENESIS_NOTE=$(openssl rand -hex 32)
    COMMITMENT=$(printf "%s" "$GENESIS_NOTE" | xxd -r -p | b3sum --no-names | awk '{print $1}')
    cat > "$GENESIS_TOML" <<EOF
genesis_note = "$GENESIS_NOTE"
commitment   = "$COMMITMENT"

[consensus]
k = 21
EOF
    echo "genesis.toml erstellt: $GENESIS_TOML"
  fi
}

start_observability() {
  echo "Starte Prometheus und Grafana via docker compose ..."
  (cd "$ROOT_DIR/docs/observability" && docker compose -f "$COMPOSE_FILE" up -d)
}

start_metrics() {
  mkdir -p "$STATE_ROOT"
  echo "Starte Metrics-HTTP (127.0.0.1:9100) ..."
  nohup phantom-node p2p-metrics-serve --addr 127.0.0.1:9100 > "$METRICS_LOG" 2>&1 &
  echo $! > "$METRICS_PID"
}

start_quic_listener() {
  mkdir -p "$STORE_DIR"
  echo "Starte QUIC-Listener (127.0.0.1:9000) ..."
  nohup phantom-node p2p-quic-listen \
    --addr 127.0.0.1:9000 \
    --genesis "$GENESIS_TOML" \
    --store-dir "$STORE_DIR" \
    --tx-proposer \
    --tx-proposer-interval-ms 5000 \
    > "$QUIC_LOG" 2>&1 &
  echo $! > "$QUIC_PID"
}

main() {
  check_prereqs
  ensure_build
  ensure_genesis
  start_observability
  start_metrics
  start_quic_listener
  echo "Lokales Netz gestartet."
  echo "Prometheus:  http://localhost:9090"
  echo "Grafana:     http://localhost:3000 (Credentials via GRAFANA_USER/GRAFANA_PASSWORD)"
  echo "Metriken:    http://localhost:9100/metrics"
  echo "State:       $STATE_ROOT"
  echo "Logs:        $METRICS_LOG, $QUIC_LOG"
}

main "$@"
