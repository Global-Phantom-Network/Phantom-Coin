#!/usr/bin/env bash
set -euo pipefail

# Phantom-Coin localnet starter
# - Startet Phantom-Node QUIC-Listener und Prometheus/Grafana Observability
# - Erzeugt eine genesis.toml, falls nicht vorhanden (benötigt: openssl, b3sum)
# - Exponiert Metriken unter 127.0.0.1:9100 und startet Prometheus/Grafana per Docker Compose

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
GENESIS_TOML="${ROOT_DIR}/genesis.toml"
STORE_DIR="${ROOT_DIR}/pc-data"
COMPOSE_FILE="${ROOT_DIR}/docs/observability/docker-compose.yml"

check_prereqs() {
  command -v cargo >/dev/null 2>&1 || { echo "cargo nicht gefunden"; exit 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl nicht gefunden (für genesis_note)"; exit 1; }
  command -v b3sum >/dev/null 2>&1 || { echo "b3sum nicht gefunden (für commitment). Installiere z. B. via 'brew install b3sum'"; exit 1; }
  command -v docker >/dev/null 2>&1 || { echo "docker nicht gefunden"; exit 1; }
  command -v docker-compose >/dev/null 2>&1 || true
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
[consensus]
k = 21

genesis_note = "$GENESIS_NOTE"
commitment   = "$COMMITMENT"
EOF
    echo "genesis.toml erstellt: $GENESIS_TOML"
  fi
}

start_observability() {
  echo "Starte Prometheus und Grafana via docker-compose ..."
  (cd "$ROOT_DIR/docs/observability" && docker compose -f "$COMPOSE_FILE" up -d)
}

start_metrics() {
  echo "Starte Metrics-HTTP (127.0.0.1:9100) ..."
  nohup phantom-node P2pMetricsServe --addr 127.0.0.1:9100 > "$ROOT_DIR/metrics.log" 2>&1 &
  echo $! > "$ROOT_DIR/metrics.pid"
}

start_quic_listener() {
  mkdir -p "$STORE_DIR"
  echo "Starte QUIC-Listener (127.0.0.1:9000) ..."
  nohup phantom-node P2pQuicListen \
    --addr 127.0.0.1:9000 \
    --genesis "$GENESIS_TOML" \
    --store_dir "$STORE_DIR" \
    --fsync false \
    --tx_proposer true \
    --tx_proposer_interval_ms 5000 \
    > "$ROOT_DIR/quic_listen.log" 2>&1 &
  echo $! > "$ROOT_DIR/quic_listen.pid"
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
  echo "Grafana:     http://localhost:3000 (admin/admin)"
  echo "Metriken:    http://localhost:9100/metrics"
  echo "Logs:        $ROOT_DIR/metrics.log, $ROOT_DIR/quic_listen.log"
}

main "$@"
