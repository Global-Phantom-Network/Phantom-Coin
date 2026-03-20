#!/usr/bin/env bash
set -euo pipefail

# E2E Genesis Bootstrap Script
# - erzeugt genesis_note.bin
# - startet StatusServe
# - ruft /genesis/bootstrap auf
# - prüft /status und /metrics
# - optional: prüft den Emissions-Control-Plane-Pfad (`/mint/template`)
# - optional: prüft Attestor-Claims-Proof Endpoint

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
STATE_ROOT="${STATE_ROOT:-${TMPDIR:-/tmp}/phantom-coin/e2e-genesis}"
STORE_DIR="${STORE_DIR:-${STATE_ROOT}/data}"
MEMPOOL_DIR="${MEMPOOL_DIR:-${STORE_DIR}/mempool}"
ADDR="${ADDR:-127.0.0.1:8080}"
NETWORK_NAME="${NETWORK_NAME:-phantom-dev}"
SHARDS_INITIAL="${SHARDS_INITIAL:-64}"
COMMITTEE_K="${COMMITTEE_K:-21}"
TXS_PER_PAYLOAD="${TXS_PER_PAYLOAD:-256}"
FEATURES="${FEATURES:-0}"

# Gates (konfigurierbar via Env)
FINALITY_GATE_ENABLE="${FINALITY_GATE_ENABLE:-0}"
FINALITY_MAX_SEC="${FINALITY_MAX_SEC:-5}"
CLAIMS_GATE_ENABLE="${CLAIMS_GATE_ENABLE:-1}"

# 1) genesis_note.bin erzeugen
cargo run -q -p phantom-node --bin genesis_bootstrap -- \
  --mempool-dir "${MEMPOOL_DIR}" \
  --network-name "${NETWORK_NAME}" \
  --shards-initial "${SHARDS_INITIAL}" \
  --committee-k "${COMMITTEE_K}" \
  --txs-per-payload "${TXS_PER_PAYLOAD}" \
  --features "${FEATURES}"

# 2) Status-Server starten (Hintergrund)
RUST_LOG=${RUST_LOG:-info} \
cargo run -q -p phantom-node --bin phantom-node -- \
  status-serve \
  --addr "${ADDR}" \
  --store-dir "${STORE_DIR}" \
  --mempool-dir "${MEMPOOL_DIR}" \
  --fsync &
NODE_PID=$!
trap 'kill ${NODE_PID} >/dev/null 2>&1 || true' EXIT

# Warten bis Server bereit (bis zu ~60s) und Liveness prüfen
READY=0
for i in $(seq 1 120); do
  if curl -sf "http://${ADDR}/readyz" >/dev/null; then
    READY=1; break
  fi
  # Prozess noch am Leben?
  if ! kill -0 ${NODE_PID} 2>/dev/null; then
    echo "ERROR: status-serve exited before readiness" >&2
    exit 1
  fi
  sleep 0.5
done
if [ "$READY" != "1" ]; then
  echo "ERROR: /readyz not ready within timeout" >&2
  exit 1
fi

# 3) Bootstrap
BOOTSTRAP_JSON=$(curl -s -X POST "http://${ADDR}/genesis/bootstrap")
echo "Bootstrap: ${BOOTSTRAP_JSON}"
echo "${BOOTSTRAP_JSON}" | grep -q '"ok":true' || { echo "ERROR: bootstrap failed" >&2; exit 1; }

# 4) Status prüfen
STATUS_JSON=$(curl -s "http://${ADDR}/status")
echo "Status: ${STATUS_JSON}" | sed 's/.*/STATUS RECEIVED/' >/dev/null  # quiet

echo "Status network_id:" $(echo "${STATUS_JSON}" | sed 's/\\/\\\\/g' | awk -F'"network_id":"' '{print $2}' | awk -F'"' '{print $1}')

# 5) Metriken prüfen (Basis)
METRICS=$(curl -s "http://${ADDR}/metrics")
echo "Metrics snippet:"
echo "${METRICS}" | grep -E 'pc_network_id|pc_genesis_height' || {
  echo "ERROR: metrics missing pc_network_id/pc_genesis_height" >&2
  exit 1
}

# 6) Optional: Emissions-Control-Plane-Gate
if [ "${FINALITY_GATE_ENABLE}" = "1" ]; then
  echo "Running emission control-plane gate (legacy FINALITY_GATE_ENABLE)..."
  echo "NOTE: /state/apply_mint_with_index was removed; this script now checks /mint/template reachability instead of direct finality mutation."
  TEMPLATE_JSON=$(curl -sS "http://${ADDR}/mint/template") || {
    echo "ERROR: /mint/template failed" >&2
    exit 1
  }
  echo "${TEMPLATE_JSON}" | grep -q '"round_id":"[0-9a-f]\{64\}"' || {
    echo "ERROR: mint/template missing round_id" >&2
    exit 1
  }
  echo "${TEMPLATE_JSON}" | grep -q '"network_id":"[0-9a-f]\{64\}"' || {
    echo "ERROR: mint/template missing network_id" >&2
    exit 1
  }
  echo "${TEMPLATE_JSON}" | grep -q '"target_bits":' || {
    echo "ERROR: mint/template missing target_bits" >&2
    exit 1
  }
  echo "Emission control-plane gate OK"
fi

# 7) Optional: Claims/Proof-Gate (Attestor)
if [ "${CLAIMS_GATE_ENABLE}" = "1" ]; then
  echo "Running attestor payout proof gate…"
  RCPT_HEX=$(openssl rand -hex 32 2>/dev/null || true)
  if [ -z "${RCPT_HEX}" ]; then RCPT_HEX="$(python3 - <<'PY'
import os, binascii
print(binascii.hexlify(os.urandom(32)).decode())
PY
)"; fi
  REQ=$(cat <<JSON
{
  "fees_total": 123456,
  "fee_params": null,
  "seats": [{"recipient_id": "${RCPT_HEX}"}],
  "recipient_id": "${RCPT_HEX}"
}
JSON
)
  RESP=$(curl -sS -X POST "http://${ADDR}/consensus/attestor_payout_proof" \
    -H 'content-type: application/json' -d "${REQ}") || { echo "ERROR: payout_proof request failed" >&2; exit 1; }
  echo "Proof resp: ${RESP}" | sed 's/.*/PROOF RECEIVED/' >/dev/null
  echo "${RESP}" | grep -q '"ok":true' || { echo "ERROR: payout_proof not ok" >&2; exit 1; }
  echo "${RESP}" | grep -q '"payout_root":"[0-9a-f]\{64\}"' || { echo "ERROR: payout_root missing" >&2; exit 1; }
fi

echo "OK: E2E Genesis completed"
