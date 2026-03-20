#!/usr/bin/env bash
set -euo pipefail

# Generate Testnet-1 (S=64, k=21) genesis artifacts
# Defaults can be overridden via environment variables.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

STATE_ROOT="${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}"
NETWORK_NAME="${NETWORK_NAME:-tn1}"
MEMPOOL_DIR="${MEMPOOL_DIR:-${STATE_ROOT}/tn1/mempool}"
SHARDS_INITIAL="${SHARDS_INITIAL:-64}"
COMMITTEE_K="${COMMITTEE_K:-21}"
TXS_PER_PAYLOAD="${TXS_PER_PAYLOAD:-256}"
FEATURES="${FEATURES:-0}"
RUST_LOG="${RUST_LOG:-info}"

export RUST_LOG
export TMPDIR="${TMPDIR:-/tmp}"
export CARGO_TARGET_TMPDIR="${CARGO_TARGET_TMPDIR:-/tmp}"

echo "[tn1] generating genesis: network=${NETWORK_NAME} shards=${SHARDS_INITIAL} k=${COMMITTEE_K} txs_per_payload=${TXS_PER_PAYLOAD}"

cargo run -p phantom-node --bin genesis_bootstrap -- \
  --mempool-dir "$MEMPOOL_DIR" \
  --network-name "$NETWORK_NAME" \
  --shards-initial "$SHARDS_INITIAL" \
  --committee-k "$COMMITTEE_K" \
  --txs-per-payload "$TXS_PER_PAYLOAD" \
  --features "$FEATURES"

echo "[tn1] genesis generation finished. Mempool path: '$MEMPOOL_DIR'."
