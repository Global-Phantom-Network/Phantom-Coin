#!/usr/bin/env bash
set -euo pipefail

# Multi-Node Local Setup - Startet 3 Phantom-Nodes lokal auf verschiedenen Ports
# Verwendung: bash scripts/testnets/multi_node_local.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STATE_ROOT="${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}"

cd "$REPO_ROOT"

# Cleanup alte Daten (optional)
if [ "${CLEAN:-0}" = "1" ]; then
  echo "Cleaning up old node data..."
  rm -rf "$STATE_ROOT"
fi

# Genesis für alle Nodes (shared)
echo "Generating shared genesis..."
mkdir -p "$STATE_ROOT/shared/mempool"
NETWORK_NAME=local-multi SHARDS_INITIAL=1 COMMITTEE_K=21 \
  MEMPOOL_DIR="$STATE_ROOT/shared/mempool" \
  bash scripts/testnets/genesis_tn0.sh

# Genesis kopieren zu allen Node-Dirs
for i in 1 2 3; do
  mkdir -p "$STATE_ROOT/node$i/mempool"
  cp "$STATE_ROOT/shared/mempool/genesis_note.bin" "$STATE_ROOT/node$i/mempool/"
done

echo ""
echo "=== Starting 3 Nodes ==="
echo "Node 1: http://127.0.0.1:18081"
echo "Node 2: http://127.0.0.1:18082"
echo "Node 3: http://127.0.0.1:18083"
echo ""

# Starte Nodes im Hintergrund
RUST_LOG=info cargo run -q -p phantom-node -- \
  status-serve \
  --addr 127.0.0.1:18081 \
  --mempool-dir "$STATE_ROOT/node1/mempool" \
  --store-dir "$STATE_ROOT/node1" \
  --fsync \
  --no-require-auth \
  --unsafe-confirm > "$STATE_ROOT/node1.log" 2>&1 &
NODE1_PID=$!

RUST_LOG=info cargo run -q -p phantom-node -- \
  status-serve \
  --addr 127.0.0.1:18082 \
  --mempool-dir "$STATE_ROOT/node2/mempool" \
  --store-dir "$STATE_ROOT/node2" \
  --fsync \
  --no-require-auth \
  --unsafe-confirm > "$STATE_ROOT/node2.log" 2>&1 &
NODE2_PID=$!

RUST_LOG=info cargo run -q -p phantom-node -- \
  status-serve \
  --addr 127.0.0.1:18083 \
  --mempool-dir "$STATE_ROOT/node3/mempool" \
  --store-dir "$STATE_ROOT/node3" \
  --fsync \
  --no-require-auth \
  --unsafe-confirm > "$STATE_ROOT/node3.log" 2>&1 &
NODE3_PID=$!

# Speichere PIDs
echo "$NODE1_PID" > "$STATE_ROOT/node1.pid"
echo "$NODE2_PID" > "$STATE_ROOT/node2.pid"
echo "$NODE3_PID" > "$STATE_ROOT/node3.pid"

echo "Nodes started with PIDs: $NODE1_PID, $NODE2_PID, $NODE3_PID"
echo "State root: $STATE_ROOT"
echo "Logs: $STATE_ROOT/node{1,2,3}.log"
echo ""

# Warte kurz und prüfe Health
sleep 3

echo "=== Health Checks ==="
for i in 1 2 3; do
  PORT=$((18080 + i))
  if curl -sf http://127.0.0.1:$PORT/healthz > /dev/null 2>&1; then
    echo "✓ Node $i (port $PORT) is healthy"
  else
    echo "✗ Node $i (port $PORT) is NOT healthy"
  fi
done

echo ""
echo "=== To view status: ==="
echo "curl http://127.0.0.1:18081/status | jq ."
echo "curl http://127.0.0.1:18082/status | jq ."
echo "curl http://127.0.0.1:18083/status | jq ."
echo ""
echo "=== To stop all nodes: ==="
echo "bash scripts/testnets/stop_multi_node.sh"
echo "# or manually: kill $NODE1_PID $NODE2_PID $NODE3_PID"
echo ""
echo "Nodes are running in background. Press Ctrl+C to exit this script (nodes keep running)."
echo "Monitoring logs with 'tail -f'..."
echo ""

# Optional: tail logs
tail -f "$STATE_ROOT/node1.log" "$STATE_ROOT/node2.log" "$STATE_ROOT/node3.log"
